// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"localhost/client/go/outline/macoscli/internal/redact"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
	"localhost/client/go/outline/macoscli/internal/tunnel"
)

// runCleanup restores routes, DNS and IPv6 from the state file left by a
// session that didn't shut down cleanly. If lockdown is on, it re-installs
// it in its disconnected form (it never removes it; only unlock does).
func runCleanup(ctx context.Context, args []string, e env) int {
	flags := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	flags.SetOutput(e.stderr)
	logLevel := flags.String("log-level", "info", "log level: debug, info, warn or error")
	dryRun := flags.Bool("dry-run", false, "print what would be restored; change nothing")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(e.stderr, "outline-cli cleanup: unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return exitUsage
	}
	logger, err := newLogger(e.stderr, *logLevel, &redact.Secrets{})
	if err != nil {
		fmt.Fprintf(e.stderr, "outline-cli cleanup: %v\n", err)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintf(e.stderr, "outline-cli cleanup: %v\n", err)
		return exitError
	}
	store := state.FileStore{Dir: e.stateDir}
	lk := e.lockdownManager(logger)

	if *dryRun {
		st, err := store.Load()
		if errors.Is(err, fs.ErrPermission) {
			return fail(fmt.Errorf("%s is only readable by root; run: sudo outline-cli cleanup --dry-run", store.Path()))
		}
		if err != nil {
			return fail(err)
		}
		if locked, err := lk.Status(); err == nil && locked != nil {
			fmt.Fprintf(e.stdout, "lockdown is on (%s): cleanup would re-install its pf rules and hosts block\n", strings.Join(locked.Entries, ", "))
		}
		if st == nil {
			fmt.Fprintln(e.stdout, "nothing to clean up: no state file")
			return exitOK
		}
		fmt.Fprintf(e.stdout, "cleanup --dry-run: nothing will be changed\n  %s\n  cleanup would run:\n", describeSession(st))
		dry := &sysexec.DryRun{Next: e.exec, IsReadOnly: sysrouter.IsReadOnly, Out: e.stdout}
		if _, err := tunnel.Cleanup(ctx, &sysrouter.Router{Exec: dry}, state.NewMemStore(st), logger); err != nil {
			return fail(err)
		}
		return exitOK
	}

	if e.geteuid() != 0 {
		return fail(errors.New("cleanup changes routes and DNS, so it must run as root: sudo outline-cli cleanup"))
	}
	unlock, err := store.Lock()
	if errors.Is(err, state.ErrLocked) {
		return fail(errors.New("outline-cli is still running; stop it with Ctrl-C (it restores the network itself)"))
	}
	if err != nil {
		return fail(err)
	}
	defer unlock()

	restored, err := tunnel.Cleanup(ctx, &sysrouter.Router{Exec: e.exec}, store, logger)
	// The lockdown is re-installed whatever happened above: after a crash
	// while connected its hosts block is missing, and after a reboot its pf
	// rules are gone.
	locked, lockErr := lk.Status()
	if lockErr == nil && locked != nil {
		lockErr = lk.Disconnected(ctx)
		if lockErr == nil {
			fmt.Fprintf(e.stdout, "lockdown re-installed: %s are blocked while the VPN is off\n", strings.Join(locked.Entries, ", "))
		}
	}
	if lockErr != nil {
		lockErr = fmt.Errorf("re-installing the lockdown failed: %w", lockErr)
	}
	if err != nil {
		return fail(fmt.Errorf("%w\nThe state file %s still lists what is left; run cleanup again, or see docs/macos-cli/README.md for manual recovery", errors.Join(err, lockErr), store.Path()))
	}
	if lockErr != nil {
		return fail(lockErr)
	}
	if restored == nil {
		fmt.Fprintln(e.stdout, "nothing to clean up: no state file")
		return exitOK
	}
	fmt.Fprintf(e.stdout, "restored the network: %s\n", describeSession(restored))
	return exitOK
}

func describeSession(st *state.State) string {
	return fmt.Sprintf("session of pid %d started %s on %q (%s), %d route(s) recorded",
		st.PID, st.StartedAt.Local().Format(time.DateTime), st.Service, st.Interface, len(st.Routes))
}
