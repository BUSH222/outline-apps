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

	"localhost/client/go/outline/macoscli/internal/lockdown"
	"localhost/client/go/outline/macoscli/internal/redact"
	"localhost/client/go/outline/macoscli/internal/state"
)

// runLockdown blocks the vpn_only domains of the rules file while the VPN is
// off: a pf anchor for the addresses learned while connected, and an
// /etc/hosts block for the names.
func runLockdown(ctx context.Context, args []string, e env) int {
	flags := flag.NewFlagSet("lockdown", flag.ContinueOnError)
	flags.SetOutput(e.stderr)
	rulesFlag := flags.String("rules", "", "rules file (default: ~/.config/outline-cli/rules.yaml of the invoking user)")
	logLevel := flags.String("log-level", "info", "log level: debug, info, warn or error")
	dryRun := flags.Bool("dry-run", false, "print what would be installed; change nothing")
	if code, ok := parseFlags(flags, args, e, "lockdown"); !ok {
		return code
	}
	logger, err := newLogger(e.stderr, *logLevel, &redact.Secrets{})
	if err != nil {
		fmt.Fprintf(e.stderr, "outline-cli lockdown: %v\n", err)
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintf(e.stderr, "outline-cli lockdown: %v\n", err)
		return exitError
	}

	loc, err := resolveRulesPath(*rulesFlag, e.getenv, e.lookupUser)
	if err != nil {
		return fail(err)
	}
	r, _, err := loadRules(loc)
	if err != nil {
		return fail(err)
	}
	if len(r.VPNOnly) == 0 {
		return fail(fmt.Errorf("the rules file %s has no vpn_only entries, so there is nothing to lock down", loc.Path))
	}
	lk := e.lockdownManager(logger)

	if *dryRun {
		fmt.Fprintln(e.stdout, "outline-cli lockdown --dry-run: nothing will be changed")
		fmt.Fprintf(e.stdout, "  rules file: %s\n  vpn_only:   %s\n", loc.Path, strings.Join(r.VPNOnly, ", "))
		fmt.Fprintf(e.stdout, "  %s would get:\n%s", e.hostsPath, indent(lockdown.HostsWithBlock("", r.ExactVPNOnly()), "    "))
		addrs, err := lk.TableAddrs(&lockdown.State{Entries: r.VPNOnly})
		if errors.Is(err, fs.ErrPermission) {
			fmt.Fprintln(e.stdout, "  pf anchor "+lockdown.Anchor+": (the learned addresses are only readable by root)")
			return exitOK
		}
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(e.stdout, "  pf anchor %s would get:\n%s", lockdown.Anchor, indent(lockdown.AnchorRules(addrs, ""), "    "))
		return exitOK
	}

	unlock, err := lockAsRoot(e, "lockdown")
	if err != nil {
		return fail(err)
	}
	defer unlock()
	if err := lk.Lock(ctx, r.VPNOnly); err != nil {
		return fail(fmt.Errorf("%w\nRun lockdown again to retry, or unlock to remove what was installed", err))
	}
	st, _ := lk.Status()
	addrs, _ := lk.TableAddrs(st)
	fmt.Fprintf(e.stdout, "lockdown is on: while the VPN is off, %s are blocked (%d learned address(es) in pf, names in %s). Undo with: sudo outline-cli unlock\n",
		strings.Join(r.VPNOnly, ", "), len(addrs), e.hostsPath)
	if len(addrs) == 0 {
		fmt.Fprintln(e.stdout, "No addresses are known yet: they are learned while connected. Until then only the names in the hosts file are blocked.")
	}
	return exitOK
}

// runUnlock removes the lockdown.
func runUnlock(ctx context.Context, args []string, e env) int {
	flags := flag.NewFlagSet("unlock", flag.ContinueOnError)
	flags.SetOutput(e.stderr)
	logLevel := flags.String("log-level", "info", "log level: debug, info, warn or error")
	if code, ok := parseFlags(flags, args, e, "unlock"); !ok {
		return code
	}
	logger, err := newLogger(e.stderr, *logLevel, &redact.Secrets{})
	if err != nil {
		fmt.Fprintf(e.stderr, "outline-cli unlock: %v\n", err)
		return exitUsage
	}
	unlock, err := lockAsRoot(e, "unlock")
	if err != nil {
		fmt.Fprintf(e.stderr, "outline-cli unlock: %v\n", err)
		return exitError
	}
	defer unlock()
	was, err := e.lockdownManager(logger).Unlock(ctx)
	if err != nil {
		fmt.Fprintf(e.stderr, "outline-cli unlock: %v\n", err)
		return exitError
	}
	if !was {
		fmt.Fprintln(e.stdout, "lockdown is not on; nothing to remove")
		return exitOK
	}
	fmt.Fprintln(e.stdout, "lockdown is off: the pf rules and the hosts block are removed")
	return exitOK
}

// parseFlags parses a subcommand's flags. ok is false when the command must
// return code.
func parseFlags(flags *flag.FlagSet, args []string, e env, cmd string) (code int, ok bool) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK, false
		}
		return exitUsage, false
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(e.stderr, "outline-cli %s: unexpected arguments: %s\n", cmd, strings.Join(flags.Args(), " "))
		return exitUsage, false
	}
	return 0, true
}

// lockAsRoot checks for root and takes the instance lock. A running session
// holds it, so lockdown changes never race a session's own changes.
func lockAsRoot(e env, cmd string) (func() error, error) {
	if e.geteuid() != 0 {
		return nil, fmt.Errorf("%s changes pf and /etc/hosts, so it must run as root: sudo outline-cli %s", cmd, cmd)
	}
	unlock, err := state.FileStore{Dir: e.stateDir}.Lock()
	if errors.Is(err, state.ErrLocked) {
		return nil, fmt.Errorf("outline-cli connect is running; disconnect first (Ctrl-C), then run %s", cmd)
	}
	return unlock, err
}

func indent(s, prefix string) string {
	lines := strings.SplitAfter(s, "\n")
	var b strings.Builder
	for _, l := range lines {
		if l != "" {
			b.WriteString(prefix + l)
		}
	}
	return b.String()
}
