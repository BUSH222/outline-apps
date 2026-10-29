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
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"localhost/client/go/outline/macoscli/internal/keys"
	"localhost/client/go/outline/macoscli/internal/redact"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
	"localhost/client/go/outline/macoscli/internal/tunnel"
)

type connectFlags struct {
	key      string
	keyFile  string
	rules    string
	logLevel string
	dryRun   bool
}

func runConnect(ctx context.Context, args []string, e env) int {
	var f connectFlags
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(e.stderr)
	flags.StringVar(&f.key, "key", "", "access key (ss://, ssconf://, https://) or config file path; lands in shell history, prefer --key-file")
	flags.StringVar(&f.keyFile, "key-file", "", "file holding the access key (recommended; mode 0600)")
	flags.StringVar(&f.rules, "rules", "", "rules file (default: ~/.config/outline-cli/rules.yaml of the invoking user)")
	flags.StringVar(&f.logLevel, "log-level", "info", "log level: debug, info, warn or error")
	flags.BoolVar(&f.dryRun, "dry-run", false, "resolve the key and print the plan; change nothing (no root needed)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(e.stderr, "outline-cli connect: unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		return exitUsage
	}

	secrets := &redact.Secrets{}
	logger, err := newLogger(e.stderr, f.logLevel, secrets)
	if err != nil {
		fmt.Fprintf(e.stderr, "outline-cli connect: %v\n", err)
		return exitUsage
	}
	if !f.dryRun {
		// Refuse before fetching anything, so a real connect never half-runs.
		// It needs interface-bound sockets (M3); without them the transport's
		// own traffic would loop into the tunnel.
		return notImplemented(e, "connect without --dry-run", "M3")
	}

	fail := func(err error) int {
		fmt.Fprintf(e.stderr, "outline-cli connect: %s\n", secrets.Error(err))
		return exitError
	}

	raw, err := keys.Read(keys.Input{Key: f.key, KeyFile: f.keyFile, Getenv: e.getenv})
	if err != nil {
		return fail(err)
	}
	for _, w := range raw.Warnings {
		logger.Warn(w)
	}
	resolver := &keys.Resolver{
		Fetcher: &keys.Fetcher{Transport: e.httpTransport},
		Secrets: secrets,
	}
	resolved, err := resolver.Resolve(ctx, raw)
	if err != nil {
		return fail(err)
	}
	parsed, err := keys.ParseClientConfig(ctx, resolved.ClientConfig, nil)
	if err != nil {
		return fail(err)
	}
	if err := keys.CheckLoopSafe(parsed.Pair); err != nil {
		return fail(err)
	}
	rules, err := resolveRulesPath(f.rules, e.getenv, e.lookupUser)
	if err != nil {
		return fail(err)
	}
	rulesStatus, err := describeRulesFile(rules)
	if err != nil {
		return fail(err)
	}
	hops, err := firstHopAddrs(ctx, parsed.Pair, e.lookup)
	if err != nil {
		return fail(err)
	}

	// Every line goes through the redactor as a last guard.
	out := &redactingWriter{w: e.stdout, secrets: secrets}
	printDryRun(out, raw, resolved, parsed, rules, rulesStatus, hops)
	fmt.Fprintf(out, "  state file:      %s\n", describeStateFile(state.FileStore{Dir: e.stateDir}))
	if err := printPlan(ctx, out, e, hops, logger); err != nil {
		return fail(err)
	}
	return exitOK
}

// printPlan runs the connect and disconnect sequences against the dry-run
// executor: read-only queries run for real, every change is only printed.
func printPlan(ctx context.Context, out io.Writer, e env, hops []netip.Addr, logger *slog.Logger) error {
	dry := &sysexec.DryRun{Next: e.exec, IsReadOnly: sysrouter.IsReadOnly, Out: out}
	opts := tunnel.Options{
		Router:  &sysrouter.Router{Exec: dry},
		Store:   state.NewMemStore(nil),
		OpenTUN: func() (tunnel.TUN, error) { return placeholderTUN{}, nil },
		StartTransport: func(context.Context, tunnel.TUN) (func(), error) {
			return func() {}, nil
		},
		FirstHops:     hops,
		LocalPrefixes: e.localPrefixes,
		// Only warnings are relevant in a dry run; "tunnel is up" would mislead.
		Logger: slog.New(warnOnly{logger.Handler()}),
	}
	fmt.Fprintln(out, "  connect would run (utunN is the utun macOS assigns):")
	session, err := tunnel.Up(ctx, opts)
	if err != nil {
		return fmt.Errorf("planning the connection: %w", err)
	}
	fmt.Fprintln(out, "  disconnect would run:")
	return session.Down(ctx)
}

// placeholderTUN stands in for the utun in a dry run.
type placeholderTUN struct{}

func (placeholderTUN) Read([]byte) (int, error)    { return 0, io.EOF }
func (placeholderTUN) Write(p []byte) (int, error) { return len(p), nil }
func (placeholderTUN) Close() error                { return nil }
func (placeholderTUN) Name() string                { return "utunN" }

// warnOnly drops records below Warn.
type warnOnly struct{ slog.Handler }

func (w warnOnly) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= slog.LevelWarn && w.Handler.Enabled(ctx, l)
}

// describeStateFile reports whether a previous session left state behind.
func describeStateFile(store state.FileStore) string {
	st, err := store.Load()
	switch {
	case errors.Is(err, fs.ErrPermission):
		return store.Path() + " (only readable by root; check with: sudo outline-cli cleanup --dry-run)"
	case err != nil:
		return fmt.Sprintf("%s (unreadable: %v)", store.Path(), err)
	case st == nil:
		return store.Path() + " (none; nothing to recover)"
	default:
		return fmt.Sprintf("%s (left by a session started %s; a real connect restores it first)",
			store.Path(), st.StartedAt.Local().Format(time.DateTime))
	}
}

// describeRulesFile says whether the rules file exists. A missing explicit
// (--rules) file is an error.
func describeRulesFile(loc rulesLocation) (string, error) {
	info, err := os.Stat(loc.Path)
	switch {
	case err == nil && info.Mode().IsRegular():
		return "found (rules are applied from milestone M4)", nil
	case err == nil:
		return "", fmt.Errorf("rules file %s is not a regular file", loc.Path)
	case errors.Is(err, fs.ErrNotExist) && !loc.Explicit:
		return "not found: running without rules", nil
	default:
		return "", fmt.Errorf("rules file: %w", err)
	}
}

func printDryRun(w io.Writer, raw *keys.RawKey, resolved *keys.Resolved, parsed *keys.Parsed, rules rulesLocation, rulesStatus string, hops []netip.Addr) {
	pair := parsed.Pair
	firstHop := resolved.FirstHop
	if firstHop == "" {
		firstHop = fmt.Sprintf("differs: TCP %s, UDP %s", orNone(pair.StreamDialer.FirstHop), orNone(pair.PacketRelay.FirstHop))
	}
	reporter := "none"
	if parsed.HasReporter {
		reporter = "present (not used by the CLI yet)"
	}

	fmt.Fprintln(w, "outline-cli connect --dry-run: nothing will be changed")
	fmt.Fprintf(w, "  key:             %s, %s (from %s)\n", resolved.Kind, resolved.Display, raw.Source)
	fmt.Fprintf(w, "  transport:       %s\n", parsed.TransportType)
	fmt.Fprintf(w, "  connection type: %s (TCP %s, UDP %s)\n", resolved.ConnectionType,
		keys.ConnTypeName(pair.StreamDialer.ConnType), keys.ConnTypeName(pair.PacketRelay.ConnType))
	fmt.Fprintf(w, "  first hop:       %s\n", firstHop)
	hopIPs := make([]string, len(hops))
	for i, h := range hops {
		hopIPs[i] = h.String()
	}
	fmt.Fprintf(w, "  first hop IPs:   %s\n", orNone(strings.Join(hopIPs, ", ")))
	fmt.Fprintf(w, "  usage reporter:  %s\n", reporter)
	fmt.Fprintf(w, "  rules file:      %s (%s; %s)\n", rules.Path, rules.Origin, rulesStatus)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// redactingWriter redacts everything written through it.
type redactingWriter struct {
	w       io.Writer
	secrets *redact.Secrets
}

func (r *redactingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(r.w, r.secrets.Redact(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
