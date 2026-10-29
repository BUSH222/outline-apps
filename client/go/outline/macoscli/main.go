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

// Command outline-cli is a command-line Outline client for macOS that runs as
// root and does not use Apple's Network Extension. See docs/macos-cli/SPEC.md.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"

	"localhost/client/go/outline/macoscli/internal/redact"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usage = `outline-cli: an Outline VPN client for macOS without a Network Extension.

Usage:
  sudo outline-cli connect  --key-file PATH | --key KEY   [--rules PATH] [--log-level LEVEL]
       outline-cli connect  ... --dry-run   resolve the key and print the plan; no root needed
  sudo outline-cli cleanup                  restore routes, DNS and IPv6 from the state file
  sudo outline-cli lockdown                 install the VPN-only block rules (persistent)
  sudo outline-cli unlock                   remove the VPN-only block rules
       outline-cli version

A key is an ss://, ssconf:// or https:// access key, or a path to a tunnel config
file. It can also come from the OUTLINE_KEY environment variable. sudo drops
most environment variables, so prefer --key-file (mode 0600), or run
"sudo env OUTLINE_KEY=... outline-cli connect".

Run "outline-cli COMMAND -h" for a command's flags.
`

// env holds the process environment, so tests can replace it.
type env struct {
	stdout     io.Writer
	stderr     io.Writer
	getenv     func(string) string
	lookupUser func(string) (*user.User, error)
	// httpTransport is used to fetch dynamic keys; nil means the default.
	httpTransport http.RoundTripper
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], env{
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		getenv:     os.Getenv,
		lookupUser: user.Lookup,
	}))
}

func run(ctx context.Context, args []string, e env) int {
	if len(args) == 0 {
		fmt.Fprint(e.stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "connect":
		return runConnect(ctx, rest, e)
	case "cleanup":
		return notImplemented(e, "cleanup", "M2")
	case "lockdown":
		return notImplemented(e, "lockdown", "M5")
	case "unlock":
		return notImplemented(e, "unlock", "M5")
	case "version", "-version", "--version":
		fmt.Fprintln(e.stdout, version)
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprint(e.stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(e.stderr, "outline-cli: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
}

func notImplemented(e env, cmd, milestone string) int {
	fmt.Fprintf(e.stderr, "outline-cli: %s is not implemented yet (milestone %s)\n", cmd, milestone)
	return exitError
}

// newLogger returns a text logger on w that redacts secrets, and makes it the
// default so upstream packages' slog calls are redacted too.
func newLogger(w io.Writer, level string, secrets *redact.Secrets) (*slog.Logger, error) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "", "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid --log-level %q (want debug, info, warn or error)", level)
	}
	logger := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level:       lvl,
		ReplaceAttr: secrets.ReplaceAttr,
	}))
	slog.SetDefault(logger)
	return logger, nil
}
