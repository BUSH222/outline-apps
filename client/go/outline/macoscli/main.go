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
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"localhost/client/go/outline/macoscli/internal/lockdown"
	"localhost/client/go/outline/macoscli/internal/netbind"
	"localhost/client/go/outline/macoscli/internal/redact"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/tunnel"
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
       outline-cli                          (or double-click it) connect with access-key.txt and
                                            rules.yaml next to the program; asks for your password
  sudo outline-cli connect  [--key-file PATH | --key KEY] [--rules PATH] [--log-level LEVEL]
       outline-cli connect  ... --dry-run   resolve the key and print the plan; no root needed
  sudo outline-cli cleanup  [--dry-run]     restore routes, DNS and IPv6 from the state file
  sudo outline-cli lockdown [--rules PATH] [--dry-run]
                                            block the vpn_only domains while the VPN is off
                                            (stays until unlock, except across a reboot)
  sudo outline-cli unlock                   remove that block
       outline-cli version

A key is an ss://, ssconf:// or https:// access key, or a path to a tunnel config
file. By default it is read from access-key.txt next to the program, and the
rules from rules.yaml there; connect creates both if they are missing. It can
also come from --key-file, --key, or the OUTLINE_KEY environment variable (sudo
drops it unless you run "sudo env OUTLINE_KEY=... outline-cli connect").

Run "outline-cli COMMAND -h" for a command's flags.
`

// env holds the process environment, so tests can replace it. Tests always
// use a simulated system executor, never the real one.
type env struct {
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	// executable returns the program's path; the default files sit next to it.
	executable func() (string, error)
	// elevate replaces the process with "sudo argv..." (for a double-click).
	elevate func(argv []string) error
	geteuid func() int
	// httpTransport is used to fetch dynamic keys; nil means the default.
	httpTransport http.RoundTripper
	// exec runs system commands (route, networksetup, ...).
	exec sysexec.Executor
	// stateDir holds the state file and lock.
	stateDir string
	// lookup resolves the server name before any DNS change.
	lookup lookupFunc
	// localPrefixes lists local IPv4 networks; nil means the host's interfaces.
	localPrefixes func() ([]netip.Prefix, error)
	// bind and interfaceIndex bind the transport's sockets to the physical interface.
	bind           netbind.BindFunc
	interfaceIndex func(string) (int, error)
	// openTUN opens the utun; startTransport runs the VPN over it.
	openTUN        func() (tunnel.TUN, error)
	startTransport startTransportFunc
	// watchInterval is how often network changes are checked; 0 means 2 s.
	watchInterval time.Duration
	// verify builds the check that runs once traffic is routed into the tunnel.
	verify verifyFunc
	// hostsPath and pfConfPath are the system files lockdown uses. Tests
	// always point them at temporary files.
	hostsPath  string
	pfConfPath string
}

// lockdownManager returns the lockdown manager for this environment.
func (e env) lockdownManager(log *slog.Logger) *lockdown.Manager {
	return &lockdown.Manager{Exec: e.exec, Dir: e.stateDir, HostsPath: e.hostsPath, PFConfPath: e.pfConfPath, Log: log}
}

func main() {
	surviveBrokenPipes()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], env{
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		getenv:     os.Getenv,
		executable: os.Executable,
		elevate:    execSudo,
		geteuid:    os.Geteuid,
		exec:       sysexec.Real{},
		stateDir:   state.DefaultDir,
		lookup:     defaultLookup,

		bind:           netbind.PlatformBind,
		interfaceIndex: netbind.InterfaceIndex,
		openTUN:        tunnel.OpenUTun,
		startTransport: startRemoteDevice,
		verify:         verifyTunnel,
		hostsPath:      lockdown.DefaultHostsPath,
		pfConfPath:     lockdown.DefaultPFConfPath,
	}))
}

func run(ctx context.Context, args []string, e env) int {
	if len(args) == 0 {
		return runDefault(ctx, e)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "connect":
		return runConnect(ctx, rest, e)
	case "cleanup":
		return runCleanup(ctx, rest, e)
	case "lockdown":
		return runLockdown(ctx, rest, e)
	case "unlock":
		return runUnlock(ctx, rest, e)
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

// runDefault is what a double-click runs: connect with the files next to the
// program. Finder starts it as the user in a Terminal window, so it first
// restarts itself through sudo, which asks for the password there. Ctrl-C
// (or closing the window) disconnects.
func runDefault(ctx context.Context, e env) int {
	if e.geteuid() == 0 {
		return runConnect(ctx, nil, e)
	}
	exe, err := e.executable()
	if err != nil {
		fmt.Fprintf(e.stderr, "outline-cli: finding the program's own location: %v\n", err)
		return exitError
	}
	fmt.Fprintln(e.stdout, "outline-cli needs administrator rights to change network settings; enter your Mac password if asked.")
	err = e.elevate([]string{exe, "connect"})
	// Only reached if sudo couldn't be started.
	fmt.Fprintf(e.stderr, "outline-cli: starting sudo: %v\nRun it yourself: sudo %s connect\n", err, exe)
	return exitError
}

// execSudo replaces the process with sudo running argv.
func execSudo(argv []string) error {
	const sudo = "/usr/bin/sudo"
	return syscall.Exec(sudo, append([]string{"sudo", "-p", "Password for %u: "}, argv...), os.Environ())
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

// surviveBrokenPipes stops a closed stdout or stderr from killing the process.
//
// By default Go exits when it writes to a closed stdout or stderr pipe
// (SIGPIPE). With "outline-cli connect | tee log", Ctrl-C also stops tee, and
// the first log line written during the restore would kill the process
// halfway. Once SIGPIPE is taken with Notify, such writes return EPIPE instead,
// so the restore always completes. (Unlike Ignore, Notify isn't inherited by
// the commands the CLI runs.)
func surviveBrokenPipes() {
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
}
