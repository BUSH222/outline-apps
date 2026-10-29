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

// Package sysexec runs system commands. It is the only place in the CLI that
// starts processes, so every system change goes through an Executor that tests
// can fake and a dry run can intercept.
package sysexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Call is one command invocation.
type Call struct {
	Name string
	Args []string
}

// Cmd builds a Call.
func Cmd(name string, args ...string) Call {
	return Call{Name: name, Args: args}
}

// String returns the call as a shell command line.
func (c Call) String() string {
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, shellQuote(c.Name))
	for _, a := range c.Args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@%+,", r)) {
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

// Executor runs commands and returns their standard output.
type Executor interface {
	Run(ctx context.Context, c Call) ([]byte, error)
}

// CommandError is returned when a command fails. Output holds both standard
// output and standard error, because tools such as route report failures on
// either.
type CommandError struct {
	Call     Call
	ExitCode int
	Output   string
	Err      error
}

func (e *CommandError) Error() string {
	out := strings.TrimSpace(e.Output)
	if out == "" {
		return fmt.Sprintf("%s: %v", e.Call, e.Err)
	}
	return fmt.Sprintf("%s: %v: %s", e.Call, e.Err, out)
}

func (e *CommandError) Unwrap() error { return e.Err }

// OutputOf returns the combined output carried by a CommandError, or "".
func OutputOf(err error) string {
	var ce *CommandError
	if errors.As(err, &ce) {
		return ce.Output
	}
	return ""
}

// DefaultTimeout bounds each real command.
const DefaultTimeout = 30 * time.Second

// Real runs commands on the host.
type Real struct {
	// Timeout bounds each command. Zero means DefaultTimeout.
	Timeout time.Duration
}

// commandEnv pins the locale, so output parsing doesn't depend on the user's
// language, and uses a fixed PATH, because sudo may pass an unexpected one.
var commandEnv = []string{
	"LC_ALL=C",
	"LANG=C",
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
}

// Run implements Executor.
func (r Real) Run(ctx context.Context, c Call) ([]byte, error) {
	timeout := r.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = commandEnv
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		exitCode := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		return stdout.Bytes(), &CommandError{
			Call:     c,
			ExitCode: exitCode,
			Output:   stdout.String() + stderr.String(),
			Err:      err,
		}
	}
	return stdout.Bytes(), nil
}

// Fake records calls and answers them with Handler. It is safe for concurrent use.
type Fake struct {
	// Handler answers a call. nil means empty output and no error.
	Handler func(c Call) ([]byte, error)

	mu    sync.Mutex
	calls []Call
}

// Run implements Executor.
func (f *Fake) Run(_ context.Context, c Call) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	if f.Handler == nil {
		return nil, nil
	}
	return f.Handler(c)
}

// Calls returns the calls so far.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// DryRun passes read-only calls to Next and records every other call without
// running it, reporting success with empty output.
type DryRun struct {
	// Next runs read-only calls.
	Next Executor
	// IsReadOnly reports whether a call only reads state. Calls it rejects are
	// never passed to Next.
	IsReadOnly func(c Call) bool
	// Out, if set, receives one line per skipped call.
	Out io.Writer

	mu      sync.Mutex
	skipped []Call
}

// Run implements Executor.
func (d *DryRun) Run(ctx context.Context, c Call) ([]byte, error) {
	if d.IsReadOnly != nil && d.IsReadOnly(c) {
		return d.Next.Run(ctx, c)
	}
	d.mu.Lock()
	d.skipped = append(d.skipped, c)
	d.mu.Unlock()
	if d.Out != nil {
		fmt.Fprintf(d.Out, "    %s\n", c)
	}
	return nil, nil
}

// Skipped returns the calls that were not run.
func (d *DryRun) Skipped() []Call {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Call(nil), d.skipped...)
}
