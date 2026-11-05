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
	"log/slog"
	"os/exec"
	"time"
)

const (
	// minimizeDelay is how long the terminal stays up after "tunnel is up".
	minimizeDelay = 5 * time.Second
	// minimizeScript minimizes Terminal's front window.
	minimizeScript = `tell application "Terminal" to set miniaturized of front window to true`
)

// minimizeTerminalSoon waits minimizeDelay and then minimizes Terminal's
// front window. It gives up if ctx ends first, and only logs a failure: the
// tunnel works the same with the window open.
func minimizeTerminalSoon(ctx context.Context, log *slog.Logger) {
	minimizeTerminalAfter(ctx, log, minimizeDelay, func(ctx context.Context) error {
		return exec.CommandContext(ctx, "osascript", "-e", minimizeScript).Run()
	})
}

func minimizeTerminalAfter(ctx context.Context, log *slog.Logger, delay time.Duration, run func(context.Context) error) {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.C:
	}
	if err := run(ctx); err != nil {
		log.Warn("minimizing the Terminal window failed", "err", err)
	}
}
