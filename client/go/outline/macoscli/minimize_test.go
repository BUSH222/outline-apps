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
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMinimizeTerminalAfterRunsAfterTheDelay(t *testing.T) {
	ran := 0
	minimizeTerminalAfter(context.Background(), slog.Default(), time.Millisecond, func(context.Context) error {
		ran++
		return nil
	})
	require.Equal(t, 1, ran)
}

func TestMinimizeTerminalAfterSkipsWhenTheSessionEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	minimizeTerminalAfter(ctx, slog.Default(), time.Hour, func(context.Context) error {
		t.Fatal("must not run after the session ended")
		return nil
	})
}

func TestMinimizeTerminalAfterToleratesFailure(t *testing.T) {
	minimizeTerminalAfter(context.Background(), slog.Default(), time.Millisecond, func(context.Context) error {
		return errors.New("boom")
	})
}
