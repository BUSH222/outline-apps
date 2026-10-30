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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// brokenPipeHelperEnv makes the test binary act as a helper process.
const brokenPipeHelperEnv = "OUTLINE_CLI_BROKEN_PIPE_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(brokenPipeHelperEnv); mode != "" {
		brokenPipeHelper(mode)
		return
	}
	os.Exit(m.Run())
}

// brokenPipeHelper writes to a stdout whose reader is already gone, then
// reports on stderr whether it survived.
func brokenPipeHelper(mode string) {
	if mode == "protected" {
		surviveBrokenPipes()
	}
	for i := 0; i < 3; i++ {
		fmt.Fprintln(os.Stdout, "log line during the restore")
	}
	fmt.Fprintln(os.Stderr, "survived")
	os.Exit(0)
}

func runBrokenPipeHelper(t *testing.T, mode string) (survived bool) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	r.Close() // the reader (tee) is gone before anything is written
	defer w.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), brokenPipeHelperEnv+"="+mode)
	cmd.Stdout = w
	var stderr strings.Builder
	cmd.Stderr = &stderr
	_ = cmd.Run() // a non-zero exit is the expected outcome for "default"
	return cmd.ProcessState.Success() && strings.Contains(stderr.String(), "survived")
}

func TestSurviveBrokenPipes(t *testing.T) {
	require.False(t, runBrokenPipeHelper(t, "default"), "control: Go's default kills the process")
	require.True(t, runBrokenPipeHelper(t, "protected"), "with surviveBrokenPipes the process keeps going")
}
