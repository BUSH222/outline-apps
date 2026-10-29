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

// Package keys reads an Outline access key, resolves dynamic keys and parses
// the resulting tunnel config, without ever exposing the key in output.
package keys

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// EnvKey is the environment variable that may hold the access key.
const EnvKey = "OUTLINE_KEY"

// maxInputSize bounds key files, config files and fetched configs.
const maxInputSize = 1 << 20

// Source says where the key came from.
type Source string

const (
	SourceFlag    Source = "--key"
	SourceKeyFile Source = "--key-file"
	SourceEnv     Source = EnvKey
)

// Input holds the possible key sources. Precedence: Key, then KeyFile, then
// the OUTLINE_KEY environment variable.
type Input struct {
	Key     string
	KeyFile string
	Getenv  func(string) string
}

// RawKey is the key text as read, before resolution.
type RawKey struct {
	Text   string
	Source Source
	// AllowPath reports whether Text may name a config file. It is false for
	// key file contents, so a key file can't point at another file.
	AllowPath bool
	// Warnings are non-fatal problems to show the user.
	Warnings []string
}

// Read returns the key from the highest-precedence source that is set.
func Read(in Input) (*RawKey, error) {
	getenv := in.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	env := strings.TrimSpace(getenv(EnvKey))

	var sources []Source
	if in.Key != "" {
		sources = append(sources, SourceFlag)
	}
	if in.KeyFile != "" {
		sources = append(sources, SourceKeyFile)
	}
	if env != "" {
		sources = append(sources, SourceEnv)
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no access key: pass --key-file PATH (recommended), --key, or set %s", EnvKey)
	}

	raw := &RawKey{Source: sources[0]}
	for _, ignored := range sources[1:] {
		raw.Warnings = append(raw.Warnings, fmt.Sprintf("ignoring %s because %s is set", ignored, sources[0]))
	}

	switch raw.Source {
	case SourceFlag:
		raw.Text = strings.TrimSpace(in.Key)
		raw.AllowPath = true
		raw.Warnings = append(raw.Warnings, "--key puts the key in your shell history; prefer --key-file")
	case SourceKeyFile:
		text, warning, err := readKeyFile(in.KeyFile)
		if err != nil {
			return nil, err
		}
		raw.Text = text
		if warning != "" {
			raw.Warnings = append(raw.Warnings, warning)
		}
	case SourceEnv:
		raw.Text = env
		raw.AllowPath = true
	}
	if raw.Text == "" {
		return nil, fmt.Errorf("the access key from %s is empty", raw.Source)
	}
	return raw, nil
}

// readKeyFile reads a key file and warns if others can read it.
func readKeyFile(path string) (text string, warning string, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("reading key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("key file %s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		warning = fmt.Sprintf("key file %s can be read by other users (mode %04o); run: chmod 600 %s", path, perm, path)
	}
	data, err := readLimited(path)
	if err != nil {
		return "", "", fmt.Errorf("reading key file: %w", err)
	}
	return strings.TrimSpace(string(data)), warning, nil
}

// readLimited reads at most maxInputSize bytes from path.
func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxInputSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputSize {
		return nil, errors.New("file is larger than 1 MiB")
	}
	return data, nil
}
