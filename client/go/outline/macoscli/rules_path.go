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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"localhost/client/go/outline/macoscli/internal/rules"
)

// rulesLocation is where the rules file is expected.
type rulesLocation struct {
	Path string
	// Explicit is true when the path came from --rules. A missing explicit
	// file is an error; a missing default file means "no rules" (and connect
	// creates it).
	Explicit bool
	// Origin explains how the path was chosen, for display.
	Origin string
}

// resolveRulesPath finds the rules file: --rules if given, otherwise
// rules.yaml in dir (the executable's directory).
func resolveRulesPath(flagValue, dir string) rulesLocation {
	if flagValue != "" {
		return rulesLocation{Path: flagValue, Explicit: true, Origin: "--rules"}
	}
	return rulesLocation{Path: filepath.Join(dir, defaultRulesName), Origin: "next to the program"}
}

// loadRules reads the rules file. A missing default file means no rules; a
// missing --rules file, or an invalid file, is an error. It also returns a
// short status for display.
func loadRules(loc rulesLocation) (*rules.Rules, string, error) {
	info, err := os.Stat(loc.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !loc.Explicit:
		return rules.Empty(), "not found: running without rules; connect creates an empty one", nil
	case err != nil:
		return nil, "", fmt.Errorf("rules file: %w", err)
	case !info.Mode().IsRegular():
		return nil, "", fmt.Errorf("rules file %s is not a regular file", loc.Path)
	}
	r, err := rules.Load(loc.Path)
	if err != nil {
		return nil, "", err
	}
	return r, fmt.Sprintf("found: %d bypass, %d vpn_only", len(r.Bypass), len(r.VPNOnly)), nil
}
