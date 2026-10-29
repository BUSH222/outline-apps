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
	"os/user"
	"path/filepath"
)

// defaultRulesRelPath is the rules file location inside a home directory.
var defaultRulesRelPath = filepath.Join(".config", "outline-cli", "rules.yaml")

// rulesLocation is where the rules file is expected.
type rulesLocation struct {
	Path string
	// Explicit is true when the path came from --rules. A missing explicit
	// file is an error; a missing default file means "no rules".
	Explicit bool
	// Origin explains how the path was chosen, for display.
	Origin string
}

// resolveRulesPath finds the rules file:
//  1. --rules, if given;
//  2. under sudo, the invoking user's home (from SUDO_USER via the user
//     database, because $HOME may be root's);
//  3. otherwise $HOME.
func resolveRulesPath(flagValue string, getenv func(string) string, lookupUser func(string) (*user.User, error)) (rulesLocation, error) {
	if flagValue != "" {
		return rulesLocation{Path: flagValue, Explicit: true, Origin: "--rules"}, nil
	}
	if sudoUser := getenv("SUDO_USER"); sudoUser != "" {
		u, err := lookupUser(sudoUser)
		if err != nil || u.HomeDir == "" {
			return rulesLocation{}, fmt.Errorf("can't find the home directory of SUDO_USER %q (%v); pass --rules PATH", sudoUser, err)
		}
		return rulesLocation{
			Path:   filepath.Join(u.HomeDir, defaultRulesRelPath),
			Origin: "home of SUDO_USER " + sudoUser,
		}, nil
	}
	home := getenv("HOME")
	if home == "" {
		return rulesLocation{}, fmt.Errorf("HOME is not set; pass --rules PATH")
	}
	return rulesLocation{Path: filepath.Join(home, defaultRulesRelPath), Origin: "$HOME"}, nil
}
