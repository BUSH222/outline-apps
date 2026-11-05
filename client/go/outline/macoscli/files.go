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
	"strconv"
)

// The default files, next to the executable, so the program can be started
// with a double-click.
const (
	defaultKeyName   = "access-key.txt"
	defaultRulesName = "rules.yaml"
)

// rulesTemplate is written to a new rules file. It only holds comments, so
// it means "no rules".
const rulesTemplate = `# outline-cli rules. Remove the "# " in front of the lines you use.
#
# bypass: domains that never use the VPN (each covers its subdomains)
# vpn_only: domains that only ever use the VPN; after "sudo outline-cli lockdown"
#           they are also blocked while the VPN is off
#
# bypass:
#   - example.com
# vpn_only:
#   - example.org
`

// exeDir returns the directory of the running executable, with symlinks
// resolved.
func exeDir(e env) (string, error) {
	path, err := e.executable()
	if err != nil {
		return "", fmt.Errorf("finding the program's own location: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	return filepath.Dir(path), nil
}

// ensureFile creates path with content and mode unless it exists. Under sudo
// the new file is given to the invoking user, so they can edit it without
// root. It reports whether the file was created.
func ensureFile(e env, path string, content []byte, mode fs.FileMode) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("creating %s: %w", path, err)
	}
	_, werr := f.Write(content)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return false, fmt.Errorf("writing %s: %w", path, err)
	}
	// The umask may have removed bits; set the intended mode exactly.
	if err := os.Chmod(path, mode); err != nil {
		return false, err
	}
	if err := chownToInvoker(e, path); err != nil {
		return false, err
	}
	return true, nil
}

// chownToInvoker gives path to the user who ran sudo (SUDO_UID, SUDO_GID).
// Without sudo, files already belong to the user.
func chownToInvoker(e env, path string) error {
	uid, err1 := strconv.Atoi(e.getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(e.getenv("SUDO_GID"))
	if err1 != nil || err2 != nil {
		return nil
	}
	if err := os.Lchown(path, uid, gid); err != nil {
		return fmt.Errorf("giving %s to user %d: %w", path, uid, err)
	}
	return nil
}
