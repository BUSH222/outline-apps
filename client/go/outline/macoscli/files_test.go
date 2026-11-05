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
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"localhost/client/go/outline/macoscli/internal/fakemac"
	"localhost/client/go/outline/macoscli/internal/rules"

	"github.com/stretchr/testify/require"
)

// programIn returns an executable function for a program in dir.
func programIn(dir string) func() (string, error) {
	return func() (string, error) { return filepath.Join(dir, "outline-cli"), nil }
}

func TestNoArguments_RestartsThroughSudo(t *testing.T) {
	dir := t.TempDir()
	var argv []string
	e := env{
		executable: programIn(dir),
		elevate: func(a []string) error {
			argv = a
			return errors.New("sudo: not found")
		},
	}
	r := runCLI(t, e)
	require.Equal(t, []string{filepath.Join(dir, "outline-cli"), "connect"}, argv)
	require.Contains(t, r.stdout, "needs administrator rights")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "Run it yourself: sudo "+filepath.Join(dir, "outline-cli")+" connect")
	// Nothing is created before root.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestNoArguments_AsRootCreatesTheFilesThenConnects(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	dir := t.TempDir()
	keyFile, rulesFile := filepath.Join(dir, defaultKeyName), filepath.Join(dir, defaultRulesName)

	// First start: both files are created, and the empty key stops it
	// before anything changes.
	e, ctx := sessionEnv(t, mac)
	e.executable = programIn(dir)
	r := runCLIContext(t, ctx, e)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stdout, "created "+keyFile+": paste your access key into it")
	require.Contains(t, r.stdout, "created "+rulesFile)
	require.Contains(t, r.stderr, "no access key yet: paste your Outline access key into "+keyFile)
	require.Equal(t, baseline, mac.Snapshot())
	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.Zero(t, info.Size())
	info, err = os.Stat(rulesFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	require.Equal(t, rulesTemplate, readFile(t, rulesFile))

	// With the key pasted in, the same double-click connects.
	require.NoError(t, os.WriteFile(keyFile, []byte(fakeSSKey+"\n"), 0o600))
	e, ctx = sessionEnv(t, mac)
	e.executable = programIn(dir)
	r = runCLIContext(t, ctx, e)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "connected:")
	require.NotContains(t, r.stdout, "created ", "existing files are kept")
	require.Contains(t, r.stderr, rulesFile+" (found: 0 bypass, 0 vpn_only)")
	require.Equal(t, baseline, mac.Snapshot())
	requireNoSecrets(t, r)
}

func TestConnect_ExplicitKeyStillCreatesTheRulesFile(t *testing.T) {
	mac := fakemac.New()
	dir := t.TempDir()
	e, ctx := sessionEnv(t, mac)
	e.executable = programIn(dir)
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey)
	require.Equal(t, exitOK, r.code, r.stderr)
	_, err := os.Stat(filepath.Join(dir, defaultRulesName))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, defaultKeyName))
	require.ErrorIs(t, err, os.ErrNotExist, "no key file when the key comes from elsewhere")

	// --rules elsewhere: nothing is created next to the program.
	dir2 := t.TempDir()
	e, ctx = sessionEnv(t, mac)
	e.executable = programIn(dir2)
	r = runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey, "--rules", writeRules(t, "bypass: []\n"))
	require.Equal(t, exitOK, r.code, r.stderr)
	entries, err := os.ReadDir(dir2)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestDryRun_DefaultFilesAreNotCreated(t *testing.T) {
	dir := t.TempDir()
	r := runCLI(t, env{executable: programIn(dir)}, "connect", "--dry-run")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no access key: put it in "+filepath.Join(dir, defaultKeyName))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Empty(t, entries)

	// With a key there, the dry run uses it and reports the missing rules file.
	require.NoError(t, os.WriteFile(filepath.Join(dir, defaultKeyName), []byte(fakeSSKey), 0o600))
	r = runCLI(t, env{executable: programIn(dir)}, "connect", "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "(from --key-file)")
	require.Contains(t, r.stdout, filepath.Join(dir, defaultRulesName)+" (next to the program; not found: running without rules; connect creates an empty one)")
	requireNoSecrets(t, r)
}

func TestExeDir_FollowsSymlinks(t *testing.T) {
	real := t.TempDir()
	exe := filepath.Join(real, "outline-cli")
	require.NoError(t, os.WriteFile(exe, nil, 0o755))
	link := filepath.Join(t.TempDir(), "outline-cli")
	require.NoError(t, os.Symlink(exe, link))
	dir, err := exeDir(env{executable: func() (string, error) { return link, nil }})
	require.NoError(t, err)
	want, err := filepath.EvalSymlinks(real)
	require.NoError(t, err)
	require.Equal(t, want, dir)
}

func TestEnsureFile_GivesTheFileToTheSudoUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access-key.txt")
	// The test can only give files to itself; that is what runs the chown.
	e := env{getenv: func(k string) string {
		switch k {
		case "SUDO_UID":
			return strconv.Itoa(os.Getuid())
		case "SUDO_GID":
			return strconv.Itoa(os.Getgid())
		}
		return ""
	}}
	created, err := ensureFile(e, path, []byte("x"), 0o600)
	require.NoError(t, err)
	require.True(t, created)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Getuid()), info.Sys().(*syscall.Stat_t).Uid)

	created, err = ensureFile(e, path, []byte("other"), 0o600)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, "x", readFile(t, path), "an existing file is never overwritten")
}

func TestRulesTemplateMeansNoRules(t *testing.T) {
	r, err := rules.Parse([]byte(rulesTemplate))
	require.NoError(t, err)
	require.True(t, r.IsEmpty())
}

func TestLockdown_UsesTheRulesNextToTheProgram(t *testing.T) {
	mac := fakemac.New()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, defaultRulesName), []byte(vpnOnlyRules), 0o644))
	e := lockdownEnv(t, mac)
	e.executable = programIn(dir)
	r := runCLI(t, e, "lockdown")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, readFile(t, e.hostsPath), "0.0.0.0 secret.example")
}
