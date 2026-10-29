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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every key and secret in this file is fake. 192.0.2.0/24 is TEST-NET-1.
var fakeSSKey = "ss://" +
	base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:FAKE-static-secret")) +
	"@192.0.2.10:8388/?outline=1#Fake%20Server"

const fakeDynamicConfig = `
transport:
  $type: tcpudp
  tcp:
    $type: shadowsocks
    endpoint: 192.0.2.20:443
    cipher: chacha20-ietf-poly1305
    secret: FAKE-dynamic-secret
  udp:
    $type: shadowsocks
    endpoint: 192.0.2.20:443
    cipher: chacha20-ietf-poly1305
    secret: FAKE-dynamic-secret
`

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, e env, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	e.stdout, e.stderr = &stdout, &stderr
	if e.getenv == nil {
		home := t.TempDir()
		e.getenv = func(k string) string {
			if k == "HOME" {
				return home
			}
			return ""
		}
	}
	if e.lookupUser == nil {
		e.lookupUser = func(string) (*user.User, error) { return nil, errors.New("no user database in tests") }
	}
	code := run(context.Background(), args, e)
	return result{code, stdout.String(), stderr.String()}
}

func requireNoSecrets(t *testing.T, r result) {
	t.Helper()
	for _, out := range []string{r.stdout, r.stderr} {
		require.NotContains(t, out, "FAKE", "output leaks a secret:\n%s", out)
	}
}

func TestVersion(t *testing.T) {
	r := runCLI(t, env{}, "version")
	require.Equal(t, exitOK, r.code)
	require.Equal(t, version+"\n", r.stdout)
}

func TestUsage(t *testing.T) {
	require.Equal(t, exitUsage, runCLI(t, env{}).code)
	r := runCLI(t, env{}, "bogus")
	require.Equal(t, exitUsage, r.code)
	require.Contains(t, r.stderr, `unknown command "bogus"`)
	require.Equal(t, exitOK, runCLI(t, env{}, "help").code)
	require.Equal(t, exitOK, runCLI(t, env{}, "connect", "-h").code)
	require.Equal(t, exitUsage, runCLI(t, env{}, "connect", "--dry-run", "extra").code)
	require.Equal(t, exitUsage, runCLI(t, env{}, "connect", "--log-level", "loud").code)
}

func TestNotImplementedCommands(t *testing.T) {
	for _, cmd := range []string{"cleanup", "lockdown", "unlock"} {
		r := runCLI(t, env{}, cmd)
		require.Equal(t, exitError, r.code, cmd)
		require.Contains(t, r.stderr, "not implemented yet")
	}
}

func TestConnectWithoutDryRunChangesNothing(t *testing.T) {
	fetched := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fetched = true }))
	defer server.Close()
	r := runCLI(t, env{httpTransport: server.Client().Transport}, "connect", "--key", server.URL+"/FAKE")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "not implemented yet")
	require.False(t, fetched, "connect must refuse before fetching the key")
}

func TestDryRun_StaticKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyFile, []byte(fakeSSKey+"\n"), 0o600))

	r := runCLI(t, env{}, "connect", "--dry-run", "--key-file", keyFile)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "nothing will be changed")
	require.Contains(t, r.stdout, "key:             static, ss://<redacted>@192.0.2.10:8388/<redacted> (from --key-file)")
	require.Contains(t, r.stdout, "transport:       shadowsocks (URL)")
	require.Contains(t, r.stdout, "connection type: tunneled (TCP tunneled, UDP tunneled)")
	require.Contains(t, r.stdout, "first hop:       192.0.2.10:8388")
	require.Contains(t, r.stdout, "not found: running without rules")
	require.Empty(t, r.stderr)
	requireNoSecrets(t, r)
}

func TestDryRun_DynamicKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/FAKE-path-token", r.URL.Path)
		w.Write([]byte(fakeDynamicConfig))
	}))
	defer server.Close()
	key := "ssconf://" + strings.TrimPrefix(server.URL, "https://") + "/FAKE-path-token?k=FAKE-query#Name"
	getenv := func(k string) string {
		switch k {
		case "OUTLINE_KEY":
			return key
		case "HOME":
			return "/nonexistent-home"
		}
		return ""
	}

	r := runCLI(t, env{getenv: getenv, httpTransport: server.Client().Transport}, "connect", "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	hostPort := strings.TrimPrefix(server.URL, "https://")
	require.Contains(t, r.stdout, "key:             dynamic, ssconf://"+hostPort+"/<redacted> (from OUTLINE_KEY)")
	require.Contains(t, r.stdout, "transport:       tcpudp")
	require.Contains(t, r.stdout, "connection type: tunneled (TCP tunneled, UDP tunneled)")
	require.Contains(t, r.stdout, "first hop:       192.0.2.20:443")
	requireNoSecrets(t, r)
}

func TestDryRun_FetchErrorIsRedacted(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer server.Close()
	r := runCLI(t, env{httpTransport: server.Client().Transport},
		"connect", "--dry-run", "--key", server.URL+"/FAKE-path?k=FAKE-query")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "404 Not Found")
	requireNoSecrets(t, r)
}

func TestDryRun_RefusesLoopingConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "basic.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("transport:\n  $type: basic-access\n"), 0o600))
	r := runCLI(t, env{}, "connect", "--dry-run", "--key", cfg)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "loop back into the tunnel")
}

func TestDryRun_InvalidStaticKeyIsRedacted(t *testing.T) {
	r := runCLI(t, env{}, "connect", "--dry-run", "--key", "ss://FAKE-garbage-userinfo@192.0.2.10:8388")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "invalid tunnel config")
	requireNoSecrets(t, r)
}

func TestDryRun_ExplicitRulesFileMustExist(t *testing.T) {
	r := runCLI(t, env{}, "connect", "--dry-run", "--key", fakeSSKey, "--rules", "/nonexistent/rules.yaml")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "rules file")

	rules := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(rules, []byte("bypass: []\n"), 0o644))
	r = runCLI(t, env{}, "connect", "--dry-run", "--key", fakeSSKey, "--rules", rules)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, rules+" (--rules; found")
	// --key warns about shell history.
	require.Contains(t, r.stderr, "prefer --key-file")
	requireNoSecrets(t, r)
}

func TestResolveRulesPath(t *testing.T) {
	envOf := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	lookup := func(name string) (*user.User, error) {
		if name == "alice" {
			return &user.User{Username: "alice", HomeDir: "/Users/alice"}, nil
		}
		return nil, user.UnknownUserError(name)
	}

	loc, err := resolveRulesPath("/etc/rules.yaml", envOf(map[string]string{"SUDO_USER": "alice"}), lookup)
	require.NoError(t, err)
	require.Equal(t, rulesLocation{Path: "/etc/rules.yaml", Explicit: true, Origin: "--rules"}, loc)

	// Under sudo, the invoking user's home wins over root's $HOME.
	loc, err = resolveRulesPath("", envOf(map[string]string{"SUDO_USER": "alice", "HOME": "/var/root"}), lookup)
	require.NoError(t, err)
	require.Equal(t, "/Users/alice/.config/outline-cli/rules.yaml", loc.Path)
	require.False(t, loc.Explicit)

	_, err = resolveRulesPath("", envOf(map[string]string{"SUDO_USER": "mallory"}), lookup)
	require.ErrorContains(t, err, "pass --rules")

	loc, err = resolveRulesPath("", envOf(map[string]string{"HOME": "/Users/bob"}), lookup)
	require.NoError(t, err)
	require.Equal(t, "/Users/bob/.config/outline-cli/rules.yaml", loc.Path)

	_, err = resolveRulesPath("", envOf(nil), lookup)
	require.ErrorContains(t, err, "HOME is not set")
}
