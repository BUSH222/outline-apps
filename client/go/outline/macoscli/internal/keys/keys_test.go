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

package keys

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/redact"

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

const fakeLegacyJSON = `{"server": "192.0.2.30", "server_port": 8388, "method": "chacha20-ietf-poly1305", "password": "FAKE-legacy-password"}`

func noEnv(string) string { return "" }

// --- Input ---

func TestRead_NoKey(t *testing.T) {
	_, err := Read(Input{Getenv: noEnv})
	require.ErrorContains(t, err, "no access key")
}

func TestRead_Precedence(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyFile, []byte(fakeSSKey+"\n"), 0o600))
	env := func(k string) string {
		if k == EnvKey {
			return "ss://env-key"
		}
		return ""
	}

	raw, err := Read(Input{Key: "ss://flag-key", KeyFile: keyFile, Getenv: env})
	require.NoError(t, err)
	require.Equal(t, SourceFlag, raw.Source)
	require.Equal(t, "ss://flag-key", raw.Text)
	require.True(t, raw.AllowPath)
	require.Contains(t, strings.Join(raw.Warnings, "\n"), "ignoring --key-file")
	require.Contains(t, strings.Join(raw.Warnings, "\n"), "ignoring OUTLINE_KEY")

	raw, err = Read(Input{KeyFile: keyFile, Getenv: env})
	require.NoError(t, err)
	require.Equal(t, SourceKeyFile, raw.Source)
	require.Equal(t, fakeSSKey, raw.Text) // trimmed
	require.False(t, raw.AllowPath)

	raw, err = Read(Input{Getenv: env})
	require.NoError(t, err)
	require.Equal(t, SourceEnv, raw.Source)
	require.Equal(t, "ss://env-key", raw.Text)
	require.Empty(t, raw.Warnings)
}

func TestRead_KeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private")
	require.NoError(t, os.WriteFile(private, []byte(fakeSSKey), 0o600))
	raw, err := Read(Input{KeyFile: private, Getenv: noEnv})
	require.NoError(t, err)
	require.Empty(t, raw.Warnings)

	shared := filepath.Join(dir, "shared")
	require.NoError(t, os.WriteFile(shared, []byte(fakeSSKey), 0o600))
	require.NoError(t, os.Chmod(shared, 0o644))
	raw, err = Read(Input{KeyFile: shared, Getenv: noEnv})
	require.NoError(t, err)
	require.Len(t, raw.Warnings, 1)
	require.Contains(t, raw.Warnings[0], "chmod 600")
	require.NotContains(t, raw.Warnings[0], "FAKE-static-secret")
}

func TestRead_KeyFileErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := Read(Input{KeyFile: filepath.Join(dir, "missing"), Getenv: noEnv})
	require.ErrorContains(t, err, "reading key file")

	_, err = Read(Input{KeyFile: dir, Getenv: noEnv})
	require.ErrorContains(t, err, "not a regular file")

	empty := filepath.Join(dir, "empty")
	require.NoError(t, os.WriteFile(empty, []byte("  \n"), 0o600))
	_, err = Read(Input{KeyFile: empty, Getenv: noEnv})
	require.ErrorContains(t, err, "empty")

	big := filepath.Join(dir, "big")
	require.NoError(t, os.WriteFile(big, make([]byte, maxInputSize+1), 0o600))
	_, err = Read(Input{KeyFile: big, Getenv: noEnv})
	require.ErrorContains(t, err, "larger than 1 MiB")
}

// --- Fetcher ---

func newTLSServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Fetcher) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return server, &Fetcher{Transport: server.Client().Transport}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

func TestFetch_OK(t *testing.T) {
	server, f := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/FAKE-path-token", r.URL.Path)
		w.Write([]byte(fakeDynamicConfig))
	})
	body, err := f.Fetch(context.Background(), mustURL(t, server.URL+"/FAKE-path-token"))
	require.NoError(t, err)
	require.Equal(t, fakeDynamicConfig, body)
}

func TestFetch_ErrorsNeverContainPathOrQuery(t *testing.T) {
	server, f := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/FAKE-status":
			http.Error(w, "nope FAKE-body-text", http.StatusForbidden)
		case "/FAKE-downgrade":
			http.Redirect(w, r, "http://192.0.2.99/FAKE-elsewhere", http.StatusFound)
		case "/FAKE-slow":
			time.Sleep(500 * time.Millisecond)
		}
	})
	f.Timeout = 100 * time.Millisecond

	for path, want := range map[string]string{
		"/FAKE-status?k=FAKE-query":    "403 Forbidden",
		"/FAKE-downgrade?k=FAKE-query": "refusing redirect to http",
		"/FAKE-slow?k=FAKE-query":      "Client.Timeout",
	} {
		_, err := f.Fetch(context.Background(), mustURL(t, server.URL+path))
		require.ErrorContains(t, err, want, path)
		require.NotContains(t, err.Error(), "FAKE", path)
	}
}

func TestFetch_ConnectionErrorHidesPath(t *testing.T) {
	// Port 1 on loopback: the connection is refused.
	f := &Fetcher{Timeout: time.Second}
	_, err := f.Fetch(context.Background(), mustURL(t, "https://127.0.0.1:1/FAKE-path?k=FAKE-query"))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "FAKE")
	require.Contains(t, err.Error(), "https://127.0.0.1:1/<redacted>")
}

func TestFetch_RefusesHTTP(t *testing.T) {
	_, err := (&Fetcher{}).Fetch(context.Background(), mustURL(t, "http://192.0.2.1/FAKE"))
	require.ErrorContains(t, err, "only https")
	require.NotContains(t, err.Error(), "FAKE")
}

func TestFetch_BodyLimit(t *testing.T) {
	server, f := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, maxInputSize+1))
	})
	_, err := f.Fetch(context.Background(), mustURL(t, server.URL))
	require.ErrorContains(t, err, "larger than 1 MiB")
}

// --- Resolver ---

func resolve(t *testing.T, r *Resolver, raw *RawKey) (*Resolved, error) {
	t.Helper()
	if r.Secrets == nil {
		r.Secrets = &redact.Secrets{}
	}
	return r.Resolve(context.Background(), raw)
}

func TestResolve_StaticKey(t *testing.T) {
	secrets := &redact.Secrets{}
	got, err := resolve(t, &Resolver{Secrets: secrets}, &RawKey{Text: fakeSSKey, Source: SourceFlag})
	require.NoError(t, err)
	require.Equal(t, KindStatic, got.Kind)
	require.Equal(t, "192.0.2.10:8388", got.FirstHop)
	require.Equal(t, "tunneled", got.ConnectionType)
	require.Equal(t, "ss://<redacted>@192.0.2.10:8388/<redacted>", got.Display)
	require.NotContains(t, got.ClientConfig, "Fake%20Server", "fragment must be stripped")
	// The secret is registered for redaction.
	require.NotContains(t, secrets.Redact("FAKE-static-secret"), "FAKE-static-secret")
}

func TestResolve_DynamicKey(t *testing.T) {
	server, f := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/FAKE-path-token", r.URL.Path)
		require.Equal(t, "k=FAKE-query-token", r.URL.RawQuery)
		w.Write([]byte(fakeDynamicConfig))
	})
	host := strings.TrimPrefix(server.URL, "https://")
	for _, key := range []string{
		"ssconf://" + host + "/FAKE-path-token?k=FAKE-query-token#Name",
		"https://" + host + "/FAKE-path-token?k=FAKE-query-token",
		"SSCONF://" + host + "/FAKE-path-token?k=FAKE-query-token",
	} {
		secrets := &redact.Secrets{}
		got, err := resolve(t, &Resolver{Fetcher: f, Secrets: secrets}, &RawKey{Text: key, Source: SourceEnv})
		require.NoError(t, err, key)
		require.Equal(t, KindDynamic, got.Kind)
		require.Equal(t, "192.0.2.20:443", got.FirstHop)
		require.Equal(t, "tunneled", got.ConnectionType)
		require.NotContains(t, got.Display, "FAKE")
		require.NotContains(t, secrets.Redact("FAKE-dynamic-secret FAKE-path-token FAKE-query-token"), "FAKE")
	}
}

func TestResolve_DynamicKeyEmptyBody(t *testing.T) {
	server, f := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(" \n")) })
	_, err := resolve(t, &Resolver{Fetcher: f}, &RawKey{Text: server.URL + "/FAKE", Source: SourceFlag})
	require.ErrorContains(t, err, "empty config")
	require.NotContains(t, err.Error(), "FAKE")
}

func TestResolve_ProviderError(t *testing.T) {
	server, f := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("error:\n  message: Your fake key has expired\n  details: FAKE-details\n"))
	})
	_, err := resolve(t, &Resolver{Fetcher: f}, &RawKey{Text: server.URL + "/FAKE", Source: SourceFlag})
	require.ErrorContains(t, err, "Your fake key has expired")
}

func TestResolve_LegacyJSONText(t *testing.T) {
	got, err := resolve(t, &Resolver{}, &RawKey{Text: fakeLegacyJSON, Source: SourceFlag, AllowPath: true})
	require.NoError(t, err)
	require.Equal(t, KindConfigText, got.Kind)
	require.Equal(t, "192.0.2.30:8388", got.FirstHop)
}

func TestResolve_ConfigFile(t *testing.T) {
	dir := t.TempDir()
	yamlFile := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(yamlFile, []byte(fakeDynamicConfig), 0o600))
	got, err := resolve(t, &Resolver{}, &RawKey{Text: yamlFile, Source: SourceFlag, AllowPath: true})
	require.NoError(t, err)
	require.Equal(t, KindConfigFile, got.Kind)
	require.Equal(t, "file "+yamlFile, got.Display)
	require.Equal(t, "192.0.2.20:443", got.FirstHop)

	ssFile := filepath.Join(dir, "key.txt")
	require.NoError(t, os.WriteFile(ssFile, []byte(fakeSSKey+"\n"), 0o600))
	got, err = resolve(t, &Resolver{}, &RawKey{Text: ssFile, Source: SourceFlag, AllowPath: true})
	require.NoError(t, err)
	require.Equal(t, "192.0.2.10:8388", got.FirstHop)

	// A path from a key file's contents is not followed.
	_, err = resolve(t, &Resolver{}, &RawKey{Text: yamlFile, Source: SourceKeyFile, AllowPath: false})
	require.Error(t, err)
}

func TestResolve_MissingConfigFile(t *testing.T) {
	_, err := resolve(t, &Resolver{}, &RawKey{Text: "/nonexistent/fake.yaml", Source: SourceFlag, AllowPath: true})
	require.ErrorContains(t, err, "config file /nonexistent/fake.yaml")
}

func TestResolve_UnsupportedScheme(t *testing.T) {
	_, err := resolve(t, &Resolver{}, &RawKey{Text: "http://192.0.2.1/FAKE", Source: SourceFlag})
	require.ErrorContains(t, err, "unsupported key type http://")
	require.NotContains(t, err.Error(), "FAKE")
}

func TestResolve_InvalidStaticKeyErrorIsRedactable(t *testing.T) {
	secrets := &redact.Secrets{}
	key := "ss://FAKE-not-base64-userinfo-without-separator@192.0.2.10:8388"
	_, err := resolve(t, &Resolver{Secrets: secrets}, &RawKey{Text: key, Source: SourceFlag})
	require.Error(t, err)
	require.NotContains(t, secrets.Error(err), "FAKE-not-base64")
}

// --- Inspection and loop safety ---

func parseText(t *testing.T, text string) *Parsed {
	t.Helper()
	resolved, err := ParseTunnelConfig(text)
	require.NoError(t, err)
	parsed, err := ParseClientConfig(context.Background(), resolved.ClientConfig, nil)
	require.NoError(t, err)
	return parsed
}

func TestParseClientConfig_TransportTypes(t *testing.T) {
	require.Equal(t, "shadowsocks (URL)", parseText(t, fakeSSKey[:strings.Index(fakeSSKey, "#")]).TransportType)
	require.Equal(t, "shadowsocks", parseText(t, fakeLegacyJSON).TransportType)
	parsed := parseText(t, fakeDynamicConfig)
	require.Equal(t, "tcpudp", parsed.TransportType)
	require.False(t, parsed.HasReporter)
	require.Equal(t, configregistry.ConnTypeTunneled, parsed.Pair.StreamDialer.ConnType)
	require.Equal(t, configregistry.ConnTypeTunneled, parsed.Pair.PacketRelay.ConnType)
	require.NoError(t, CheckLoopSafe(parsed.Pair))
}

func TestCheckLoopSafe_RefusesDirect(t *testing.T) {
	for name, cfg := range map[string]string{
		"basic-access": "transport:\n  $type: basic-access\n",
		"udp direct": `
transport:
  $type: tcpudp
  tcp: {$type: shadowsocks, endpoint: 192.0.2.20:443, cipher: chacha20-ietf-poly1305, secret: FAKE}
  udp: {$type: direct}
`,
		"udp missing": `
transport:
  $type: tcpudp
  tcp: {$type: shadowsocks, endpoint: 192.0.2.20:443, cipher: chacha20-ietf-poly1305, secret: FAKE}
`,
		"tcp direct": `
transport:
  $type: tcpudp
  tcp: {$type: direct}
  udp: {$type: shadowsocks, endpoint: 192.0.2.20:443, cipher: chacha20-ietf-poly1305, secret: FAKE}
`,
	} {
		t.Run(name, func(t *testing.T) {
			err := CheckLoopSafe(parseText(t, cfg).Pair)
			require.ErrorContains(t, err, "loop back into the tunnel")
		})
	}
}

func TestCheckLoopSafe_AllowsPartialTCP(t *testing.T) {
	// iptable mixes direct (bound by the CLI) and tunneled TCP; that is loop safe.
	parsed := parseText(t, `
transport:
  $type: tcpudp
  tcp:
    $type: iptable
    table:
      - ips: [198.51.100.0/24]
        dialer: {$type: direct}
    fallback: {$type: shadowsocks, endpoint: 192.0.2.20:443, cipher: chacha20-ietf-poly1305, secret: FAKE}
  udp: {$type: shadowsocks, endpoint: 192.0.2.20:443, cipher: chacha20-ietf-poly1305, secret: FAKE}
`)
	require.Equal(t, configregistry.ConnTypePartial, parsed.Pair.StreamDialer.ConnType)
	require.NoError(t, CheckLoopSafe(parsed.Pair))
}

func TestConnTypeName(t *testing.T) {
	require.Equal(t, "tunneled", ConnTypeName(configregistry.ConnTypeTunneled))
	require.Equal(t, "direct", ConnTypeName(configregistry.ConnTypeDirect))
	require.Equal(t, "unknown", ConnTypeName(configregistry.ConnType(99)))
}
