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

package redact

import (
	"bytes"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// All keys below are fake. 192.0.2.0/24 and 198.51.100.0/24 are TEST-NET ranges.
var (
	fakeUserInfo = base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:FAKE-ss-password"))
	fakeSSKey    = "ss://" + fakeUserInfo + "@192.0.2.10:8388/?outline=1#My%20Server"
	fakeLegacy   = "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:FAKE-legacy-pw@192.0.2.11:8388")) + "#Legacy"
	fakeSSConf   = "ssconf://config.example.test/FAKE-path-token?key=FAKE-query-token#Name"
)

func TestURL(t *testing.T) {
	cases := map[string]string{
		fakeSSKey:                            "ss://<redacted>@192.0.2.10:8388/<redacted>",
		fakeLegacy:                           "ss://<redacted>",
		fakeSSConf:                           "ssconf://config.example.test/<redacted>",
		"https://example.test/a/b?c=d#e":     "https://example.test/<redacted>",
		"https://example.test/":              "https://example.test/",
		"https://example.test":               "https://example.test",
		"HTTPS://user:pw@example.test:8443/": "https://<redacted>@example.test:8443/",
		"not a url":                          "<redacted>",
		"https://exa mple/":                  "https://<redacted>",
	}
	for in, want := range cases {
		require.Equal(t, want, URL(in), "input %q", in)
	}
}

func TestAddKey_StaticKey(t *testing.T) {
	var s Secrets
	s.AddKey(fakeSSKey)
	for _, leak := range []string{fakeSSKey, fakeUserInfo, "FAKE-ss-password", "chacha20-ietf-poly1305:FAKE-ss-password"} {
		out := s.Redact("error: " + leak + " failed")
		require.NotContains(t, out, "FAKE-ss-password", "leak %q", leak)
		require.NotContains(t, out, fakeUserInfo)
	}
	// The server address alone is not secret and stays readable.
	require.Equal(t, "dial 192.0.2.10:8388", s.Redact("dial 192.0.2.10:8388"))
}

func TestAddKey_LegacyKey(t *testing.T) {
	var s Secrets
	s.AddKey(fakeLegacy)
	require.NotContains(t, s.Redact("bad password FAKE-legacy-pw"), "FAKE-legacy-pw")
	require.NotContains(t, s.Redact(fakeLegacy), "FAKE-legacy-pw")
}

func TestAddKey_DynamicKey(t *testing.T) {
	var s Secrets
	s.AddKey(fakeSSConf)
	for _, text := range []string{
		`Get "https://config.example.test/FAKE-path-token?key=FAKE-query-token": EOF`,
		"path /FAKE-path-token was rejected",
		"token FAKE-query-token expired",
		"FAKE-path-token",
	} {
		out := s.Redact(text)
		require.NotContains(t, out, "FAKE-path-token", "text %q", text)
		require.NotContains(t, out, "FAKE-query-token", "text %q", text)
	}
}

func TestRedact_URLPatternWithoutRegistration(t *testing.T) {
	var s Secrets
	out := s.Redact(`unexpected key "` + fakeSSConf + `" and ` + fakeSSKey)
	require.NotContains(t, out, "FAKE-path-token")
	require.NotContains(t, out, "FAKE-query-token")
	require.NotContains(t, out, fakeUserInfo)
	require.Contains(t, out, "ssconf://config.example.test/<redacted>")
}

func TestAddConfig_YAML(t *testing.T) {
	var s Secrets
	s.AddConfig(`
transport:
  $type: tcpudp
  tcp:
    $type: shadowsocks
    endpoint:
      $type: websocket
      url: wss://ws.example.test/FAKE-ws-path
    cipher: chacha20-ietf-poly1305
    secret: FAKE-yaml-secret
    prefix: "FAKE-prefix"
  udp:
    $type: shadowsocks
    endpoint: 192.0.2.20:443
    cipher: chacha20-ietf-poly1305
    password: FAKE-yaml-password
`)
	out := s.Redact("FAKE-yaml-secret FAKE-yaml-password FAKE-prefix /FAKE-ws-path")
	for _, leak := range []string{"FAKE-yaml-secret", "FAKE-yaml-password", "FAKE-prefix", "FAKE-ws-path"} {
		require.NotContains(t, out, leak)
	}
	// Non-secret fields stay readable.
	require.Equal(t, "cipher chacha20-ietf-poly1305 at 192.0.2.20:443", s.Redact("cipher chacha20-ietf-poly1305 at 192.0.2.20:443"))
}

func TestAddConfig_InvalidYAMLRegistersLines(t *testing.T) {
	var s Secrets
	s.AddConfig("{broken: FAKE-broken-secret-line\n")
	require.NotContains(t, s.Redact("[1:2] {broken: FAKE-broken-secret-line"), "FAKE-broken-secret-line")
}

func TestAdd_IgnoresShortValues(t *testing.T) {
	var s Secrets
	s.Add("a", "ab", "abc", "")
	require.Equal(t, "a ab abc", s.Redact("a ab abc"))
}

func TestReplaceAttr(t *testing.T) {
	var s Secrets
	s.AddKey(fakeSSConf)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: s.ReplaceAttr}))
	logger.Info("fetching "+fakeSSConf,
		"url", "https://config.example.test/FAKE-path-token",
		"err", errors.New("token FAKE-query-token"),
		slog.Group("g", "inner", "FAKE-path-token"))
	out := buf.String()
	require.NotContains(t, out, "FAKE-path-token")
	require.NotContains(t, out, "FAKE-query-token")
	require.True(t, strings.Contains(out, Mask), out)
}

func TestRedact_IsIdempotentOnDisplayForms(t *testing.T) {
	// Output is redacted again as a last guard, so display forms must survive it.
	var s Secrets
	s.AddKey(fakeSSConf)
	for _, key := range []string{fakeSSKey, fakeLegacy, fakeSSConf, "https://example.test/x", "https://example.test/"} {
		display := URL(key)
		line := "key: " + display + " (from --key)"
		require.Equal(t, line, s.Redact(line), "key %q", key)
	}
}
