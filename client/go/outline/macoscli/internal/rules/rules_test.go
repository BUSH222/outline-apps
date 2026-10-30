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

package rules

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, yaml string) *Rules {
	t.Helper()
	r, err := Parse([]byte(yaml))
	require.NoError(t, err)
	return r
}

func TestMatch_LabelSuffix(t *testing.T) {
	r := mustParse(t, "bypass: [lichess.org]")
	for name, want := range map[string]Class{
		"lichess.org":           Bypass,
		"www.lichess.org":       Bypass,
		"a.b.lichess.org":       Bypass,
		"LiChess.ORG.":          Bypass, // case and trailing dot
		"notlichess.org":        None,   // not a label boundary
		"lichess.org.evil.com":  None,
		"org":                   None,
		"":                      None,
		".":                     None,
		"www.lichess.organizer": None,
	} {
		got, _ := r.Match(name)
		require.Equal(t, want, got, name)
	}
}

func TestMatch_Wildcard(t *testing.T) {
	r := mustParse(t, `bypass: ["*.example.org"]`)
	c, _ := r.Match("example.org")
	require.Equal(t, None, c, "*.example.org doesn't cover example.org itself")
	c, rule := r.Match("cdn.example.org")
	require.Equal(t, Bypass, c)
	require.Equal(t, "*.example.org", rule)
	require.Empty(t, r.ExactBypass(), "wildcards can't be resolved ahead of time")
}

func TestMatch_VPNOnlyWins(t *testing.T) {
	r := mustParse(t, `
bypass: [example.com, private.example.net, shared.test]
vpn_only: [secret.example.com, example.net, shared.test]
`)
	for name, want := range map[string]Class{
		"example.com":            Bypass,
		"www.example.com":        Bypass,
		"secret.example.com":     VPNOnly, // nested: the more specific vpn_only entry
		"a.secret.example.com":   VPNOnly,
		"private.example.net":    VPNOnly, // nested the other way: vpn_only still wins
		"x.private.example.net":  VPNOnly,
		"shared.test":            VPNOnly, // listed in both
		"unrelated.example.test": None,
	} {
		got, _ := r.Match(name)
		require.Equal(t, want, got, name)
	}
	require.Len(t, r.Warnings, 2)
	require.Contains(t, r.Warnings[0], `"private.example.net" is covered by vpn_only entry "example.net"`)
	require.Contains(t, r.Warnings[1], `"shared.test"`)
	require.Equal(t, []string{"example.com"}, r.ExactBypass())
}

func TestMatch_IDN(t *testing.T) {
	r := mustParse(t, "bypass: [Bücher.example]")
	require.Equal(t, []string{"xn--bcher-kva.example"}, r.Bypass)
	// DNS messages carry the punycode form.
	c, _ := r.Match("www.xn--bcher-kva.example.")
	require.Equal(t, Bypass, c)
}

func TestParse_Defaults(t *testing.T) {
	for _, in := range []string{"", "  \n", "bypass: []", "# only a comment\n"} {
		r := mustParse(t, in)
		require.True(t, r.IsEmpty(), in)
		require.Equal(t, DefaultMinTTL, r.MinTTL)
		require.Equal(t, DefaultMaxTTL, r.MaxTTL)
	}
}

func TestParse_Full(t *testing.T) {
	r := mustParse(t, `
bypass:
  - Example.COM.
  - example.com     # duplicate after normalizing
  - "*.cdn.example"
vpn_only: [secret.example]
direct_dns: [192.0.2.53, "198.51.100.53"]
min_ttl: 30s
max_ttl: 2h
`)
	require.Equal(t, []string{"example.com", "*.cdn.example"}, r.Bypass)
	require.Equal(t, []string{"secret.example"}, r.VPNOnly)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("198.51.100.53")}, r.DirectDNS)
	require.Equal(t, 30*time.Second, r.MinTTL)
	require.Equal(t, 2*time.Hour, r.MaxTTL)
	require.Empty(t, r.Warnings)
	require.False(t, r.IsEmpty())
}

func TestParse_Errors(t *testing.T) {
	for in, want := range map[string]string{
		"bypass: [example.com":              "invalid YAML",
		"bypas: [example.com]":              "invalid YAML", // a typo must not drop rules silently
		`bypass: [""]`:                      "bypass entry 1",
		"bypass: [ok.example, '*']":         "bypass entry 2",
		"bypass: [a.*.example]":             "wildcard",
		"bypass: [.example.com]":            "leading dot",
		"bypass: [https://example.com/]":    "not a domain name",
		"bypass: [example.com:443]":         "not a domain name",
		"vpn_only: [192.0.2.1]":             "IP addresses aren't supported",
		"bypass: [bad_name.example]":        "not a valid domain name",
		"direct_dns: [2001:db8::1]":         "not an IPv4 address",
		"direct_dns: [resolver.example]":    "not an IPv4 address",
		"min_ttl: 60":                       "with a unit",
		"min_ttl: soon":                     "min_ttl",
		"max_ttl: -1s":                      "must be positive",
		"min_ttl: 2h\nmax_ttl: 1h":          "greater than max_ttl",
		"bypass: example.com":               "invalid YAML",
		"bypass: [example.com]\nbypass: []": "invalid YAML", // duplicate key
	} {
		_, err := Parse([]byte(in))
		require.ErrorContains(t, err, want, in)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(path, []byte("bypass: [example.com]\n"), 0o644))
	r, err := Load(path)
	require.NoError(t, err)
	require.Equal(t, []string{"example.com"}, r.Bypass)

	require.NoError(t, os.WriteFile(path, []byte("bypass: [https://x/]\n"), 0o644))
	_, err = Load(path)
	require.ErrorContains(t, err, path)

	_, err = Load(filepath.Join(dir, "missing.yaml"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
