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

// Package rules loads the domain rules file and matches names against it.
//
// The file is YAML:
//
//	bypass:            # never through the VPN; covers each domain and its subdomains
//	  - example.com
//	  - "*.example.org"  # subdomains only, not example.org itself
//	vpn_only: []       # always through the VPN (wins over bypass)
//	direct_dns: []     # optional IPv4 resolvers for bypass names; default: the network's
//	min_ttl: 60s       # learned addresses are kept at least this long
//	max_ttl: 1h        # and at most this long
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	"golang.org/x/net/idna"
)

// Class is what the rules say about a name or address. A higher class wins.
type Class uint8

const (
	// None: no rule matches; traffic goes through the tunnel.
	None Class = iota
	// Bypass: traffic goes directly, never through the tunnel.
	Bypass
	// VPNOnly: traffic always goes through the tunnel, never directly.
	VPNOnly
)

func (c Class) String() string {
	switch c {
	case None:
		return "none"
	case Bypass:
		return "bypass"
	case VPNOnly:
		return "vpn_only"
	default:
		return fmt.Sprintf("Class(%d)", c)
	}
}

// Default TTL bounds for learned addresses.
const (
	DefaultMinTTL = 60 * time.Second
	DefaultMaxTTL = time.Hour
)

// Rules is a loaded rules file. The zero value is not valid; use Empty, Parse
// or Load.
type Rules struct {
	// Bypass and VPNOnly are the normalized entries (in punycode, "*." kept).
	Bypass  []string
	VPNOnly []string
	// DirectDNS, if set, replaces the network's resolvers for bypass names.
	DirectDNS []netip.Addr
	// MinTTL and MaxTTL bound how long a learned address is kept.
	MinTTL, MaxTTL time.Duration
	// Warnings are problems that don't stop the rules from loading.
	Warnings []string

	names map[string]*entry
}

// entry holds the classes a domain's rules give to the domain itself (apex)
// and to its subdomains (sub).
type entry struct {
	apex, sub Class
	// rule is the entry as written, for logs.
	apexRule, subRule string
}

// Empty returns rules that match nothing.
func Empty() *Rules {
	return &Rules{MinTTL: DefaultMinTTL, MaxTTL: DefaultMaxTTL, names: map[string]*entry{}}
}

// IsEmpty reports whether no domain is listed.
func (r *Rules) IsEmpty() bool {
	return len(r.Bypass) == 0 && len(r.VPNOnly) == 0
}

type file struct {
	Bypass    []string `yaml:"bypass"`
	VPNOnly   []string `yaml:"vpn_only"`
	DirectDNS []string `yaml:"direct_dns"`
	MinTTL    any      `yaml:"min_ttl"`
	MaxTTL    any      `yaml:"max_ttl"`
}

// Load reads and parses a rules file.
func Load(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("rules file %s: %w", path, err)
	}
	return r, nil
}

// Parse parses the rules file format. Unknown keys are errors, so a typo
// can't silently drop a rule.
func Parse(data []byte) (*Rules, error) {
	r := Empty()
	if len(bytes.TrimSpace(data)) == 0 {
		return r, nil
	}
	var f file
	if err := yaml.UnmarshalWithOptions(data, &f, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	var err error
	if r.MinTTL, err = parseTTL("min_ttl", f.MinTTL, DefaultMinTTL); err != nil {
		return nil, err
	}
	if r.MaxTTL, err = parseTTL("max_ttl", f.MaxTTL, DefaultMaxTTL); err != nil {
		return nil, err
	}
	if r.MinTTL > r.MaxTTL {
		return nil, fmt.Errorf("min_ttl (%s) is greater than max_ttl (%s)", r.MinTTL, r.MaxTTL)
	}

	for i, s := range f.DirectDNS {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !addr.Unmap().Is4() {
			return nil, fmt.Errorf("direct_dns entry %d (%q) is not an IPv4 address (IPv6 is off during a session)", i+1, s)
		}
		r.DirectDNS = append(r.DirectDNS, addr.Unmap())
	}

	if r.Bypass, err = r.addList("bypass", f.Bypass, Bypass); err != nil {
		return nil, err
	}
	if r.VPNOnly, err = r.addList("vpn_only", f.VPNOnly, VPNOnly); err != nil {
		return nil, err
	}
	for _, b := range r.Bypass {
		if c, rule := r.matchEntry(b); c == VPNOnly {
			r.Warnings = append(r.Warnings,
				fmt.Sprintf("bypass entry %q is covered by vpn_only entry %q, which wins; the bypass entry has no effect", b, rule))
		}
	}
	return r, nil
}

func parseTTL(key string, v any, def time.Duration) (time.Duration, error) {
	if v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return 0, fmt.Errorf("%s: want a duration with a unit, like 60s or 1h, not %v", key, v)
	}
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%s: want a duration like 60s or 1h: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, not %s", key, s)
	}
	return d, nil
}

// addList validates and adds a list of entries, returning them normalized
// and without duplicates.
func (r *Rules) addList(key string, list []string, class Class) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for i, raw := range list {
		name, wildcard, err := normalizeEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("%s entry %d (%q): %w", key, i+1, raw, err)
		}
		written := name
		if wildcard {
			written = "*." + name
		}
		if seen[written] {
			continue
		}
		seen[written] = true
		out = append(out, written)

		e := r.names[name]
		if e == nil {
			e = &entry{}
			r.names[name] = e
		}
		if !wildcard && class > e.apex {
			e.apex, e.apexRule = class, written
		}
		if class > e.sub {
			e.sub, e.subRule = class, written
		}
	}
	return out, nil
}

// normalizeEntry turns a rules entry into a lowercase punycode name, and says
// whether it was written as "*.name" (subdomains only).
func normalizeEntry(raw string) (name string, wildcard bool, err error) {
	s := strings.TrimSpace(raw)
	if rest, ok := strings.CutPrefix(s, "*."); ok {
		wildcard, s = true, rest
	}
	s = strings.TrimSuffix(s, ".")
	switch {
	case s == "":
		return "", false, errors.New("empty")
	case strings.HasPrefix(s, "."):
		return "", false, fmt.Errorf("write it without the leading dot (%q also covers its subdomains)", strings.TrimLeft(s, "."))
	case strings.Contains(s, "*"):
		return "", false, errors.New(`a wildcard is only allowed as a leading "*."`)
	case strings.ContainsAny(s, "/:@ "):
		return "", false, errors.New("not a domain name (URLs, ports and addresses aren't supported)")
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false, errors.New("IP addresses aren't supported; list domain names")
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(s))
	if err != nil {
		return "", false, fmt.Errorf("not a valid domain name: %w", err)
	}
	return ascii, wildcard, nil
}

// Normalize prepares a name from a DNS message for matching: lowercase,
// without the trailing dot. Names on the wire are already ASCII (punycode).
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Match returns the class of a name and the entry that decided it. A name is
// covered by an entry for itself or for any parent domain, label by label:
// "example.com" covers "www.example.com" but not "notexample.com". If several
// entries match, vpn_only wins (fail closed).
func (r *Rules) Match(name string) (Class, string) {
	return r.matchEntry(Normalize(name))
}

func (r *Rules) matchEntry(name string) (Class, string) {
	if name == "" || len(r.names) == 0 {
		return None, ""
	}
	name = strings.TrimPrefix(name, "*.")
	best, rule := None, ""
	if e := r.names[name]; e != nil && e.apex > best {
		best, rule = e.apex, e.apexRule
	}
	for s := name; ; {
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
		if e := r.names[s]; e != nil && e.sub > best {
			best, rule = e.sub, e.subRule
		}
	}
	return best, rule
}

// ExactBypass lists the bypass names that can be resolved ahead of time: the
// entries written without "*." that vpn_only doesn't override.
func (r *Rules) ExactBypass() []string {
	var out []string
	for _, b := range r.Bypass {
		if strings.HasPrefix(b, "*.") {
			continue
		}
		if c, _ := r.matchEntry(b); c == Bypass {
			out = append(out, b)
		}
	}
	return out
}
