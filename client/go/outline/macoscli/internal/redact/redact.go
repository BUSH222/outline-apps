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

// Package redact keeps access keys and other secrets out of logs and errors.
//
// Two layers are used: a set of known secret strings, which is filled in as
// keys and configs are read, and a pattern that rewrites anything that looks
// like a key or config URL into a display form without credentials, path,
// query or fragment.
package redact

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
)

// Mask replaces redacted content.
const Mask = "<redacted>"

// minSecretLen is the shortest string treated as a secret. Shorter strings would
// mangle unrelated text.
const minSecretLen = 4

// minSegmentLen is the shortest single URL path segment treated as a secret.
const minSegmentLen = 8

// secretConfigKeys are config field names whose values are always secret.
var secretConfigKeys = map[string]bool{
	"secret":   true,
	"password": true,
	"prefix":   true,
}

// urlPattern matches URLs of the schemes that can carry access keys or secret
// config locations.
var urlPattern = regexp.MustCompile(`(?i)\b(?:ss|ssconf|https?|wss?)://[^\s"'<>]+`)

// URL returns a display form of an access key or URL: the scheme and host are
// kept, while user info, path, query and fragment are replaced with [Mask].
// Legacy ss:// keys, whose whole body is base64, are masked entirely.
func URL(raw string) string {
	raw = strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || scheme == "" {
		return Mask
	}
	scheme = strings.ToLower(scheme)
	rest, _, _ = strings.Cut(rest, "#")

	authority, tail := rest, ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, tail = rest[:i], rest[i:]
	}
	host := authority
	hasUserInfo := false
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		host = authority[i+1:]
		hasUserInfo = true
	}
	if (scheme == "ss" && !hasUserInfo) || !isHostPort(host) {
		return scheme + "://" + Mask
	}

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	if hasUserInfo {
		b.WriteString(Mask)
		b.WriteString("@")
	}
	b.WriteString(host)
	switch tail {
	case "":
	case "/":
		// Keep a bare slash, so re-redacting an already masked "host/<redacted>"
		// (the pattern stops at "<") keeps its slash.
		b.WriteString("/")
	default:
		b.WriteString("/")
		b.WriteString(Mask)
	}
	return b.String()
}

// isHostPort reports whether s only contains characters valid in a host name,
// an IP literal and an optional port.
func isHostPort(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(".-_:[]%", r):
		default:
			return false
		}
	}
	return true
}

// Secrets is a concurrency-safe set of secret strings to scrub from text.
// The zero value is ready to use.
type Secrets struct {
	mu   sync.RWMutex
	list []string // sorted longest first, so longer secrets win over their substrings
}

// Add registers secret values. Values shorter than 4 bytes are ignored.
func (s *Secrets) Add(values ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range values {
		if len(v) < minSecretLen || v == Mask {
			continue
		}
		if !containsString(s.list, v) {
			s.list = append(s.list, v)
		}
	}
	sort.SliceStable(s.list, func(i, j int) bool { return len(s.list[i]) > len(s.list[j]) })
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// AddKey registers the secret parts of an access key or URL: the whole key,
// its user info (raw, unescaped and base64-decoded), path and query.
func (s *Secrets) AddKey(raw string) {
	raw = strings.TrimSpace(raw)
	s.Add(raw)
	noFragment, _, _ := strings.Cut(raw, "#")
	s.Add(noFragment)

	scheme, rest, ok := strings.Cut(noFragment, "://")
	if !ok {
		return
	}
	if strings.EqualFold(scheme, "ssconf") {
		s.Add("https://" + rest)
	}

	authority, tail := rest, ""
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		authority, tail = rest[:i], rest[i:]
	}
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		s.addUserInfo(authority[:i])
	} else if strings.EqualFold(scheme, "ss") {
		// Legacy ss://BASE64(method:password@host:port): the whole body is secret.
		s.addUserInfo(authority)
	}

	if tail == "" {
		return
	}
	s.Add(tail)
	path, query, _ := strings.Cut(tail, "?")
	if path != "/" {
		s.Add(path)
		if unescaped, err := url.PathUnescape(path); err == nil {
			s.Add(unescaped)
		}
		// Single segments are registered too, but only long ones, so common words
		// such as "config" in a path don't get masked everywhere.
		for _, segment := range strings.Split(path, "/") {
			if unescaped, err := url.PathUnescape(segment); err == nil && len(unescaped) >= minSegmentLen {
				s.Add(segment, unescaped)
			}
		}
	}
	if query != "" {
		s.Add(query)
		if values, err := url.ParseQuery(query); err == nil {
			for _, vs := range values {
				s.Add(vs...)
			}
		}
	}
}

// addUserInfo registers user info and, if it is base64, its decoded form and
// the password after the first ':'.
func (s *Secrets) addUserInfo(userInfo string) {
	s.Add(userInfo)
	if unescaped, err := url.PathUnescape(userInfo); err == nil {
		s.Add(unescaped)
		if _, password, ok := strings.Cut(unescaped, ":"); ok {
			s.Add(password)
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.URLEncoding.WithPadding(base64.NoPadding),
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
	} {
		decoded, err := enc.DecodeString(userInfo)
		if err != nil {
			continue
		}
		text := string(decoded)
		s.Add(text)
		if _, password, ok := strings.Cut(text, ":"); ok {
			// Legacy keys decode to "method:password@host:port".
			if i := strings.LastIndex(password, "@"); i >= 0 {
				password = password[:i]
			}
			s.Add(password)
		}
	}
}

// AddConfig registers secrets found in tunnel config text: values of secret
// fields (secret, password, prefix) and every embedded URL. If the text isn't
// valid YAML, every line of 8 or more characters is registered instead,
// because its structure is unknown.
func (s *Secrets) AddConfig(text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	s.Add(text)
	var node any
	if err := yaml.Unmarshal([]byte(text), &node); err != nil {
		for _, line := range strings.Split(text, "\n") {
			if line = strings.TrimSpace(line); len(line) >= 8 {
				s.Add(line)
			}
		}
		return
	}
	s.addConfigNode("", node)
}

func (s *Secrets) addConfigNode(key string, node any) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			s.addConfigNode(strings.ToLower(k), child)
		}
	case []any:
		for _, child := range v {
			s.addConfigNode(key, child)
		}
	case string:
		if secretConfigKeys[key] {
			s.Add(v)
		}
		if strings.Contains(v, "://") {
			s.AddKey(v)
		}
	}
}

// Redact returns text with every registered secret and every key-like URL
// replaced.
func (s *Secrets) Redact(text string) string {
	// Rewrite URLs first so they keep a readable scheme and host.
	text = urlPattern.ReplaceAllStringFunc(text, URL)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, secret := range s.list {
		text = strings.ReplaceAll(text, secret, Mask)
	}
	return text
}

// Error returns err's message, redacted.
func (s *Secrets) Error(err error) string {
	if err == nil {
		return ""
	}
	return s.Redact(err.Error())
}

// ReplaceAttr is a [slog.HandlerOptions] ReplaceAttr hook that redacts string,
// error and Stringer attribute values, including the log message.
func (s *Secrets) ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(s.Redact(a.Value.String()))
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			a.Value = slog.StringValue(s.Redact(v.Error()))
		case fmt.Stringer:
			a.Value = slog.StringValue(s.Redact(v.String()))
		}
	}
	return a
}
