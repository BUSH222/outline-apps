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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"localhost/client/go/outline"
	"localhost/client/go/outline/macoscli/internal/redact"
	"localhost/client/go/outline/platerrors"
)

// Kind is the kind of key that was resolved.
type Kind string

const (
	// KindStatic is an ss:// key.
	KindStatic Kind = "static"
	// KindDynamic is an ssconf:// or https:// key whose config is fetched.
	KindDynamic Kind = "dynamic"
	// KindConfigFile is a path to a file with a tunnel config (YAML, JSON or an ss:// line).
	KindConfigFile Kind = "config-file"
	// KindConfigText is tunnel config text given directly.
	KindConfigText Kind = "config-text"
)

// Resolved is a key resolved to a client config, as ParseTunnelConfig returns it.
type Resolved struct {
	Kind Kind
	// Display is a redacted description of the key, safe to print.
	Display string
	// ClientConfig is the client config JSON ({"transport": ...}) that
	// outline.ProviderClientConfig decodes.
	ClientConfig string
	// FirstHop is the first-hop address, or "" if TCP and UDP use different ones.
	FirstHop string
	// ConnectionType is "tunneled", "direct", "partial" or "blocked".
	ConnectionType string
}

// ParseFunc parses tunnel config text into a client config.
type ParseFunc func(tunnelConfigText string) (*Resolved, error)

// Resolver turns a RawKey into a Resolved config.
type Resolver struct {
	// Fetcher downloads dynamic keys. nil means a default Fetcher.
	Fetcher *Fetcher
	// Secrets receives every secret found while resolving. Required.
	Secrets *redact.Secrets
	// Parse parses tunnel config text. nil means ParseTunnelConfig.
	Parse ParseFunc
}

// Resolve resolves the key. For dynamic keys it fetches the config, so it must
// run before any route or DNS change.
func (r *Resolver) Resolve(ctx context.Context, raw *RawKey) (*Resolved, error) {
	if r.Secrets == nil {
		return nil, errors.New("keys: Resolver.Secrets is required")
	}
	text := strings.TrimSpace(raw.Text)
	if scheme, ok := keyScheme(text); ok {
		r.Secrets.AddKey(text)
		return r.resolveURL(ctx, scheme, text)
	}
	r.Secrets.AddConfig(text)

	if raw.AllowPath && isSingleLine(text) {
		info, err := os.Stat(text)
		switch {
		case err == nil && info.Mode().IsRegular():
			return r.resolveFile(ctx, text)
		case looksLikePath(text):
			return nil, fmt.Errorf("config file %s: %w", text, errNotFound(err))
		}
	}
	return r.parse(KindConfigText, "config text", text)
}

func errNotFound(err error) error {
	if err == nil {
		return errors.New("not a regular file")
	}
	return err
}

func (r *Resolver) resolveFile(ctx context.Context, path string) (*Resolved, error) {
	data, err := readLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}
	content := strings.TrimSpace(string(data))
	if scheme, ok := keyScheme(content); ok && scheme != "ss" {
		// A file holding a dynamic key: resolve it, but report where it came from.
		r.Secrets.AddKey(content)
		resolved, err := r.resolveURL(ctx, scheme, content)
		if err != nil {
			return nil, err
		}
		resolved.Display = "file " + path + " → " + resolved.Display
		return resolved, nil
	}
	if strings.HasPrefix(content, "ss://") {
		r.Secrets.AddKey(content)
		content = stripFragment(content)
	} else {
		r.Secrets.AddConfig(content)
	}
	return r.parse(KindConfigFile, "file "+path, content)
}

func (r *Resolver) resolveURL(ctx context.Context, scheme, key string) (*Resolved, error) {
	display := redact.URL(key)
	noFragment := stripFragment(key)
	switch scheme {
	case "ss":
		return r.parse(KindStatic, display, noFragment)

	case "ssconf", "https":
		// Same rewrite as the app: ssconf:// is https:// with another name.
		_, rest, _ := strings.Cut(noFragment, "://")
		location, err := url.Parse("https://" + rest)
		if err != nil || location.Host == "" {
			return nil, fmt.Errorf("invalid dynamic key %s", display)
		}
		fetcher := r.Fetcher
		if fetcher == nil {
			fetcher = &Fetcher{}
		}
		body, err := fetcher.Fetch(ctx, location)
		if err != nil {
			return nil, err
		}
		body = strings.TrimSpace(body)
		if body == "" {
			return nil, fmt.Errorf("dynamic key %s returned an empty config", display)
		}
		r.Secrets.AddConfig(body)
		return r.parse(KindDynamic, display, body)

	default:
		return nil, fmt.Errorf("unsupported key type %s:// (want ss://, ssconf:// or https://)", scheme)
	}
}

func (r *Resolver) parse(kind Kind, display, text string) (*Resolved, error) {
	parse := r.Parse
	if parse == nil {
		parse = ParseTunnelConfig
	}
	resolved, err := parse(text)
	if err != nil {
		return nil, err
	}
	resolved.Kind = kind
	resolved.Display = display
	r.Secrets.AddConfig(resolved.ClientConfig)
	return resolved, nil
}

// keyScheme returns the lowercase scheme if text looks like "scheme://...".
func keyScheme(text string) (string, bool) {
	scheme, _, ok := strings.Cut(text, "://")
	if !ok || scheme == "" || strings.ContainsAny(scheme, " \t\n{}[]:\"'") {
		return "", false
	}
	return strings.ToLower(scheme), true
}

func stripFragment(key string) string {
	noFragment, _, _ := strings.Cut(key, "#")
	return noFragment
}

func isSingleLine(text string) bool {
	return !strings.ContainsAny(text, "\n\r")
}

// looksLikePath reports whether text was probably meant as a file path, so a
// missing file is reported instead of parsing the path as config text.
func looksLikePath(text string) bool {
	if strings.HasPrefix(text, "/") || strings.HasPrefix(text, "./") ||
		strings.HasPrefix(text, "../") || strings.HasPrefix(text, "~") {
		return true
	}
	for _, ext := range []string{".yaml", ".yml", ".json", ".conf", ".txt"} {
		if strings.HasSuffix(strings.ToLower(text), ext) {
			return true
		}
	}
	return false
}

// parseTunnelConfigResponse mirrors firstHopAndTunnelConfigJSON in
// client/go/outline/parse.go.
type parseTunnelConfigResponse struct {
	Client         string `json:"client"`
	FirstHop       string `json:"firstHop"`
	ConnectionType string `json:"connectionType"`
}

// ParseTunnelConfig calls the app's ParseTunnelConfig method. It accepts an
// ss:// URL, legacy Shadowsocks JSON, or a YAML/JSON tunnel config, and
// reports a provider-supplied error as an error.
func ParseTunnelConfig(tunnelConfigText string) (*Resolved, error) {
	result := outline.InvokeMethod(outline.MethodParseTunnelConfig, tunnelConfigText)
	if result.Error != nil {
		return nil, describePlatformError(result.Error)
	}
	var resp parseTunnelConfigResponse
	if err := json.Unmarshal([]byte(result.Value), &resp); err != nil {
		return nil, fmt.Errorf("unexpected ParseTunnelConfig output: %w", err)
	}
	return &Resolved{
		ClientConfig:   resp.Client,
		FirstHop:       resp.FirstHop,
		ConnectionType: resp.ConnectionType,
	}, nil
}

// describePlatformError turns a PlatformError into a readable error. It never
// includes Details, which can hold URLs and fetched bodies.
func describePlatformError(pe *platerrors.PlatformError) error {
	if pe.Code == platerrors.ProviderError {
		return fmt.Errorf("the key provider returned an error: %s", pe.Message)
	}
	msg := pe.Message
	for cause := pe.Cause; cause != nil; cause = cause.Cause {
		msg += ": " + cause.Message
	}
	return fmt.Errorf("invalid tunnel config (%s): %s", pe.Code, msg)
}
