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
	"errors"
	"fmt"
	"net"
	"strings"

	"localhost/client/go/configyaml"
	"localhost/client/go/outline"
	"localhost/client/go/outline/configregistry"

	"github.com/goccy/go-yaml"
	"golang.getoutline.org/sdk/transport"
)

// Parsed is a client config parsed into a transport.
type Parsed struct {
	// Pair is the transport. In a dry run it is built with unbound dialers and
	// must not be used for traffic.
	Pair *configregistry.TransportPair
	// TransportType is the top-level transport type, for display.
	TransportType string
	// HasReporter reports whether the config includes a usage reporter.
	HasReporter bool
}

// ParseClientConfig decodes a client config (as in Resolved.ClientConfig) and
// parses its transport with provider. This is what client.go does in
// ClientConfig.New, minus the Client wrapper the CLI doesn't need.
//
// A nil provider means configregistry.NewDefaultTransportProvider with plain,
// unbound dialers. That is fine for inspection: parsing does no network I/O on
// darwin. It must not be used to carry traffic, which needs bound dialers.
func ParseClientConfig(ctx context.Context, clientConfig string, provider *configyaml.TypeParser[*configregistry.TransportPair]) (*Parsed, error) {
	var cfg outline.ProviderClientConfig
	if err := yaml.Unmarshal([]byte(clientConfig), &cfg); err != nil {
		return nil, fmt.Errorf("client config is not valid YAML: %w", err)
	}
	if provider == nil {
		provider = configregistry.NewDefaultTransportProvider(
			&transport.TCPDialer{Dialer: net.Dialer{KeepAlive: -1}}, &transport.UDPDialer{})
	}
	pair, err := provider.Parse(ctx, cfg.Transport)
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			return nil, fmt.Errorf("unsupported transport config: %w", err)
		}
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}
	return &Parsed{
		Pair:          pair,
		TransportType: transportType(cfg.Transport),
		HasReporter:   cfg.Reporter != nil,
	}, nil
}

// transportType names the top-level transport, mirroring how the registry
// dispatches: a string is a Shadowsocks URL, a map without $type is
// Shadowsocks (the backwards-compatible default).
func transportType(node configyaml.ConfigNode) string {
	switch v := node.(type) {
	case string:
		return "shadowsocks (URL)"
	case map[string]any:
		if t, ok := v[configyaml.ConfigTypeKey].(string); ok && t != "" {
			return t
		}
		return "shadowsocks"
	case nil:
		return "none"
	default:
		return fmt.Sprintf("unknown (%T)", v)
	}
}

// CheckLoopSafe refuses transports that would send traffic directly through
// sockets the CLI can't bind to the physical interface. Upstream builds the
// direct TCP of basic-access and every direct UDP listener with unbound
// sockets (configregistry/config_proxyless.go, registry.go), which would loop
// back into the tunnel once the default routes point at the utun.
func CheckLoopSafe(pair *configregistry.TransportPair) error {
	var problems []string
	if pair.StreamDialer == nil || pair.StreamDialer.ConnType == configregistry.ConnTypeDirect {
		problems = append(problems, "TCP is not proxied (for example a basic-access transport)")
	}
	if pair.PacketRelay == nil || pair.PacketRelay.ConnType == configregistry.ConnTypeDirect {
		problems = append(problems, "UDP is not proxied (for example udp: direct or a missing udp entry)")
	}
	if len(problems) > 0 {
		return fmt.Errorf("this config can't be used by the CLI: %s; direct sockets from such configs would loop back into the tunnel",
			strings.Join(problems, "; "))
	}
	return nil
}

// ConnTypeName returns the JSON name of a connection type ("tunneled", ...).
func ConnTypeName(c configregistry.ConnType) string {
	b, err := c.MarshalJSON()
	if err != nil {
		return "unknown"
	}
	return strings.Trim(string(b), `"`)
}
