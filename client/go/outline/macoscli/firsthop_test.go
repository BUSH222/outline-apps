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
	"context"
	"errors"
	"net/netip"
	"testing"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/keys"

	"golang.getoutline.org/sdk/transport"

	"github.com/stretchr/testify/require"
)

func TestFirstHopAddrs(t *testing.T) {
	ctx := context.Background()
	pairWith := func(tcp, udp string) *configregistry.TransportPair {
		return &configregistry.TransportPair{
			StreamDialer: &configregistry.Dialer[transport.StreamConn]{ConnectionProviderInfo: configregistry.ConnectionProviderInfo{FirstHop: tcp}},
			PacketRelay:  &configregistry.PacketRelay{ConnectionProviderInfo: configregistry.ConnectionProviderInfo{FirstHop: udp}},
		}
	}
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "server.example.test":
			return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:192.0.2.2")}, nil
		case "v6only.example.test":
			return []netip.Addr{netip.MustParseAddr("2001:db8::2")}, nil
		}
		return nil, errors.New("no such host")
	}

	addrs, byName, err := firstHopAddrs(ctx, pairWith("server.example.test:443", "192.0.2.9:443"), lookup)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.9")}, addrs)
	require.Equal(t, map[string][]netip.Addr{
		"server.example.test": {netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")},
	}, byName, "only host names, IPv4 only")

	_, _, err = firstHopAddrs(ctx, pairWith("v6only.example.test:443", ""), lookup)
	require.ErrorContains(t, err, "IPv6-only")
	_, _, err = firstHopAddrs(ctx, pairWith("missing.example.test:443", ""), lookup)
	require.ErrorContains(t, err, "resolving the server missing.example.test")

	// A parsed key works too.
	parsed, err := keys.ParseClientConfig(ctx, `{"transport": "`+fakeSSKey+`"}`, nil)
	require.NoError(t, err)
	addrs, byName, err = firstHopAddrs(ctx, parsed.Pair, lookup)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.10")}, addrs)
	require.Empty(t, byName)
}
