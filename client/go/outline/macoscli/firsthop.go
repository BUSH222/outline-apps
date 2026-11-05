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
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"localhost/client/go/outline/configregistry"
)

const firstHopLookupTimeout = 5 * time.Second

// lookupFunc resolves a host name to addresses.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// firstHopAddrs resolves the transport's first hops (TCP and UDP) to IPv4
// addresses. It runs before any DNS change, so it uses the system resolver.
// IPv6-only servers are refused, because IPv6 is turned off during a session.
// It also returns the addresses of each host name, for the binder to fall
// back on when it can't look the name up later.
func firstHopAddrs(ctx context.Context, pair *configregistry.TransportPair, lookup lookupFunc) ([]netip.Addr, map[string][]netip.Addr, error) {
	var hops []string
	for _, hop := range []string{pair.StreamDialer.FirstHop, pair.PacketRelay.FirstHop} {
		if hop != "" && (len(hops) == 0 || hops[0] != hop) {
			hops = append(hops, hop)
		}
	}
	if len(hops) == 0 {
		return nil, nil, nil
	}

	var addrs []netip.Addr
	byName := map[string][]netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, hop := range hops {
		host, _, err := net.SplitHostPort(hop)
		if err != nil {
			host = hop
		}
		var found []netip.Addr
		if addr, err := netip.ParseAddr(host); err == nil {
			found = []netip.Addr{addr}
		} else {
			lookupCtx, cancel := context.WithTimeout(ctx, firstHopLookupTimeout)
			found, err = lookup(lookupCtx, host)
			cancel()
			if err != nil {
				return nil, nil, fmt.Errorf("resolving the server %s: %w", host, err)
			}
			for _, a := range found {
				if a = a.Unmap(); a.Is4() && !slices.Contains(byName[host], a) {
					byName[host] = append(byName[host], a)
				}
			}
		}
		for _, a := range found {
			a = a.Unmap()
			if a.Is4() && !seen[a] {
				seen[a] = true
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 {
		return nil, nil, errors.New("the server has no IPv4 address; IPv6-only servers are not supported because IPv6 is turned off during a session")
	}
	return addrs, byName, nil
}
