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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/connectivity"
	"localhost/client/go/outline/macoscli/internal/sysrouter"

	"golang.getoutline.org/sdk/transport"
)

const (
	verifyTimeout    = 10 * time.Second
	verifyDNSTimeout = 5 * time.Second
)

// verifyURLs are plain-HTTP connectivity endpoints, as used by the app's own
// TCP check (client/go/outline/connectivity).
var verifyURLs = []string{
	"http://captive.apple.com/",
	"http://connectivitycheck.gstatic.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
}

// verifyFunc builds the post-routing check for a transport.
type verifyFunc func(pair *configregistry.TransportPair, log *slog.Logger) func(ctx context.Context) error

// verifyTunnel runs once routes and DNS point into the tunnel. The health
// check before routing can't see two failures that only appear afterwards:
//  1. the transport's own sockets can no longer reach the server, and
//  2. ordinary traffic (system DNS, default routes) doesn't make it through
//     the utun and lwIP.
//
// When 2 fails, a direct query to the tunnel's DNS address tells whether DNS
// is the problem.
func verifyTunnel(pair *configregistry.TransportPair, log *slog.Logger) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if err := connectivity.CheckTCPConnectivity(pair); err != nil {
			return fmt.Errorf("check 1/2 failed: the server can't be reached once traffic is routed into the tunnel: %w", err)
		}
		log.Info("check 1/2 passed: the server is reachable with the tunnel routes in place")

		// An unbound dialer and the system resolver: exactly what apps use.
		appErr := connectivity.CheckTCPConnectivityWithHTTP(verifyTimeout, &transport.TCPDialer{}, verifyURLs)
		if appErr == nil {
			log.Info("check 2/2 passed: traffic flows through the tunnel")
			return nil
		}
		if dnsErr := lookupThroughTunnel(ctx); dnsErr != nil {
			return fmt.Errorf("check 2/2 failed: traffic through the tunnel doesn't work (%v), and DNS at %s doesn't answer: %w",
				appErr, sysrouter.OutlineDNS, dnsErr)
		}
		return fmt.Errorf("check 2/2 failed: DNS through the tunnel answers, but connections through it fail: %w", appErr)
	}
}

// lookupThroughTunnel sends one DNS query straight to the tunnel's DNS address.
func lookupThroughTunnel(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, verifyDNSTimeout)
	defer cancel()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp4", netip.AddrPortFrom(sysrouter.OutlineDNS, 53).String())
		},
	}
	_, err := resolver.LookupNetIP(ctx, "ip4", "captive.apple.com")
	return err
}
