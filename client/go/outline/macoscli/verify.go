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
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/connectivity"
	"localhost/client/go/outline/macoscli/internal/sysrouter"

	"golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
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

// verifyInput is what the post-routing checks need.
type verifyInput struct {
	// pair is the transport itself, without the domain rules.
	pair *configregistry.TransportPair
	// direct dials interface-bound sockets, like bypass traffic.
	direct transport.StreamDialer
	// firstHops have host routes via the physical gateway.
	firstHops []netip.Addr
	log       *slog.Logger
}

// verifyFunc builds the post-routing check for a transport.
type verifyFunc func(in verifyInput) func(ctx context.Context) error

// verifyTunnel runs once routes and DNS point into the tunnel. The health
// check before routing can't see two failures that only appear afterwards:
//  1. the transport's own sockets can no longer reach the server, and
//  2. ordinary traffic (system DNS, default routes) doesn't make it through
//     the utun and lwIP.
//
// When 2 fails, a direct query to the tunnel's DNS address tells whether DNS
// is the problem.
//
// Check 3 is informational only (see checkDirectPath).
func verifyTunnel(in verifyInput) func(ctx context.Context) error {
	pair, log := in.pair, in.log
	return func(ctx context.Context) error {
		if err := connectivity.CheckTCPConnectivity(pair); err != nil {
			return fmt.Errorf("check 1/3 failed: the server can't be reached once traffic is routed into the tunnel: %w", err)
		}
		log.Info("check 1/3 passed: the server is reachable with the tunnel routes in place")

		// An unbound dialer and the system resolver: exactly what apps use.
		appErr := connectivity.CheckTCPConnectivityWithHTTP(verifyTimeout, &transport.TCPDialer{}, verifyURLs)
		if appErr != nil {
			if dnsErr := lookupThroughTunnel(ctx); dnsErr != nil {
				return fmt.Errorf("check 2/3 failed: traffic through the tunnel doesn't work (%v), and DNS at %s doesn't answer: %w",
					appErr, sysrouter.OutlineDNS, dnsErr)
			}
			return fmt.Errorf("check 2/3 failed: DNS through the tunnel answers, but connections through it fail: %w", appErr)
		}
		log.Info("check 2/3 passed: traffic flows through the tunnel")

		checkDirectPath(ctx, in.direct, pair, in.firstHops, log)
		return nil
	}
}

// egressResolver answers "whoami.cloudflare" (class CH, type TXT) with the
// public address the query came from.
var egressResolver = netip.MustParseAddrPort("1.1.1.1:53")

// checkDirectPath logs whether a socket bound to the physical interface
// leaves from the physical network when its destination has no host route
// (only the utun's 0/1 and 128/1 routes match it). Bypass traffic depends on
// that. A plain connect can't tell: lwIP accepts any connection itself. So the
// public address seen through a bound socket is compared with the one seen
// through the tunnel; they differ only if the bound socket skips the tunnel.
// The addresses themselves are never logged.
//
// It never fails the connect.
func checkDirectPath(ctx context.Context, direct, tunneled transport.StreamDialer, firstHops []netip.Addr, log *slog.Logger) {
	const name = "check 3/3 (informational)"
	if direct == nil {
		return
	}
	if slices.Contains(firstHops, egressResolver.Addr()) {
		log.Info(name+" skipped: its probe address is the server's, which has a host route", "probe", egressResolver.Addr().String())
		return
	}
	ctx, cancel := context.WithTimeout(ctx, verifyDNSTimeout)
	defer cancel()
	type result struct {
		addr netip.Addr
		err  error
	}
	directCh, tunnelCh := make(chan result, 1), make(chan result, 1)
	go func() { a, err := publicAddress(ctx, direct); directCh <- result{a, err} }()
	go func() { a, err := publicAddress(ctx, tunneled); tunnelCh <- result{a, err} }()
	d, t := <-directCh, <-tunnelCh

	switch {
	case d.err != nil:
		log.Warn(name+" failed: a bound socket can't reach an address that has no host route; bypass would need host routes",
			"probe", egressResolver.String(), "err", d.err)
	case t.err != nil:
		log.Warn(name+" is inconclusive: a bound socket reached an address that has no host route, but the tunnel's answer to compare with failed",
			"probe", egressResolver.String(), "err", t.err)
	case d.addr == t.addr:
		log.Warn(name+" failed: a bound socket to an address that has no host route went through the tunnel; bypass would need host routes",
			"probe", egressResolver.String())
	default:
		log.Info(name+" passed: a bound socket to an address that has no host route leaves from the physical network, not the tunnel",
			"probe", egressResolver.String())
	}
}

// publicAddress asks egressResolver, over DNS on TCP through sd, which
// address the query came from.
func publicAddress(ctx context.Context, sd transport.StreamDialer) (netip.Addr, error) {
	q, err := dns.NewQuestion("whoami.cloudflare.", dnsmessage.TypeTXT)
	if err != nil {
		return netip.Addr{}, err
	}
	q.Class = dnsmessage.ClassCHAOS
	msg, err := dns.NewTCPResolver(sd, egressResolver.String()).Query(ctx, *q)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range msg.Answers {
		txt, ok := a.Body.(*dnsmessage.TXTResource)
		if !ok {
			continue
		}
		for _, s := range txt.TXT {
			if addr, err := netip.ParseAddr(s); err == nil {
				return addr.Unmap(), nil
			}
		}
	}
	return netip.Addr{}, errors.New("the answer holds no address")
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
