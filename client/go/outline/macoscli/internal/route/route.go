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

// Package route wraps the transport with the domain rules. It is the
// outermost layer between lwIP and the transport, so it sees every TCP
// connection and UDP packet from the utun, by destination address:
//
//   - DNS to the tunnel's DNS address goes to the dnsrelay, which resolves
//     bypass names directly and learns the addresses of listed domains;
//   - traffic to an address learned for a bypass domain goes directly, on
//     sockets bound to the physical interface, and never falls back to the
//     tunnel;
//   - everything else, including addresses of vpn_only domains, goes through
//     the transport. vpn_only addresses never go directly, even if an address
//     was also learned for a bypass domain or the tunnel fails.
package route

import (
	"context"
	"io"
	"log/slog"
	"net/netip"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/dnsrelay"
	"localhost/client/go/outline/macoscli/internal/ipcache"
	"localhost/client/go/outline/macoscli/internal/rules"

	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
)

// Config is what the router needs.
type Config struct {
	// Inner is the transport.
	Inner *configregistry.TransportPair
	// DirectStream and DirectPackets reach the network without the tunnel,
	// on sockets bound to the physical interface.
	DirectStream  transport.StreamDialer
	DirectPackets packetrelay.PacketRelay
	// DNS handles queries to DNSAddr and holds the learned addresses.
	DNS     *dnsrelay.Relay
	DNSAddr netip.AddrPort
	Log     *slog.Logger
}

// Router decides, per destination, between the tunnel and the direct path.
type Router struct {
	cfg   Config
	cache *ipcache.Cache
	log   *slog.Logger
}

// New returns a router.
func New(cfg Config) *Router {
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Router{cfg: cfg, cache: cfg.DNS.Cache, log: log}
}

// Pair returns the transport pair to hand to lwIP: the inner pair's
// connection info (type, first hop) and network-change hook, with the
// router's dialer and relay.
func (r *Router) Pair() *configregistry.TransportPair {
	inner := r.cfg.Inner
	return &configregistry.TransportPair{
		StreamDialer: &configregistry.Dialer[transport.StreamConn]{
			ConnectionProviderInfo: inner.StreamDialer.ConnectionProviderInfo,
			Dial:                   r.DialStream,
		},
		PacketRelay: &configregistry.PacketRelay{
			ConnectionProviderInfo: inner.PacketRelay.ConnectionProviderInfo,
			PacketRelay:            &packetRelay{r},
			NotifyNetworkChanged:   inner.PacketRelay.NotifyNetworkChanged,
		},
	}
}

func (r *Router) isDNS(dst netip.AddrPort) bool {
	return dst.Addr().Unmap() == r.cfg.DNSAddr.Addr() && dst.Port() == r.cfg.DNSAddr.Port()
}

// classify returns the class of a destination address.
func (r *Router) classify(addr netip.Addr) (rules.Class, string) {
	return r.cache.Lookup(addr)
}

// DialStream connects a TCP connection from the utun.
func (r *Router) DialStream(ctx context.Context, addr string) (transport.StreamConn, error) {
	dst, err := netip.ParseAddrPort(addr)
	if err != nil {
		// A host name (lwIP only gives addresses; the transport's own checks
		// may use names): through the tunnel.
		return r.cfg.Inner.StreamDialer.Dial(ctx, addr)
	}
	if r.isDNS(dst) {
		return r.cfg.DNS.StreamConn(r.cfg.DNSAddr, func(ctx context.Context) (transport.StreamConn, error) {
			return r.cfg.Inner.StreamDialer.Dial(ctx, addr)
		}), nil
	}
	if class, domain := r.classify(dst.Addr()); class == rules.Bypass {
		conn, err := r.cfg.DirectStream.DialStream(ctx, addr)
		if err != nil {
			// No fallback to the tunnel: the user asked for this domain to
			// stay off the VPN.
			r.log.Debug("a bypass connection failed", "domain", domain, "to", addr, "err", err)
			return nil, err
		}
		r.log.Debug("bypass: connected directly", "domain", domain, "to", addr)
		return conn, nil
	}
	return r.cfg.Inner.StreamDialer.Dial(ctx, addr)
}
