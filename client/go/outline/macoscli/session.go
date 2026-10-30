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
	"net/netip"
	"sync/atomic"
	"time"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/dnsrelay"
	"localhost/client/go/outline/macoscli/internal/ipcache"
	"localhost/client/go/outline/macoscli/internal/netbind"
	"localhost/client/go/outline/macoscli/internal/route"
	"localhost/client/go/outline/macoscli/internal/rules"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
	"localhost/client/go/outline/macoscli/internal/tunnel"
	"localhost/client/go/outline/vpn"

	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	defaultWatchInterval = 2 * time.Second
	// disconnectTimeout bounds the restore after Ctrl-C.
	disconnectTimeout = 60 * time.Second
)

// startTransportFunc connects the transport to the utun and returns once it
// is healthy.
type startTransportFunc func(ctx context.Context, tun tunnel.TUN, pair *configregistry.TransportPair, log *slog.Logger) (stop func(), err error)

// prepareSession checks for root, takes the instance lock and restores the
// network from a session that didn't shut down cleanly. It returns the unlock
// function.
func prepareSession(ctx context.Context, e env, log *slog.Logger) (func() error, error) {
	if e.geteuid() != 0 {
		return nil, errors.New("connect changes routes and DNS, so it must run as root: sudo outline-cli connect ... (or try --dry-run)")
	}
	store := state.FileStore{Dir: e.stateDir}
	unlock, err := store.Lock()
	if errors.Is(err, state.ErrLocked) {
		return nil, errors.New("another outline-cli session is running")
	}
	if err != nil {
		return nil, err
	}
	restored, err := tunnel.Cleanup(ctx, &sysrouter.Router{Exec: e.exec}, store, log)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("restoring the network from a previous session failed: %w; fix it with: sudo outline-cli cleanup", err)
	}
	if restored != nil {
		log.Warn("restored the network left behind by a previous session that didn't exit cleanly", "pid", restored.PID)
		// The crashed session may have left the lockdown in its connected
		// form (hosts block removed). Put it back now, in case this connect
		// fails before it switches the lockdown over itself.
		if err := e.lockdownManager(log).Disconnected(ctx); err != nil {
			unlock()
			return nil, fmt.Errorf("re-installing the lockdown failed: %w; fix it with: sudo outline-cli cleanup", err)
		}
	}
	return unlock, nil
}

// runSession brings the tunnel up, keeps it in sync with network changes, and
// restores everything when ctx is canceled (Ctrl-C, SIGTERM, SIGHUP).
//
// With domain rules, lwIP gets the transport wrapped by the router (see
// newDomainRouting); the post-routing checks still use the bare transport.
func runSession(ctx context.Context, e env, log *slog.Logger, pair *configregistry.TransportPair, binder *netbind.Binder, hops []netip.Addr, domainRules *rules.Rules) error {
	tunnelPair := pair
	var dnsRelay *dnsrelay.Relay
	if !domainRules.IsEmpty() {
		var err error
		if tunnelPair, dnsRelay, err = newDomainRouting(pair, binder, domainRules, log); err != nil {
			return err
		}
	}
	lk := e.lockdownManager(log)
	if len(domainRules.VPNOnly) > 0 {
		// The server's addresses must never end up in the lockdown's block.
		if err := lk.SetFirstHops(hops); err != nil {
			log.Warn("recording the server's addresses for the lockdown failed", "err", err)
		}
	}
	// live is the session once it is up. Bypass addresses learned from DNS
	// get host routes via the physical gateway through it; vpn_only addresses
	// are remembered for the lockdown.
	var live atomic.Pointer[tunnel.Session]
	if dnsRelay != nil {
		dnsRelay.OnLearn = func(addrs []netip.Addr) {
			if s := live.Load(); s != nil {
				syncDirectRoutes(s, dnsRelay.Cache, addrs, log)
			}
			if vpnOnly := vpnOnlyAddrs(dnsRelay.Cache, addrs); len(vpnOnly) > 0 {
				// Not urgent: while connected, the tunnel carries them anyway.
				go func() {
					if err := lk.Learn(context.Background(), vpnOnly); err != nil {
						log.Warn("recording vpn_only addresses for the lockdown failed", "err", err)
					}
				}()
			}
		}
	}
	var transportStarted atomic.Bool
	notify := func() {
		if pair.PacketRelay.NotifyNetworkChanged != nil {
			pair.PacketRelay.NotifyNetworkChanged()
		}
	}
	opts := tunnel.Options{
		Router:  &sysrouter.Router{Exec: e.exec},
		Store:   state.FileStore{Dir: e.stateDir},
		OpenTUN: e.openTUN,
		StartTransport: func(ctx context.Context, tun tunnel.TUN) (func(), error) {
			stop, err := e.startTransport(ctx, tun, tunnelPair, log)
			if err == nil {
				transportStarted.Store(true)
			}
			return stop, err
		},
		FirstHops:     hops,
		LocalPrefixes: e.localPrefixes,
		// Bind the transport's sockets to the physical interface before it
		// starts, and follow the interface when the network changes.
		OnNetwork: func(route sysrouter.DefaultRoute, resolvers []netip.Addr) error {
			if err := binder.SetInterface(route.Interface); err != nil {
				return err
			}
			binder.SetResolvers(resolvers)
			log.Debug("sockets bound", "interface", route.Interface, "resolvers", fmt.Sprint(binder.Resolvers()))
			if transportStarted.Load() {
				notify()
			}
			return nil
		},
		Verify: e.verify(verifyInput{pair: pair, log: log}),
		Logger: log,
	}
	binder.SetLogger(log)

	session, err := tunnel.Up(ctx, opts)
	if err != nil {
		return err
	}
	live.Store(session)
	if err := lk.Connected(ctx, session.State().UTun); err != nil {
		// Fails closed: the disconnected form still blocks the vpn_only domains.
		log.Warn("lockdown: letting vpn_only domains through the tunnel failed, so they stay blocked", "err", err)
	}
	name, _ := binder.Interface()
	fmt.Fprintf(e.stdout, "connected: traffic goes through the tunnel (bound to %s). Press Ctrl-C to disconnect.\n", name)

	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	interval := e.watchInterval
	if interval == 0 {
		interval = defaultWatchInterval
	}
	go session.Watch(watchCtx, interval)
	if dnsRelay != nil {
		go dnsRelay.Prefetch(watchCtx, domainRules.ExactBypass())
		// vpn_only names are only ever looked up through the tunnel.
		if names := domainRules.ExactVPNOnly(); len(names) > 0 {
			tunnelDNS := &dnsrelay.StreamExchanger{Dial: func(ctx context.Context) (transport.StreamConn, error) {
				return pair.StreamDialer.Dial(ctx, netip.AddrPortFrom(sysrouter.OutlineDNS, 53).String())
			}}
			go dnsRelay.PrefetchVia(watchCtx, names, tunnelDNS, dnsmessage.TypeA, dnsmessage.TypeAAAA)
		}
	}

	<-ctx.Done()
	stopWatch()
	log.Info("disconnecting")
	downCtx, cancel := context.WithTimeout(context.Background(), disconnectTimeout)
	defer cancel()
	downErr := session.Down(downCtx)
	// Even if the network couldn't be fully restored: the block must come back.
	lockErr := lk.Disconnected(downCtx)
	if downErr != nil || lockErr != nil {
		return fmt.Errorf("restoring the network failed: %w; fix it with: sudo outline-cli cleanup", errors.Join(downErr, lockErr))
	}
	fmt.Fprintln(e.stdout, "disconnected: routes, DNS and IPv6 are restored")
	return nil
}

// vpnOnlyAddrs returns the addresses whose class is vpn_only, with their domain.
func vpnOnlyAddrs(cache *ipcache.Cache, addrs []netip.Addr) map[netip.Addr]string {
	var out map[netip.Addr]string
	for _, a := range addrs {
		if class, domain := cache.Lookup(a); class == rules.VPNOnly {
			if out == nil {
				out = map[netip.Addr]string{}
			}
			out[a] = domain
		}
	}
	return out
}

// directUDPIdleTimeout closes a direct UDP association after this long
// without sending, like the transport's own (configregistry).
const directUDPIdleTimeout = 30 * time.Second

// newDomainRouting wraps the transport with the domain rules: DNS to the
// tunnel's address goes through the DNS relay, and traffic to addresses
// learned for bypass domains goes directly on interface-bound sockets.
func newDomainRouting(pair *configregistry.TransportPair, binder *netbind.Binder, r *rules.Rules, log *slog.Logger) (*configregistry.TransportPair, *dnsrelay.Relay, error) {
	directPackets, err := packetrelay.NewPacketRelayFromPacketListener(binder.PacketListener(), directUDPIdleTimeout)
	if err != nil {
		return nil, nil, err
	}
	servers := binder.Resolvers
	if len(r.DirectDNS) > 0 {
		fixed := make([]netip.AddrPort, len(r.DirectDNS))
		for i, a := range r.DirectDNS {
			fixed[i] = netip.AddrPortFrom(a, 53)
		}
		servers = func() []netip.AddrPort { return fixed }
	}
	relay := &dnsrelay.Relay{
		Rules: r,
		Cache: ipcache.New(r.MinTTL, r.MaxTTL, nil),
		Direct: &dnsrelay.Direct{
			Packet:  binder.PacketDialer(),
			Stream:  binder.StreamDialer(),
			Servers: servers,
		},
		Log: log,
	}
	router := route.New(route.Config{
		Inner:         pair,
		DirectStream:  binder.StreamDialer(),
		DirectPackets: directPackets,
		DNS:           relay,
		DNSAddr:       netip.AddrPortFrom(sysrouter.OutlineDNS, 53),
		Log:           log,
	})
	log.Info("domain rules are on", "bypass", len(r.Bypass), "vpn_only", len(r.VPNOnly))
	return router.Pair(), relay, nil
}

// directRouteTimeout bounds the route changes for one DNS answer.
const directRouteTimeout = 10 * time.Second

// directRouter adds and removes host routes around the tunnel.
type directRouter interface {
	RouteDirect(ctx context.Context, addr netip.Addr) error
	UnrouteDirect(ctx context.Context, addr netip.Addr) error
}

// syncDirectRoutes gives the addresses an answer taught a host route via the
// physical gateway if they belong to a bypass domain, and takes it away
// otherwise (an address also learned for a vpn_only domain must go through
// the tunnel). Binding sockets alone doesn't get past the utun's routes on
// macOS (manual test 7), and with the route, apps' own connections to the
// address skip the tunnel too.
func syncDirectRoutes(r directRouter, cache *ipcache.Cache, addrs []netip.Addr, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), directRouteTimeout)
	defer cancel()
	for _, a := range addrs {
		class, domain := cache.Lookup(a)
		var err error
		if class == rules.Bypass {
			err = r.RouteDirect(ctx, a)
		} else {
			err = r.UnrouteDirect(ctx, a)
		}
		if err != nil {
			log.Warn("updating the direct route of an address failed; its traffic may not bypass the VPN",
				"addr", a.String(), "domain", domain, "class", class.String(), "err", err)
		}
	}
}

// startRemoteDevice connects the lwIP stack to the transport, waits for the
// TCP health check, then relays packets between the utun and the stack.
func startRemoteDevice(ctx context.Context, tun tunnel.TUN, pair *configregistry.TransportPair, log *slog.Logger) (func(), error) {
	device, err := vpn.ConnectRemoteDevice(ctx, pair, pair.PacketRelay)
	if err != nil {
		return nil, err
	}
	// As Client.StartSession does: start the UDP check, which switches DNS
	// from TCP-only (truncate) to UDP when UDP works.
	if pair.PacketRelay.NotifyNetworkChanged != nil {
		pair.PacketRelay.NotifyNetworkChanged()
	}
	if err := device.GetHealthStatus(); err != nil {
		device.Close()
		return nil, fmt.Errorf("the server can't be reached over TCP: %w", err)
	}
	log.Info("the server is reachable")
	go vpn.RelayTraffic(device, tun)
	go vpn.RelayTraffic(tun, device)
	return func() { device.Close() }, nil
}
