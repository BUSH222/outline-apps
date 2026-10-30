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

// Package tunnel brings the system's routes and DNS up and down around a utun.
//
// Every change is recorded in the state file before it is made, so the whole
// session can be undone from the state file alone (see Cleanup), even after
// kill -9. Routes are only touched after the transport reports healthy.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
)

// DefaultExcluded mirrors kExcludedSubnets in
// client/src/cordova/apple/OutlineLib/VpnExtension/Sources/PacketTunnelProvider.swift:
// local and reserved ranges that stay off the tunnel.
var DefaultExcluded = mustPrefixes(
	"10.0.0.0/8",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
)

// utunCandidates mirror kVpnSubnetCandidates in PacketTunnelProvider.swift.
var utunCandidates = mustPrefixes(
	"10.111.222.0/24",
	"172.16.9.0/24",
	"192.168.20.0/24",
	"169.254.19.0/24",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Route purposes recorded in the state file.
const (
	PurposeExclude  = "exclude"
	PurposeFirstHop = "first-hop"
	PurposeDNS      = "dns"
	PurposeDefault  = "default"
)

// TUN is an open utun device.
type TUN interface {
	io.ReadWriteCloser
	Name() string
}

// Options configure a session.
type Options struct {
	Router sysrouter.SystemRouter
	Store  state.Store
	// OpenTUN opens the utun.
	OpenTUN func() (TUN, error)
	// StartTransport connects the transport to the utun and returns once it is
	// healthy. No route or DNS change happens before it succeeds. stop is
	// called on teardown, after the routes are gone.
	StartTransport func(ctx context.Context, tun TUN) (stop func(), err error)
	// LocalPrefixes returns the IPv4 prefixes of local interfaces, to pick a
	// utun subnet that doesn't collide. nil means the host's interfaces.
	LocalPrefixes func() ([]netip.Prefix, error)
	// Excluded are kept off the tunnel. nil means DefaultExcluded.
	Excluded []netip.Prefix
	// FirstHops are the resolved IPv4 addresses of the server(s). They get
	// host routes via the physical gateway as defense in depth; the transport's
	// sockets are also bound to the physical interface.
	FirstHops []netip.Addr
	// OnNetwork is called with the physical network and its resolvers: once
	// after capturing them, before the transport starts (an error aborts the
	// connect), and again after each network change.
	OnNetwork func(route sysrouter.DefaultRoute, resolvers []netip.Addr) error
	// Verify, if set, runs after routes and DNS point into the tunnel. If it
	// fails, everything is rolled back and Up returns its error. It catches a
	// tunnel that passed the health check but breaks once traffic is routed.
	Verify func(ctx context.Context) error
	Logger *slog.Logger
}

func (o *Options) logger() *slog.Logger {
	if o.Logger == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return o.Logger
}

// Session is a connected tunnel.
type Session struct {
	opts Options
	log  *slog.Logger

	mu            sync.Mutex
	st            *state.State
	tun           TUN
	stopTransport func()
	current       sysrouter.DefaultRoute
	offline       bool
	closed        bool
}

// Up captures the current network settings, opens and configures the utun,
// starts the transport and, once it is healthy, routes traffic and DNS into
// the tunnel. On any failure it undoes what it did and returns the error.
func Up(ctx context.Context, opts Options) (_ *Session, err error) {
	log := opts.logger()
	r := opts.Router

	routes, err := r.DefaultRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading routes: %w", err)
	}
	primary, ok := sysrouter.PrimaryDefault(routes, "")
	if !ok {
		return nil, errors.New("there is no default route; connect to a network first")
	}
	if active := sysrouter.ActiveInterfaces(routes, ""); len(active) > 1 {
		log.Warn("several network interfaces are active; only the primary one's DNS and IPv6 are changed, so the others may leak",
			"primary", primary.Interface, "active", strings.Join(active, ","))
	}
	service, err := r.ServiceForInterface(ctx, primary.Interface)
	if err != nil {
		return nil, err
	}
	dns, err := r.DNSServers(ctx, service)
	if err != nil {
		return nil, fmt.Errorf("reading DNS servers of %q: %w", service, err)
	}
	resolvers, err := r.SystemResolvers(ctx, primary.Interface)
	if err != nil {
		return nil, fmt.Errorf("reading system resolvers: %w", err)
	}
	ipv6, err := r.IPv6(ctx, service)
	if err != nil {
		return nil, fmt.Errorf("reading IPv6 setting of %q: %w", service, err)
	}

	s := &Session{
		opts:    opts,
		log:     log,
		current: primary,
		st: &state.State{
			Version:         state.CurrentVersion,
			PID:             os.Getpid(),
			StartedAt:       time.Now().UTC(),
			Interface:       primary.Interface,
			Gateway:         addrString(primary.Gateway),
			Service:         service,
			SystemResolvers: addrStrings(resolvers),
		},
	}
	// The state file exists before anything changes.
	if err := s.save(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			// Not a deferred recover: a crash (panic) must leave the state file for cleanup.
			if undoErr := s.teardown(context.WithoutCancel(ctx)); undoErr != nil {
				err = errors.Join(err, fmt.Errorf("undoing the partial setup failed; run outline-cli cleanup: %w", undoErr))
			}
		}
	}()

	if opts.OnNetwork != nil {
		if err := opts.OnNetwork(primary, resolvers); err != nil {
			return nil, err
		}
	}

	tun, err := opts.OpenTUN()
	if err != nil {
		return nil, fmt.Errorf("opening utun: %w", err)
	}
	s.tun = tun
	s.st.UTun = tun.Name()
	if err := s.save(); err != nil {
		return nil, err
	}
	local, peer, err := s.chooseUTunAddrs()
	if err != nil {
		return nil, err
	}
	if err := r.ConfigureUTun(ctx, tun.Name(), local, peer); err != nil {
		return nil, fmt.Errorf("configuring %s: %w", tun.Name(), err)
	}

	stop, err := opts.StartTransport(ctx, tun)
	if err != nil {
		return nil, fmt.Errorf("the transport is not working, so no routes were changed: %w", err)
	}
	s.stopTransport = stop

	for _, route := range s.planRoutes(primary) {
		if err := s.addRoute(ctx, route); err != nil {
			return nil, err
		}
	}

	if err := s.applyServiceSettings(ctx, service, dns, ipv6); err != nil {
		return nil, err
	}
	// Last, so cached answers from before the change are dropped.
	if err := r.FlushDNSCache(ctx); err != nil {
		log.Warn("flushing the DNS cache failed", "err", err)
	}
	if opts.Verify != nil {
		if err := opts.Verify(ctx); err != nil {
			return nil, fmt.Errorf("the tunnel doesn't carry traffic, so every change was rolled back: %w", err)
		}
	}
	log.Info("tunnel is up", "utun", tun.Name(), "network", primary.String(), "service", service)
	return s, nil
}

// applyServiceSettings points the service's DNS at the tunnel and turns its
// IPv6 off, recording the previous values first.
func (s *Session) applyServiceSettings(ctx context.Context, service string, dns []string, ipv6 sysrouter.IPv6Config) error {
	r := s.opts.Router
	s.st.PrevDNS = &state.SavedDNS{Servers: dns}
	if err := s.save(); err != nil {
		return err
	}
	if err := r.SetDNS(ctx, service, []string{sysrouter.OutlineDNS.String()}); err != nil {
		return fmt.Errorf("setting DNS of %q: %w", service, err)
	}

	switch {
	case ipv6.Mode == sysrouter.IPv6Off:
		// Nothing to do.
	case ipv6.Restorable():
		s.st.PrevIPv6 = &ipv6
		if err := s.save(); err != nil {
			return err
		}
		if err := r.SetIPv6(ctx, service, sysrouter.IPv6Config{Mode: sysrouter.IPv6Off}); err != nil {
			return fmt.Errorf("turning IPv6 off on %q: %w", service, err)
		}
	default:
		s.log.Warn("IPv6 is left as is because its setting can't be restored exactly; IPv6 traffic may bypass the tunnel",
			"service", service, "ipv6", ipv6.Raw)
	}
	return nil
}

// planRoutes lists the routes for a physical network, in the order they are added.
func (s *Session) planRoutes(primary sysrouter.DefaultRoute) []state.Route {
	routes := s.physicalRoutes(primary)
	utun := s.st.UTun
	routes = append(routes,
		state.Route{RouteSpec: sysrouter.RouteSpec{Dst: netip.PrefixFrom(sysrouter.OutlineDNS, 32), Interface: utun}, Purpose: PurposeDNS},
		// Two /1 routes win over the default route without replacing it.
		state.Route{RouteSpec: sysrouter.RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/1"), Interface: utun}, Purpose: PurposeDefault},
		state.Route{RouteSpec: sysrouter.RouteSpec{Dst: netip.MustParsePrefix("128.0.0.0/1"), Interface: utun}, Purpose: PurposeDefault},
	)
	return routes
}

// physicalRoutes are the routes that go via the physical network: the
// exclusions and the first-hop host routes.
func (s *Session) physicalRoutes(primary sysrouter.DefaultRoute) []state.Route {
	via := func(dst netip.Prefix, purpose string) state.Route {
		spec := sysrouter.RouteSpec{Dst: dst}
		if primary.Gateway.IsValid() {
			spec.Gateway = primary.Gateway
		} else {
			spec.Interface = primary.Interface
		}
		return state.Route{RouteSpec: spec, Purpose: purpose}
	}
	excluded := s.excluded()
	var routes []state.Route
	for _, p := range excluded {
		routes = append(routes, via(p, PurposeExclude))
	}
	for _, hop := range s.opts.FirstHops {
		hop = hop.Unmap()
		if !hop.Is4() || containedIn(hop, excluded) {
			// Excluded ranges are already off the tunnel.
			continue
		}
		routes = append(routes, via(netip.PrefixFrom(hop, 32), PurposeFirstHop))
	}
	return routes
}

func (s *Session) excluded() []netip.Prefix {
	if s.opts.Excluded != nil {
		return s.opts.Excluded
	}
	return DefaultExcluded
}

func containedIn(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// addRoute adds a route unless one for the same destination already exists
// (then it isn't ours, and it is never recorded or removed). The route is
// journaled before it is added, so a crash right after the add is undone.
//
// A kernel-cloned cache entry for the destination doesn't count as existing:
// macOS creates one for every recently contacted host (for example the server
// a dynamic key was just fetched from), and it would block the real route.
// It is deleted first; it is never restored, since it is only a cache.
func (s *Session) addRoute(ctx context.Context, route state.Route) error {
	r := s.opts.Router
	status, err := r.LookupRoute(ctx, route.Dst)
	if err != nil {
		// Adding anyway is safe: if a route for this destination does exist,
		// the add fails with "File exists" and the route is left alone.
		s.log.Warn("couldn't read the existing route; adding ours anyway", "route", route.Dst.String(), "err", err)
		status = sysrouter.RouteAbsent
	}
	switch status {
	case sysrouter.RoutePresent:
		s.log.Debug("route already exists; leaving it alone", "route", route.Dst.String())
		return nil
	case sysrouter.RouteCloned:
		s.log.Debug("replacing the kernel's cached route", "route", route.Dst.String())
		if err := r.DeleteClonedRoute(ctx, route.Dst); err != nil {
			return fmt.Errorf("deleting the cached route for %s: %w", route.Dst, err)
		}
	}
	s.st.Routes = append(s.st.Routes, route)
	if err := s.save(); err != nil {
		return err
	}
	added, err := r.AddRoute(ctx, route.RouteSpec)
	if err != nil {
		return fmt.Errorf("adding route %s: %w", route.RouteSpec, err)
	}
	if !added {
		// Someone else added it in the meantime: not ours.
		s.st.Routes = s.st.Routes[:len(s.st.Routes)-1]
		if route.Purpose == PurposeFirstHop {
			s.log.Warn("the server's host route couldn't be added; relying on interface binding alone", "route", route.RouteSpec.String())
		}
		return s.save()
	}
	return nil
}

func (s *Session) chooseUTunAddrs() (local, peer netip.Addr, err error) {
	localPrefixes := s.opts.LocalPrefixes
	if localPrefixes == nil {
		localPrefixes = hostPrefixes
	}
	prefixes, err := localPrefixes()
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("listing local addresses: %w", err)
	}
	subnet := utunCandidates[0]
	for _, c := range utunCandidates {
		if !overlapsAny(c, prefixes) {
			subnet = c
			break
		}
	}
	local = subnet.Addr().Next()
	return local, local.Next(), nil
}

func overlapsAny(p netip.Prefix, prefixes []netip.Prefix) bool {
	for _, q := range prefixes {
		if p.Overlaps(q) {
			return true
		}
	}
	return false
}

func hostPrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok || !addr.Unmap().Is4() {
			continue
		}
		bits, _ := ipNet.Mask.Size()
		out = append(out, netip.PrefixFrom(addr.Unmap(), bits).Masked())
	}
	return out, nil
}

func (s *Session) save() error {
	if err := s.opts.Store.Save(s.st); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}
	return nil
}

// State returns a copy of the session state.
func (s *Session) State() *state.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.Clone()
}

// Down undoes everything and closes the utun. It is safe to call more than once.
func (s *Session) Down(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.teardown(ctx)
}

func (s *Session) teardown(ctx context.Context) error {
	closeTUN := func() error {
		var err error
		if s.tun != nil {
			err = s.tun.Close()
			s.tun = nil
		}
		if s.stopTransport != nil {
			s.stopTransport()
			s.stopTransport = nil
		}
		return err
	}
	return undo(ctx, s.opts.Router, s.opts.Store, s.st, closeTUN, s.log)
}

// Cleanup restores the system from the state file left by a session whose
// process is gone. It returns the state it restored, or nil if there was none.
// The caller must hold the state lock.
func Cleanup(ctx context.Context, r sysrouter.SystemRouter, store state.Store, log *slog.Logger) (*state.State, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	st, err := store.Load()
	if err != nil || st == nil {
		return nil, err
	}
	restored := st.Clone()
	log.Info("restoring the network from a previous session", "pid", st.PID, "started", st.StartedAt, "service", st.Service)
	// The utun of a dead process is already gone; nothing to close.
	return restored, undo(ctx, r, store, st, nil, log)
}

// undo reverts what st records, in this order: DNS and IPv6, routes (newest
// first), the utun, then flushes the DNS cache. Each step is saved as it
// completes, so a failed or interrupted undo can be resumed. The state file is
// removed only when everything was restored.
func undo(ctx context.Context, r sysrouter.SystemRouter, store state.Store, st *state.State, closeTUN func() error, log *slog.Logger) error {
	var errs []error
	// Flush only if something that affects name resolution was undone.
	changed := !st.Empty()
	save := func() {
		if err := store.Save(st); err != nil {
			errs = append(errs, fmt.Errorf("saving state: %w", err))
		}
	}

	if st.PrevDNS != nil {
		if err := r.SetDNS(ctx, st.Service, st.PrevDNS.Servers); err != nil {
			errs = append(errs, fmt.Errorf("restoring DNS of %q: %w", st.Service, err))
		} else {
			st.PrevDNS = nil
			save()
		}
	}
	if st.PrevIPv6 != nil {
		if err := r.SetIPv6(ctx, st.Service, *st.PrevIPv6); err != nil {
			errs = append(errs, fmt.Errorf("restoring IPv6 of %q: %w", st.Service, err))
		} else {
			st.PrevIPv6 = nil
			save()
		}
	}

	remaining := st.Routes[:0:0]
	for i := len(st.Routes) - 1; i >= 0; i-- {
		route := st.Routes[i]
		if err := r.DeleteRoute(ctx, route.RouteSpec); err != nil {
			errs = append(errs, fmt.Errorf("deleting route %s: %w", route.RouteSpec, err))
			remaining = append([]state.Route{route}, remaining...)
		}
	}
	st.Routes = remaining
	save()

	if closeTUN != nil {
		if err := closeTUN(); err != nil {
			log.Warn("closing the utun failed", "utun", st.UTun, "err", err)
		}
	}
	st.UTun = ""

	// Last, after DNS (and in M5 /etc/hosts) is back.
	if changed {
		if err := r.FlushDNSCache(ctx); err != nil {
			log.Warn("flushing the DNS cache failed", "err", err)
		}
	}

	if len(errs) == 0 && st.Empty() {
		if err := store.Remove(); err != nil {
			errs = append(errs, fmt.Errorf("removing state file: %w", err))
		}
	} else {
		save()
	}
	return errors.Join(errs...)
}

// CheckNetwork adjusts the system if the physical network changed: the
// physical routes move to the new gateway, DNS and IPv6 move to the new
// service, and OnNetwork is called.
func (s *Session) CheckNetwork(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	r := s.opts.Router
	routes, err := r.DefaultRoutes(ctx)
	if err != nil {
		return err
	}
	primary, ok := sysrouter.PrimaryDefault(routes, s.st.UTun)
	if !ok {
		if !s.offline {
			s.log.Warn("the network is gone; waiting for it to come back")
		}
		s.offline = true
		return nil
	}
	s.offline = false
	if primary == s.current {
		return nil
	}
	s.log.Info("the network changed", "from", s.current.String(), "to", primary.String())

	// Move the physical routes to the new network.
	var kept []state.Route
	for _, route := range s.st.Routes {
		if route.Purpose != PurposeExclude && route.Purpose != PurposeFirstHop {
			kept = append(kept, route)
			continue
		}
		if err := r.DeleteRoute(ctx, route.RouteSpec); err != nil {
			s.log.Warn("deleting an old route failed", "route", route.RouteSpec.String(), "err", err)
			kept = append(kept, route)
		}
	}
	s.st.Routes = kept
	if err := s.save(); err != nil {
		return err
	}
	for _, route := range s.physicalRoutes(primary) {
		if err := s.addRoute(ctx, route); err != nil {
			return err
		}
	}

	service, err := r.ServiceForInterface(ctx, primary.Interface)
	if err != nil {
		return err
	}
	if service != s.st.Service {
		if err := s.moveServiceSettings(ctx, service, primary.Interface); err != nil {
			return err
		}
	}
	s.st.Interface = primary.Interface
	s.st.Gateway = addrString(primary.Gateway)
	if err := s.save(); err != nil {
		return err
	}
	s.current = primary
	if err := r.FlushDNSCache(ctx); err != nil {
		s.log.Warn("flushing the DNS cache failed", "err", err)
	}
	if s.opts.OnNetwork != nil {
		if err := s.opts.OnNetwork(primary, parseAddrs(s.st.SystemResolvers)); err != nil {
			return fmt.Errorf("switching to the new network: %w", err)
		}
	}
	return nil
}

// moveServiceSettings restores the old service's DNS and IPv6 and applies the
// tunnel settings to the new service.
func (s *Session) moveServiceSettings(ctx context.Context, service, iface string) error {
	r := s.opts.Router
	if s.st.PrevDNS != nil {
		if err := r.SetDNS(ctx, s.st.Service, s.st.PrevDNS.Servers); err != nil {
			return fmt.Errorf("restoring DNS of %q: %w", s.st.Service, err)
		}
		s.st.PrevDNS = nil
	}
	if s.st.PrevIPv6 != nil {
		if err := r.SetIPv6(ctx, s.st.Service, *s.st.PrevIPv6); err != nil {
			return fmt.Errorf("restoring IPv6 of %q: %w", s.st.Service, err)
		}
		s.st.PrevIPv6 = nil
	}
	if err := s.save(); err != nil {
		return err
	}

	dns, err := r.DNSServers(ctx, service)
	if err != nil {
		return err
	}
	ipv6, err := r.IPv6(ctx, service)
	if err != nil {
		return err
	}
	if resolvers, err := r.SystemResolvers(ctx, iface); err == nil && len(resolvers) > 0 {
		s.st.SystemResolvers = addrStrings(resolvers)
	}
	s.st.Service = service
	return s.applyServiceSettings(ctx, service, dns, ipv6)
}

// Watch polls for network changes every interval until ctx is done or the
// session is closed.
func (s *Session) Watch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.CheckNetwork(ctx); err != nil {
				s.log.Warn("adjusting to the network change failed; will retry", "err", err)
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
		}
	}
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func addrStrings(addrs []netip.Addr) []string {
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func parseAddrs(ss []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}
