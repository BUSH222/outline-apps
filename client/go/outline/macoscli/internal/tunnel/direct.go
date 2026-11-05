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

package tunnel

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
)

// PurposeBypass marks a host route for an address of a bypass domain.
const PurposeBypass = "bypass"

// RouteDirect sends traffic to addr around the tunnel, with a host route via
// the physical gateway.
//
// Binding a socket to the physical interface is not enough on its own: macOS
// refuses a bound socket's connection ("network is unreachable") when the
// only routes matching the destination are the utun's 0/1 and 128/1 (manual
// test 7). With the host route, both the CLI's bound sockets and apps' own
// connections to addr leave through the physical network.
//
// The route is journaled like every other route, follows network changes, and
// stays until UnrouteDirect or the end of the session, so long-lived
// connections aren't cut when a DNS answer expires. While offline, addr is
// only remembered, and routed once the network is back. IPv6 addresses are
// ignored (IPv6 is off during a session), and so are addresses that are
// already routed physically (excluded ranges, the server).
func (s *Session) RouteDirect(ctx context.Context, addr netip.Addr) error {
	addr = addr.Unmap()
	if !addr.Is4() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.direct[addr] {
		return nil
	}
	if s.direct == nil {
		s.direct = map[netip.Addr]bool{}
	}
	s.direct[addr] = true
	if s.offline || s.alreadyPhysical(addr) {
		return nil
	}
	if err := s.addRoute(ctx, s.via(s.current, netip.PrefixFrom(addr, 32), PurposeBypass)); err != nil {
		// Forget it, so the next answer for addr tries again. The route was
		// journaled before the add, so undo that too.
		delete(s.direct, addr)
		if dropErr := s.dropBypassRoute(ctx, addr); dropErr != nil {
			s.log.Warn("undoing a failed direct route failed; cleanup will retry", "addr", addr.String(), "err", dropErr)
		}
		return err
	}
	s.log.Debug("added a direct route for a bypass address", "addr", addr.String(), "via", s.current.String())
	return nil
}

// UnrouteDirect removes addr's bypass route, if any, so its traffic goes
// through the tunnel again (for example once addr is learned for a vpn_only
// domain).
func (s *Session) UnrouteDirect(ctx context.Context, addr netip.Addr) error {
	addr = addr.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.direct[addr] {
		return nil
	}
	delete(s.direct, addr)
	if err := s.dropBypassRoute(ctx, addr); err != nil {
		s.direct[addr] = true
		return err
	}
	s.log.Debug("removed the direct route for an address", "addr", addr.String())
	return nil
}

// dropBypassRoute deletes addr's journaled bypass route, if any, and removes
// it from the state. Deleting a route that doesn't exist is not an error.
func (s *Session) dropBypassRoute(ctx context.Context, addr netip.Addr) error {
	dst := netip.PrefixFrom(addr, 32)
	i := slices.IndexFunc(s.st.Routes, func(r state.Route) bool { return r.Purpose == PurposeBypass && r.Dst == dst })
	if i < 0 {
		return nil
	}
	if err := s.opts.Router.DeleteRoute(ctx, s.st.Routes[i].RouteSpec); err != nil {
		return fmt.Errorf("deleting the direct route for %s: %w", addr, err)
	}
	s.st.Routes = slices.Delete(s.st.Routes, i, i+1)
	return s.save()
}

// DirectAddrs returns the addresses RouteDirect was asked to route, sorted.
func (s *Session) DirectAddrs() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]netip.Addr, 0, len(s.direct))
	for a := range s.direct {
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// directRoutes lists the bypass routes for a physical network, in a stable
// order. The caller holds s.mu (or is Up, before anyone else sees s).
func (s *Session) directRoutes(primary sysrouter.DefaultRoute) []state.Route {
	addrs := make([]netip.Addr, 0, len(s.direct))
	for a := range s.direct {
		if !s.alreadyPhysical(a) {
			addrs = append(addrs, a)
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	routes := make([]state.Route, len(addrs))
	for i, a := range addrs {
		routes[i] = s.via(primary, netip.PrefixFrom(a, 32), PurposeBypass)
	}
	return routes
}

// alreadyPhysical reports whether addr is routed via the gateway anyway.
func (s *Session) alreadyPhysical(addr netip.Addr) bool {
	if containedIn(addr, s.excluded()) {
		return true
	}
	for _, hop := range s.opts.FirstHops {
		if hop.Unmap() == addr {
			return true
		}
	}
	return false
}
