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

// Package netbind creates sockets bound to the physical network interface, so
// the transport's own traffic (and, later, bypass traffic) never enters the
// tunnel, whatever the routing table says. On macOS this uses IP_BOUND_IF.
//
// A Binder refuses to create any socket until an interface is set: an unbound
// socket would follow the tunnel's default routes and loop.
package netbind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"golang.getoutline.org/sdk/transport"
)

// ErrNotBound is returned when a socket is requested before an interface is set.
var ErrNotBound = errors.New("no physical interface to bind to yet")

// FallbackResolver is used for direct lookups when no system resolver was
// captured (decision D2).
var FallbackResolver = netip.MustParseAddrPort("1.1.1.1:53")

const resolverDialTimeout = 5 * time.Second

// BindFunc binds a socket to an interface index. network is the socket's
// network as net.Dialer.Control sees it ("tcp4", "udp6", ...).
type BindFunc func(fd uintptr, network string, ifIndex int) error

// Binder makes interface-bound dialers. It is safe for concurrent use; the
// interface and resolvers can change while connections are open (new sockets
// use the new values).
type Binder struct {
	bind           BindFunc
	interfaceIndex func(name string) (int, error)

	ifIndex   atomic.Int64
	ifName    atomic.Pointer[string]
	resolvers atomic.Pointer[[]netip.AddrPort]
}

// PlatformBind binds a socket with the platform's mechanism (IP_BOUND_IF on
// macOS; unsupported elsewhere).
var PlatformBind BindFunc = platformBind

// InterfaceIndex returns an interface's index from its name.
func InterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// New returns a Binder that uses PlatformBind and InterfaceIndex.
func New() *Binder {
	return NewWith(PlatformBind, InterfaceIndex)
}

// NewWith returns a Binder with injected functions, for tests.
func NewWith(bind BindFunc, interfaceIndex func(string) (int, error)) *Binder {
	return &Binder{bind: bind, interfaceIndex: interfaceIndex}
}

// SetInterface binds future sockets to the named interface.
func (b *Binder) SetInterface(name string) error {
	idx, err := b.interfaceIndex(name)
	if err != nil {
		return fmt.Errorf("finding interface %s: %w", name, err)
	}
	if idx <= 0 {
		return fmt.Errorf("interface %s has invalid index %d", name, idx)
	}
	b.ifName.Store(&name)
	b.ifIndex.Store(int64(idx))
	return nil
}

// Interface returns the bound interface name and index, or "" and 0.
func (b *Binder) Interface() (string, int) {
	name := b.ifName.Load()
	if name == nil {
		return "", 0
	}
	return *name, int(b.ifIndex.Load())
}

// SetResolvers sets the resolvers for direct lookups. Only IPv4 addresses are
// kept (IPv6 is off during a session); with none left, FallbackResolver is used.
func (b *Binder) SetResolvers(addrs []netip.Addr) {
	var servers []netip.AddrPort
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			servers = append(servers, netip.AddrPortFrom(a, 53))
		}
	}
	if len(servers) == 0 {
		servers = []netip.AddrPort{FallbackResolver}
	}
	b.resolvers.Store(&servers)
}

// Resolvers returns the resolvers for direct lookups.
func (b *Binder) Resolvers() []netip.AddrPort {
	if r := b.resolvers.Load(); r != nil {
		return *r
	}
	return []netip.AddrPort{FallbackResolver}
}

// Control is a net.Dialer / net.ListenConfig Control function that binds the
// socket to the current interface, or fails if there is none.
func (b *Binder) Control(network, _ string, c syscall.RawConn) error {
	idx := int(b.ifIndex.Load())
	if idx <= 0 {
		return ErrNotBound
	}
	var bindErr error
	if err := c.Control(func(fd uintptr) { bindErr = b.bind(fd, network, idx) }); err != nil {
		return err
	}
	if bindErr != nil {
		return fmt.Errorf("binding %s socket to interface %d: %w", network, idx, bindErr)
	}
	return nil
}

func (b *Binder) dialer() *net.Dialer {
	return &net.Dialer{
		KeepAlive: -1, // like the app's base TCP dialer
		Control:   b.Control,
		Resolver:  b.Resolver(),
	}
}

// StreamDialer dials bound IPv4 TCP connections. Host names are resolved with
// Resolver, never through the tunnel.
func (b *Binder) StreamDialer() transport.StreamDialer {
	return transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		conn, err := b.dialer().DialContext(ctx, "tcp4", addr)
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	})
}

// PacketDialer dials bound IPv4 UDP connections.
func (b *Binder) PacketDialer() transport.PacketDialer {
	return transport.FuncPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		return b.dialer().DialContext(ctx, "udp4", addr)
	})
}

// PacketListener listens on bound IPv4 UDP sockets. It uses "udp4" so the
// socket is AF_INET; a wildcard "udp" socket would be dual-stack AF_INET6.
func (b *Binder) PacketListener() transport.PacketListener {
	return packetListener{b}
}

type packetListener struct{ b *Binder }

func (l packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: l.b.Control}
	return lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
}

// Resolver returns a Go resolver whose queries go to the direct resolvers over
// bound sockets, trying each in turn. The address the resolver asks for (from
// /etc/resolv.conf) is ignored: during a session it would be the tunnel's.
func (b *Binder) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			network4 := "udp4"
			if network == "tcp" || network == "tcp4" || network == "tcp6" {
				network4 = "tcp4"
			}
			d := net.Dialer{Control: b.Control, Timeout: resolverDialTimeout}
			var errs []error
			for _, server := range b.Resolvers() {
				conn, err := d.DialContext(ctx, network4, server.String())
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, fmt.Errorf("no direct DNS resolver reachable: %w", errors.Join(errs...))
		},
	}
}
