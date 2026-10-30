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
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
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

// resolverTimeout bounds one lookup on one resolver, so a dead resolver (for
// example the previous network's router) is skipped quickly.
const resolverTimeout = 3 * time.Second

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
	// known maps host names to addresses to use when a lookup fails.
	known atomic.Pointer[map[string][]netip.Addr]

	log          atomic.Pointer[slog.Logger]
	lastWarnNano atomic.Int64
}

// dialWarnInterval limits dial-failure warnings; the rest are logged at debug level.
const dialWarnInterval = 5 * time.Second

// SetLogger makes the Binder log its dials: failures as warnings (at most one
// every 5 s), successes at debug level.
func (b *Binder) SetLogger(l *slog.Logger) { b.log.Store(l) }

func (b *Binder) logDial(network, addr string, conn net.Conn, err error) {
	l := b.log.Load()
	if l == nil {
		return
	}
	iface, _ := b.Interface()
	if err == nil {
		l.Debug("bound connection opened", "network", network, "to", addr, "from", conn.LocalAddr().String(), "interface", iface)
		return
	}
	now := time.Now().UnixNano()
	last := b.lastWarnNano.Load()
	if now-last >= int64(dialWarnInterval) && b.lastWarnNano.CompareAndSwap(last, now) {
		l.Warn("a connection from the physical interface failed", "network", network, "to", addr, "interface", iface, "err", err)
		return
	}
	l.Debug("a connection from the physical interface failed", "network", network, "to", addr, "interface", iface, "err", err)
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

// SetResolvers sets the resolvers for direct lookups, tried in order. Only
// IPv4 addresses are kept (IPv6 is off during a session), and
// FallbackResolver is always tried last.
func (b *Binder) SetResolvers(addrs []netip.Addr) {
	var servers []netip.AddrPort
	add := func(s netip.AddrPort) {
		for _, x := range servers {
			if x == s {
				return
			}
		}
		servers = append(servers, s)
	}
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			add(netip.AddrPortFrom(a, 53))
		}
	}
	add(FallbackResolver)
	b.resolvers.Store(&servers)
}

// Resolvers returns the resolvers for direct lookups, in the order they are tried.
func (b *Binder) Resolvers() []netip.AddrPort {
	if r := b.resolvers.Load(); r != nil {
		return *r
	}
	return []netip.AddrPort{FallbackResolver}
}

// SetKnownAddrs sets addresses for host names (the server's, resolved when
// connecting) to dial when looking a name up fails.
//
// Bound sockets can only reach a resolver that has a route on the physical
// interface (FINDINGS 16): the router's DNS does, a public resolver set by a
// network's DHCP doesn't. On such a network the server's name can't be looked
// up after a network change, but its addresses from connect time still work:
// they have host routes via the gateway.
func (b *Binder) SetKnownAddrs(byName map[string][]netip.Addr) {
	m := make(map[string][]netip.Addr, len(byName))
	for name, addrs := range byName {
		m[strings.ToLower(name)] = slices.Clone(addrs)
	}
	b.known.Store(&m)
}

func (b *Binder) knownAddrs(host string) []netip.Addr {
	if m := b.known.Load(); m != nil {
		return (*m)[strings.ToLower(host)]
	}
	return nil
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
	}
}

// dial connects a bound IPv4 socket. A host name is resolved with LookupIPv4
// (never through the tunnel) and each address is tried in turn.
func (b *Binder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return b.dialer().DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
	}
	ips, err := b.LookupIPv4(ctx, host)
	if err != nil {
		known := b.knownAddrs(host)
		if len(known) == 0 || ctx.Err() != nil {
			return nil, fmt.Errorf("resolving %s: %w", host, err)
		}
		if l := b.log.Load(); l != nil {
			l.Warn("looking up the server failed; using its addresses from when the session started", "host", host, "err", err)
		}
		ips = known
	}
	var errs []error
	for _, ip := range ips {
		conn, err := b.dialer().DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// StreamDialer dials bound IPv4 TCP connections.
func (b *Binder) StreamDialer() transport.StreamDialer {
	return transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		conn, err := b.dial(ctx, "tcp4", addr)
		b.logDial("tcp4", addr, conn, err)
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	})
}

// PacketDialer dials bound IPv4 UDP connections.
func (b *Binder) PacketDialer() transport.PacketDialer {
	return transport.FuncPacketDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := b.dial(ctx, "udp4", addr)
		b.logDial("udp4", addr, conn, err)
		return conn, err
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

// LookupIPv4 resolves host to IPv4 addresses through the direct resolvers,
// over bound sockets, trying each resolver in turn (with its own timeout)
// until one answers. The system resolver is never used: during a session it
// points into the tunnel.
func (b *Binder) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if b.ifIndex.Load() <= 0 {
		return nil, ErrNotBound
	}
	var errs []error
	for _, server := range b.Resolvers() {
		addrs, err := b.lookupWith(ctx, server, host)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		if err == nil {
			err = errors.New("no IPv4 address")
		}
		errs = append(errs, fmt.Errorf("via %s: %w", server, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func (b *Binder) lookupWith(ctx context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolverTimeout)
	defer cancel()
	r := &net.Resolver{
		PreferGo: true,
		// The address the Go resolver asks for comes from /etc/resolv.conf;
		// it is ignored in favor of server.
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			network4 := "udp4"
			if strings.HasPrefix(network, "tcp") {
				network4 = "tcp4"
			}
			return b.dialer().DialContext(ctx, network4, server.String())
		},
	}
	addrs, err := r.LookupNetIP(ctx, "ip4", host)
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	return addrs, err
}
