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

package netbind

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type bindCall struct {
	network string
	ifIndex int
}

// recordingBinder records bind calls instead of calling setsockopt, so these
// tests run on any OS and only use loopback.
func recordingBinder() (*Binder, func() []bindCall) {
	var mu sync.Mutex
	var calls []bindCall
	bind := func(_ uintptr, network string, ifIndex int) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, bindCall{network, ifIndex})
		return nil
	}
	indexes := map[string]int{"en0": 6, "en7": 14}
	lookup := func(name string) (int, error) {
		if idx, ok := indexes[name]; ok {
			return idx, nil
		}
		return 0, errors.New("no such interface")
	}
	return NewWith(bind, lookup), func() []bindCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]bindCall(nil), calls...)
	}
}

func listenTCP(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	accepted := make(chan struct{}, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			c.Close()
		}
	}()
	return l.Addr().String(), accepted
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestUnboundBinderRefusesEverySocket(t *testing.T) {
	b, calls := recordingBinder()
	addr, accepted := listenTCP(t)

	_, err := b.StreamDialer().DialStream(ctx(t), addr)
	require.ErrorIs(t, err, ErrNotBound)
	_, err = b.PacketDialer().DialPacket(ctx(t), "127.0.0.1:9")
	require.ErrorIs(t, err, ErrNotBound)
	_, err = b.PacketListener().ListenPacket(ctx(t))
	require.ErrorIs(t, err, ErrNotBound)
	_, err = b.Resolver().LookupNetIP(ctx(t), "ip4", "example.test")
	require.Error(t, err)

	require.Empty(t, calls())
	select {
	case <-accepted:
		t.Fatal("an unbound dial reached the network")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBoundSocketsUseTheInterfaceAndIPv4(t *testing.T) {
	b, calls := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))
	name, idx := b.Interface()
	require.Equal(t, "en0", name)
	require.Equal(t, 6, idx)

	addr, accepted := listenTCP(t)
	conn, err := b.StreamDialer().DialStream(ctx(t), addr)
	require.NoError(t, err)
	conn.Close()
	<-accepted

	pconn, err := b.PacketDialer().DialPacket(ctx(t), "127.0.0.1:9")
	require.NoError(t, err)
	pconn.Close()

	lconn, err := b.PacketListener().ListenPacket(ctx(t))
	require.NoError(t, err)
	local := lconn.LocalAddr().(*net.UDPAddr)
	require.NotNil(t, local.IP.To4(), "the listener must be IPv4-only, not dual-stack")
	lconn.Close()

	require.Equal(t, []bindCall{{"tcp4", 6}, {"udp4", 6}, {"udp4", 6}}, calls())
}

func TestStreamDialerRefusesIPv6(t *testing.T) {
	b, _ := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))
	_, err := b.StreamDialer().DialStream(ctx(t), "[::1]:9")
	require.Error(t, err, "IPv6 is off during a session; IPv6 destinations must fail")
}

func TestInterfaceChangeAppliesToNewSockets(t *testing.T) {
	b, calls := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))
	addr, _ := listenTCP(t)
	c, err := b.StreamDialer().DialStream(ctx(t), addr)
	require.NoError(t, err)
	c.Close()

	require.NoError(t, b.SetInterface("en7"))
	c, err = b.StreamDialer().DialStream(ctx(t), addr)
	require.NoError(t, err)
	c.Close()
	require.Equal(t, []bindCall{{"tcp4", 6}, {"tcp4", 14}}, calls())
}

func TestSetInterfaceErrors(t *testing.T) {
	b, _ := recordingBinder()
	require.ErrorContains(t, b.SetInterface("en9"), "finding interface en9")
	zero := NewWith(func(uintptr, string, int) error { return nil }, func(string) (int, error) { return 0, nil })
	require.ErrorContains(t, zero.SetInterface("x"), "invalid index")
	_, err := zero.StreamDialer().DialStream(ctx(t), "127.0.0.1:9")
	require.ErrorIs(t, err, ErrNotBound)
}

func TestBindFailureFailsTheDial(t *testing.T) {
	b := NewWith(func(uintptr, string, int) error { return errors.New("setsockopt failed") },
		func(string) (int, error) { return 6, nil })
	require.NoError(t, b.SetInterface("en0"))
	addr, accepted := listenTCP(t)
	_, err := b.StreamDialer().DialStream(ctx(t), addr)
	require.ErrorContains(t, err, "setsockopt failed")
	select {
	case <-accepted:
		t.Fatal("a socket that couldn't be bound was used")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSetResolvers(t *testing.T) {
	b, _ := recordingBinder()
	require.Equal(t, []netip.AddrPort{FallbackResolver}, b.Resolvers(), "default before capture")
	b.SetResolvers([]netip.Addr{netip.MustParseAddr("fe80::1%en0"), netip.MustParseAddr("192.168.1.254"), netip.MustParseAddr("::ffff:10.0.0.53")})
	require.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.254:53"),
		netip.MustParseAddrPort("10.0.0.53:53"),
	}, b.Resolvers())
	b.SetResolvers([]netip.Addr{netip.MustParseAddr("2001:db8::53")})
	require.Equal(t, []netip.AddrPort{FallbackResolver}, b.Resolvers(), "IPv6-only capture falls back")
}

func TestResolverDialsTheDirectServersInOrder(t *testing.T) {
	b, calls := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))

	// A closed port first (refused), then a listening one.
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := netip.MustParseAddrPort(closed.Addr().String())
	closed.Close()
	open, _ := listenTCP(t)
	servers := []netip.AddrPort{closedAddr, netip.MustParseAddrPort(open)}
	b.resolvers.Store(&servers)

	// The address the Go resolver asks for (the system's, possibly the
	// tunnel's 169.254.113.53) must be ignored.
	conn, err := b.Resolver().Dial(ctx(t), "tcp", "169.254.113.53:53")
	require.NoError(t, err)
	require.Equal(t, open, conn.RemoteAddr().String())
	conn.Close()
	for _, c := range calls() {
		require.Equal(t, bindCall{"tcp4", 6}, c, "resolver sockets are bound too")
	}

	uconn, err := b.Resolver().Dial(ctx(t), "udp", "169.254.113.53:53")
	require.NoError(t, err)
	require.Equal(t, closedAddr.String(), uconn.RemoteAddr().String(), "UDP connect doesn't fail, so the first server is used")
	uconn.Close()
}
