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
	"log/slog"
	"net"
	"net/netip"
	"strings"
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
	_, err = b.LookupIPv4(ctx(t), "example.test")
	require.ErrorIs(t, err, ErrNotBound)

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
	require.Empty(t, b.Resolvers(), "none before capture")
	b.SetResolvers([]netip.Addr{
		netip.MustParseAddr("fe80::1%en0"),
		netip.MustParseAddr("192.168.1.254"),
		netip.MustParseAddr("::ffff:10.0.0.53"),
		netip.MustParseAddr("192.168.1.254"),
	})
	require.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.254:53"),
		netip.MustParseAddrPort("10.0.0.53:53"),
	}, b.Resolvers(), "IPv4 only, deduplicated, no public fallback")
	b.SetResolvers([]netip.Addr{netip.MustParseAddr("2001:db8::53")})
	require.Empty(t, b.Resolvers())
}

// fakeDNS answers every A query with answer, on loopback UDP.
func fakeDNS(t *testing.T, answer netip.Addr) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if reply := dnsReply(buf[:n], answer); reply != nil {
				pc.WriteTo(reply, from)
			}
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// dnsReply builds a minimal response to one question: one A record for an A
// query, no records otherwise.
func dnsReply(q []byte, answer netip.Addr) []byte {
	if len(q) < 12 {
		return nil
	}
	end := 12
	for end < len(q) && q[end] != 0 {
		end += int(q[end]) + 1
	}
	end += 5 // zero label, type, class
	if end > len(q) {
		return nil
	}
	question := q[12:end]
	qtype := uint16(question[len(question)-4])<<8 | uint16(question[len(question)-3])
	ancount := byte(0)
	if qtype == 1 {
		ancount = 1
	}
	resp := []byte{q[0], q[1], 0x81, 0x80, 0, 1, 0, ancount, 0, 0, 0, 0}
	resp = append(resp, question...)
	if ancount == 1 {
		a := answer.As4()
		resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, a[0], a[1], a[2], a[3])
	}
	return resp
}

func TestLookupIPv4FailsOverToTheNextResolver(t *testing.T) {
	b, calls := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))

	// The first resolver is gone, like the previous network's router; UDP to a
	// closed loopback port fails at once with "connection refused".
	dead, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := netip.MustParseAddrPort(dead.LocalAddr().String())
	dead.Close()
	live := fakeDNS(t, netip.MustParseAddr("100.200.0.10"))
	servers := []netip.AddrPort{deadAddr, live}
	b.resolvers.Store(&servers)

	addrs, err := b.LookupIPv4(ctx(t), "server.example.test")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("100.200.0.10")}, addrs)
	for _, c := range calls() {
		require.Equal(t, bindCall{"udp4", 6}, c, "resolver sockets are bound too")
	}
}

func TestLookupIPv4ReportsEveryResolver(t *testing.T) {
	b, _ := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))
	dead, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := netip.MustParseAddrPort(dead.LocalAddr().String())
	dead.Close()
	servers := []netip.AddrPort{deadAddr}
	b.resolvers.Store(&servers)
	_, err = b.LookupIPv4(ctx(t), "server.example.test")
	require.ErrorContains(t, err, "via "+deadAddr.String())
}

func TestStreamDialerResolvesHostNamesDirectly(t *testing.T) {
	b, _ := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))
	addr, accepted := listenTCP(t)
	_, port, _ := net.SplitHostPort(addr)
	servers := []netip.AddrPort{fakeDNS(t, netip.MustParseAddr("127.0.0.1"))}
	b.resolvers.Store(&servers)

	conn, err := b.StreamDialer().DialStream(ctx(t), net.JoinHostPort("server.example.test", port))
	require.NoError(t, err)
	conn.Close()
	<-accepted
}

func TestDialLogging(t *testing.T) {
	b, _ := recordingBinder()
	var buf syncLog
	b.SetLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	require.NoError(t, b.SetInterface("en0"))
	addr, _ := listenTCP(t)
	c, err := b.StreamDialer().DialStream(ctx(t), addr)
	require.NoError(t, err)
	c.Close()
	require.Contains(t, buf.String(), "bound connection opened")
	require.Contains(t, buf.String(), "interface=en0")

	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := closed.Addr().String()
	closed.Close()
	for i := 0; i < 3; i++ {
		_, err = b.StreamDialer().DialStream(ctx(t), closedAddr)
		require.Error(t, err)
	}
	require.Equal(t, 1, strings.Count(buf.String(), "level=WARN"), "failures warn at most once per interval")
	require.Equal(t, 3, strings.Count(buf.String(), "a connection from the physical interface failed"))
}

type syncLog struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncLog) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestStreamDialerFallsBackToKnownAddresses(t *testing.T) {
	b, _ := recordingBinder()
	var buf syncLog
	b.SetLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	require.NoError(t, b.SetInterface("en0"))
	// The network's resolver can't be reached (like a public resolver
	// without a route on the physical interface).
	dead, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	servers := []netip.AddrPort{netip.MustParseAddrPort(dead.LocalAddr().String())}
	dead.Close()
	b.resolvers.Store(&servers)
	addr, accepted := listenTCP(t)
	_, port, _ := net.SplitHostPort(addr)

	_, err = b.StreamDialer().DialStream(ctx(t), net.JoinHostPort("server.example.test", port))
	require.ErrorContains(t, err, "resolving server.example.test")

	b.SetKnownAddrs(map[string][]netip.Addr{"Server.Example.Test": {netip.MustParseAddr("127.0.0.1")}})
	conn, err := b.StreamDialer().DialStream(ctx(t), net.JoinHostPort("server.example.test", port))
	require.NoError(t, err)
	conn.Close()
	<-accepted
	require.Contains(t, buf.String(), "using its addresses from when the session started")

	// Other names don't get the server's addresses.
	_, err = b.StreamDialer().DialStream(ctx(t), net.JoinHostPort("other.example.test", port))
	require.ErrorContains(t, err, "resolving other.example.test")
}

func TestLookupIPv4WithoutResolvers(t *testing.T) {
	b, _ := recordingBinder()
	require.NoError(t, b.SetInterface("en0"))
	_, err := b.LookupIPv4(ctx(t), "server.example.test")
	require.ErrorContains(t, err, "no DNS server")
	_, err = b.StreamDialer().DialStream(ctx(t), "server.example.test:443")
	require.ErrorContains(t, err, "no DNS server")
}
