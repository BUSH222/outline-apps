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

package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/dnsrelay"
	"localhost/client/go/outline/macoscli/internal/dnstest"
	"localhost/client/go/outline/macoscli/internal/ipcache"
	"localhost/client/go/outline/macoscli/internal/rules"

	"golang.getoutline.org/sdk/network/packetrelay"
	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/stretchr/testify/require"
)

// Documentation addresses throughout.
var (
	dnsAddr     = netip.MustParseAddrPort("169.254.113.53:53")
	bypassIP    = netip.MustParseAddr("192.0.2.1")
	vpnOnlyIP   = netip.MustParseAddr("192.0.2.2")
	sharedIP    = netip.MustParseAddr("192.0.2.3")
	unlistedDst = "198.51.100.1:443"
)

const testRules = `
bypass: [lichess.org, cdn.example]
vpn_only: [secret.example]
`

// pipeConn adds the half-close methods of a StreamConn to a net.Pipe end.
type pipeConn struct{ net.Conn }

func (c pipeConn) CloseRead() error  { return nil }
func (c pipeConn) CloseWrite() error { return nil }

// recordingDialer records dial addresses and fails or returns a pipe.
type recordingDialer struct {
	mu    sync.Mutex
	addrs []string
	err   error
}

func (d *recordingDialer) DialStream(_ context.Context, addr string) (transport.StreamConn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	c, server := net.Pipe()
	go func() {
		// Swallow whatever is sent, like a server that doesn't answer.
		io.Copy(io.Discard, server)
		server.Close()
	}()
	return pipeConn{c}, nil
}

func (d *recordingDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

type packet struct {
	data []byte
	addr netip.AddrPort
}

// fakeRelay hands out associations that record what is sent on them; the
// test pushes replies into them.
type fakeRelay struct {
	mu     sync.Mutex
	assocs []*fakeAssoc
	err    error
}

func (f *fakeRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, nil, f.err
	}
	a := &fakeAssoc{sent: make(chan packet, 10), in: make(chan packet, 10), done: make(chan struct{})}
	f.assocs = append(f.assocs, a)
	return a, a, nil
}

func (f *fakeRelay) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.assocs)
}

func (f *fakeRelay) assoc(i int) *fakeAssoc {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.assocs[i]
}

type fakeAssoc struct {
	sent, in chan packet
	done     chan struct{}
	once     sync.Once
	closed   atomic.Bool
}

func (a *fakeAssoc) SendPacket(p []byte, dst netip.AddrPort) error {
	if a.closed.Load() {
		return packetrelay.ErrClosed
	}
	a.sent <- packet{bytes.Clone(p), dst}
	return nil
}

func (a *fakeAssoc) Close() error {
	a.once.Do(func() { a.closed.Store(true); close(a.done) })
	return nil
}

func (a *fakeAssoc) ReceivePackets(h packetrelay.PacketHandler) error {
	for {
		select {
		case p := <-a.in:
			h.HandlePacket(p.data, p.addr)
		case <-a.done:
			return nil
		}
	}
}

// fakeExchanger answers direct DNS queries.
type fakeExchanger struct {
	calls  atomic.Int32
	answer func(q []byte) ([]byte, error)
}

func (f *fakeExchanger) Exchange(_ context.Context, q []byte, _ bool) ([]byte, error) {
	f.calls.Add(1)
	return f.answer(q)
}

type fixture struct {
	router       *Router
	pair         *configregistry.TransportPair
	cache        *ipcache.Cache
	tunnelStream *recordingDialer
	directStream *recordingDialer
	tunnelUDP    *fakeRelay
	directUDP    *fakeRelay
	directDNS    *fakeExchanger
	notified     atomic.Int32
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rs, err := rules.Parse([]byte(testRules))
	require.NoError(t, err)
	f := &fixture{
		cache:        ipcache.New(rs.MinTTL, rs.MaxTTL, nil),
		tunnelStream: &recordingDialer{},
		directStream: &recordingDialer{},
		tunnelUDP:    &fakeRelay{},
		directUDP:    &fakeRelay{},
		directDNS: &fakeExchanger{answer: func(q []byte) ([]byte, error) {
			return dnstest.ReplyTo(q, dnstest.Options{}, dnstest.RR{Name: dnstest.QuestionName(q), Addr: "203.0.113.10", TTL: 60}), nil
		}},
	}
	f.cache.Learn(bypassIP, rules.Bypass, "lichess.org", time.Hour)
	f.cache.Learn(vpnOnlyIP, rules.VPNOnly, "secret.example", time.Hour)
	f.cache.Learn(sharedIP, rules.Bypass, "cdn.example", time.Hour)
	f.cache.Learn(sharedIP, rules.VPNOnly, "secret.example", time.Hour)

	inner := &configregistry.TransportPair{
		StreamDialer: &configregistry.Dialer[transport.StreamConn]{
			ConnectionProviderInfo: configregistry.ConnectionProviderInfo{ConnType: configregistry.ConnTypeTunneled, FirstHop: "192.0.2.200:443"},
			Dial:                   f.tunnelStream.DialStream,
		},
		PacketRelay: &configregistry.PacketRelay{
			ConnectionProviderInfo: configregistry.ConnectionProviderInfo{ConnType: configregistry.ConnTypeTunneled, FirstHop: "192.0.2.200:443"},
			PacketRelay:            f.tunnelUDP,
			NotifyNetworkChanged:   func() { f.notified.Add(1) },
		},
	}
	f.router = New(Config{
		Inner:         inner,
		DirectStream:  f.directStream,
		DirectPackets: f.directUDP,
		DNS:           &dnsrelay.Relay{Rules: rs, Cache: f.cache, Direct: f.directDNS},
		DNSAddr:       dnsAddr,
	})
	f.pair = f.router.Pair()
	return f
}

func addr(ip netip.Addr, port uint16) string { return netip.AddrPortFrom(ip, port).String() }

func TestPair_KeepsTheTransportInfo(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, configregistry.ConnTypeTunneled, f.pair.StreamDialer.ConnType)
	require.Equal(t, "192.0.2.200:443", f.pair.StreamDialer.FirstHop)
	require.Equal(t, "192.0.2.200:443", f.pair.PacketRelay.FirstHop)
	f.pair.PacketRelay.NotifyNetworkChanged()
	require.Equal(t, int32(1), f.notified.Load())
}

func TestDialStream_Decisions(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		dst        string
		wantDirect bool
	}{
		"bypass address goes directly":           {addr(bypassIP, 443), true},
		"mapped bypass address goes directly":    {"[::ffff:192.0.2.1]:443", true},
		"vpn_only address goes through":          {addr(vpnOnlyIP, 443), false},
		"vpn_only wins for a shared address":     {addr(sharedIP, 443), false},
		"unlisted address goes through":          {unlistedDst, false},
		"host name goes through":                 {"captive.example:80", false},
		"other port on the DNS address goes too": {"169.254.113.53:80", false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			conn, err := f.pair.DialStream(ctx, tc.dst)
			require.NoError(t, err)
			conn.Close()
			if tc.wantDirect {
				require.Equal(t, []string{tc.dst}, f.directStream.dialed())
				require.Empty(t, f.tunnelStream.dialed())
			} else {
				require.Equal(t, []string{tc.dst}, f.tunnelStream.dialed())
				require.Empty(t, f.directStream.dialed())
			}
		})
	}
}

func TestDialStream_BypassFailureDoesNotUseTheTunnel(t *testing.T) {
	f := newFixture(t)
	f.directStream.err = errors.New("network is unreachable")
	_, err := f.pair.DialStream(context.Background(), addr(bypassIP, 443))
	require.ErrorContains(t, err, "network is unreachable")
	require.Empty(t, f.tunnelStream.dialed())
}

func TestDialStream_VPNOnlyNeverGoesDirectEvenIfTheTunnelFails(t *testing.T) {
	f := newFixture(t)
	f.tunnelStream.err = errors.New("tunnel down")
	for _, ip := range []netip.Addr{vpnOnlyIP, sharedIP} {
		_, err := f.pair.DialStream(context.Background(), addr(ip, 443))
		require.ErrorContains(t, err, "tunnel down")
	}
	require.Empty(t, f.directStream.dialed())
}

func TestDialStream_ExpiredBypassGoesThroughTheTunnel(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.cache = ipcache.New(time.Minute, time.Hour, func() time.Time { return now })
	f.router.cache = f.cache
	f.cache.Learn(bypassIP, rules.Bypass, "lichess.org", time.Minute)
	now = now.Add(time.Minute)
	conn, err := f.pair.DialStream(context.Background(), addr(bypassIP, 443))
	require.NoError(t, err)
	conn.Close()
	require.Empty(t, f.directStream.dialed())
}

func TestDialStream_DNSOverTCP(t *testing.T) {
	f := newFixture(t)
	conn, err := f.pair.DialStream(context.Background(), "169.254.113.53:53")
	require.NoError(t, err)
	defer conn.Close()
	// A bypass query is answered directly; no tunnel connection is opened.
	_, err = conn.Write(dnstest.Frame(dnstest.Query(5, dnsmessage.TypeA, "www.lichess.org")))
	require.NoError(t, err)
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Greater(t, n, 2)
	require.Equal(t, uint16(5), dnstest.ID(buf[2:n]))
	require.Equal(t, int32(1), f.directDNS.calls.Load())
	require.Empty(t, f.tunnelStream.dialed())
	class, _ := f.cache.Lookup(netip.MustParseAddr("203.0.113.10"))
	require.Equal(t, rules.Bypass, class)

	// Any other query goes through the tunnel, to the same DNS address (the
	// transport's own interception forwards it).
	_, err = conn.Write(dnstest.Frame(dnstest.Query(6, dnsmessage.TypeA, "example.com")))
	require.NoError(t, err)
	require.Equal(t, []string{"169.254.113.53:53"}, f.tunnelStream.dialed())
}

// handler collects what an association delivers.
type handler struct{ got chan packet }

func newHandler() *handler { return &handler{got: make(chan packet, 10)} }

func (h *handler) HandlePacket(p []byte, src netip.AddrPort) error {
	h.got <- packet{bytes.Clone(p), src}
	return nil
}

func (h *handler) next(t *testing.T) packet {
	t.Helper()
	select {
	case p := <-h.got:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no packet delivered")
		return packet{}
	}
}

func recvSent(t *testing.T, a *fakeAssoc) packet {
	t.Helper()
	select {
	case p := <-a.sent:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("nothing sent")
		return packet{}
	}
}

func newAssoc(t *testing.T, f *fixture) (packetrelay.PacketSender, *handler, chan error) {
	t.Helper()
	s, r, err := f.pair.PacketRelay.NewAssociation()
	require.NoError(t, err)
	h := newHandler()
	done := make(chan error, 1)
	go func() { done <- r.ReceivePackets(h) }()
	return s, h, done
}

func TestUDP_Decisions(t *testing.T) {
	f := newFixture(t)
	s, h, done := newAssoc(t, f)

	bypass := netip.AddrPortFrom(bypassIP, 3478)
	require.NoError(t, s.SendPacket([]byte("to bypass"), bypass))
	require.NoError(t, s.SendPacket([]byte("to vpn_only"), netip.AddrPortFrom(vpnOnlyIP, 3478)))
	require.NoError(t, s.SendPacket([]byte("to shared"), netip.AddrPortFrom(sharedIP, 3478)))
	require.NoError(t, s.SendPacket([]byte("to unlisted"), netip.MustParseAddrPort(unlistedDst)))
	require.NoError(t, s.SendPacket([]byte("again to bypass"), bypass))

	require.Equal(t, 1, f.directUDP.count(), "one direct sub-association, reused")
	require.Equal(t, 1, f.tunnelUDP.count(), "one tunnel sub-association, reused")
	direct, tunnel := f.directUDP.assoc(0), f.tunnelUDP.assoc(0)
	require.Equal(t, "to bypass", string(recvSent(t, direct).data))
	require.Equal(t, "again to bypass", string(recvSent(t, direct).data))
	for _, want := range []string{"to vpn_only", "to shared", "to unlisted"} {
		require.Equal(t, want, string(recvSent(t, tunnel).data))
	}

	// Replies from both paths reach the app with their real source.
	direct.in <- packet{[]byte("from bypass"), bypass}
	require.Equal(t, packet{[]byte("from bypass"), bypass}, h.next(t))
	tunnel.in <- packet{[]byte("from unlisted"), netip.MustParseAddrPort(unlistedDst)}
	require.Equal(t, "from unlisted", string(h.next(t).data))

	require.NoError(t, s.Close())
	require.NoError(t, <-done)
	require.True(t, direct.closed.Load())
	require.True(t, tunnel.closed.Load())
	require.ErrorIs(t, s.SendPacket([]byte("x"), bypass), packetrelay.ErrClosed)
}

func TestUDP_VPNOnlyNeverGoesDirectEvenIfTheTunnelFails(t *testing.T) {
	f := newFixture(t)
	f.tunnelUDP.err = errors.New("tunnel down")
	for _, ip := range []netip.Addr{vpnOnlyIP, sharedIP} {
		s, _, done := newAssoc(t, f)
		require.ErrorContains(t, s.SendPacket([]byte("x"), netip.AddrPortFrom(ip, 443)), "tunnel down")
		// Nothing is active, so the association closed itself.
		require.NoError(t, <-done)
		require.ErrorIs(t, s.SendPacket([]byte("x"), netip.AddrPortFrom(ip, 443)), packetrelay.ErrClosed)
	}
	require.Zero(t, f.directUDP.count())
}

func TestUDP_BypassFailureDoesNotUseTheTunnel(t *testing.T) {
	f := newFixture(t)
	f.directUDP.err = errors.New("network is unreachable")
	s, _, _ := newAssoc(t, f)
	require.ErrorContains(t, s.SendPacket([]byte("x"), netip.AddrPortFrom(bypassIP, 443)), "network is unreachable")
	require.Zero(t, f.tunnelUDP.count())
}

func TestUDP_BypassDNSIsAnsweredDirectly(t *testing.T) {
	f := newFixture(t)
	s, h, done := newAssoc(t, f)
	q := dnstest.Query(9, dnsmessage.TypeA, "www.lichess.org")
	require.NoError(t, s.SendPacket(q, netip.MustParseAddrPort("[::ffff:169.254.113.53]:53")))
	reply := h.next(t)
	require.Equal(t, dnsAddr, reply.addr, "the reply comes from the DNS address the app asked")
	require.Equal(t, uint16(9), dnstest.ID(reply.data))
	require.Zero(t, f.tunnelUDP.count())
	class, domain := f.cache.Lookup(netip.MustParseAddr("203.0.113.10"))
	require.Equal(t, rules.Bypass, class)
	require.Equal(t, "www.lichess.org", domain)
	// The query was the only activity, so the association ends, as upstream's does.
	require.NoError(t, <-done)
}

func TestUDP_TruncatedDirectReplyIsPassedOn(t *testing.T) {
	f := newFixture(t)
	f.directDNS.answer = func(q []byte) ([]byte, error) {
		return dnstest.ReplyTo(q, dnstest.Options{Truncated: true}), nil
	}
	s, h, _ := newAssoc(t, f)
	require.NoError(t, s.SendPacket(dnstest.Query(9, dnsmessage.TypeA, "lichess.org"), dnsAddr))
	reply := h.next(t)
	require.Equal(t, byte(0x02), reply.data[2]&0x02, "TC bit kept")
	require.Zero(t, f.tunnelUDP.count())
}

func TestUDP_OtherDNSGoesThroughTheTunnelAndIsLearned(t *testing.T) {
	f := newFixture(t)
	s, h, done := newAssoc(t, f)
	q := dnstest.Query(3, dnsmessage.TypeA, "files.secret.example")
	require.NoError(t, s.SendPacket(q, dnsAddr))
	tunnel := f.tunnelUDP.assoc(0)
	sent := recvSent(t, tunnel)
	require.Equal(t, dnsAddr, sent.addr, "sent unchanged; the transport forwards it")
	require.Equal(t, q, sent.data)

	tunnel.in <- packet{dnstest.ReplyTo(q, dnstest.Options{}, dnstest.RR{Name: "files.secret.example", Addr: "203.0.113.20", TTL: 60}), dnsAddr}
	require.Equal(t, dnsAddr, h.next(t).addr)
	class, _ := f.cache.Lookup(netip.MustParseAddr("203.0.113.20"))
	require.Equal(t, rules.VPNOnly, class)
	require.Zero(t, f.directDNS.calls.Load())

	// When the tunnel's sub-association ends, so does the association.
	tunnel.Close()
	require.NoError(t, <-done)
}

func TestUDP_DirectDNSFailureFailsTheLookup(t *testing.T) {
	f := newFixture(t)
	f.directDNS.answer = func([]byte) ([]byte, error) { return nil, errors.New("no answer") }
	s, h, done := newAssoc(t, f)
	q := dnstest.Query(4, dnsmessage.TypeA, "lichess.org")
	require.NoError(t, s.SendPacket(q, dnsAddr))
	reply := h.next(t)
	require.Equal(t, dnsAddr, reply.addr)
	require.Equal(t, uint16(4), dnstest.ID(reply.data))
	require.Equal(t, byte(dnsmessage.RCodeServerFailure), reply.data[3]&0x0f)
	require.NoError(t, <-done)
	require.Zero(t, f.tunnelUDP.count(), "a bypass name is never looked up through the tunnel")
}

func TestUDP_MixedDNSQueryIsRefused(t *testing.T) {
	f := newFixture(t)
	s, h, _ := newAssoc(t, f)
	require.NoError(t, s.SendPacket(dnstest.Query(5, dnsmessage.TypeA, "lichess.org", "example.com"), dnsAddr))
	reply := h.next(t)
	require.Equal(t, byte(dnsmessage.RCodeServerFailure), reply.data[3]&0x0f)
	require.Zero(t, f.tunnelUDP.count())
	require.Zero(t, f.directDNS.calls.Load())
}

func TestUDP_EndedSubAssociationIsReplaced(t *testing.T) {
	f := newFixture(t)
	s, _, _ := newAssoc(t, f)
	// Keep the association alive with a direct sub-association.
	require.NoError(t, s.SendPacket([]byte("keep"), netip.AddrPortFrom(bypassIP, 443)))
	require.NoError(t, s.SendPacket([]byte("1"), netip.MustParseAddrPort(unlistedDst)))
	first := f.tunnelUDP.assoc(0)
	recvSent(t, first)
	// The tunnel's association closes (idle timeout) without its receiver
	// having returned yet: the next send replaces it.
	first.closed.Store(true)
	require.NoError(t, s.SendPacket([]byte("2"), netip.MustParseAddrPort(unlistedDst)))
	require.Equal(t, 2, f.tunnelUDP.count())
	require.Equal(t, "2", string(recvSent(t, f.tunnelUDP.assoc(1)).data))
}

func TestUDP_ReceivePacketsTwice(t *testing.T) {
	f := newFixture(t)
	_, r, err := f.pair.PacketRelay.NewAssociation()
	require.NoError(t, err)
	go r.ReceivePackets(newHandler())
	require.Eventually(t, func() bool {
		return r.ReceivePackets(newHandler()) != nil
	}, time.Second, time.Millisecond)
}
