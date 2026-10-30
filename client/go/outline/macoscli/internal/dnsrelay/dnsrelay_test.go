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

package dnsrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"localhost/client/go/outline/macoscli/internal/dnstest"
	"localhost/client/go/outline/macoscli/internal/ipcache"
	"localhost/client/go/outline/macoscli/internal/rules"

	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/stretchr/testify/require"
)

// All names and addresses are documentation values.
const testRules = `
bypass: [lichess.org, cdn.example]
vpn_only: [secret.example]
min_ttl: 60s
max_ttl: 1h
`

func testRelay(t *testing.T, direct Exchanger) *Relay {
	t.Helper()
	r, err := rules.Parse([]byte(testRules))
	require.NoError(t, err)
	return &Relay{Rules: r, Cache: ipcache.New(r.MinTTL, r.MaxTTL, nil), Direct: direct}
}

func lookup(r *Relay, addr string) rules.Class {
	c, _ := r.Cache.Lookup(netip.MustParseAddr(addr))
	return c
}

func TestClassify(t *testing.T) {
	r, err := rules.Parse([]byte(testRules))
	require.NoError(t, err)
	a := dnsmessage.TypeA
	for name, tc := range map[string]struct {
		msg  []byte
		want rules.Class
	}{
		"bypass":                {dnstest.Query(1, a, "www.lichess.org"), rules.Bypass},
		"bypass AAAA":           {dnstest.Query(1, dnsmessage.TypeAAAA, "lichess.org"), rules.Bypass},
		"not a label boundary":  {dnstest.Query(1, a, "notlichess.org"), rules.None},
		"vpn_only":              {dnstest.Query(1, a, "a.secret.example"), rules.VPNOnly},
		"unlisted":              {dnstest.Query(1, a, "example.com"), rules.None},
		"all bypass":            {dnstest.Query(1, a, "lichess.org", "cdn.example"), rules.Bypass},
		"mixed goes the tunnel": {dnstest.Query(1, a, "lichess.org", "example.com"), rules.None},
		"any vpn_only wins":     {dnstest.Query(1, a, "lichess.org", "secret.example"), rules.VPNOnly},
		"a response":            {dnstest.Response(1, "lichess.org", dnstest.Options{}), rules.None},
		"malformed":             {[]byte{0, 1, 2}, rules.None},
		"empty":                 {nil, rules.None},
	} {
		got, _ := Classify(tc.msg, r)
		require.Equal(t, tc.want, got, name)
	}
}

func TestSnoop(t *testing.T) {
	r, err := rules.Parse([]byte(testRules))
	require.NoError(t, err)
	ok := dnstest.Options{}

	t.Run("A and AAAA answers", func(t *testing.T) {
		got := Snoop(dnstest.Response(1, "lichess.org", ok,
			dnstest.RR{Name: "lichess.org", Addr: "192.0.2.1", TTL: 300},
			dnstest.RR{Name: "lichess.org", Addr: "2001:db8::1", TTL: 200},
		), r)
		require.Equal(t, []Learned{
			{netip.MustParseAddr("192.0.2.1"), rules.Bypass, "lichess.org", 300 * time.Second},
			{netip.MustParseAddr("2001:db8::1"), rules.Bypass, "lichess.org", 200 * time.Second},
		}, got)
	})
	t.Run("CNAME chain keeps the smallest TTL", func(t *testing.T) {
		got := Snoop(dnstest.Response(1, "www.lichess.org", ok,
			dnstest.RR{Name: "www.lichess.org", CNAME: "edge.provider.example", TTL: 30},
			dnstest.RR{Name: "edge.provider.example", CNAME: "a1.provider.example", TTL: 600},
			dnstest.RR{Name: "a1.provider.example", Addr: "192.0.2.2", TTL: 600},
		), r)
		require.Equal(t, []Learned{{netip.MustParseAddr("192.0.2.2"), rules.Bypass, "www.lichess.org", 30 * time.Second}}, got)
	})
	t.Run("CNAME into a bypass domain counts", func(t *testing.T) {
		got := Snoop(dnstest.Response(1, "alias.example.com", ok,
			dnstest.RR{Name: "alias.example.com", CNAME: "files.cdn.example", TTL: 120},
			dnstest.RR{Name: "files.cdn.example", Addr: "192.0.2.3", TTL: 120},
		), r)
		require.Len(t, got, 1)
		require.Equal(t, rules.Bypass, got[0].Class)
		require.Equal(t, "alias.example.com", got[0].Domain)
	})
	t.Run("CNAME into a vpn_only domain wins", func(t *testing.T) {
		got := Snoop(dnstest.Response(1, "lichess.org", ok,
			dnstest.RR{Name: "lichess.org", CNAME: "x.secret.example", TTL: 120},
			dnstest.RR{Name: "x.secret.example", Addr: "192.0.2.4", TTL: 120},
		), r)
		require.Len(t, got, 1)
		require.Equal(t, rules.VPNOnly, got[0].Class)
	})
	t.Run("answers out of order and in another case", func(t *testing.T) {
		got := Snoop(dnstest.Response(1, "WWW.Lichess.org", ok,
			dnstest.RR{Name: "edge.provider.example", Addr: "192.0.2.5", TTL: 90},
			dnstest.RR{Name: "www.lichess.ORG", CNAME: "EDGE.provider.example", TTL: 100},
		), r)
		require.Len(t, got, 1)
		require.Equal(t, 90*time.Second, got[0].TTL)
	})
	t.Run("CNAME loop ends", func(t *testing.T) {
		got := Snoop(dnstest.Response(1, "lichess.org", ok,
			dnstest.RR{Name: "lichess.org", CNAME: "loop.example", TTL: 60},
			dnstest.RR{Name: "loop.example", CNAME: "lichess.org", TTL: 60},
		), r)
		require.Empty(t, got)
	})
	t.Run("addresses of other names are ignored", func(t *testing.T) {
		got := Snoop(dnstest.Response(1, "lichess.org", ok,
			dnstest.RR{Name: "lichess.org", Addr: "192.0.2.6", TTL: 60},
			dnstest.RR{Name: "unrelated.example", Addr: "192.0.2.7", TTL: 60},
		), r)
		require.Len(t, got, 1)
		require.Equal(t, netip.MustParseAddr("192.0.2.6"), got[0].Addr)
	})
	t.Run("nothing to learn", func(t *testing.T) {
		for name, msg := range map[string][]byte{
			"unlisted":  dnstest.Response(1, "example.com", ok, dnstest.RR{Name: "example.com", Addr: "192.0.2.8", TTL: 60}),
			"NXDOMAIN":  dnstest.Response(1, "nope.lichess.org", dnstest.Options{RCode: dnsmessage.RCodeNameError}),
			"truncated": dnstest.Response(1, "lichess.org", dnstest.Options{Truncated: true}),
			"a query":   dnstest.Query(1, dnsmessage.TypeA, "lichess.org"),
			"malformed": {1, 2, 3, 4},
		} {
			require.Empty(t, Snoop(msg, r), name)
		}
	})
}

func TestFramer(t *testing.T) {
	q1 := dnstest.Query(1, dnsmessage.TypeA, "lichess.org")
	q2 := dnstest.Query(2, dnsmessage.TypeA, "example.com")
	stream := append(dnstest.Frame(q1), dnstest.Frame(q2)...)

	t.Run("several messages in one segment", func(t *testing.T) {
		var f Framer
		msgs, err := f.Push(stream)
		require.NoError(t, err)
		require.Equal(t, [][]byte{q1, q2}, msgs)
	})
	t.Run("split everywhere, including inside the length prefix", func(t *testing.T) {
		for cut := 1; cut < len(stream); cut++ {
			var f Framer
			var got [][]byte
			for _, part := range [][]byte{stream[:1], stream[1:cut], stream[cut:]} {
				msgs, err := f.Push(part)
				require.NoError(t, err)
				got = append(got, msgs...)
			}
			require.Equal(t, [][]byte{q1, q2}, got, "cut at %d", cut)
		}
	})
	t.Run("zero length", func(t *testing.T) {
		var f Framer
		_, err := f.Push([]byte{0, 0})
		require.ErrorIs(t, err, errEmptyFrame)
	})
}

// pipeConn adds the half-close methods of a StreamConn to a net.Pipe end.
type pipeConn struct{ net.Conn }

func (c pipeConn) CloseRead() error  { return nil }
func (c pipeConn) CloseWrite() error { return nil }

// fakeServer serves one exchange per dial over an in-memory pipe.
type fakeServer struct {
	mu    sync.Mutex
	dials []string
	// serve handles one connection to addr; nil refuses the dial.
	serve func(addr string, conn net.Conn)
}

func (s *fakeServer) dial(addr string) (net.Conn, error) {
	s.mu.Lock()
	s.dials = append(s.dials, addr)
	s.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		s.serve(addr, server)
	}()
	return client, nil
}

func (s *fakeServer) packetDialer() transport.PacketDialer {
	return transport.FuncPacketDialer(func(_ context.Context, addr string) (net.Conn, error) { return s.dial(addr) })
}

func (s *fakeServer) streamDialer() transport.StreamDialer {
	return transport.FuncStreamDialer(func(_ context.Context, addr string) (transport.StreamConn, error) {
		c, err := s.dial(addr)
		if err != nil {
			return nil, err
		}
		return pipeConn{c}, nil
	})
}

func servers(addrs ...string) func() []netip.AddrPort {
	return func() []netip.AddrPort {
		var out []netip.AddrPort
		for _, a := range addrs {
			out = append(out, netip.MustParseAddrPort(a))
		}
		return out
	}
}

func readPacket(conn net.Conn) []byte {
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func TestDirect_UDPTriesEachServer(t *testing.T) {
	answer := dnstest.RR{Name: "lichess.org", Addr: "192.0.2.1", TTL: 60}
	srv := &fakeServer{serve: func(addr string, conn net.Conn) {
		q := readPacket(conn)
		switch addr {
		case "192.0.2.53:53": // the old network's resolver: never answers
			io.Copy(io.Discard, conn)
		case "198.51.100.53:53":
			conn.Write(dnstest.ReplyTo(q, dnstest.Options{RCode: dnsmessage.RCodeServerFailure}))
		default:
			// A stray packet with another ID is ignored.
			conn.Write(dnstest.Response(dnstest.ID(q)+1, "lichess.org", dnstest.Options{}, answer))
			conn.Write(dnstest.ReplyTo(q, dnstest.Options{}, answer))
		}
	}}
	d := &Direct{
		Packet:  srv.packetDialer(),
		Servers: servers("192.0.2.53:53", "198.51.100.53:53", "203.0.113.53:53"),
		Timeout: 50 * time.Millisecond,
	}
	q := dnstest.Query(7, dnsmessage.TypeA, "lichess.org")
	reply, err := d.Exchange(context.Background(), q, false)
	require.NoError(t, err)
	require.Equal(t, uint16(7), dnstest.ID(reply))
	require.Equal(t, []string{"192.0.2.53:53", "198.51.100.53:53", "203.0.113.53:53"}, srv.dials)
}

func TestDirect_AllFail(t *testing.T) {
	srv := &fakeServer{serve: func(_ string, conn net.Conn) {
		q := readPacket(conn)
		conn.Write(dnstest.ReplyTo(q, dnstest.Options{RCode: dnsmessage.RCodeRefused}))
	}}
	d := &Direct{Packet: srv.packetDialer(), Servers: servers("192.0.2.53:53", "198.51.100.53:53")}
	_, err := d.Exchange(context.Background(), dnstest.Query(7, dnsmessage.TypeA, "lichess.org"), false)
	require.ErrorContains(t, err, "via 192.0.2.53:53: answered RCodeRefused")
	require.ErrorContains(t, err, "via 198.51.100.53:53")
}

func TestDirect_NXDOMAINIsAnAnswer(t *testing.T) {
	srv := &fakeServer{serve: func(_ string, conn net.Conn) {
		conn.Write(dnstest.ReplyTo(readPacket(conn), dnstest.Options{RCode: dnsmessage.RCodeNameError}))
	}}
	d := &Direct{Packet: srv.packetDialer(), Servers: servers("192.0.2.53:53", "198.51.100.53:53")}
	reply, err := d.Exchange(context.Background(), dnstest.Query(7, dnsmessage.TypeA, "nope.lichess.org"), false)
	require.NoError(t, err)
	require.Equal(t, dnsmessage.RCodeNameError, rcode(reply))
	require.Len(t, srv.dials, 1)
}

func TestDirect_TCP(t *testing.T) {
	srv := &fakeServer{serve: func(_ string, conn net.Conn) {
		var f Framer
		buf := make([]byte, 512)
		for {
			n, err := conn.Read(buf)
			msgs, _ := f.Push(buf[:n])
			if len(msgs) > 0 {
				reply := dnstest.Frame(dnstest.ReplyTo(msgs[0], dnstest.Options{},
					dnstest.RR{Name: "lichess.org", Addr: "192.0.2.1", TTL: 60}))
				// Byte by byte: the reader must reassemble the frame.
				for i := range reply {
					conn.Write(reply[i : i+1])
				}
				return
			}
			if err != nil {
				return
			}
		}
	}}
	d := &Direct{Stream: srv.streamDialer(), Servers: servers("192.0.2.53:53")}
	reply, err := d.Exchange(context.Background(), dnstest.Query(9, dnsmessage.TypeA, "lichess.org"), true)
	require.NoError(t, err)
	require.Equal(t, uint16(9), dnstest.ID(reply))
}

func TestDirect_CanceledContextStopsWaiting(t *testing.T) {
	srv := &fakeServer{serve: func(_ string, conn net.Conn) { io.Copy(io.Discard, conn) }}
	d := &Direct{Packet: srv.packetDialer(), Servers: servers("192.0.2.53:53"), Timeout: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	_, err := d.Exchange(ctx, dnstest.Query(1, dnsmessage.TypeA, "lichess.org"), false)
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}

// fakeExchanger answers queries from a function.
type fakeExchanger struct {
	calls  atomic.Int32
	answer func(query []byte, overTCP bool) ([]byte, error)
}

func (f *fakeExchanger) Exchange(_ context.Context, q []byte, overTCP bool) ([]byte, error) {
	f.calls.Add(1)
	return f.answer(q, overTCP)
}

func TestRelay_ResolveDirectLearns(t *testing.T) {
	r := testRelay(t, &fakeExchanger{answer: func(q []byte, _ bool) ([]byte, error) {
		return dnstest.ReplyTo(q, dnstest.Options{}, dnstest.RR{Name: "lichess.org", Addr: "192.0.2.1", TTL: 5}), nil
	}})
	_, err := r.ResolveDirect(context.Background(), dnstest.Query(1, dnsmessage.TypeA, "lichess.org"), false)
	require.NoError(t, err)
	require.Equal(t, rules.Bypass, lookup(r, "192.0.2.1"))
}

// tunnelDNS is a fake DNS server behind the tunnel: it answers each framed
// query on a pipe, until the client half-closes or closes.
type tunnelDNS struct {
	dials   atomic.Int32
	queries chan string
	answer  func(q []byte) []byte
}

func (s *tunnelDNS) dial(context.Context) (transport.StreamConn, error) {
	s.dials.Add(1)
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		var f Framer
		buf := make([]byte, 512)
		for {
			n, err := server.Read(buf)
			msgs, _ := f.Push(buf[:n])
			for _, m := range msgs {
				s.queries <- dnstest.QuestionName(m)
				server.Write(dnstest.Frame(s.answer(m)))
			}
			if err != nil {
				return
			}
		}
	}()
	return &halfClosePipe{Conn: client}, nil
}

// halfClosePipe ends the server's reads on CloseWrite, like a TCP FIN.
type halfClosePipe struct {
	net.Conn
	once sync.Once
}

func (c *halfClosePipe) CloseRead() error { return nil }
func (c *halfClosePipe) CloseWrite() error {
	// net.Pipe has no half-close; closing after a short delay lets the
	// server's last reply through.
	c.once.Do(func() { time.AfterFunc(50*time.Millisecond, func() { c.Conn.Close() }) })
	return nil
}

var dnsAddr = netip.MustParseAddrPort("169.254.113.53:53")

// readReplies reads framed replies from conn until EOF.
func readReplies(t *testing.T, conn io.Reader) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	var f Framer
	buf := make([]byte, 7) // small, so frames arrive in pieces
	for {
		n, err := conn.Read(buf)
		msgs, ferr := f.Push(buf[:n])
		require.NoError(t, ferr)
		for _, m := range msgs {
			out[dnstest.QuestionName(m)] = m
		}
		if errors.Is(err, io.EOF) {
			return out
		}
		require.NoError(t, err)
	}
}

func TestStreamConn_SplitsQueriesBetweenDirectAndTunnel(t *testing.T) {
	direct := &fakeExchanger{answer: func(q []byte, overTCP bool) ([]byte, error) {
		require.True(t, overTCP, "a TCP query goes direct over TCP")
		return dnstest.ReplyTo(q, dnstest.Options{}, dnstest.RR{Name: dnstest.QuestionName(q), Addr: "192.0.2.1", TTL: 60}), nil
	}}
	r := testRelay(t, direct)
	tun := &tunnelDNS{queries: make(chan string, 10), answer: func(q []byte) []byte {
		name := dnstest.QuestionName(q)
		return dnstest.ReplyTo(q, dnstest.Options{}, dnstest.RR{Name: name, Addr: map[string]string{
			"example.com": "198.51.100.1", "secret.example": "198.51.100.2",
		}[name], TTL: 60})
	}}
	conn := r.StreamConn(dnsAddr, tun.dial)
	require.Equal(t, dnsAddr.String(), conn.RemoteAddr().String())

	stream := append(dnstest.Frame(dnstest.Query(1, dnsmessage.TypeA, "lichess.org")),
		dnstest.Frame(dnstest.Query(2, dnsmessage.TypeA, "example.com"))...)
	stream = append(stream, dnstest.Frame(dnstest.Query(3, dnsmessage.TypeA, "secret.example"))...)

	done := make(chan map[string][]byte)
	go func() { done <- readReplies(t, conn) }()
	// Two queries and the start of the third in one segment, the rest later.
	_, err := conn.Write(stream[:len(stream)-5])
	require.NoError(t, err)
	_, err = conn.Write(stream[len(stream)-5:])
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite())

	replies := <-done
	require.Len(t, replies, 3)
	require.Equal(t, uint16(1), dnstest.ID(replies["lichess.org"]))
	require.Equal(t, int32(1), direct.calls.Load())
	require.Equal(t, int32(1), tun.dials.Load(), "one tunnel connection for all tunnel queries")
	require.ElementsMatch(t, []string{"example.com", "secret.example"}, []string{<-tun.queries, <-tun.queries})

	require.Equal(t, rules.Bypass, lookup(r, "192.0.2.1"))
	require.Equal(t, rules.None, lookup(r, "198.51.100.1"), "unlisted answers aren't stored")
	require.Equal(t, rules.VPNOnly, lookup(r, "198.51.100.2"), "tunnel answers are learned too")
	require.NoError(t, conn.Close())
}

func TestStreamConn_DirectFailureFallsBackToTheTunnel(t *testing.T) {
	r := testRelay(t, &fakeExchanger{answer: func([]byte, bool) ([]byte, error) {
		return nil, errors.New("network DNS unreachable")
	}})
	tun := &tunnelDNS{queries: make(chan string, 10), answer: func(q []byte) []byte {
		return dnstest.ReplyTo(q, dnstest.Options{}, dnstest.RR{Name: "lichess.org", Addr: "203.0.113.1", TTL: 60})
	}}
	conn := r.StreamConn(dnsAddr, tun.dial)
	done := make(chan map[string][]byte)
	go func() { done <- readReplies(t, conn) }()
	_, err := conn.Write(dnstest.Frame(dnstest.Query(1, dnsmessage.TypeA, "lichess.org")))
	require.NoError(t, err)
	require.NoError(t, conn.CloseWrite())
	replies := <-done
	require.Contains(t, replies, "lichess.org")
	require.Equal(t, "lichess.org", <-tun.queries)
	// The answer still names a bypass domain, so its address goes direct.
	require.Equal(t, rules.Bypass, lookup(r, "203.0.113.1"))
}

func TestStreamConn_TunnelDialFailureFailsTheWrite(t *testing.T) {
	r := testRelay(t, &fakeExchanger{})
	conn := r.StreamConn(dnsAddr, func(context.Context) (transport.StreamConn, error) {
		return nil, errors.New("tunnel down")
	})
	_, err := conn.Write(dnstest.Frame(dnstest.Query(1, dnsmessage.TypeA, "example.com")))
	require.ErrorContains(t, err, "tunnel down")
	require.NoError(t, conn.Close())
	_, err = conn.Write([]byte{0})
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestStreamConn_CloseStopsReads(t *testing.T) {
	r := testRelay(t, &fakeExchanger{})
	conn := r.StreamConn(dnsAddr, nil)
	errc := make(chan error)
	go func() {
		_, err := conn.Read(make([]byte, 10))
		errc <- err
	}()
	require.NoError(t, conn.CloseRead())
	require.ErrorIs(t, <-errc, net.ErrClosed)
}

func TestPrefetch_RefreshesAt80PercentOfTheTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		direct := &fakeExchanger{answer: func(q []byte, overTCP bool) ([]byte, error) {
			if !overTCP {
				// A truncated UDP answer is retried over TCP.
				return dnstest.ReplyTo(q, dnstest.Options{Truncated: true}), nil
			}
			return dnstest.ReplyTo(q, dnstest.Options{},
				dnstest.RR{Name: "lichess.org", Addr: "192.0.2.1", TTL: 600},
				dnstest.RR{Name: "lichess.org", Addr: "192.0.2.2", TTL: 300},
			), nil
		}}
		r := testRelay(t, direct)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			r.Prefetch(ctx, []string{"lichess.org"})
			close(done)
		}()
		synctest.Wait()
		require.Equal(t, int32(2), direct.calls.Load()) // UDP, then TCP
		require.Equal(t, rules.Bypass, lookup(r, "192.0.2.1"))
		require.Equal(t, rules.Bypass, lookup(r, "192.0.2.2"))

		// The smallest TTL is 300 s, so the next lookup is at 240 s.
		time.Sleep(239 * time.Second)
		synctest.Wait()
		require.Equal(t, int32(2), direct.calls.Load())
		time.Sleep(time.Second)
		synctest.Wait()
		require.Equal(t, int32(4), direct.calls.Load())

		cancel()
		<-done
	})
}

func TestPrefetch_RetriesFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		direct := &fakeExchanger{answer: func(q []byte, _ bool) ([]byte, error) {
			return dnstest.ReplyTo(q, dnstest.Options{RCode: dnsmessage.RCodeNameError}), nil
		}}
		r := testRelay(t, direct)
		ctx, cancel := context.WithCancel(context.Background())
		go r.Prefetch(ctx, []string{"lichess.org", "cdn.example"})
		synctest.Wait()
		require.Equal(t, int32(2), direct.calls.Load())
		time.Sleep(prefetchRetry)
		synctest.Wait()
		require.Equal(t, int32(4), direct.calls.Load())
		cancel()
		synctest.Wait()
	})
}
