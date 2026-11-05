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

// Package dnsrelay handles the DNS queries that the system sends to the
// tunnel's DNS address (169.254.113.53), before the transport's own DNS
// interception sees them.
//
//   - Queries for bypass names are answered by the network's own resolvers,
//     over sockets bound to the physical interface, so content networks
//     answer with servers near the user. They never go through the tunnel: if
//     those resolvers fail, the app gets "server failure".
//   - Every other query goes through the tunnel unchanged.
//   - Every answer is read on the way back, and the addresses of listed
//     domains are remembered in an ipcache.Cache, which is how traffic to an
//     address is tied back to the rules.
package dnsrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"localhost/client/go/outline/macoscli/internal/ipcache"
	"localhost/client/go/outline/macoscli/internal/rules"

	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// Exchanger sends a DNS query and returns the response.
type Exchanger interface {
	Exchange(ctx context.Context, query []byte, overTCP bool) ([]byte, error)
}

// DefaultServerTimeout bounds one query to one resolver.
const DefaultServerTimeout = 3 * time.Second

// Direct queries resolvers over the given (interface-bound) dialers, trying
// each server in turn until one answers.
type Direct struct {
	Packet transport.PacketDialer
	Stream transport.StreamDialer
	// Servers returns the resolvers to try, in order.
	Servers func() []netip.AddrPort
	// Timeout bounds the query to one server; 0 means DefaultServerTimeout.
	Timeout time.Duration
}

// Exchange sends query to each server until one gives a usable response. A
// SERVFAIL or REFUSED response moves on to the next server.
func (d *Direct) Exchange(ctx context.Context, query []byte, overTCP bool) ([]byte, error) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = DefaultServerTimeout
	}
	servers := d.Servers()
	if len(servers) == 0 {
		return nil, errors.New("no direct resolver")
	}
	var errs []error
	for _, server := range servers {
		reply, err := d.exchangeOne(ctx, server, query, overTCP, timeout)
		if err == nil {
			switch rcode(reply) {
			case dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused:
				err = fmt.Errorf("answered %v", rcode(reply))
			default:
				return reply, nil
			}
		}
		errs = append(errs, fmt.Errorf("via %s: %w", server, err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func (d *Direct) exchangeOne(ctx context.Context, server netip.AddrPort, query []byte, overTCP bool, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var conn net.Conn
	var err error
	if overTCP {
		conn, err = d.Stream.DialStream(ctx, server.String())
	} else {
		conn, err = d.Packet.DialPacket(ctx, server.String())
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	// Unblock reads if ctx is canceled before the deadline.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if overTCP {
		return roundTripTCP(conn, query)
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore stray packets; a forged answer would also need the ID.
		if isResponseTo(buf[:n], query) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// roundTripTCP sends a query on a DNS-over-TCP connection and reads frames
// until the response to it arrives.
func roundTripTCP(conn net.Conn, query []byte) ([]byte, error) {
	if _, err := conn.Write(frame(query)); err != nil {
		return nil, err
	}
	var f Framer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		msgs, ferr := f.Push(buf[:n])
		for _, m := range msgs {
			if isResponseTo(m, query) {
				return m, nil
			}
		}
		if ferr != nil {
			return nil, ferr
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("closed without an answer")
			}
			return nil, err
		}
	}
}

// StreamExchanger sends each query over a new DNS-over-TCP connection from
// Dial, for example through the tunnel.
type StreamExchanger struct {
	Dial DialFunc
	// Timeout bounds one query; 0 means DefaultServerTimeout.
	Timeout time.Duration
}

// Exchange implements Exchanger. It always uses TCP.
func (s *StreamExchanger) Exchange(ctx context.Context, query []byte, _ bool) ([]byte, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = DefaultServerTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := s.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	reply, err := roundTripTCP(conn, query)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return reply, err
}

// Relay classifies queries, resolves bypass names directly and learns the
// addresses of listed domains from every answer.
type Relay struct {
	Rules *rules.Rules
	Cache *ipcache.Cache
	// Direct resolves bypass names without the tunnel.
	Direct Exchanger
	// OnLearn, if set, is called with the addresses each answer taught,
	// after the cache is updated and before the answer is passed on to the
	// app. So a route it adds for an address exists by the time the app
	// connects to it.
	OnLearn func(addrs []netip.Addr)
	Log     *slog.Logger

	lastFailureWarn atomic.Int64
}

// failureWarnInterval limits warnings about direct lookups that failed.
const failureWarnInterval = 30 * time.Second

func (r *Relay) log() *slog.Logger {
	if r.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return r.Log
}

// Decide returns where a query goes (see the package function).
func (r *Relay) Decide(query []byte) (Action, string) {
	return Decide(query, r.Rules)
}

// Learn records the listed domains' addresses from a DNS response, then
// calls OnLearn.
func (r *Relay) Learn(response []byte) {
	var addrs []netip.Addr
	for _, l := range Snoop(response, r.Rules) {
		r.Cache.Learn(l.Addr, l.Class, l.Domain, l.TTL)
		r.log().Debug("learned an address", "domain", l.Domain, "addr", l.Addr.String(), "class", l.Class.String(),
			"ttl", r.Cache.Clamp(l.TTL).String())
		if !slices.Contains(addrs, l.Addr) {
			addrs = append(addrs, l.Addr)
		}
	}
	if r.OnLearn != nil && len(addrs) > 0 {
		r.OnLearn(addrs)
	}
}

// ResolveDirect sends a query to the direct resolvers and learns from the
// answer. On failure the caller answers the app with ServFail: a bypass name
// never goes through the tunnel.
func (r *Relay) ResolveDirect(ctx context.Context, query []byte, overTCP bool) ([]byte, error) {
	reply, err := r.Direct.Exchange(ctx, query, overTCP)
	if err != nil {
		r.noteFailure(query, err)
		return nil, err
	}
	r.Learn(reply)
	return reply, nil
}

const directFailureMsg = "the network's DNS didn't answer for a bypass name, so the lookup failed (bypass names are never looked up through the VPN)"

func (r *Relay) noteFailure(query []byte, err error) {
	_, name := r.Decide(query)
	now := time.Now().UnixNano()
	last := r.lastFailureWarn.Load()
	if now-last >= int64(failureWarnInterval) && r.lastFailureWarn.CompareAndSwap(last, now) {
		r.log().Warn(directFailureMsg, "name", name, "err", err)
		return
	}
	r.log().Debug(directFailureMsg, "name", name, "err", err)
}
