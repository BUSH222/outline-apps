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
	"time"

	"localhost/client/go/outline/macoscli/internal/rules"

	"golang.getoutline.org/sdk/transport"
)

// DialFunc opens a TCP connection to the DNS address through the tunnel.
type DialFunc func(ctx context.Context) (transport.StreamConn, error)

// StreamConn returns the connection that an app's DNS-over-TCP connection to
// local is relayed to. It reads the app's queries from the stream:
//   - bypass queries go to the direct resolvers over TCP (or, if they fail,
//     through the tunnel);
//   - every other query goes through the tunnel, over one connection dialed
//     with dialTunnel when the first such query arrives.
//
// Replies are written back as they arrive, possibly out of order (allowed by
// RFC 7766; clients match them by ID), and learned from on the way.
func (r *Relay) StreamConn(local netip.AddrPort, dialTunnel DialFunc) transport.StreamConn {
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	return &streamConn{
		relay:      r,
		local:      local,
		dialTunnel: dialTunnel,
		ctx:        ctx,
		cancel:     cancel,
		pr:         pr,
		pw:         pw,
	}
}

type streamConn struct {
	relay      *Relay
	local      netip.AddrPort
	dialTunnel DialFunc
	ctx        context.Context
	cancel     context.CancelFunc

	// Replies to the app. Each reply is one Write, so replies never interleave.
	pr *io.PipeReader
	pw *io.PipeWriter

	// framer is only used by Write; the app's data arrives from one goroutine.
	framer Framer

	mu          sync.Mutex
	inner       transport.StreamConn
	writeClosed bool
	// pending counts direct queries in flight and the tunnel reader. Once the
	// app has closed its side and pending drops to zero, the reply stream ends.
	pending   sync.WaitGroup
	closeOnce sync.Once
}

var _ transport.StreamConn = (*streamConn)(nil)

// Write takes the app's queries.
func (c *streamConn) Write(p []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	msgs, err := c.framer.Push(p)
	for _, q := range msgs {
		if class, _ := c.relay.Classify(q); class == rules.Bypass {
			c.pending.Add(1)
			go c.resolveDirect(q)
			continue
		}
		if err := c.sendTunnel(q); err != nil {
			return 0, err
		}
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *streamConn) resolveDirect(q []byte) {
	defer c.pending.Done()
	reply, err := c.relay.ResolveDirect(c.ctx, q, true)
	if err != nil {
		if c.ctx.Err() == nil {
			c.sendTunnel(q)
		}
		return
	}
	c.writeReply(reply)
}

// sendTunnel sends a query through the tunnel, dialing it on first use.
func (c *streamConn) sendTunnel(q []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inner == nil {
		inner, err := c.dialTunnel(c.ctx)
		if err != nil {
			return err
		}
		c.inner = inner
		c.pending.Add(1)
		go c.readTunnel(inner)
	}
	if _, err := c.inner.Write(frame(q)); err != nil {
		return err
	}
	if c.writeClosed {
		// A late query (a direct lookup that fell back): the app has already
		// finished sending, so let the server finish too.
		c.inner.CloseWrite()
	}
	return nil
}

// readTunnel copies the tunnel's replies to the app until it closes.
func (c *streamConn) readTunnel(inner transport.StreamConn) {
	defer c.pending.Done()
	var f Framer
	buf := make([]byte, 4096)
	for {
		n, err := inner.Read(buf)
		msgs, ferr := f.Push(buf[:n])
		for _, m := range msgs {
			c.relay.Learn(m)
			c.writeReply(m)
		}
		if err != nil || ferr != nil {
			break
		}
	}
	inner.Close()
	c.mu.Lock()
	if c.inner == inner {
		// Dial again for the next query, if any.
		c.inner = nil
	}
	c.mu.Unlock()
}

func (c *streamConn) writeReply(msg []byte) {
	c.pw.Write(frame(msg))
}

// Read returns the replies.
func (c *streamConn) Read(p []byte) (int, error) {
	return c.pr.Read(p)
}

// CloseWrite: the app has sent all its queries. The replies still in flight
// are delivered, then Read returns io.EOF.
func (c *streamConn) CloseWrite() error {
	c.mu.Lock()
	if c.writeClosed {
		c.mu.Unlock()
		return nil
	}
	c.writeClosed = true
	if c.inner != nil {
		c.inner.CloseWrite()
	}
	c.mu.Unlock()
	go func() {
		c.pending.Wait()
		c.pw.Close()
	}()
	return nil
}

// CloseRead: nobody reads the replies any more, so everything stops.
func (c *streamConn) CloseRead() error {
	return c.Close()
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		// Pending and later reads return net.ErrClosed; reply writes fail.
		c.pw.CloseWithError(net.ErrClosed)
		c.mu.Lock()
		if c.inner != nil {
			c.inner.Close()
		}
		c.mu.Unlock()
	})
	return nil
}

func (c *streamConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero}
}

func (c *streamConn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(c.local)
}

// Deadlines aren't supported; lwIP's relay doesn't use them.
func (c *streamConn) SetDeadline(time.Time) error      { return errNoDeadlines }
func (c *streamConn) SetReadDeadline(time.Time) error  { return errNoDeadlines }
func (c *streamConn) SetWriteDeadline(time.Time) error { return errNoDeadlines }

var errNoDeadlines = errors.New("deadlines are not supported on the DNS relay connection")
