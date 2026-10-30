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

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.getoutline.org/sdk/transport"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/stretchr/testify/require"
)

// whoamiDialer answers DNS-over-TCP queries in memory with a TXT record
// holding addr, as 1.1.1.1 answers "whoami.cloudflare". No socket is opened.
func whoamiDialer(t *testing.T, addr string) transport.StreamDialer {
	return transport.FuncStreamDialer(func(ctx context.Context, dst string) (transport.StreamConn, error) {
		require.Equal(t, egressResolver.String(), dst)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var size [2]byte
			if _, err := io.ReadFull(server, size[:]); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(query)
			if err != nil {
				return
			}
			q, err := p.Question()
			if err != nil {
				return
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			b.TXTResource(dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class}, dnsmessage.TXTResource{TXT: []string{addr}})
			msg, _ := b.Finish()
			server.Write(binary.BigEndian.AppendUint16(nil, uint16(len(msg))))
			server.Write(msg)
		}()
		return pipeConn{client}, nil
	})
}

// pipeConn adds the half-close methods of a StreamConn to a net.Pipe end.
type pipeConn struct{ net.Conn }

func (c pipeConn) CloseRead() error  { return nil }
func (c pipeConn) CloseWrite() error { return nil }

func failingDialer(err error) transport.StreamDialer {
	return transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
		return nil, err
	})
}

func logTo(sb *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(sb, nil))
}

func TestCheckDirectPath(t *testing.T) {
	ctx := context.Background()
	// Documentation addresses: the Mac's own public address and the server's.
	own, server := "198.51.100.7", "203.0.113.9"

	t.Run("bound socket skips the tunnel", func(t *testing.T) {
		var logs strings.Builder
		checkDirectPath(ctx, whoamiDialer(t, own), whoamiDialer(t, server), nil, logTo(&logs))
		require.Contains(t, logs.String(), "check 3/3 (informational) passed")
		// Public addresses are never logged.
		require.NotContains(t, logs.String(), own)
		require.NotContains(t, logs.String(), server)
	})
	t.Run("bound socket enters the tunnel", func(t *testing.T) {
		var logs strings.Builder
		checkDirectPath(ctx, whoamiDialer(t, server), whoamiDialer(t, server), nil, logTo(&logs))
		require.Contains(t, logs.String(), "went through the tunnel")
		require.Contains(t, logs.String(), "level=WARN")
		require.NotContains(t, logs.String(), server)
	})
	t.Run("bound socket fails", func(t *testing.T) {
		var logs strings.Builder
		checkDirectPath(ctx, failingDialer(errors.New("network is unreachable")), whoamiDialer(t, server), nil, logTo(&logs))
		require.Contains(t, logs.String(), "can't reach an address that has no host route")
		require.Contains(t, logs.String(), "network is unreachable")
	})
	t.Run("tunnel fails", func(t *testing.T) {
		var logs strings.Builder
		checkDirectPath(ctx, whoamiDialer(t, own), failingDialer(errors.New("tunnel down")), nil, logTo(&logs))
		require.Contains(t, logs.String(), "inconclusive")
	})
	t.Run("probe address is the server", func(t *testing.T) {
		var logs strings.Builder
		dialed := false
		d := transport.FuncStreamDialer(func(context.Context, string) (transport.StreamConn, error) {
			dialed = true
			return nil, errors.New("unexpected")
		})
		checkDirectPath(ctx, d, d, []netip.Addr{egressResolver.Addr()}, logTo(&logs))
		require.Contains(t, logs.String(), "skipped")
		require.False(t, dialed)
	})
}
