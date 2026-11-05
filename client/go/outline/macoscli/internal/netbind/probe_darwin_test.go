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

//go:build darwin

package netbind

// These probes check, without root and without changing anything, that
// IP_BOUND_IF really scopes sockets (assumptions N1 and N2 in
// docs/macos-cli/FINDINGS.md). Sockets are bound to the loopback interface:
// loopback destinations must work, and a TEST-NET destination (192.0.2.1,
// never routed) must fail with "no route" instead of leaving through the real
// network. Every operation has a short deadline, so nothing can hang.

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	probeTimeout = 2 * time.Second
	testNet      = "192.0.2.1:9"
)

func loopbackBinder(t *testing.T) *Binder {
	t.Helper()
	b := New()
	require.NoError(t, b.SetInterface("lo0"))
	return b
}

func probeCtx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), probeTimeout)
	t.Cleanup(cancel)
	return c
}

// isNoRoute reports whether err means the kernel found no route in the
// socket's interface scope.
func isNoRoute(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EADDRNOTAVAIL)
}

func TestProbe_TCPBoundToLoopback(t *testing.T) {
	b := loopbackBinder(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	conn, err := b.StreamDialer().DialStream(probeCtx(t), l.Addr().String())
	require.NoError(t, err, "a socket bound to lo0 must reach loopback")
	conn.Close()

	start := time.Now()
	_, err = b.StreamDialer().DialStream(probeCtx(t), testNet)
	require.Error(t, err)
	require.True(t, isNoRoute(err), "N1: a socket bound to lo0 must get 'no route' for %s, got: %v (after %v)", testNet, err, time.Since(start))
}

func TestProbe_UDPBoundToLoopback(t *testing.T) {
	b := loopbackBinder(t)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()

	conn, err := b.PacketDialer().DialPacket(probeCtx(t), server.LocalAddr().String())
	require.NoError(t, err)
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	server.SetReadDeadline(time.Now().Add(probeTimeout))
	buf := make([]byte, 16)
	n, _, err := server.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))
	conn.Close()

	listener, err := b.PacketListener().ListenPacket(probeCtx(t))
	require.NoError(t, err)
	defer listener.Close()
	listener.SetWriteDeadline(time.Now().Add(probeTimeout))
	_, err = listener.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9})
	require.True(t, isNoRoute(err), "N1: a bound UDP listener must get 'no route' for %s, got: %v", testNet, err)

	dialed, err := b.PacketDialer().DialPacket(probeCtx(t), testNet)
	if err == nil {
		dialed.SetWriteDeadline(time.Now().Add(probeTimeout))
		_, err = dialed.Write([]byte("x"))
		dialed.Close()
	}
	require.True(t, isNoRoute(err), "N1: a bound UDP dial must get 'no route' for %s, got: %v", testNet, err)
}

// TestProbe_DualStackSocket records whether IPV6_BOUND_IF on a dual-stack
// AF_INET6 socket also scopes IPv4-mapped traffic (N2). The CLI doesn't rely
// on it (all its sockets are IPv4), so the result is logged, not asserted.
func TestProbe_DualStackSocket(t *testing.T) {
	lo0, err := net.InterfaceByName("lo0")
	require.NoError(t, err)
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	require.NoError(t, unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0))
	require.NoError(t, platformBind(uintptr(fd), "udp6", lo0.Index))
	require.NoError(t, unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 2}))

	// 192.0.2.1 as an IPv4-mapped IPv6 address.
	mapped := &unix.SockaddrInet6{Port: 9, Addr: [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 1}}
	err = unix.Sendto(fd, []byte("x"), 0, mapped)
	if isNoRoute(err) {
		t.Logf("N2 holds: IPV6_BOUND_IF scopes IPv4-mapped traffic (%v)", err)
	} else {
		t.Logf("N2 does NOT hold: IPv4-mapped send on a dual-stack socket bound with IPV6_BOUND_IF returned %v; the CLI only uses IPv4 sockets, so it is unaffected", err)
	}
}
