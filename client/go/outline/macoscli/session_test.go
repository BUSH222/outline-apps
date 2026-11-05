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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/fakemac"
	"localhost/client/go/outline/macoscli/internal/ipcache"
	"localhost/client/go/outline/macoscli/internal/rules"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/tunnel"

	"github.com/stretchr/testify/require"
)

// cancelOnConnected cancels ctx once the CLI reports it is connected, which
// simulates pressing Ctrl-C right after connecting.
type cancelOnConnected struct {
	once   sync.Once
	cancel context.CancelFunc
}

func (c *cancelOnConnected) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "connected:") {
		c.once.Do(c.cancel)
	}
	return len(p), nil
}

// sessionEnv returns a root environment on a simulated Mac.
func sessionEnv(t *testing.T, mac *fakemac.Mac) (env, context.Context) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return env{
		exec:     mac.Executor(),
		stateDir: t.TempDir(),
		geteuid:  func() int { return 0 },
		stdout:   &cancelOnConnected{cancel: cancel},
	}, ctx
}

func TestConnect_UpThenCtrlCRestoresEverything(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)

	var boundTo []string
	// Record the bind and refuse the socket, so the test never sends
	// anything over the real network.
	e.bind = func(_ uintptr, network string, ifIndex int) error {
		boundTo = append(boundTo, network)
		return errors.New("test: no real sockets")
	}
	var transportTUN string
	stopped := false
	e.startTransport = func(ctx context.Context, tun tunnel.TUN, pair *configregistry.TransportPair, _ *slog.Logger) (func(), error) {
		transportTUN = tun.Name()
		// The transport is built on bound sockets: dialing through it must go
		// through the binder (which refuses the socket in this test).
		_, err := pair.StreamDialer.Dial(ctx, "127.0.0.1:1")
		require.ErrorContains(t, err, "test: no real sockets")
		// Nothing has been routed into the tunnel yet.
		_, routed := mac.HasRoute("0.0.0.0/1")
		require.False(t, routed, "routes must not change before the transport is healthy")
		return func() { stopped = true }, nil
	}

	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "connected: traffic goes through the tunnel (bound to en0)")
	require.Contains(t, r.stdout, "disconnected: routes, DNS and IPv6 are restored")
	require.Equal(t, "utunN", transportTUN)
	require.True(t, stopped)
	require.NotEmpty(t, boundTo, "the transport's sockets must be bound")
	for _, n := range boundTo {
		require.Equal(t, "tcp4", n)
	}
	require.Equal(t, baseline, mac.Snapshot())
	st, err := state.FileStore{Dir: e.stateDir}.Load()
	require.NoError(t, err)
	require.Nil(t, st)
	requireNoSecrets(t, r)
}

func TestConnect_RecoversACrashedSessionBeforeFetchingTheKey(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)
	leaveCrashedSession(t, mac, e.stateDir)

	fetchedOnCleanNetwork := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchedOnCleanNetwork = mac.Snapshot().DNS["Wi-Fi"] == "DHCP"
		w.Write([]byte(fakeDynamicConfig))
	}))
	defer server.Close()
	e.httpTransport = server.Client().Transport

	r := runCLIContext(t, ctx, e, "connect", "--key", server.URL+"/FAKE-path")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "restored the network left behind by a previous session")
	require.True(t, fetchedOnCleanNetwork, "the key must be fetched after the old session is undone")
	require.Equal(t, baseline, mac.Snapshot())
	requireNoSecrets(t, r)
}

func TestConnect_UnhealthyTransportChangesNothing(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)
	e.startTransport = func(context.Context, tunnel.TUN, *configregistry.TransportPair, *slog.Logger) (func(), error) {
		return nil, errors.New("the server can't be reached over TCP")
	}
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no routes were changed")
	require.Equal(t, baseline, mac.Snapshot())
}

func TestConnect_UnknownInterfaceAbortsBeforeAnyChange(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)
	e.interfaceIndex = func(string) (int, error) { return 0, errors.New("no such interface") }
	started := false
	e.startTransport = func(context.Context, tunnel.TUN, *configregistry.TransportPair, *slog.Logger) (func(), error) {
		started = true
		return func() {}, nil
	}
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no such interface")
	require.False(t, started, "the transport must not start with unbound sockets")
	require.Equal(t, baseline, mac.Snapshot())
}

func TestConnect_RefusesASecondInstance(t *testing.T) {
	mac := fakemac.New()
	e, ctx := sessionEnv(t, mac)
	unlock, err := state.FileStore{Dir: e.stateDir}.Lock()
	require.NoError(t, err)
	defer unlock()
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "another outline-cli session is running")
}

func TestConnect_RefusesLoopingConfigBeforeChangingAnything(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)
	r := runCLIContext(t, ctx, e, "connect", "--key", `{"transport": {"$type": "basic-access"}}`)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "loop back into the tunnel")
	require.Equal(t, baseline, mac.Snapshot())
}

func TestConnect_FailedVerificationRestoresTheNetwork(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)
	e.verify = func(verifyInput) func(context.Context) error {
		return func(context.Context) error {
			return errors.New("check 2/2 failed: DNS at 169.254.113.53 doesn't answer")
		}
	}
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "every change was rolled back")
	require.Contains(t, r.stderr, "169.254.113.53 doesn't answer")
	require.NotContains(t, r.stdout, "connected:")
	require.Equal(t, baseline, mac.Snapshot())
}

func writeRules(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// dnsDialErr dials the tunnel's DNS address over TCP through pair. Without
// domain rules that goes to the transport, whose sockets the test refuses;
// with them, the DNS relay takes the connection without opening any socket.
func dnsDialErr(pair *configregistry.TransportPair) error {
	conn, err := pair.StreamDialer.Dial(context.Background(), "169.254.113.53:53")
	if err == nil {
		conn.Close()
	}
	return err
}

func TestConnect_DomainRulesWrapTheTransport(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)
	var transportErr, verifyErr error
	var verifyPair *configregistry.TransportPair
	e.startTransport = func(_ context.Context, _ tunnel.TUN, pair *configregistry.TransportPair, _ *slog.Logger) (func(), error) {
		transportErr = dnsDialErr(pair)
		// The rules keep the transport's own type and first hop.
		require.Equal(t, configregistry.ConnTypeTunneled, pair.StreamDialer.ConnType)
		require.Equal(t, "192.0.2.10:8388", pair.StreamDialer.FirstHop)
		return func() {}, nil
	}
	e.verify = func(in verifyInput) func(context.Context) error {
		return func(context.Context) error {
			verifyPair = in.pair
			verifyErr = dnsDialErr(in.pair)
			return nil
		}
	}
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey, "--rules", writeRules(t, "bypass: [lichess.org]\n"))
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "domain rules are on")
	require.NoError(t, transportErr, "lwIP gets the router, which relays DNS itself")
	require.NotNil(t, verifyPair)
	require.ErrorContains(t, verifyErr, "test: no real sockets", "the checks use the bare transport")
	require.Equal(t, baseline, mac.Snapshot())
	requireNoSecrets(t, r)
}

func TestConnect_NoRulesKeepsTheBareTransport(t *testing.T) {
	mac := fakemac.New()
	e, ctx := sessionEnv(t, mac)
	var transportErr error
	e.startTransport = func(_ context.Context, _ tunnel.TUN, pair *configregistry.TransportPair, _ *slog.Logger) (func(), error) {
		transportErr = dnsDialErr(pair)
		return func() {}, nil
	}
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey, "--rules", writeRules(t, "bypass: []\n"))
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stderr, "domain rules are on")
	require.ErrorContains(t, transportErr, "test: no real sockets")
}

func TestConnect_InvalidRulesChangeNothing(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e, ctx := sessionEnv(t, mac)
	started := false
	e.startTransport = func(context.Context, tunnel.TUN, *configregistry.TransportPair, *slog.Logger) (func(), error) {
		started = true
		return func() {}, nil
	}
	r := runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey, "--rules", writeRules(t, "bypass: [https://lichess.org/]\n"))
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "not a domain name")
	require.False(t, started)
	require.Equal(t, baseline, mac.Snapshot())
}

// fakeDirectRouter records route changes.
type fakeDirectRouter struct {
	routed, unrouted []string
	err              error
}

func (f *fakeDirectRouter) RouteDirect(_ context.Context, a netip.Addr) error {
	f.routed = append(f.routed, a.String())
	return f.err
}

func (f *fakeDirectRouter) UnrouteDirect(_ context.Context, a netip.Addr) error {
	f.unrouted = append(f.unrouted, a.String())
	return f.err
}

func TestSyncDirectRoutes(t *testing.T) {
	cache := ipcache.New(time.Minute, time.Hour, nil)
	bypass, vpnOnly, shared, unknown := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")
	cache.Learn(bypass, rules.Bypass, "lichess.org", time.Hour)
	cache.Learn(vpnOnly, rules.VPNOnly, "secret.example", time.Hour)
	cache.Learn(shared, rules.Bypass, "cdn.example", time.Hour)
	cache.Learn(shared, rules.VPNOnly, "secret.example", time.Hour)

	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))
	r := &fakeDirectRouter{}
	syncDirectRoutes(r, cache, []netip.Addr{bypass, vpnOnly, shared, unknown}, log)
	require.Equal(t, []string{"192.0.2.1"}, r.routed)
	require.Equal(t, []string{"192.0.2.2", "192.0.2.3", "192.0.2.4"}, r.unrouted, "vpn_only wins for a shared address")
	require.Empty(t, logs.String())

	r.err = errors.New("route: injected")
	syncDirectRoutes(r, cache, []netip.Addr{bypass}, log)
	require.Contains(t, logs.String(), "updating the direct route of an address failed")
}

func TestVPNOnlyAddrs(t *testing.T) {
	cache := ipcache.New(time.Minute, time.Hour, nil)
	vpnOnly, bypass := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1")
	cache.Learn(vpnOnly, rules.VPNOnly, "secret.example", time.Hour)
	cache.Learn(bypass, rules.Bypass, "lichess.org", time.Hour)
	require.Equal(t, map[netip.Addr]string{vpnOnly: "secret.example"}, vpnOnlyAddrs(cache, []netip.Addr{vpnOnly, bypass}))
	require.Nil(t, vpnOnlyAddrs(cache, []netip.Addr{bypass}))
}
