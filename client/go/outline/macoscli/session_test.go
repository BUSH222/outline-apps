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
	"strings"
	"sync"
	"testing"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/fakemac"
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
