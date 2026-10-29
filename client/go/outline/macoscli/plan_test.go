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
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"localhost/client/go/outline/macoscli/internal/fakemac"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
	"localhost/client/go/outline/macoscli/internal/tunnel"

	"github.com/stretchr/testify/require"
)

// A fake config whose server is a host name, to exercise first-hop lookup.
const fakeHostnameConfig = `
transport:
  $type: tcpudp
  tcp: {$type: shadowsocks, endpoint: "server.example.test:443", cipher: chacha20-ietf-poly1305, secret: FAKE-host-secret}
  udp: {$type: shadowsocks, endpoint: "server.example.test:443", cipher: chacha20-ietf-poly1305, secret: FAKE-host-secret}
`

// A Mac whose every change fails the test: dry runs must only read.
func readOnlyMac(t *testing.T) (*fakemac.Mac, sysexec.Executor) {
	mac := fakemac.New()
	mac.BeforeMutation = func(_ int, c sysexec.Call) error {
		t.Errorf("a dry run changed the system: %s", c)
		return errors.New("forbidden")
	}
	return mac, mac.Executor()
}

func TestDryRun_PrintsConnectAndDisconnectPlan(t *testing.T) {
	mac, exec := readOnlyMac(t)
	before := mac.Snapshot()
	r := runCLI(t, env{exec: exec}, "connect", "--dry-run", "--key", fakeSSKey)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "first hop IPs:   192.0.2.10\n")
	require.Contains(t, r.stdout, "(none; nothing to recover)")
	require.Contains(t, r.stdout, "  connect would run (utunN is the utun macOS assigns):\n")
	require.Contains(t, r.stdout, "    ifconfig utunN inet 10.111.222.1 10.111.222.2 netmask 255.255.255.255 mtu 1500 up\n")
	require.Contains(t, r.stdout, "    route -n add -net 0.0.0.0/1 -interface utunN\n")
	require.Contains(t, r.stdout, "    networksetup -setdnsservers Wi-Fi 169.254.113.53\n")
	require.Contains(t, r.stdout, "    networksetup -setv6off Wi-Fi\n")
	require.Contains(t, r.stdout, "  disconnect would run:\n")
	require.Contains(t, r.stdout, "    networksetup -setdnsservers Wi-Fi empty\n")
	require.Contains(t, r.stdout, "    route -n delete -net 0.0.0.0/1 -interface utunN\n")
	require.NotContains(t, r.stdout, "169.254.0.0/16", "the existing link-local route is left alone")
	require.NotContains(t, r.stderr, "tunnel is up", "a dry run must not claim the tunnel is up")
	require.Equal(t, before, mac.Snapshot())
	requireNoSecrets(t, r)
}

func TestDryRun_ResolvesHostNameFirstHop(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(fakeHostnameConfig), 0o600))
	_, exec := readOnlyMac(t)
	var looked []string
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		looked = append(looked, host)
		return []netip.Addr{netip.MustParseAddr("2001:db8::7"), netip.MustParseAddr("100.200.0.10")}, nil
	}
	r := runCLI(t, env{exec: exec, lookup: lookup}, "connect", "--dry-run", "--key", cfg)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Equal(t, []string{"server.example.test"}, looked, "TCP and UDP share one first hop")
	require.Contains(t, r.stdout, "first hop IPs:   100.200.0.10\n")
	require.Contains(t, r.stdout, "    route -n add -host 100.200.0.10 192.168.1.1\n")
	requireNoSecrets(t, r)
}

func TestDryRun_RefusesIPv6OnlyServer(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(fakeHostnameConfig), 0o600))
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::7")}, nil
	}
	r := runCLI(t, env{lookup: lookup}, "connect", "--dry-run", "--key", cfg)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "IPv6-only servers are not supported")
}

func TestDryRun_ReportsLeftoverState(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, state.FileStore{Dir: dir}.Save(&state.State{Version: state.CurrentVersion, PID: 99, Service: "Wi-Fi"}))
	r := runCLI(t, env{stateDir: dir}, "connect", "--dry-run", "--key", fakeSSKey)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "a real connect restores it first")
}

func TestDryRun_Offline(t *testing.T) {
	mac := fakemac.New()
	mac.GoOffline()
	r := runCLI(t, env{exec: mac.Executor()}, "connect", "--dry-run", "--key", fakeSSKey)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no default route")
}

// leaveCrashedSession connects with the fake Mac and abandons the session, as
// if the process had been killed: the kernel drops the utun, the state stays.
func leaveCrashedSession(t *testing.T, mac *fakemac.Mac, dir string) {
	t.Helper()
	_, err := tunnel.Up(context.Background(), tunnel.Options{
		Router:  &sysrouter.Router{Exec: mac.Executor()},
		Store:   state.FileStore{Dir: dir},
		OpenTUN: func() (tunnel.TUN, error) { return placeholderTUN{}, nil },
		StartTransport: func(context.Context, tunnel.TUN) (func(), error) {
			return func() {}, nil
		},
		LocalPrefixes: func() ([]netip.Prefix, error) { return nil, nil },
	})
	require.NoError(t, err)
	mac.DestroyUTun("utunN")
}

func TestCleanup_RequiresRoot(t *testing.T) {
	r := runCLI(t, env{geteuid: func() int { return 501 }}, "cleanup")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "must run as root")
}

func TestCleanup_NothingToDo(t *testing.T) {
	r := runCLI(t, env{geteuid: func() int { return 0 }}, "cleanup")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "nothing to clean up")
	r = runCLI(t, env{}, "cleanup", "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "nothing to clean up")
}

func TestCleanup_RestoresCrashedSession(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	dir := t.TempDir()
	leaveCrashedSession(t, mac, dir)
	require.NotEqual(t, baseline, mac.Snapshot())

	// The dry run lists the restore and changes nothing.
	snap := mac.Snapshot()
	r := runCLI(t, env{exec: mac.Executor(), stateDir: dir}, "cleanup", "--dry-run")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "    networksetup -setdnsservers Wi-Fi empty\n")
	require.Contains(t, r.stdout, "    networksetup -setv6automatic Wi-Fi\n")
	require.Contains(t, r.stdout, "    route -n delete -net 10.0.0.0/8 192.168.1.1\n")
	require.Equal(t, snap, mac.Snapshot())

	r = runCLI(t, env{exec: mac.Executor(), stateDir: dir, geteuid: func() int { return 0 }}, "cleanup")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "restored the network")
	require.Equal(t, baseline, mac.Snapshot())
	st, err := state.FileStore{Dir: dir}.Load()
	require.NoError(t, err)
	require.Nil(t, st)
}

func TestCleanup_RefusesWhileRunning(t *testing.T) {
	dir := t.TempDir()
	unlock, err := state.FileStore{Dir: dir}.Lock()
	require.NoError(t, err)
	defer unlock()
	r := runCLI(t, env{stateDir: dir, geteuid: func() int { return 0 }}, "cleanup")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "still running")
}

func TestCleanup_UnreadableStateWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	dir := t.TempDir()
	require.NoError(t, state.FileStore{Dir: dir}.Save(&state.State{Version: state.CurrentVersion}))
	require.NoError(t, os.Chmod(state.FileStore{Dir: dir}.Path(), 0o000))
	r := runCLI(t, env{stateDir: dir}, "cleanup", "--dry-run")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "sudo outline-cli cleanup --dry-run")
}
