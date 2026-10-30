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
	"os"
	"strings"
	"sync"
	"testing"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/fakemac"
	"localhost/client/go/outline/macoscli/internal/lockdown"
	"localhost/client/go/outline/macoscli/internal/rules"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysexec"

	"golang.getoutline.org/sdk/transport"

	"github.com/stretchr/testify/require"
)

const vpnOnlyRules = "vpn_only: [secret.example]\n"

// lockdownEnv is a root environment on a simulated Mac with its own hosts
// file, shared by every command a test runs.
func lockdownEnv(t *testing.T, mac *fakemac.Mac) env {
	return env{
		exec:      mac.Executor(),
		stateDir:  t.TempDir(),
		hostsPath: testHostsFile(t),
		geteuid:   func() int { return 0 },
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func TestLockdown_NeedsRootAndVPNOnlyEntries(t *testing.T) {
	mac := fakemac.New()
	e := lockdownEnv(t, mac)
	e.geteuid = func() int { return 501 }
	r := runCLI(t, e, "lockdown", "--rules", writeRules(t, vpnOnlyRules))
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "must run as root")

	e.geteuid = func() int { return 0 }
	r = runCLI(t, e, "lockdown", "--rules", writeRules(t, "bypass: [lichess.org]\n"))
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "no vpn_only entries")

	require.Equal(t, testHostsContent, readFile(t, e.hostsPath))
	require.Empty(t, mac.PFAnchor(lockdown.Anchor))
}

func TestLockdownThenUnlock(t *testing.T) {
	mac := fakemac.New()
	baseline := mac.Snapshot()
	e := lockdownEnv(t, mac)

	r := runCLI(t, e, "lockdown", "--rules", writeRules(t, "vpn_only: [secret.example, \"*.wild.example\"]\n"))
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "lockdown is on")
	require.Contains(t, r.stdout, "No addresses are known yet")
	require.Contains(t, readFile(t, e.hostsPath), "0.0.0.0 secret.example\n:: secret.example\n")
	require.Contains(t, mac.PFAnchor(lockdown.Anchor), "block drop out quick from any to <outline_vpn_only>")
	enabled, _ := mac.PFEnabled()
	require.True(t, enabled)

	// Running it again refreshes; it doesn't take a second pf reference.
	r = runCLI(t, e, "lockdown", "--rules", writeRules(t, vpnOnlyRules))
	require.Equal(t, exitOK, r.code, r.stderr)
	_, refs := mac.PFEnabled()
	require.Equal(t, 1, refs)

	r = runCLI(t, e, "unlock")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "lockdown is off")
	require.Equal(t, testHostsContent, readFile(t, e.hostsPath))
	require.Equal(t, baseline, mac.Snapshot())

	r = runCLI(t, e, "unlock")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "lockdown is not on")
}

func TestLockdown_RefusedWhileConnected(t *testing.T) {
	mac := fakemac.New()
	e := lockdownEnv(t, mac)
	unlock, err := state.FileStore{Dir: e.stateDir}.Lock()
	require.NoError(t, err)
	defer unlock()
	for _, cmd := range []string{"lockdown", "unlock"} {
		r := runCLI(t, e, cmd, "--rules", writeRules(t, vpnOnlyRules))
		if cmd == "unlock" {
			r = runCLI(t, e, cmd)
		}
		require.Equal(t, exitError, r.code, cmd)
		require.Contains(t, r.stderr, "disconnect first", cmd)
	}
	require.Equal(t, testHostsContent, readFile(t, e.hostsPath))
}

func TestLockdown_DryRun(t *testing.T) {
	mac := fakemac.New()
	e := lockdownEnv(t, mac)
	e.geteuid = func() int { return 501 }
	exec := e.exec.(*sysexec.Fake)
	r := runCLI(t, e, "lockdown", "--dry-run", "--rules", writeRules(t, vpnOnlyRules))
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "nothing will be changed")
	require.Contains(t, r.stdout, "    0.0.0.0 secret.example\n")
	require.Contains(t, r.stdout, "    block drop out quick from any to <outline_vpn_only>\n")
	require.Empty(t, exec.Calls(), "a dry run runs nothing, not even read-only pf queries")
	require.Equal(t, testHostsContent, readFile(t, e.hostsPath))
}

// connectedView records the hosts file and the pf anchor at the moment the
// CLI reports it is connected, then disconnects.
type connectedView struct {
	cancel    context.CancelFunc
	hostsPath string
	mac       *fakemac.Mac

	once         sync.Once
	hosts, rules string
}

func (c *connectedView) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "connected:") {
		c.once.Do(func() {
			data, _ := os.ReadFile(c.hostsPath)
			c.hosts, c.rules = string(data), c.mac.PFAnchor(lockdown.Anchor)
			c.cancel()
		})
	}
	return len(p), nil
}

func TestConnect_WithLockdown(t *testing.T) {
	mac := fakemac.New()
	e := lockdownEnv(t, mac)
	rulesFile := writeRules(t, vpnOnlyRules)
	r := runCLI(t, e, "lockdown", "--rules", rulesFile)
	require.Equal(t, exitOK, r.code, r.stderr)
	locked := mac.Snapshot()
	lockedHosts := readFile(t, e.hostsPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	view := &connectedView{cancel: cancel, hostsPath: e.hostsPath, mac: mac}
	e.stdout = view
	r = runCLIContext(t, ctx, e, "connect", "--key", fakeSSKey, "--rules", rulesFile)
	require.Equal(t, exitOK, r.code, r.stderr)

	// While connected: the names resolve, and their addresses pass through the utun.
	require.Equal(t, testHostsContent, view.hosts)
	require.Contains(t, view.rules, "pass out quick on utunN from any to <outline_vpn_only>")
	require.Contains(t, r.stderr, "vpn_only domains are reachable through the tunnel")
	// After disconnecting: blocked again, exactly as before connecting.
	require.Equal(t, lockedHosts, readFile(t, e.hostsPath))
	require.Equal(t, locked, mac.Snapshot())
	requireNoSecrets(t, r)
}

func TestCleanup_ReinstallsTheLockdown(t *testing.T) {
	mac := fakemac.New()
	e := lockdownEnv(t, mac)
	r := runCLI(t, e, "lockdown", "--rules", writeRules(t, vpnOnlyRules))
	require.Equal(t, exitOK, r.code, r.stderr)
	lockedHosts := readFile(t, e.hostsPath)

	// A session crashed while connected (hosts block removed), then the Mac
	// rebooted (pf disabled, rules gone).
	require.NoError(t, e.lockdownManager(nil).Connected(context.Background(), "utun9"))
	require.Equal(t, testHostsContent, readFile(t, e.hostsPath))
	mac.Reboot()

	r = runCLI(t, e, "cleanup")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "lockdown re-installed: secret.example are blocked")
	require.Equal(t, lockedHosts, readFile(t, e.hostsPath))
	enabled, _ := mac.PFEnabled()
	require.True(t, enabled)
	require.NotContains(t, mac.PFAnchor(lockdown.Anchor), "pass out")
	require.Contains(t, mac.PFAnchor(lockdown.Anchor), "block drop out quick")
}

func TestConnect_RecoveringACrashReinstallsTheLockdown(t *testing.T) {
	mac := fakemac.New()
	e := lockdownEnv(t, mac)
	r := runCLI(t, e, "lockdown", "--rules", writeRules(t, vpnOnlyRules))
	require.Equal(t, exitOK, r.code, r.stderr)
	lockedHosts := readFile(t, e.hostsPath)
	require.NoError(t, e.lockdownManager(nil).Connected(context.Background(), "utun9"))
	leaveCrashedSession(t, mac, e.stateDir)

	// The next connect fails after recovering (no key): the block is back.
	r = runCLI(t, e, "connect", "--key", "")
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "restored the network left behind")
	require.Equal(t, lockedHosts, readFile(t, e.hostsPath))
}

func TestCheckVPNOnlyTransport(t *testing.T) {
	pair := func(tcp, udp configregistry.ConnType) *configregistry.TransportPair {
		return &configregistry.TransportPair{
			StreamDialer: &configregistry.Dialer[transport.StreamConn]{ConnectionProviderInfo: configregistry.ConnectionProviderInfo{ConnType: tcp}},
			PacketRelay:  &configregistry.PacketRelay{ConnectionProviderInfo: configregistry.ConnectionProviderInfo{ConnType: udp}},
		}
	}
	withVPNOnly, err := rules.Parse([]byte(vpnOnlyRules))
	require.NoError(t, err)
	tunneled, partial := configregistry.ConnTypeTunneled, configregistry.ConnTypePartial

	require.NoError(t, checkVPNOnlyTransport(pair(tunneled, tunneled), withVPNOnly))
	require.NoError(t, checkVPNOnlyTransport(pair(partial, tunneled), rules.Empty()), "no vpn_only entries, no constraint")
	err = checkVPNOnlyTransport(pair(partial, tunneled), withVPNOnly)
	require.ErrorContains(t, err, "TCP partial, UDP tunneled")
	require.ErrorContains(t, checkVPNOnlyTransport(pair(tunneled, partial), withVPNOnly), "doesn't send everything through the server")
}
