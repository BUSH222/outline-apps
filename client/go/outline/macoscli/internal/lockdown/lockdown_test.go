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

package lockdown

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localhost/client/go/outline/macoscli/internal/fakemac"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"

	"github.com/stretchr/testify/require"
)

// Documentation addresses and names only.
var (
	addrA  = netip.MustParseAddr("192.0.2.1")
	addrB  = netip.MustParseAddr("2001:db8::1")
	server = netip.MustParseAddr("198.51.100.10")
)

func TestAnchorRules(t *testing.T) {
	require.Equal(t, `# Managed by outline-cli. Remove with: sudo outline-cli unlock
table <outline_vpn_only> persist
block drop out quick from any to <outline_vpn_only>
`, AnchorRules(nil, ""))

	require.Equal(t, `# Managed by outline-cli. Remove with: sudo outline-cli unlock
table <outline_vpn_only> persist { 192.0.2.1, 2001:db8::1 }
pass out quick on utun4 from any to <outline_vpn_only>
block drop out quick from any to <outline_vpn_only>
`, AnchorRules([]netip.Addr{addrA, addrB}, "utun4"))
}

func TestParseToken(t *testing.T) {
	require.Equal(t, "17986094", parseToken("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 17986094\n"))
	require.Equal(t, "", parseToken("pf enabled\n"))
}

const stockHosts = `##
# Host Database
##
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
`

const block = `# BEGIN outline-cli (managed by outline-cli; remove with: sudo outline-cli unlock)
0.0.0.0 secret.example
:: secret.example
0.0.0.0 xn--bcher-kva.example
:: xn--bcher-kva.example
# END outline-cli
`

func TestHostsBlock(t *testing.T) {
	names := []string{"secret.example", "xn--bcher-kva.example"}
	with := HostsWithBlock(stockHosts, names)
	require.Equal(t, stockHosts+block, with)
	require.Equal(t, with, HostsWithBlock(with, names), "installing twice changes nothing")
	require.Equal(t, stockHosts, HostsWithoutBlock(with))
	require.Equal(t, stockHosts, HostsWithoutBlock(stockHosts), "removing without a block changes nothing")
	require.Equal(t, stockHosts, HostsWithBlock(with, nil), "no names removes the block")

	// Replacing keeps the user's own lines, wherever they are.
	user := stockHosts + "10.0.0.5 nas.local\n"
	replaced := HostsWithBlock(user+block+"10.0.0.6 printer.local\n", []string{"other.example"})
	require.Equal(t, user+"10.0.0.6 printer.local\n"+
		"# BEGIN outline-cli (managed by outline-cli; remove with: sudo outline-cli unlock)\n"+
		"0.0.0.0 other.example\n:: other.example\n# END outline-cli\n", replaced)

	// A file without a final newline.
	require.Equal(t, "127.0.0.1 localhost\n"+block, HostsWithBlock("127.0.0.1 localhost", names))
	// A block whose end marker was deleted runs to the end of the file.
	require.Equal(t, stockHosts, HostsWithoutBlock(stockHosts+strings.TrimSuffix(block, "# END outline-cli\n")))
}

type harness struct {
	mac   *fakemac.Mac
	exec  *sysexec.Fake
	m     *Manager
	hosts string
	clock time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{mac: fakemac.New(), hosts: filepath.Join(dir, "hosts"), clock: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	require.NoError(t, os.WriteFile(h.hosts, []byte(stockHosts), 0o644))
	pfConf := filepath.Join(dir, "pf.conf")
	require.NoError(t, os.WriteFile(pfConf, []byte("scrub-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n"), 0o644))
	h.exec = h.mac.Executor()
	h.m = &Manager{Exec: h.exec, Dir: filepath.Join(dir, "state"), HostsPath: h.hosts, PFConfPath: pfConf, Now: func() time.Time { return h.clock }}
	return h
}

func (h *harness) hostsFile(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(h.hosts)
	require.NoError(t, err)
	return string(data)
}

func (h *harness) commands(from int) []string {
	var out []string
	for _, c := range h.exec.Calls()[from:] {
		out = append(out, c.String())
	}
	return out
}

func (h *harness) anchorFile() string { return filepath.Join(h.m.Dir, anchorFileName) }

func TestLockConnectLearnDisconnectUnlock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	baseline := h.mac.Snapshot()

	// Addresses learned in an earlier session; the server's is never blocked,
	// and neither is one for a domain the lockdown doesn't cover.
	require.NoError(t, h.m.SetFirstHops([]netip.Addr{server}))
	require.NoError(t, h.m.Learn(ctx, map[netip.Addr]string{
		addrA:                             "www.secret.example",
		server:                            "secret.example",
		netip.MustParseAddr("192.0.2.99"): "unrelated.example",
	}))
	require.Empty(t, h.exec.Calls(), "learning while disconnected changes nothing on the system")

	// lockdown
	require.NoError(t, h.m.Lock(ctx, []string{"Secret.example", "*.wild.example"}))
	require.Equal(t, []string{
		"pfctl -s info",
		"pfctl -E",
		"pfctl -s rules",
		"pfctl -a com.apple/outline-cli -f " + h.anchorFile(),
		"dscacheutil -flushcache",
		"killall -HUP mDNSResponder",
	}, h.commands(0))
	require.Equal(t, AnchorRules([]netip.Addr{addrA}, ""), h.mac.PFAnchor(Anchor)+"\n")
	enabled, refs := h.mac.PFEnabled()
	require.True(t, enabled)
	require.Equal(t, 1, refs)
	require.Equal(t, stockHosts+"# BEGIN outline-cli (managed by outline-cli; remove with: sudo outline-cli unlock)\n"+
		"0.0.0.0 secret.example\n:: secret.example\n# END outline-cli\n", h.hostsFile(t), "wildcards can't go in hosts")
	st, err := h.m.Status()
	require.NoError(t, err)
	require.Equal(t, []string{"secret.example", "*.wild.example"}, st.Entries)
	require.Equal(t, "7001", st.Token)
	backup, err := os.ReadFile(filepath.Join(h.m.Dir, hostsBackupName))
	require.NoError(t, err)
	require.Equal(t, stockHosts, string(backup))

	// connect
	n := len(h.exec.Calls())
	require.NoError(t, h.m.Connected(ctx, "utun4"))
	require.Equal(t, []string{
		"pfctl -a com.apple/outline-cli -f " + h.anchorFile(),
		"dscacheutil -flushcache",
		"killall -HUP mDNSResponder",
	}, h.commands(n))
	require.Equal(t, AnchorRules([]netip.Addr{addrA}, "utun4"), h.mac.PFAnchor(Anchor)+"\n")
	require.Equal(t, stockHosts, h.hostsFile(t), "the names resolve through the tunnel while connected")

	// A new vpn_only address goes into the table at once; a known one doesn't reload.
	n = len(h.exec.Calls())
	require.NoError(t, h.m.Learn(ctx, map[netip.Addr]string{addrB: "x.wild.example"}))
	require.Equal(t, []string{"pfctl -a com.apple/outline-cli -f " + h.anchorFile()}, h.commands(n))
	require.Equal(t, AnchorRules([]netip.Addr{addrA, addrB}, "utun4"), h.mac.PFAnchor(Anchor)+"\n")
	n = len(h.exec.Calls())
	require.NoError(t, h.m.Learn(ctx, map[netip.Addr]string{addrB: "x.wild.example"}))
	require.Empty(t, h.commands(n))

	// disconnect
	n = len(h.exec.Calls())
	require.NoError(t, h.m.Disconnected(ctx))
	require.Equal(t, []string{
		"pfctl -s info",
		"pfctl -s rules",
		"pfctl -a com.apple/outline-cli -f " + h.anchorFile(),
		"dscacheutil -flushcache",
		"killall -HUP mDNSResponder",
	}, h.commands(n), "pf is already enabled with our reference")
	require.Equal(t, AnchorRules([]netip.Addr{addrA, addrB}, ""), h.mac.PFAnchor(Anchor)+"\n")
	require.Contains(t, h.hostsFile(t), "0.0.0.0 secret.example")

	// unlock
	n = len(h.exec.Calls())
	unlocked, err := h.m.Unlock(ctx)
	require.NoError(t, err)
	require.True(t, unlocked)
	require.Equal(t, []string{
		"dscacheutil -flushcache",
		"killall -HUP mDNSResponder",
		"pfctl -a com.apple/outline-cli -F all",
		"pfctl -X 7001",
	}, h.commands(n))
	require.Equal(t, stockHosts, h.hostsFile(t))
	require.Equal(t, baseline, h.mac.Snapshot(), "pf is as before")
	st, err = h.m.Status()
	require.NoError(t, err)
	require.Nil(t, st)
	_, err = os.Stat(h.anchorFile())
	require.ErrorIs(t, err, os.ErrNotExist)

	again, err := h.m.Unlock(ctx)
	require.NoError(t, err)
	require.False(t, again)
}

func TestNotLockedDown_DoesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.m.Connected(ctx, "utun4"))
	require.NoError(t, h.m.Learn(ctx, map[netip.Addr]string{addrA: "secret.example"}))
	require.NoError(t, h.m.Disconnected(ctx))
	require.Empty(t, h.exec.Calls())
	require.Equal(t, stockHosts, h.hostsFile(t))
}

func TestLock_NeedsVPNOnlyEntries(t *testing.T) {
	h := newHarness(t)
	require.ErrorContains(t, h.m.Lock(context.Background(), nil), "no vpn_only entries")
	require.ErrorContains(t, h.m.Lock(context.Background(), []string{"https://x/"}), "not a domain")
	require.Empty(t, h.exec.Calls())
}

func TestDisconnected_AfterRebootReinstallsEverything(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.m.Lock(ctx, []string{"secret.example"}))
	require.NoError(t, h.m.Connected(ctx, "utun4"))
	// A crash while connected leaves the hosts block out; then a reboot
	// disables pf and drops every rule.
	h.mac.Reboot()

	// cleanup
	n := len(h.exec.Calls())
	require.NoError(t, h.m.Disconnected(ctx))
	require.Equal(t, []string{
		"pfctl -s info",
		"pfctl -E",
		"pfctl -s rules",
		"pfctl -f " + h.m.PFConfPath,
		"pfctl -a com.apple/outline-cli -f " + h.anchorFile(),
		"dscacheutil -flushcache",
		"killall -HUP mDNSResponder",
	}, h.commands(n))
	enabled, _ := h.mac.PFEnabled()
	require.True(t, enabled)
	require.Equal(t, AnchorRules(nil, ""), h.mac.PFAnchor(Anchor)+"\n")
	require.Contains(t, h.hostsFile(t), "0.0.0.0 secret.example")
	st, err := h.m.Status()
	require.NoError(t, err)
	require.Equal(t, "7001", st.Token, "a fresh reference after the reboot")
}

func TestLock_RefusesAForeignMainRuleset(t *testing.T) {
	h := newHarness(t)
	h.mac.SetPFMainRules("block drop in all")
	err := h.m.Lock(context.Background(), []string{"secret.example"})
	require.ErrorContains(t, err, `doesn't evaluate the "com.apple/*" anchors`)
	require.Empty(t, h.mac.PFAnchor(Anchor))
	// Recorded anyway, so a later cleanup or lockdown retries; unlock still works.
	unlocked, err := h.m.Unlock(context.Background())
	require.NoError(t, err)
	require.True(t, unlocked)
}

func TestLearn_ForgetsOldAddresses(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.m.Learn(ctx, map[netip.Addr]string{addrA: "secret.example"}))
	h.clock = h.clock.Add(learnedMaxAge + time.Hour)
	require.NoError(t, h.m.Learn(ctx, map[netip.Addr]string{addrB: "secret.example"}))
	addrs, err := h.m.TableAddrs(&State{Entries: []string{"secret.example"}})
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{addrB}, addrs)
}

func TestStateFilesArePrivate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.m.Lock(ctx, []string{"secret.example"}))
	require.NoError(t, h.m.Learn(ctx, map[netip.Addr]string{addrA: "secret.example"}))
	for _, name := range []string{stateName, learnedName, anchorFileName, hostsBackupName} {
		info, err := os.Stat(filepath.Join(h.m.Dir, name))
		require.NoError(t, err, name)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), name)
	}
	info, err := os.Stat(h.hosts)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm(), "the hosts file keeps its mode")
}

// The commands lockdown runs are all known to the dry-run allowlist: the
// read-only ones pass, every change is held back.
func TestCommandsAreClassified(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.m.Lock(context.Background(), []string{"secret.example"}))
	var readOnly []string
	for _, c := range h.exec.Calls() {
		if sysrouter.IsReadOnly(c) {
			readOnly = append(readOnly, c.String())
		}
	}
	require.Equal(t, []string{"pfctl -s info", "pfctl -s rules"}, readOnly)
}
