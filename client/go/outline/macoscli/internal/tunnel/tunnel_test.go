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

package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"localhost/client/go/outline/macoscli/internal/fakemac"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"

	"github.com/stretchr/testify/require"
)

// firstHop is an arbitrary address outside the excluded ranges. Nothing is dialed.
var firstHop = netip.MustParseAddr("100.200.0.10")

type fakeTUN struct {
	name   string
	closed atomic.Bool
}

func (f *fakeTUN) Read([]byte) (int, error)    { return 0, errors.New("fake") }
func (f *fakeTUN) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeTUN) Close() error                { f.closed.Store(true); return nil }
func (f *fakeTUN) Name() string                { return f.name }

type harness struct {
	mac       *fakemac.Mac
	exec      *sysexec.Fake
	store     *state.MemStore
	tun       *fakeTUN
	stopped   atomic.Bool
	opts      Options
	logs      *bytes.Buffer
	baseline  fakemac.Snapshot
	netChange []sysrouter.DefaultRoute
	resolvers [][]netip.Addr
}

func newHarness(t *testing.T, configure ...func(*fakemac.Mac)) *harness {
	t.Helper()
	h := &harness{mac: fakemac.New(), store: state.NewMemStore(nil), tun: &fakeTUN{name: "utun7"}, logs: &bytes.Buffer{}}
	for _, c := range configure {
		c(h.mac)
	}
	h.baseline = h.mac.Snapshot()
	h.exec = h.mac.Executor()
	h.opts = Options{
		Router:  &sysrouter.Router{Exec: h.exec},
		Store:   h.store,
		OpenTUN: func() (TUN, error) { return h.tun, nil },
		StartTransport: func(context.Context, TUN) (func(), error) {
			return func() { h.stopped.Store(true) }, nil
		},
		LocalPrefixes: func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil },
		FirstHops:     []netip.Addr{firstHop},
		OnNetwork: func(r sysrouter.DefaultRoute, resolvers []netip.Addr) error {
			h.netChange = append(h.netChange, r)
			h.resolvers = append(h.resolvers, resolvers)
			return nil
		},
		Logger: slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	return h
}

func mutations(calls []sysexec.Call) []string {
	var out []string
	for _, c := range calls {
		if !sysrouter.IsReadOnly(c) {
			out = append(out, c.String())
		}
	}
	return out
}

func (h *harness) requireRestored(t *testing.T) {
	t.Helper()
	require.Equal(t, h.baseline, h.mac.Snapshot(), "the system must be exactly as before")
	st, err := h.store.Load()
	require.NoError(t, err)
	require.Nil(t, st, "the state file must be gone")
}

// The exact system changes of one connect and disconnect.
var connectCommands = []string{
	"ifconfig utun7 inet 10.111.222.1 10.111.222.2 netmask 255.255.255.255 mtu 1500 up",
	"route -n add -net 10.0.0.0/8 192.168.1.1",
	"route -n add -net 100.64.0.0/10 192.168.1.1",
	// 169.254.0.0/16 already exists (the link-local route) and is skipped.
	"route -n add -net 172.16.0.0/12 192.168.1.1",
	"route -n add -net 192.0.0.0/24 192.168.1.1",
	"route -n add -net 192.0.2.0/24 192.168.1.1",
	"route -n add -net 192.31.196.0/24 192.168.1.1",
	"route -n add -net 192.52.193.0/24 192.168.1.1",
	"route -n add -net 192.88.99.0/24 192.168.1.1",
	"route -n add -net 192.168.0.0/16 192.168.1.1",
	"route -n add -net 192.175.48.0/24 192.168.1.1",
	"route -n add -net 198.18.0.0/15 192.168.1.1",
	"route -n add -net 198.51.100.0/24 192.168.1.1",
	"route -n add -net 203.0.113.0/24 192.168.1.1",
	"route -n add -net 240.0.0.0/4 192.168.1.1",
	"route -n add -host 100.200.0.10 192.168.1.1",
	"route -n add -host 169.254.113.53 -interface utun7",
	"route -n add -net 0.0.0.0/1 -interface utun7",
	"route -n add -net 128.0.0.0/1 -interface utun7",
	"networksetup -setdnsservers Wi-Fi 169.254.113.53",
	"networksetup -setv6off Wi-Fi",
	"dscacheutil -flushcache",
	"killall -HUP mDNSResponder",
}

var disconnectCommands = []string{
	"networksetup -setdnsservers Wi-Fi empty",
	"networksetup -setv6automatic Wi-Fi",
	"route -n delete -net 128.0.0.0/1 -interface utun7",
	"route -n delete -net 0.0.0.0/1 -interface utun7",
	"route -n delete -host 169.254.113.53 -interface utun7",
	"route -n delete -host 100.200.0.10 192.168.1.1",
	"route -n delete -net 240.0.0.0/4 192.168.1.1",
	"route -n delete -net 203.0.113.0/24 192.168.1.1",
	"route -n delete -net 198.51.100.0/24 192.168.1.1",
	"route -n delete -net 198.18.0.0/15 192.168.1.1",
	"route -n delete -net 192.175.48.0/24 192.168.1.1",
	"route -n delete -net 192.168.0.0/16 192.168.1.1",
	"route -n delete -net 192.88.99.0/24 192.168.1.1",
	"route -n delete -net 192.52.193.0/24 192.168.1.1",
	"route -n delete -net 192.31.196.0/24 192.168.1.1",
	"route -n delete -net 192.0.2.0/24 192.168.1.1",
	"route -n delete -net 192.0.0.0/24 192.168.1.1",
	"route -n delete -net 172.16.0.0/12 192.168.1.1",
	"route -n delete -net 100.64.0.0/10 192.168.1.1",
	"route -n delete -net 10.0.0.0/8 192.168.1.1",
	"dscacheutil -flushcache",
	"killall -HUP mDNSResponder",
}

func TestUpDown_ExactCommandsAndFullRestore(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	require.Equal(t, connectCommands, mutations(h.exec.Calls()))

	// While connected.
	snap := h.mac.Snapshot()
	require.Equal(t, "169.254.113.53", snap.DNS["Wi-Fi"])
	require.Equal(t, sysrouter.IPv6Off, snap.IPv6["Wi-Fi"].Mode)
	route, ok := h.mac.HasRoute("0.0.0.0/1")
	require.True(t, ok)
	require.Equal(t, "utun7", route.Interface)
	st := s.State()
	require.Equal(t, "Wi-Fi", st.Service)
	require.Equal(t, []string{"192.168.1.1"}, st.SystemResolvers)
	require.Len(t, st.Routes, len(connectCommands)-5, "everything but ifconfig, DNS, IPv6 and the two flush commands")
	require.False(t, h.tun.closed.Load())

	n := len(h.exec.Calls())
	require.NoError(t, s.Down(ctx))
	require.Equal(t, disconnectCommands, mutations(h.exec.Calls()[n:]))
	require.True(t, h.tun.closed.Load())
	require.True(t, h.stopped.Load())
	h.requireRestored(t)

	require.NoError(t, s.Down(ctx), "Down is idempotent")
}

func TestUp_TransportFailureChangesNoRoutesOrDNS(t *testing.T) {
	h := newHarness(t)
	h.opts.StartTransport = func(context.Context, TUN) (func(), error) {
		return nil, errors.New("TCP health check failed")
	}
	_, err := Up(context.Background(), h.opts)
	require.ErrorContains(t, err, "no routes were changed")
	for _, m := range mutations(h.exec.Calls()) {
		require.False(t, strings.HasPrefix(m, "route ") || strings.HasPrefix(m, "networksetup "), "unexpected change: %s", m)
	}
	require.True(t, h.tun.closed.Load())
	h.requireRestored(t)
}

func TestUp_RollsBackOnFailure(t *testing.T) {
	for _, failOn := range []string{"0.0.0.0/1", "-setdnsservers", "-setv6off"} {
		t.Run(failOn, func(t *testing.T) {
			h := newHarness(t)
			failed := false
			h.mac.BeforeMutation = func(_ int, c sysexec.Call) error {
				if !failed && strings.Contains(c.String(), failOn) {
					failed = true
					return errors.New("injected failure")
				}
				return nil
			}
			_, err := Up(context.Background(), h.opts)
			require.ErrorContains(t, err, "injected failure")
			h.mac.BeforeMutation = nil
			require.True(t, h.tun.closed.Load())
			h.requireRestored(t)
		})
	}
}

// TestCrashAtEveryStep kills the process (a panic, so no rollback runs) before
// each system change of a connect, then runs cleanup from the saved state
// alone. The system must come back exactly, whether or not the kernel removed
// the utun's routes.
func TestCrashAtEveryStep(t *testing.T) {
	total := len(connectCommands)
	for crashAt := 1; crashAt <= total+1; crashAt++ {
		for _, kernelDropsUTunRoutes := range []bool{true, false} {
			name := fmt.Sprintf("before change %d, kernel drops utun routes=%v", crashAt, kernelDropsUTunRoutes)
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				h.mac.BeforeMutation = func(n int, c sysexec.Call) error {
					if n == crashAt {
						panic(fakemac.Crash{Call: c})
					}
					return nil
				}
				crashed := func() (crashed bool) {
					defer func() {
						if r := recover(); r != nil {
							_, crashed = r.(fakemac.Crash)
							if !crashed {
								panic(r)
							}
						}
					}()
					_, err := Up(context.Background(), h.opts)
					require.NoError(t, err)
					return false
				}()
				require.Equal(t, crashAt <= total, crashed)
				// The process is gone.
				h.mac.BeforeMutation = nil
				if kernelDropsUTunRoutes {
					h.mac.DestroyUTun("utun7")
				}

				// A new process runs cleanup with a fresh executor.
				restored, err := Cleanup(context.Background(), &sysrouter.Router{Exec: h.mac.Executor()}, h.store, nil)
				require.NoError(t, err)
				require.NotNil(t, restored, "the state file must exist from the start")
				h.requireRestored(t)

				again, err := Cleanup(context.Background(), &sysrouter.Router{Exec: h.mac.Executor()}, h.store, nil)
				require.NoError(t, err)
				require.Nil(t, again, "cleanup is idempotent")
			})
		}
	}
}

func TestCleanup_NoState(t *testing.T) {
	h := newHarness(t)
	restored, err := Cleanup(context.Background(), h.opts.Router, h.store, nil)
	require.NoError(t, err)
	require.Nil(t, restored)
	require.Empty(t, h.exec.Calls())
}

func TestCleanup_FailureKeepsStateForRetry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := Up(ctx, h.opts)
	require.NoError(t, err)

	h.mac.BeforeMutation = func(_ int, c sysexec.Call) error {
		if strings.Contains(c.String(), "delete -net 0.0.0.0/1") {
			return errors.New("injected failure")
		}
		return nil
	}
	_, err = Cleanup(ctx, &sysrouter.Router{Exec: h.mac.Executor()}, h.store, nil)
	require.ErrorContains(t, err, "injected failure")
	st, err := h.store.Load()
	require.NoError(t, err)
	require.NotNil(t, st)
	require.Len(t, st.Routes, 1, "only the route that failed is left")
	require.Nil(t, st.PrevDNS)

	h.mac.BeforeMutation = nil
	_, err = Cleanup(ctx, &sysrouter.Router{Exec: h.mac.Executor()}, h.store, nil)
	require.NoError(t, err)
	h.requireRestored(t)
}

func TestUp_ExistingRoutesAreNeverTouched(t *testing.T) {
	theirs := sysrouter.RouteSpec{Dst: netip.MustParsePrefix("10.0.0.0/8"), Interface: "en5"}
	h := newHarness(t, func(m *fakemac.Mac) { m.AddExistingRoute(theirs) })
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	for _, r := range s.State().Routes {
		require.NotEqual(t, theirs.Dst, r.Dst, "a pre-existing route must not be recorded")
	}
	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
	got, ok := h.mac.HasRoute("10.0.0.0/8")
	require.True(t, ok)
	require.Equal(t, theirs, got)
}

func TestUp_ManualSettingsAreRestored(t *testing.T) {
	h := newHarness(t, func(m *fakemac.Mac) {
		m.SetManualDNS("Wi-Fi", []string{"1.1.1.1", "9.9.9.9"})
		m.SetIPv6("Wi-Fi", sysrouter.IPv6Config{Mode: sysrouter.IPv6Manual, Raw: "Manual", Address: "2001:db8::5", PrefixLength: 64, Router: "2001:db8::1"})
	})
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	require.Equal(t, sysrouter.IPv6Off, h.mac.Snapshot().IPv6["Wi-Fi"].Mode)
	n := len(h.exec.Calls())
	require.NoError(t, s.Down(ctx))
	require.Contains(t, mutations(h.exec.Calls()[n:]), "networksetup -setv6manual Wi-Fi 2001:db8::5 64 2001:db8::1")
	require.Contains(t, mutations(h.exec.Calls()[n:]), "networksetup -setdnsservers Wi-Fi 1.1.1.1 9.9.9.9")
	h.requireRestored(t)
}

func TestUp_UnrestorableIPv6IsLeftAlone(t *testing.T) {
	h := newHarness(t, func(m *fakemac.Mac) {
		m.SetIPv6("Wi-Fi", sysrouter.IPv6Config{Mode: sysrouter.IPv6Unknown, Raw: "Link-local only"})
	})
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	for _, m := range mutations(h.exec.Calls()) {
		require.NotContains(t, m, "-setv6")
	}
	require.Contains(t, h.logs.String(), "IPv6 is left as is")
	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
}

func TestUp_IPv6AlreadyOff(t *testing.T) {
	h := newHarness(t, func(m *fakemac.Mac) {
		m.SetIPv6("Wi-Fi", sysrouter.IPv6Config{Mode: sysrouter.IPv6Off, Raw: "Off"})
	})
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	require.Nil(t, s.State().PrevIPv6)
	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
}

func TestUp_Offline(t *testing.T) {
	h := newHarness(t, func(m *fakemac.Mac) { m.GoOffline() })
	_, err := Up(context.Background(), h.opts)
	require.ErrorContains(t, err, "no default route")
	require.Empty(t, mutations(h.exec.Calls()))
	h.requireRestored(t)
}

func TestUp_WarnsAboutOtherActiveInterfaces(t *testing.T) {
	h := newHarness(t, func(m *fakemac.Mac) { m.AlsoConnected(fakemac.Ethernet) })
	s, err := Up(context.Background(), h.opts)
	require.NoError(t, err)
	require.Contains(t, h.logs.String(), "several network interfaces are active")
	require.NoError(t, s.Down(context.Background()))
}

func TestUp_UTunSubnetAvoidsLocalNetworks(t *testing.T) {
	h := newHarness(t)
	h.opts.LocalPrefixes = func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil
	}
	s, err := Up(context.Background(), h.opts)
	require.NoError(t, err)
	require.Equal(t, "172.16.9.1", h.mac.UTunAddress("utun7"))
	require.NoError(t, s.Down(context.Background()))
}

func TestUp_FirstHopRoutes(t *testing.T) {
	h := newHarness(t)
	h.opts.FirstHops = []netip.Addr{
		netip.MustParseAddr("192.168.1.50"),       // on the LAN: already excluded
		netip.MustParseAddr("2001:db8::10"),       // IPv6: not routed (IPv6 is off)
		netip.MustParseAddr("::ffff:100.200.0.9"), // IPv4-mapped
	}
	s, err := Up(context.Background(), h.opts)
	require.NoError(t, err)
	var hops []string
	for _, r := range s.State().Routes {
		if r.Purpose == PurposeFirstHop {
			hops = append(hops, r.RouteSpec.String())
		}
	}
	require.Equal(t, []string{"100.200.0.9/32 via 192.168.1.1"}, hops)
	require.NoError(t, s.Down(context.Background()))
}

func TestNetworkChange(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)

	// Same network: nothing happens.
	n := len(h.exec.Calls())
	require.NoError(t, s.CheckNetwork(ctx))
	require.Empty(t, mutations(h.exec.Calls()[n:]))

	// Offline: nothing happens, and it is reported once.
	h.mac.GoOffline()
	require.NoError(t, s.CheckNetwork(ctx))
	require.NoError(t, s.CheckNetwork(ctx))
	require.Equal(t, 1, strings.Count(h.logs.String(), "the network is gone"))
	require.Empty(t, mutations(h.exec.Calls()[n:]))

	// Switch from Wi-Fi to Ethernet.
	h.mac.SwitchTo(fakemac.Ethernet)
	require.NoError(t, s.CheckNetwork(ctx))
	snap := h.mac.Snapshot()
	require.Equal(t, "DHCP", snap.DNS["Wi-Fi"], "the old service is restored")
	require.Equal(t, sysrouter.IPv6Automatic, snap.IPv6["Wi-Fi"].Mode)
	require.Equal(t, "169.254.113.53", snap.DNS["USB 10/100/1000 LAN"])
	require.Equal(t, sysrouter.IPv6Off, snap.IPv6["USB 10/100/1000 LAN"].Mode)
	route, ok := h.mac.HasRoute("10.0.0.0/8")
	require.True(t, ok)
	require.Equal(t, "10.20.0.1", route.Gateway.String())
	route, ok = h.mac.HasRoute("100.200.0.10/32")
	require.True(t, ok)
	require.Equal(t, "10.20.0.1", route.Gateway.String())
	route, ok = h.mac.HasRoute("0.0.0.0/1")
	require.True(t, ok)
	require.Equal(t, "utun7", route.Interface, "tunnel routes stay")

	st := s.State()
	require.Equal(t, "USB 10/100/1000 LAN", st.Service)
	require.Equal(t, "en7", st.Interface)
	require.Equal(t, []string{"10.20.0.53"}, st.SystemResolvers)
	require.Len(t, h.netChange, 2, "once at start, once for the change")
	require.Equal(t, "en0", h.netChange[0].Interface)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, h.resolvers[0])
	require.Equal(t, "en7", h.netChange[1].Interface)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.20.0.53")}, h.resolvers[1])

	// A crash now is still recoverable from the state file alone.
	h.mac.DestroyUTun("utun7")
	_, err = Cleanup(ctx, &sysrouter.Router{Exec: h.mac.Executor()}, h.store, nil)
	require.NoError(t, err)
	require.Equal(t, h.baseline, h.mac.Snapshot())
}

func TestNetworkChange_ThenDown(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	h.mac.SwitchTo(fakemac.Ethernet)
	require.NoError(t, s.CheckNetwork(ctx))
	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
	require.NoError(t, s.CheckNetwork(ctx), "a closed session ignores network checks")
}

func TestDryRunNeverChangesTheSystem(t *testing.T) {
	h := newHarness(t)
	h.mac.BeforeMutation = func(_ int, c sysexec.Call) error {
		t.Fatalf("the dry run ran a mutating command: %s", c)
		return nil
	}
	var plan bytes.Buffer
	dry := &sysexec.DryRun{Next: h.exec, IsReadOnly: sysrouter.IsReadOnly, Out: &plan}
	h.opts.Router = &sysrouter.Router{Exec: dry}
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	require.NoError(t, s.Down(ctx))

	var skipped []string
	for _, c := range dry.Skipped() {
		skipped = append(skipped, c.String())
	}
	require.Equal(t, append(append([]string{}, connectCommands...), disconnectCommands...), skipped)
	require.Contains(t, plan.String(), "    route -n add -net 0.0.0.0/1 -interface utun7\n")
	require.Equal(t, h.baseline, h.mac.Snapshot())
}

func TestChooseUTunAddrs_AllTaken(t *testing.T) {
	s := &Session{opts: Options{LocalPrefixes: func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, nil
	}}}
	local, peer, err := s.chooseUTunAddrs()
	require.NoError(t, err)
	require.Equal(t, "10.111.222.1", local.String())
	require.Equal(t, "10.111.222.2", peer.String())
}

func TestUp_OnNetworkRunsBeforeTheTransport(t *testing.T) {
	h := newHarness(t)
	var order []string
	h.opts.OnNetwork = func(r sysrouter.DefaultRoute, _ []netip.Addr) error {
		order = append(order, "network "+r.Interface)
		return nil
	}
	h.opts.StartTransport = func(context.Context, TUN) (func(), error) {
		order = append(order, "transport")
		return func() {}, nil
	}
	s, err := Up(context.Background(), h.opts)
	require.NoError(t, err)
	require.Equal(t, []string{"network en0", "transport"}, order)
	require.NoError(t, s.Down(context.Background()))
}

func TestUp_OnNetworkErrorAbortsBeforeAnyChange(t *testing.T) {
	h := newHarness(t)
	h.opts.OnNetwork = func(sysrouter.DefaultRoute, []netip.Addr) error {
		return errors.New("no such interface")
	}
	_, err := Up(context.Background(), h.opts)
	require.ErrorContains(t, err, "no such interface")
	require.Empty(t, mutations(h.exec.Calls()))
	h.requireRestored(t)
}
