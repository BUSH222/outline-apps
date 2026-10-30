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
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"localhost/client/go/outline/macoscli/internal/fakemac"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"

	"github.com/stretchr/testify/require"
)

// Addresses outside every excluded range (the documentation ranges are all
// excluded), and not the server's.
var (
	bypassA = netip.MustParseAddr("100.200.1.1")
	bypassB = netip.MustParseAddr("100.200.1.2")
)

func bypassRoutes(s *Session) []string {
	var out []string
	for _, r := range s.State().Routes {
		if r.Purpose == PurposeBypass {
			out = append(out, r.RouteSpec.String())
		}
	}
	return out
}

func TestRouteDirect_AddsAJournaledHostRoute(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)

	n := len(h.exec.Calls())
	require.NoError(t, s.RouteDirect(ctx, bypassA))
	require.Equal(t, []string{"route -n add -host 100.200.1.1 192.168.1.1"}, mutations(h.exec.Calls()[n:]))
	require.Equal(t, []string{"100.200.1.1/32 via 192.168.1.1"}, bypassRoutes(s))
	route, ok := h.mac.HasRoute("100.200.1.1/32")
	require.True(t, ok)
	require.Equal(t, "192.168.1.1", route.Gateway.String())

	// Asking again, or with the IPv4-mapped form, changes nothing.
	n = len(h.exec.Calls())
	require.NoError(t, s.RouteDirect(ctx, bypassA))
	require.NoError(t, s.RouteDirect(ctx, netip.MustParseAddr("::ffff:100.200.1.1")))
	require.Empty(t, h.exec.Calls()[n:])

	// Already physical, or IPv6: nothing to add.
	n = len(h.exec.Calls())
	for _, a := range []string{"192.168.1.50", "100.200.0.10", "2001:db8::1"} {
		require.NoError(t, s.RouteDirect(ctx, netip.MustParseAddr(a)), a)
	}
	require.Empty(t, mutations(h.exec.Calls()[n:]))
	require.Len(t, bypassRoutes(s), 1)

	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
	require.NoError(t, s.RouteDirect(ctx, bypassB), "a closed session ignores it")
	h.requireRestored(t)
}

func TestUnrouteDirect(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	require.NoError(t, s.RouteDirect(ctx, bypassA))
	require.NoError(t, s.RouteDirect(ctx, bypassB))

	n := len(h.exec.Calls())
	require.NoError(t, s.UnrouteDirect(ctx, bypassA))
	require.Equal(t, []string{"route -n delete -host 100.200.1.1 192.168.1.1"}, mutations(h.exec.Calls()[n:]))
	require.Equal(t, []string{"100.200.1.2/32 via 192.168.1.1"}, bypassRoutes(s))
	require.Equal(t, []netip.Addr{bypassB}, s.DirectAddrs())
	_, ok := h.mac.HasRoute("100.200.1.1/32")
	require.False(t, ok)

	n = len(h.exec.Calls())
	require.NoError(t, s.UnrouteDirect(ctx, bypassA), "unknown addresses are ignored")
	require.Empty(t, h.exec.Calls()[n:])

	// It can be routed again later.
	require.NoError(t, s.RouteDirect(ctx, bypassA))
	require.Len(t, bypassRoutes(s), 2)
	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
}

func TestRouteDirect_FailureIsRetriedNextTime(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	failOn := func(substr string) {
		h.mac.BeforeMutation = func(_ int, c sysexec.Call) error {
			if strings.Contains(c.String(), substr) {
				return errors.New("injected")
			}
			return nil
		}
	}
	failOn("add -host 100.200.1.1")
	require.Error(t, s.RouteDirect(ctx, bypassA))
	require.Empty(t, bypassRoutes(s), "the failed route's journal entry is undone")
	h.mac.BeforeMutation = nil
	require.NoError(t, s.RouteDirect(ctx, bypassA))
	require.Equal(t, []string{"100.200.1.1/32 via 192.168.1.1"}, bypassRoutes(s))

	// If undoing fails too, the leftover entry is harmless: disconnect still
	// restores everything.
	failOn("100.200.1.2")
	require.Error(t, s.RouteDirect(ctx, bypassB))
	h.mac.BeforeMutation = nil
	require.NoError(t, s.RouteDirect(ctx, bypassB))
	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
}

func TestRouteDirect_FollowsNetworkChanges(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	require.NoError(t, s.RouteDirect(ctx, bypassA))

	h.mac.SwitchTo(fakemac.Ethernet)
	require.NoError(t, s.CheckNetwork(ctx))
	route, ok := h.mac.HasRoute("100.200.1.1/32")
	require.True(t, ok)
	require.Equal(t, "10.20.0.1", route.Gateway.String(), "moved to the new router")
	require.Equal(t, []string{"100.200.1.1/32 via 10.20.0.1"}, bypassRoutes(s))
	require.Empty(t, h.mac.StaleRoutes())

	// Learned while offline: routed once the network is back.
	h.mac.GoOffline()
	require.NoError(t, s.CheckNetwork(ctx))
	n := len(h.exec.Calls())
	require.NoError(t, s.RouteDirect(ctx, bypassB))
	require.Empty(t, mutations(h.exec.Calls()[n:]))
	h.mac.SwitchTo(fakemac.WiFi)
	require.NoError(t, s.CheckNetwork(ctx))
	require.Equal(t, []string{"100.200.1.1/32 via 192.168.1.1", "100.200.1.2/32 via 192.168.1.1"}, bypassRoutes(s))

	require.NoError(t, s.Down(ctx))
	h.requireRestored(t)
}

func TestRouteDirect_CrashIsCleanedUp(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	s, err := Up(ctx, h.opts)
	require.NoError(t, err)
	require.NoError(t, s.RouteDirect(ctx, bypassA))
	// kill -9: the utun and its routes go, the gateway routes stay.
	h.mac.DestroyUTun("utun7")
	_, ok := h.mac.HasRoute("100.200.1.1/32")
	require.True(t, ok)

	_, err = Cleanup(ctx, &sysrouter.Router{Exec: h.mac.Executor()}, h.store, nil)
	require.NoError(t, err)
	h.requireRestored(t)
}
