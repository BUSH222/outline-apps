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

package ipcache

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"localhost/client/go/outline/macoscli/internal/rules"

	"github.com/stretchr/testify/require"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newCache() (*Cache, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	return New(time.Minute, time.Hour, clock.now), clock
}

var (
	ip1 = netip.MustParseAddr("192.0.2.1")
	ip2 = netip.MustParseAddr("198.51.100.2")
)

func TestClampsTTL(t *testing.T) {
	c, clock := newCache()
	c.Learn(ip1, rules.Bypass, "short.example", 5*time.Second) // raised to min_ttl (1m)
	c.Learn(ip2, rules.Bypass, "long.example", 24*time.Hour)   // cut to max_ttl (1h)

	clock.advance(59 * time.Second)
	class, domain := c.Lookup(ip1)
	require.Equal(t, rules.Bypass, class)
	require.Equal(t, "short.example", domain)
	clock.advance(time.Second)
	class, _ = c.Lookup(ip1)
	require.Equal(t, rules.None, class, "expired at min_ttl")

	clock.advance(time.Hour - time.Minute - time.Nanosecond)
	class, _ = c.Lookup(ip2)
	require.Equal(t, rules.Bypass, class)
	clock.advance(time.Nanosecond)
	class, _ = c.Lookup(ip2)
	require.Equal(t, rules.None, class, "expired at max_ttl")
}

func TestVPNOnlyWinsForASharedAddress(t *testing.T) {
	c, clock := newCache()
	c.Learn(ip1, rules.VPNOnly, "secret.example", 2*time.Minute)
	c.Learn(ip1, rules.Bypass, "cdn.example", 10*time.Minute)
	class, domain := c.Lookup(ip1)
	require.Equal(t, rules.VPNOnly, class)
	require.Equal(t, "secret.example", domain)

	// Once the vpn_only answer expires, the bypass one still holds.
	clock.advance(2 * time.Minute)
	class, domain = c.Lookup(ip1)
	require.Equal(t, rules.Bypass, class)
	require.Equal(t, "cdn.example", domain)
}

func TestLearnOnlyExtends(t *testing.T) {
	c, clock := newCache()
	c.Learn(ip1, rules.Bypass, "a.example", 10*time.Minute)
	c.Learn(ip1, rules.Bypass, "b.example", 2*time.Minute) // shorter: ignored
	clock.advance(5 * time.Minute)
	class, domain := c.Lookup(ip1)
	require.Equal(t, rules.Bypass, class)
	require.Equal(t, "a.example", domain)
}

func TestIgnoresNoneAndInvalid(t *testing.T) {
	c, _ := newCache()
	c.Learn(ip1, rules.None, "x.example", time.Hour)
	c.Learn(netip.Addr{}, rules.Bypass, "x.example", time.Hour)
	require.Zero(t, c.Len())
}

func TestUnmapsAddresses(t *testing.T) {
	c, _ := newCache()
	c.Learn(netip.MustParseAddr("::ffff:192.0.2.1"), rules.Bypass, "x.example", time.Hour)
	class, _ := c.Lookup(ip1)
	require.Equal(t, rules.Bypass, class)
	class, _ = c.Lookup(netip.MustParseAddr("::ffff:192.0.2.1"))
	require.Equal(t, rules.Bypass, class)
}

func TestIPv6(t *testing.T) {
	c, _ := newCache()
	v6 := netip.MustParseAddr("2001:db8::1")
	c.Learn(v6, rules.Bypass, "x.example", time.Hour)
	class, _ := c.Lookup(v6)
	require.Equal(t, rules.Bypass, class)
}

func TestSnapshotAndPurge(t *testing.T) {
	c, clock := newCache()
	c.Learn(ip2, rules.VPNOnly, "secret.example", time.Hour)
	c.Learn(ip1, rules.VPNOnly, "secret.example", time.Minute)
	c.Learn(netip.MustParseAddr("203.0.113.3"), rules.Bypass, "x.example", time.Hour)
	require.Equal(t, []netip.Addr{ip1, ip2}, c.Snapshot(rules.VPNOnly))
	require.Len(t, c.Snapshot(rules.Bypass), 1)
	require.Empty(t, c.Snapshot(rules.None))

	clock.advance(2 * time.Minute)
	require.Equal(t, []netip.Addr{ip2}, c.Snapshot(rules.VPNOnly))
	// Expired entries are dropped on a later Learn.
	c.Learn(netip.MustParseAddr("203.0.113.4"), rules.Bypass, "y.example", time.Hour)
	require.Equal(t, 3, c.Len())
}

func TestConcurrentUse(t *testing.T) {
	c := New(time.Minute, time.Hour, nil)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 200 {
				addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(j)})
				c.Learn(addr, rules.Class(1+i%2), "x.example", time.Minute)
				c.Lookup(addr)
				c.Snapshot(rules.Bypass)
			}
		})
	}
	wg.Wait()
	require.Equal(t, 200, c.Len())
}
