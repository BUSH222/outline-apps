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

// Package ipcache remembers which addresses belong to listed domains, as
// learned from DNS answers, for as long as the answers are valid.
//
// Traffic only carries addresses, so this is how a connection to an address
// is tied back to the domain rules.
package ipcache

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"localhost/client/go/outline/macoscli/internal/rules"
)

// purgeInterval is how often expired entries are dropped.
const purgeInterval = time.Minute

// Cache maps addresses to the class of the domains they were learned for. It
// is safe for concurrent use.
type Cache struct {
	minTTL, maxTTL time.Duration
	now            func() time.Time

	mu        sync.Mutex
	entries   map[netip.Addr]*entry
	lastPurge time.Time
}

// entry keeps one expiry per class, so learning an address for a bypass
// domain never shortens or hides what was learned for a vpn_only domain.
type entry struct {
	bypassUntil, vpnOnlyUntil time.Time
	bypassDomain, vpnDomain   string
}

// New returns a cache that keeps entries between minTTL and maxTTL. now is
// the clock; nil means time.Now.
func New(minTTL, maxTTL time.Duration, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{minTTL: minTTL, maxTTL: maxTTL, now: now, entries: map[netip.Addr]*entry{}}
}

// Clamp bounds a DNS TTL to the cache's limits.
func (c *Cache) Clamp(ttl time.Duration) time.Duration {
	return min(max(ttl, c.minTTL), c.maxTTL)
}

// Learn records that addr belongs to domain, of the given class, for ttl
// (clamped). An existing entry is only ever extended. Class None is ignored.
func (c *Cache) Learn(addr netip.Addr, class rules.Class, domain string, ttl time.Duration) {
	if class == rules.None || !addr.IsValid() {
		return
	}
	addr = addr.Unmap()
	now := c.now()
	until := now.Add(c.Clamp(ttl))

	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked(now)
	e := c.entries[addr]
	if e == nil {
		e = &entry{}
		c.entries[addr] = e
	}
	switch class {
	case rules.Bypass:
		if until.After(e.bypassUntil) {
			e.bypassUntil, e.bypassDomain = until, domain
		}
	case rules.VPNOnly:
		if until.After(e.vpnOnlyUntil) {
			e.vpnOnlyUntil, e.vpnDomain = until, domain
		}
	}
}

// Lookup returns the class of addr and the domain it was learned for. If an
// address was learned for both a bypass and a vpn_only domain, vpn_only wins.
func (c *Cache) Lookup(addr netip.Addr) (rules.Class, string) {
	addr = addr.Unmap()
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[addr]
	switch {
	case e == nil:
		return rules.None, ""
	case now.Before(e.vpnOnlyUntil):
		return rules.VPNOnly, e.vpnDomain
	case now.Before(e.bypassUntil):
		return rules.Bypass, e.bypassDomain
	default:
		return rules.None, ""
	}
}

// Snapshot returns the unexpired addresses whose class is class, sorted.
func (c *Cache) Snapshot(class rules.Class) []netip.Addr {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []netip.Addr
	for addr, e := range c.entries {
		got := rules.None
		switch {
		case now.Before(e.vpnOnlyUntil):
			got = rules.VPNOnly
		case now.Before(e.bypassUntil):
			got = rules.Bypass
		}
		if got == class && class != rules.None {
			out = append(out, addr)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// Len returns the number of stored entries, expired or not.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) purgeLocked(now time.Time) {
	if now.Sub(c.lastPurge) < purgeInterval {
		return
	}
	c.lastPurge = now
	for addr, e := range c.entries {
		if !now.Before(e.bypassUntil) && !now.Before(e.vpnOnlyUntil) {
			delete(c.entries, addr)
		}
	}
}
