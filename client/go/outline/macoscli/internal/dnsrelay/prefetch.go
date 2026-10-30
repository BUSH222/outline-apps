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

package dnsrelay

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// prefetchRetry is how long to wait after a lookup that gave no address.
const prefetchRetry = 30 * time.Second

// refreshAt is the share of the TTL after which a name is looked up again.
const refreshAt = 0.8

// Prefetch resolves names (A records) directly ahead of time, so their
// addresses are known before an app asks, and looks each one up again at 80%
// of its (clamped) TTL. It returns when ctx is done.
func (r *Relay) Prefetch(ctx context.Context, names []string) {
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Go(func() {
			for {
				wait := prefetchRetry
				if ttl, ok := r.prefetchOnce(ctx, name); ok {
					wait = time.Duration(float64(r.Cache.Clamp(ttl)) * refreshAt)
				}
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
				}
			}
		})
	}
	wg.Wait()
}

// prefetchOnce resolves one name and learns its addresses. It returns the
// smallest TTL among them, and false if none was found.
func (r *Relay) prefetchOnce(ctx context.Context, name string) (time.Duration, bool) {
	query, err := NewQuery(uint16(rand.Uint32()), name, dnsmessage.TypeA)
	if err != nil {
		r.log().Warn("can't build a query to resolve a bypass name ahead of time", "name", name, "err", err)
		return 0, false
	}
	reply, err := r.Direct.Exchange(ctx, query, false)
	if err == nil && truncated(reply) {
		reply, err = r.Direct.Exchange(ctx, query, true)
	}
	if err != nil {
		if ctx.Err() == nil {
			r.log().Debug("resolving a bypass name ahead of time failed; will retry", "name", name, "err", err)
		}
		return 0, false
	}
	learned := Snoop(reply, r.Rules)
	if len(learned) == 0 {
		r.log().Debug("a bypass name has no address yet; will retry", "name", name, "rcode", rcode(reply).String())
		return 0, false
	}
	r.Learn(reply)
	ttl := learned[0].TTL
	for _, l := range learned[1:] {
		ttl = min(ttl, l.TTL)
	}
	return ttl, true
}
