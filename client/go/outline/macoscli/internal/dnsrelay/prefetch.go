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

// prefetchFirstRetry is the wait after a first failed lookup. It doubles
// after each further failure (1, 2, 4, ... minutes) up to max_ttl.
const prefetchFirstRetry = time.Minute

// prefetchParallel bounds the lookups in flight at once. Home routers drop
// bursts: twenty lookups at once all timed out, while the same names asked
// one at a time were answered in milliseconds (FINDINGS 24).
const prefetchParallel = 4

// refreshAt is the share of the TTL after which a name is looked up again.
const refreshAt = 0.8

// Prefetch resolves names (A records) directly ahead of time, so their
// addresses are known before an app asks, and looks each one up again at 80%
// of its (clamped) TTL. It returns when ctx is done.
func (r *Relay) Prefetch(ctx context.Context, names []string) {
	r.PrefetchVia(ctx, names, r.Direct, dnsmessage.TypeA)
}

// PrefetchVia is Prefetch through a given exchanger (such as the tunnel) and
// for the given record types, with at most prefetchParallel lookups at once.
// An answer without addresses is asked again after max_ttl. A failure is
// retried after 1 minute, then 2, 4, 8, ... up to max_ttl; a success resets
// that.
func (r *Relay) PrefetchVia(ctx context.Context, names []string, ex Exchanger, qtypes ...dnsmessage.Type) {
	slots := make(chan struct{}, prefetchParallel)
	var wg sync.WaitGroup
	for _, name := range names {
		for _, qtype := range qtypes {
			wg.Go(func() { r.prefetchLoop(ctx, ex, slots, name, qtype) })
		}
	}
	wg.Wait()
}

func (r *Relay) prefetchLoop(ctx context.Context, ex Exchanger, slots chan struct{}, name string, qtype dnsmessage.Type) {
	maxWait := r.Cache.Clamp(time.Duration(1 << 62))
	failures := 0
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		ttl, found, answered := r.prefetchOnce(ctx, ex, name, qtype)
		<-slots
		var wait time.Duration
		switch {
		case found:
			failures = 0
			wait = time.Duration(float64(r.Cache.Clamp(ttl)) * refreshAt)
		case answered:
			failures = 0
			wait = maxWait
		default:
			wait = maxWait
			if failures < 30 {
				wait = min(prefetchFirstRetry<<failures, maxWait)
			}
			failures++
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// prefetchOnce resolves one name and learns its addresses. It returns the
// smallest TTL among them and whether any was found, and whether the server
// answered at all.
func (r *Relay) prefetchOnce(ctx context.Context, ex Exchanger, name string, qtype dnsmessage.Type) (ttl time.Duration, found, answered bool) {
	query, err := NewQuery(uint16(rand.Uint32()), name, qtype)
	if err != nil {
		r.log().Warn("can't build a query to resolve a listed name ahead of time", "name", name, "err", err)
		return 0, false, false
	}
	reply, err := ex.Exchange(ctx, query, false)
	if err == nil && truncated(reply) {
		reply, err = ex.Exchange(ctx, query, true)
	}
	if err != nil {
		if ctx.Err() == nil {
			r.log().Debug("resolving a listed name ahead of time failed; will retry", "name", name, "type", qtype.String(), "err", err)
		}
		return 0, false, false
	}
	learned := Snoop(reply, r.Rules)
	if len(learned) == 0 {
		r.log().Debug("a listed name has no address of this type", "name", name, "type", qtype.String(), "rcode", rcode(reply).String())
		return 0, false, true
	}
	r.Learn(reply)
	ttl = learned[0].TTL
	for _, l := range learned[1:] {
		ttl = min(ttl, l.TTL)
	}
	return ttl, true, true
}
