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
	r.PrefetchVia(ctx, names, r.Direct, dnsmessage.TypeA)
}

// PrefetchVia is Prefetch through a given exchanger (such as the tunnel) and
// for the given record types. An answer without addresses is asked again
// after the longest TTL; a failure after 30 s.
func (r *Relay) PrefetchVia(ctx context.Context, names []string, ex Exchanger, qtypes ...dnsmessage.Type) {
	var wg sync.WaitGroup
	for _, name := range names {
		for _, qtype := range qtypes {
			wg.Go(func() { r.prefetchLoop(ctx, ex, name, qtype) })
		}
	}
	wg.Wait()
}

func (r *Relay) prefetchLoop(ctx context.Context, ex Exchanger, name string, qtype dnsmessage.Type) {
	for {
		wait := prefetchRetry
		switch ttl, found, answered := r.prefetchOnce(ctx, ex, name, qtype); {
		case found:
			wait = time.Duration(float64(r.Cache.Clamp(ttl)) * refreshAt)
		case answered:
			wait = r.Cache.Clamp(time.Duration(1 << 62))
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
