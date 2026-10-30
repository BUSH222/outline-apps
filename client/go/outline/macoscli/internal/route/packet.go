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

package route

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"

	"localhost/client/go/outline/macoscli/internal/rules"

	"golang.getoutline.org/sdk/network/packetrelay"
)

// packetRelay routes the UDP packets of each lwIP association (one per app
// socket) by destination. Modeled on the SDK's dnsintercept association:
//   - sub-associations on the tunnel and on the direct relay are created
//     when first needed, and re-created if they end;
//   - a bypass DNS query is resolved directly in its own goroutine;
//   - the association closes itself once nothing is active any more (its
//     sub-associations ended and no query is in flight), which lets lwIP
//     release the app's socket, as upstream does.
type packetRelay struct{ r *Router }

func (p *packetRelay) NewAssociation() (packetrelay.PacketSender, packetrelay.PacketReceiver, error) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &assoc{
		r:            p.r,
		ctx:          ctx,
		cancel:       cancel,
		closed:       make(chan struct{}),
		handlerReady: make(chan struct{}),
	}
	return &sender{a}, &receiver{a}, nil
}

type subKind int

const (
	subTunnel subKind = iota
	subDirect
)

type assoc struct {
	r      *Router
	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	isClosed bool
	// active counts the live sub-associations and the direct queries in
	// flight. When it drops to zero, the association closes.
	active int
	closed chan struct{}
	// subs are the current sub-association senders, by kind.
	subs [2]packetrelay.PacketSender

	handler      packetrelay.PacketHandler
	handlerReady chan struct{}
}

func (a *assoc) send(p []byte, dst netip.AddrPort) error {
	if a.r.isDNS(dst) {
		if class, _ := a.r.cfg.DNS.Classify(p); class == rules.Bypass {
			return a.resolveDirect(p)
		}
		return a.sendVia(subTunnel, p, dst)
	}
	if class, domain := a.r.classify(dst.Addr()); class == rules.Bypass {
		a.r.log.Debug("bypass: UDP goes directly", "domain", domain, "to", dst.String())
		return a.sendVia(subDirect, p, dst)
	}
	return a.sendVia(subTunnel, p, dst)
}

// sendVia sends on the sub-association of the given kind. If it has just
// ended (an idle timeout, or the tunnel's DNS association closing after its
// answer), it is re-created once.
func (a *assoc) sendVia(kind subKind, p []byte, dst netip.AddrPort) error {
	s, err := a.sub(kind)
	if err != nil {
		return err
	}
	err = s.SendPacket(p, dst)
	if !errors.Is(err, packetrelay.ErrClosed) {
		return err
	}
	a.mu.Lock()
	if a.subs[kind] == s {
		a.subs[kind] = nil
	}
	a.mu.Unlock()
	if s, err = a.sub(kind); err != nil {
		return err
	}
	return s.SendPacket(p, dst)
}

// sub returns the sub-association of the given kind, creating it if needed.
func (a *assoc) sub(kind subKind) (packetrelay.PacketSender, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isClosed {
		return nil, packetrelay.ErrClosed
	}
	if s := a.subs[kind]; s != nil {
		return s, nil
	}
	relay := a.r.cfg.DirectPackets
	if kind == subTunnel {
		relay = a.r.cfg.Inner.PacketRelay
	}
	s, recv, err := relay.NewAssociation()
	if err != nil {
		if a.active == 0 {
			// Nothing else will ever close this association.
			a.closeLocked()
		}
		return nil, err
	}
	a.subs[kind] = s
	a.active++
	go a.receive(kind, s, recv)
	return s, nil
}

// receive delivers a sub-association's packets until it ends. Replies from
// the tunnel's DNS address are learned from on the way.
func (a *assoc) receive(kind subKind, s packetrelay.PacketSender, recv packetrelay.PacketReceiver) {
	_ = recv.ReceivePackets(handlerFunc(func(p []byte, source netip.AddrPort) error {
		if kind == subTunnel && a.r.isDNS(source) {
			a.r.cfg.DNS.Learn(p)
		}
		return a.deliver(p, source)
	}))
	s.Close()
	a.mu.Lock()
	if a.subs[kind] == s {
		a.subs[kind] = nil
	}
	a.mu.Unlock()
	a.release()
}

// resolveDirect answers a bypass query from the direct resolvers. If they
// fail, the query goes through the tunnel instead.
func (a *assoc) resolveDirect(p []byte) error {
	a.mu.Lock()
	if a.isClosed {
		a.mu.Unlock()
		return packetrelay.ErrClosed
	}
	a.active++
	a.mu.Unlock()

	query := bytes.Clone(p)
	go func() {
		defer a.release()
		reply, err := a.r.cfg.DNS.ResolveDirect(a.ctx, query, false)
		if err != nil {
			if a.ctx.Err() == nil {
				a.sendVia(subTunnel, query, a.r.cfg.DNSAddr)
			}
			return
		}
		// A truncated reply is passed on as is; the app retries over TCP.
		a.deliver(reply, a.r.cfg.DNSAddr)
	}()
	return nil
}

func (a *assoc) deliver(p []byte, source netip.AddrPort) error {
	select {
	case <-a.handlerReady:
		return a.handler.HandlePacket(p, source)
	case <-a.closed:
		return packetrelay.ErrClosed
	}
}

func (a *assoc) release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	if a.active == 0 && !a.isClosed {
		a.closeLocked()
	}
}

func (a *assoc) closeLocked() {
	a.isClosed = true
	close(a.closed)
	a.cancel()
	for _, s := range a.subs {
		if s != nil {
			s.Close()
		}
	}
}

type sender struct{ a *assoc }

func (s *sender) SendPacket(p []byte, dst netip.AddrPort) error { return s.a.send(p, dst) }

func (s *sender) Close() error {
	s.a.mu.Lock()
	defer s.a.mu.Unlock()
	if s.a.isClosed {
		return packetrelay.ErrClosed
	}
	s.a.closeLocked()
	return nil
}

type receiver struct{ a *assoc }

// ReceivePackets passes the replies from every path to handler, until the
// association closes.
func (r *receiver) ReceivePackets(handler packetrelay.PacketHandler) error {
	a := r.a
	a.mu.Lock()
	if a.handler != nil {
		a.mu.Unlock()
		return errors.New("ReceivePackets called more than once")
	}
	a.handler = handler
	close(a.handlerReady)
	a.mu.Unlock()
	<-a.closed
	return nil
}

type handlerFunc func(p []byte, source netip.AddrPort) error

func (f handlerFunc) HandlePacket(p []byte, source netip.AddrPort) error { return f(p, source) }
