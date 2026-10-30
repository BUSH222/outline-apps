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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"localhost/client/go/outline/configregistry"
	"localhost/client/go/outline/macoscli/internal/netbind"
	"localhost/client/go/outline/macoscli/internal/state"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
	"localhost/client/go/outline/macoscli/internal/tunnel"
	"localhost/client/go/outline/vpn"
)

const (
	defaultWatchInterval = 2 * time.Second
	// disconnectTimeout bounds the restore after Ctrl-C.
	disconnectTimeout = 60 * time.Second
)

// startTransportFunc connects the transport to the utun and returns once it
// is healthy.
type startTransportFunc func(ctx context.Context, tun tunnel.TUN, pair *configregistry.TransportPair, log *slog.Logger) (stop func(), err error)

// prepareSession checks for root, takes the instance lock and restores the
// network from a session that didn't shut down cleanly. It returns the unlock
// function.
func prepareSession(ctx context.Context, e env, log *slog.Logger) (func() error, error) {
	if e.geteuid() != 0 {
		return nil, errors.New("connect changes routes and DNS, so it must run as root: sudo outline-cli connect ... (or try --dry-run)")
	}
	store := state.FileStore{Dir: e.stateDir}
	unlock, err := store.Lock()
	if errors.Is(err, state.ErrLocked) {
		return nil, errors.New("another outline-cli session is running")
	}
	if err != nil {
		return nil, err
	}
	restored, err := tunnel.Cleanup(ctx, &sysrouter.Router{Exec: e.exec}, store, log)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("restoring the network from a previous session failed: %w; fix it with: sudo outline-cli cleanup", err)
	}
	if restored != nil {
		log.Warn("restored the network left behind by a previous session that didn't exit cleanly", "pid", restored.PID)
	}
	return unlock, nil
}

// runSession brings the tunnel up, keeps it in sync with network changes, and
// restores everything when ctx is canceled (Ctrl-C, SIGTERM, SIGHUP).
func runSession(ctx context.Context, e env, log *slog.Logger, pair *configregistry.TransportPair, binder *netbind.Binder, hops []netip.Addr) error {
	var transportStarted atomic.Bool
	notify := func() {
		if pair.PacketRelay.NotifyNetworkChanged != nil {
			pair.PacketRelay.NotifyNetworkChanged()
		}
	}
	opts := tunnel.Options{
		Router:  &sysrouter.Router{Exec: e.exec},
		Store:   state.FileStore{Dir: e.stateDir},
		OpenTUN: e.openTUN,
		StartTransport: func(ctx context.Context, tun tunnel.TUN) (func(), error) {
			stop, err := e.startTransport(ctx, tun, pair, log)
			if err == nil {
				transportStarted.Store(true)
			}
			return stop, err
		},
		FirstHops:     hops,
		LocalPrefixes: e.localPrefixes,
		// Bind the transport's sockets to the physical interface before it
		// starts, and follow the interface when the network changes.
		OnNetwork: func(route sysrouter.DefaultRoute, resolvers []netip.Addr) error {
			if err := binder.SetInterface(route.Interface); err != nil {
				return err
			}
			binder.SetResolvers(resolvers)
			log.Debug("sockets bound", "interface", route.Interface, "resolvers", fmt.Sprint(binder.Resolvers()))
			if transportStarted.Load() {
				notify()
			}
			return nil
		},
		Verify: e.verify(verifyInput{pair: pair, direct: binder.StreamDialer(), firstHops: hops, log: log}),
		Logger: log,
	}
	binder.SetLogger(log)

	session, err := tunnel.Up(ctx, opts)
	if err != nil {
		return err
	}
	name, _ := binder.Interface()
	fmt.Fprintf(e.stdout, "connected: traffic goes through the tunnel (bound to %s). Press Ctrl-C to disconnect.\n", name)

	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	interval := e.watchInterval
	if interval == 0 {
		interval = defaultWatchInterval
	}
	go session.Watch(watchCtx, interval)

	<-ctx.Done()
	stopWatch()
	log.Info("disconnecting")
	downCtx, cancel := context.WithTimeout(context.Background(), disconnectTimeout)
	defer cancel()
	if err := session.Down(downCtx); err != nil {
		return fmt.Errorf("restoring the network failed: %w; fix it with: sudo outline-cli cleanup", err)
	}
	fmt.Fprintln(e.stdout, "disconnected: routes, DNS and IPv6 are restored")
	return nil
}

// startRemoteDevice connects the lwIP stack to the transport, waits for the
// TCP health check, then relays packets between the utun and the stack.
func startRemoteDevice(ctx context.Context, tun tunnel.TUN, pair *configregistry.TransportPair, log *slog.Logger) (func(), error) {
	device, err := vpn.ConnectRemoteDevice(ctx, pair, pair.PacketRelay)
	if err != nil {
		return nil, err
	}
	// As Client.StartSession does: start the UDP check, which switches DNS
	// from TCP-only (truncate) to UDP when UDP works.
	if pair.PacketRelay.NotifyNetworkChanged != nil {
		pair.PacketRelay.NotifyNetworkChanged()
	}
	if err := device.GetHealthStatus(); err != nil {
		device.Close()
		return nil, fmt.Errorf("the server can't be reached over TCP: %w", err)
	}
	log.Info("the server is reachable")
	go vpn.RelayTraffic(device, tun)
	go vpn.RelayTraffic(tun, device)
	return func() { device.Close() }, nil
}
