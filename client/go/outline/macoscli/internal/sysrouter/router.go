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

// Package sysrouter reads and changes macOS routes, DNS and IPv6 settings by
// running route, netstat, networksetup, scutil, ifconfig and friends through a
// sysexec.Executor. It builds the exact commands; it never decides what to
// change (that is the tunnel package's job).
package sysrouter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"localhost/client/go/outline/macoscli/internal/sysexec"
)

// OutlineDNS is the link-local resolver address the transport intercepts.
// Must match linkLocalDNS in client/go/outline/configregistry/outline_dns_intercept.go.
var OutlineDNS = netip.MustParseAddr("169.254.113.53")

// RouteSpec is an IPv4 route. Exactly one of Gateway and Interface is set.
type RouteSpec struct {
	Dst       netip.Prefix `json:"dst"`
	Gateway   netip.Addr   `json:"gateway,omitzero"`
	Interface string       `json:"interface,omitempty"`
}

func (r RouteSpec) String() string {
	if r.Gateway.IsValid() {
		return r.Dst.String() + " via " + r.Gateway.String()
	}
	return r.Dst.String() + " on " + r.Interface
}

// SystemRouter is everything the tunnel manager needs from the system.
type SystemRouter interface {
	DefaultRoutes(ctx context.Context) ([]DefaultRoute, error)
	ServiceForInterface(ctx context.Context, iface string) (string, error)
	DNSServers(ctx context.Context, service string) ([]string, error)
	SystemResolvers(ctx context.Context, iface string) ([]netip.Addr, error)
	IPv6(ctx context.Context, service string) (IPv6Config, error)
	ConfigureUTun(ctx context.Context, name string, local, peer netip.Addr) error
	RouteExists(ctx context.Context, dst netip.Prefix) (bool, error)
	AddRoute(ctx context.Context, r RouteSpec) (added bool, err error)
	DeleteRoute(ctx context.Context, r RouteSpec) error
	SetDNS(ctx context.Context, service string, servers []string) error
	SetIPv6(ctx context.Context, service string, c IPv6Config) error
	FlushDNSCache(ctx context.Context) error
}

// Router implements SystemRouter with macOS commands.
type Router struct {
	Exec sysexec.Executor
}

var _ SystemRouter = (*Router)(nil)

// IsReadOnly reports whether a call only reads system state. The dry run
// executes these and nothing else.
func IsReadOnly(c sysexec.Call) bool {
	switch c.Name {
	case "netstat":
		return true
	case "scutil":
		return len(c.Args) == 1 && c.Args[0] == "--dns"
	case "route":
		return len(c.Args) >= 2 && c.Args[0] == "-n" && c.Args[1] == "get"
	case "networksetup":
		if len(c.Args) == 0 {
			return false
		}
		switch c.Args[0] {
		case "-listnetworkserviceorder", "-listallnetworkservices", "-getdnsservers", "-getinfo":
			return true
		}
	}
	return false
}

func (r *Router) run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := r.Exec.Run(ctx, sysexec.Cmd(name, args...))
	return string(out), err
}

// DefaultRoutes returns all IPv4 default routes.
func (r *Router) DefaultRoutes(ctx context.Context) ([]DefaultRoute, error) {
	out, err := r.run(ctx, "netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	return parseNetstatDefaults(out)
}

// ServiceForInterface returns the network service name of an interface.
func (r *Router) ServiceForInterface(ctx context.Context, iface string) (string, error) {
	out, err := r.run(ctx, "networksetup", "-listnetworkserviceorder")
	if err != nil {
		return "", err
	}
	return parseServiceForDevice(out, iface)
}

// DNSServers returns the manually set DNS servers of a service; nil means none
// (DHCP-provided).
func (r *Router) DNSServers(ctx context.Context, service string) ([]string, error) {
	out, err := r.run(ctx, "networksetup", "-getdnsservers", service)
	if err != nil {
		return nil, err
	}
	return parseDNSServers(out)
}

// SystemResolvers returns the resolvers in effect for iface, excluding OutlineDNS.
func (r *Router) SystemResolvers(ctx context.Context, iface string) ([]netip.Addr, error) {
	out, err := r.run(ctx, "scutil", "--dns")
	if err != nil {
		return nil, err
	}
	return pickSystemResolvers(parseScutilDNS(out), iface, OutlineDNS), nil
}

// IPv6 returns a service's IPv6 setting.
func (r *Router) IPv6(ctx context.Context, service string) (IPv6Config, error) {
	out, err := r.run(ctx, "networksetup", "-getinfo", service)
	if err != nil {
		return IPv6Config{}, err
	}
	return parseIPv6Info(out)
}

// ConfigureUTun assigns a point-to-point address to the utun and brings it up.
func (r *Router) ConfigureUTun(ctx context.Context, name string, local, peer netip.Addr) error {
	_, err := r.run(ctx, "ifconfig", name, "inet", local.String(), peer.String(),
		"netmask", "255.255.255.255", "mtu", "1500", "up")
	return err
}

// RouteExists reports whether a route for exactly dst is already in the table.
func (r *Router) RouteExists(ctx context.Context, dst netip.Prefix) (bool, error) {
	out, err := r.run(ctx, "route", append([]string{"-n", "get"}, destArgs(dst)...)...)
	if err != nil {
		if isNotInTable(out, err) {
			return false, nil
		}
		return false, err
	}
	res, err := parseRouteGet(out)
	if err != nil {
		return false, err
	}
	return res.matches(dst), nil
}

// AddRoute adds a route. added is false if the route already existed.
func (r *Router) AddRoute(ctx context.Context, spec RouteSpec) (bool, error) {
	args, err := routeArgs("add", spec)
	if err != nil {
		return false, err
	}
	out, err := r.run(ctx, "route", args...)
	if strings.Contains(out+sysexec.OutputOf(err), "File exists") {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// DeleteRoute deletes a route. A missing route is not an error.
func (r *Router) DeleteRoute(ctx context.Context, spec RouteSpec) error {
	args, err := routeArgs("delete", spec)
	if err != nil {
		return err
	}
	out, err := r.run(ctx, "route", args...)
	if err != nil && isNotInTable(out, err) {
		return nil
	}
	return err
}

func isNotInTable(out string, err error) bool {
	return strings.Contains(out+sysexec.OutputOf(err), "not in table")
}

func destArgs(dst netip.Prefix) []string {
	if dst.IsSingleIP() {
		return []string{"-host", dst.Addr().String()}
	}
	return []string{"-net", dst.String()}
}

func routeArgs(verb string, spec RouteSpec) ([]string, error) {
	if !spec.Dst.IsValid() || !spec.Dst.Addr().Is4() {
		return nil, fmt.Errorf("invalid IPv4 route destination %v", spec.Dst)
	}
	args := append([]string{"-n", verb}, destArgs(spec.Dst.Masked())...)
	switch {
	case spec.Gateway.IsValid() && spec.Interface == "":
		args = append(args, spec.Gateway.String())
	case !spec.Gateway.IsValid() && spec.Interface != "":
		args = append(args, "-interface", spec.Interface)
	default:
		return nil, fmt.Errorf("route %v needs exactly one of a gateway or an interface", spec.Dst)
	}
	return args, nil
}

// SetDNS sets a service's DNS servers. nil restores DHCP-provided servers.
func (r *Router) SetDNS(ctx context.Context, service string, servers []string) error {
	args := []string{"-setdnsservers", service}
	if len(servers) == 0 {
		args = append(args, "empty")
	} else {
		args = append(args, servers...)
	}
	_, err := r.run(ctx, "networksetup", args...)
	return err
}

// SetIPv6 applies an IPv6 setting to a service.
func (r *Router) SetIPv6(ctx context.Context, service string, c IPv6Config) error {
	var args []string
	switch c.Mode {
	case IPv6Automatic:
		args = []string{"-setv6automatic", service}
	case IPv6Off:
		args = []string{"-setv6off", service}
	case IPv6Manual:
		if !c.Restorable() {
			return errors.New("incomplete manual IPv6 setting")
		}
		args = []string{"-setv6manual", service, c.Address, strconv.Itoa(c.PrefixLength), c.Router}
	default:
		return fmt.Errorf("can't apply IPv6 mode %q", c.Raw)
	}
	_, err := r.run(ctx, "networksetup", args...)
	return err
}

// FlushDNSCache flushes the system DNS caches.
func (r *Router) FlushDNSCache(ctx context.Context) error {
	_, err1 := r.run(ctx, "dscacheutil", "-flushcache")
	_, err2 := r.run(ctx, "killall", "-HUP", "mDNSResponder")
	return errors.Join(err1, err2)
}
