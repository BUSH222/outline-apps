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

// Package fakemac simulates the parts of macOS the CLI changes (routes, DNS,
// IPv6, network services) behind a sysexec.Executor, for tests. It answers the
// same commands as the real tools, in the same output formats the parsers
// expect, and can inject failures or a crash before any mutating command.
package fakemac

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
)

// Service is a network service.
type Service struct {
	Name   string
	Device string
}

// Network is one physical network the Mac can be on.
type Network struct {
	Service   Service
	Gateway   netip.Addr
	Resolvers []netip.Addr // DHCP-provided
}

// Snapshot is the comparable part of the system state.
type Snapshot struct {
	Routes []string // sorted RouteSpec strings
	DNS    map[string]string
	IPv6   map[string]sysrouter.IPv6Config
}

// Crash is panicked by the executor to simulate the process dying.
type Crash struct{ Call sysexec.Call }

// Mac is a simulated Mac. Lock-protected; safe for concurrent use.
type Mac struct {
	mu       sync.Mutex
	services []Service
	primary  *Network
	others   []*Network
	routes   map[netip.Prefix]sysrouter.RouteSpec
	cloned   map[netip.Prefix]bool // kernel cache entries (WASCLONED)
	dns      map[string][]string   // manual DNS; nil = DHCP
	ipv6     map[string]sysrouter.IPv6Config
	utuns    map[string]string
	flushes  int
	mutation int

	// BeforeMutation, if set, runs before each mutating command with its
	// 1-based index. Returning an error fails the command; it may also panic
	// with Crash.
	BeforeMutation func(n int, c sysexec.Call) error
}

// WiFi is the default primary network: Wi-Fi on en0 behind 192.168.1.1.
var WiFi = Network{
	Service:   Service{Name: "Wi-Fi", Device: "en0"},
	Gateway:   netip.MustParseAddr("192.168.1.1"),
	Resolvers: []netip.Addr{netip.MustParseAddr("192.168.1.1")},
}

// Ethernet is a second network on en7.
var Ethernet = Network{
	Service:   Service{Name: "USB 10/100/1000 LAN", Device: "en7"},
	Gateway:   netip.MustParseAddr("10.20.0.1"),
	Resolvers: []netip.Addr{netip.MustParseAddr("10.20.0.53")},
}

// New returns a Mac on Wi-Fi with IPv6 Automatic, DHCP DNS and the usual
// link-local route on en0, plus an Ethernet service that is not connected.
func New() *Mac {
	wifi := WiFi
	m := &Mac{
		services: []Service{WiFi.Service, Ethernet.Service},
		primary:  &wifi,
		routes:   map[netip.Prefix]sysrouter.RouteSpec{},
		cloned:   map[netip.Prefix]bool{},
		dns:      map[string][]string{},
		ipv6: map[string]sysrouter.IPv6Config{
			WiFi.Service.Name:     {Mode: sysrouter.IPv6Automatic, Raw: "Automatic"},
			Ethernet.Service.Name: {Mode: sysrouter.IPv6Automatic, Raw: "Automatic"},
		},
		utuns: map[string]string{},
	}
	link := netip.MustParsePrefix("169.254.0.0/16")
	m.routes[link] = sysrouter.RouteSpec{Dst: link, Interface: "en0"}
	return m
}

// Executor returns an executor backed by this Mac.
func (m *Mac) Executor() *sysexec.Fake {
	return &sysexec.Fake{Handler: m.handle}
}

// SetManualDNS sets a service's manual DNS servers (nil = DHCP).
func (m *Mac) SetManualDNS(service string, servers []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dns[service] = servers
}

// SetIPv6 sets a service's IPv6 configuration.
func (m *Mac) SetIPv6(service string, c sysrouter.IPv6Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipv6[service] = c
}

// AddExistingRoute adds a route that the CLI did not create.
func (m *Mac) AddExistingRoute(r sysrouter.RouteSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes[r.Dst] = r
}

// AddClonedRoute adds a kernel-cloned host route, as macOS creates for a
// recently contacted host. Cloned routes are a cache and are left out of
// snapshots.
func (m *Mac) AddClonedRoute(host string, gateway netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dst := netip.PrefixFrom(netip.MustParseAddr(host), 32)
	m.routes[dst] = sysrouter.RouteSpec{Dst: dst, Gateway: gateway}
	m.cloned[dst] = true
}

// SwitchTo makes n the primary network, as when joining another network.
func (m *Mac) SwitchTo(n Network) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.primary = &n
}

// GoOffline removes the default route.
func (m *Mac) GoOffline() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.primary = nil
}

// AlsoConnected adds another active network (a scoped default route).
func (m *Mac) AlsoConnected(n Network) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.others = append(m.others, &n)
}

// DestroyUTun simulates the kernel removing a utun and its routes when the
// process that opened it dies.
func (m *Mac) DestroyUTun(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.utuns, name)
	for dst, r := range m.routes {
		if r.Interface == name {
			delete(m.routes, dst)
		}
	}
}

// Flushes returns how many DNS cache flushes ran.
func (m *Mac) Flushes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushes
}

// UTunAddress returns the address configured on a utun.
func (m *Mac) UTunAddress(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.utuns[name]
}

// Snapshot returns the comparable system state.
func (m *Mac) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{DNS: map[string]string{}, IPv6: map[string]sysrouter.IPv6Config{}}
	for dst, r := range m.routes {
		if !m.cloned[dst] {
			s.Routes = append(s.Routes, r.String())
		}
	}
	sort.Strings(s.Routes)
	for _, svc := range m.services {
		servers := m.dns[svc.Name]
		if servers == nil {
			s.DNS[svc.Name] = "DHCP"
		} else {
			s.DNS[svc.Name] = strings.Join(servers, ",")
		}
		s.IPv6[svc.Name] = m.ipv6[svc.Name]
	}
	return s
}

// HasRoute reports whether a route to dst exists.
func (m *Mac) HasRoute(dst string) (sysrouter.RouteSpec, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.routes[netip.MustParsePrefix(dst)]
	return r, ok
}

func (m *Mac) handle(c sysexec.Call) ([]byte, error) {
	if !sysrouter.IsReadOnly(c) {
		m.mu.Lock()
		m.mutation++
		n := m.mutation
		before := m.BeforeMutation
		m.mu.Unlock()
		if before != nil {
			if err := before(n, c); err != nil {
				return nil, &sysexec.CommandError{Call: c, ExitCode: 1, Output: err.Error(), Err: err}
			}
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out, failure := m.dispatch(c)
	if failure != "" {
		return []byte(out), &sysexec.CommandError{Call: c, ExitCode: 1, Output: out + failure, Err: errors.New("exit status 1")}
	}
	return []byte(out), nil
}

func (m *Mac) serviceByName(name string) (Service, bool) {
	for _, s := range m.services {
		if s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}

// dispatch returns the output and, for a failure, the error text.
func (m *Mac) dispatch(c sysexec.Call) (string, string) {
	a := c.Args
	switch c.Name {
	case "netstat":
		return m.netstat(), ""
	case "scutil":
		return m.scutilDNS(), ""
	case "networksetup":
		return m.networksetup(a)
	case "route":
		return m.route(a)
	case "ifconfig":
		if len(a) < 4 || !strings.HasPrefix(a[0], "utun") {
			return "", "ifconfig: unexpected arguments\n"
		}
		m.utuns[a[0]] = a[2]
		return "", ""
	case "ipconfig":
		return m.ipconfig(a)
	case "dscacheutil", "killall":
		m.flushes++
		return "", ""
	}
	return "", fmt.Sprintf("fakemac: unknown command %s\n", c)
}

func (m *Mac) netstat() string {
	var b strings.Builder
	b.WriteString("Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n")
	if m.primary != nil {
		fmt.Fprintf(&b, "default            %-18s UGScg               %5s\n", m.primary.Gateway, m.primary.Service.Device)
	}
	for _, n := range m.others {
		fmt.Fprintf(&b, "default            %-18s UGScIg              %5s\n", n.Gateway, n.Service.Device)
	}
	b.WriteString("127                127.0.0.1          UCS                   lo0\n")
	return b.String()
}

func (m *Mac) effectiveResolvers(n *Network) []string {
	if manual := m.dns[n.Service.Name]; manual != nil {
		return manual
	}
	var out []string
	for _, r := range n.Resolvers {
		out = append(out, r.String())
	}
	return out
}

func (m *Mac) scutilDNS() string {
	var b strings.Builder
	b.WriteString("DNS configuration\n\n")
	if m.primary != nil {
		b.WriteString("resolver #1\n")
		for i, r := range m.effectiveResolvers(m.primary) {
			fmt.Fprintf(&b, "  nameserver[%d] : %s\n", i, r)
		}
		fmt.Fprintf(&b, "  if_index : 6 (%s)\n\n", m.primary.Service.Device)
	}
	b.WriteString("DNS configuration (for scoped queries)\n\n")
	all := append([]*Network(nil), m.others...)
	if m.primary != nil {
		all = append([]*Network{m.primary}, all...)
	}
	for i, n := range all {
		fmt.Fprintf(&b, "resolver #%d\n", i+1)
		for j, r := range m.effectiveResolvers(n) {
			fmt.Fprintf(&b, "  nameserver[%d] : %s\n", j, r)
		}
		fmt.Fprintf(&b, "  if_index : %d (%s)\n  flags    : Scoped\n\n", 6+i, n.Service.Device)
	}
	return b.String()
}

func (m *Mac) networksetup(a []string) (string, string) {
	if len(a) == 0 {
		return "", "networksetup: missing arguments\n"
	}
	if a[0] == "-listnetworkserviceorder" {
		var b strings.Builder
		b.WriteString("An asterisk (*) denotes that a network service is disabled.\n")
		for i, s := range m.services {
			fmt.Fprintf(&b, "(%d) %s\n(Hardware Port: %s, Device: %s)\n\n", i+1, s.Name, s.Name, s.Device)
		}
		return b.String(), ""
	}
	if len(a) < 2 {
		return "", "networksetup: missing service\n"
	}
	svc, ok := m.serviceByName(a[1])
	if !ok {
		return "", a[1] + " is not a recognized network service.\n"
	}
	switch a[0] {
	case "-getdnsservers":
		servers := m.dns[svc.Name]
		if servers == nil {
			return fmt.Sprintf("There aren't any DNS Servers set on %s.\n", svc.Name), ""
		}
		return strings.Join(servers, "\n") + "\n", ""
	case "-getinfo":
		v6 := m.ipv6[svc.Name]
		out := "DHCP Configuration\nIP address: 192.168.1.23\nIPv6: " + v6.Raw + "\n"
		if v6.Mode == sysrouter.IPv6Manual {
			out += fmt.Sprintf("IPv6 IP address: %s\nIPv6 Prefix Length: %d\nIPv6 Router: %s\n", v6.Address, v6.PrefixLength, v6.Router)
		} else {
			out += "IPv6 IP address: none\nIPv6 Router: none\n"
		}
		return out, ""
	case "-setdnsservers":
		if len(a) < 3 {
			return "", "networksetup: missing servers\n"
		}
		if a[2] == "empty" {
			m.dns[svc.Name] = nil
		} else {
			m.dns[svc.Name] = append([]string(nil), a[2:]...)
		}
		return "", ""
	case "-setv6off":
		m.ipv6[svc.Name] = sysrouter.IPv6Config{Mode: sysrouter.IPv6Off, Raw: "Off"}
		return "", ""
	case "-setv6automatic":
		m.ipv6[svc.Name] = sysrouter.IPv6Config{Mode: sysrouter.IPv6Automatic, Raw: "Automatic"}
		return "", ""
	case "-setv6manual":
		if len(a) != 5 {
			return "", "networksetup: bad -setv6manual arguments\n"
		}
		prefix, _ := strconv.Atoi(a[3])
		m.ipv6[svc.Name] = sysrouter.IPv6Config{Mode: sysrouter.IPv6Manual, Raw: "Manual", Address: a[2], PrefixLength: prefix, Router: a[4]}
		return "", ""
	}
	return "", "networksetup: unsupported " + a[0] + "\n"
}

func (m *Mac) route(a []string) (string, string) {
	if len(a) < 4 || a[0] != "-n" {
		return "", "route: unsupported arguments\n"
	}
	verb := a[1]
	var dst netip.Prefix
	switch a[2] {
	case "-net":
		p, err := netip.ParsePrefix(a[3])
		if err != nil {
			return "", "route: bad address\n"
		}
		dst = p.Masked()
	case "-host":
		addr, err := netip.ParseAddr(a[3])
		if err != nil {
			return "", "route: bad address\n"
		}
		dst = netip.PrefixFrom(addr, 32)
	default:
		return "", "route: unsupported destination\n"
	}
	rest := a[4:]
	switch verb {
	case "get":
		if r, ok := m.routes[dst]; ok {
			out := "destination: " + r.Dst.Addr().String() + "\n"
			if !r.Dst.IsSingleIP() {
				out += "       mask: " + maskString(r.Dst.Bits()) + "\n"
			}
			if m.cloned[dst] {
				out += "      flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF>\n"
			} else {
				out += "      flags: <UP,DONE,STATIC>\n"
			}
			return out, ""
		}
		if m.primary == nil {
			return "", "route: writing to routing socket: not in table\n"
		}
		return "destination: default\n       mask: default\n    gateway: " + m.primary.Gateway.String() + "\n", ""
	case "add":
		spec := sysrouter.RouteSpec{Dst: dst}
		switch {
		case len(rest) == 2 && rest[0] == "-interface":
			spec.Interface = rest[1]
		case len(rest) == 1:
			spec.Gateway = netip.MustParseAddr(rest[0])
		default:
			return "", "route: bad gateway\n"
		}
		if _, ok := m.routes[dst]; ok {
			return "", "route: writing to routing socket: File exists\nadd net " + dst.String() + ": File exists\n"
		}
		m.routes[dst] = spec
		return "add net " + dst.String() + "\n", ""
	case "delete":
		if _, ok := m.routes[dst]; !ok {
			return "", "route: writing to routing socket: not in table\ndelete net " + dst.String() + ": not in table\n"
		}
		delete(m.routes, dst)
		delete(m.cloned, dst)
		return "delete net " + dst.String() + "\n", ""
	}
	return "", "route: unsupported verb\n"
}

func maskString(bits int) string {
	var v uint32
	if bits > 0 {
		v = ^uint32(0) << (32 - bits)
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
}

// ipconfig answers `ipconfig getpacket IFACE` with the network's DHCP lease,
// which lists the DHCP-provided DNS servers whatever DNS is set manually.
func (m *Mac) ipconfig(a []string) (string, string) {
	if len(a) != 2 || a[0] != "getpacket" {
		return "", "ipconfig: unsupported arguments\n"
	}
	all := append([]*Network(nil), m.others...)
	if m.primary != nil {
		all = append(all, m.primary)
	}
	for _, n := range all {
		if n.Service.Device != a[1] {
			continue
		}
		var dns []string
		for _, r := range n.Resolvers {
			dns = append(dns, r.String())
		}
		return fmt.Sprintf("op = BOOTREPLY\noptions:\nrouter (ip_mult): {%s}\ndomain_name_server (ip_mult): {%s}\nend (none): \n",
			n.Gateway, strings.Join(dns, ", ")), ""
	}
	return "", " "
}

// Hotspot is a network on the same Wi-Fi interface as WiFi, with its own
// gateway and DHCP-provided DNS, like an iPhone hotspot.
var Hotspot = Network{
	Service:   WiFi.Service,
	Gateway:   netip.MustParseAddr("172.20.10.1"),
	Resolvers: []netip.Addr{netip.MustParseAddr("172.20.10.1")},
}
