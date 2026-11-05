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

package sysrouter

import (
	"bufio"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// DefaultRoute is an IPv4 default route.
type DefaultRoute struct {
	Interface string
	// Gateway is the next hop. It is invalid for interface (link#N) routes.
	Gateway netip.Addr
	// Scoped is true for interface-scoped defaults (flag I), which macOS keeps
	// for every active interface besides the primary one.
	Scoped bool
}

// String describes the route for logs.
func (d DefaultRoute) String() string {
	if d.Gateway.IsValid() {
		return d.Gateway.String() + " on " + d.Interface
	}
	return d.Interface
}

// parseNetstatDefaults parses `netstat -rn -f inet` and returns every IPv4
// default route, in table order.
func parseNetstatDefaults(out string) ([]DefaultRoute, error) {
	var routes []DefaultRoute
	inInternet := false
	sawHeader := false
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "Internet:":
			inInternet = true
			continue
		case strings.HasSuffix(line, ":") && !strings.Contains(line, " "):
			// Another section (for example "Internet6:").
			inInternet = false
			continue
		}
		if !inInternet || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if fields[0] == "Destination" {
			sawHeader = true
			continue
		}
		if fields[0] != "default" || len(fields) < 4 {
			continue
		}
		route := DefaultRoute{Interface: fields[3], Scoped: strings.Contains(fields[2], "I")}
		if gw, err := netip.ParseAddr(fields[1]); err == nil {
			route.Gateway = gw
		} else if !strings.HasPrefix(fields[1], "link#") {
			return nil, fmt.Errorf("unexpected default gateway %q in netstat output", fields[1])
		}
		routes = append(routes, route)
	}
	if !sawHeader {
		return nil, fmt.Errorf("unexpected netstat output: no IPv4 routing table found")
	}
	return routes, nil
}

// PrimaryDefault returns the first unscoped default route that isn't on
// ignoreIface (the CLI's own utun).
func PrimaryDefault(routes []DefaultRoute, ignoreIface string) (DefaultRoute, bool) {
	for _, r := range routes {
		if !r.Scoped && r.Interface != ignoreIface {
			return r, true
		}
	}
	return DefaultRoute{}, false
}

// ActiveInterfaces returns the distinct interfaces that have a default route,
// ignoring ignoreIface.
func ActiveInterfaces(routes []DefaultRoute, ignoreIface string) []string {
	var ifaces []string
	seen := map[string]bool{}
	for _, r := range routes {
		if r.Interface == ignoreIface || seen[r.Interface] {
			continue
		}
		seen[r.Interface] = true
		ifaces = append(ifaces, r.Interface)
	}
	return ifaces
}

var (
	serviceLine = regexp.MustCompile(`^\((\d+|\*)\)\s+(.+)$`)
	deviceLine  = regexp.MustCompile(`Device:\s*([^)\s]+)\s*\)`)
)

// parseServiceForDevice parses `networksetup -listnetworkserviceorder` and
// returns the enabled service bound to device.
func parseServiceForDevice(out, device string) (string, error) {
	var service string
	disabled := false
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if m := serviceLine.FindStringSubmatch(line); m != nil {
			service = m[2]
			disabled = m[1] == "*" || strings.HasPrefix(service, "*")
			continue
		}
		if m := deviceLine.FindStringSubmatch(line); m != nil && service != "" {
			if m[1] == device && !disabled {
				return service, nil
			}
			service = ""
		}
	}
	return "", fmt.Errorf("no enabled network service uses interface %s", device)
}

// parseDNSServers parses `networksetup -getdnsservers SERVICE`. nil means no
// servers are set manually (they come from DHCP), restored with "empty".
func parseDNSServers(out string) ([]string, error) {
	text := strings.TrimSpace(out)
	if text == "" || strings.HasPrefix(text, "There aren't any DNS Servers set") {
		return nil, nil
	}
	var servers []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := netip.ParseAddr(line); err != nil {
			return nil, fmt.Errorf("unexpected DNS server line %q", line)
		}
		servers = append(servers, line)
	}
	return servers, nil
}

var (
	resolverHeader = regexp.MustCompile(`^resolver #\d+`)
	nameserverLine = regexp.MustCompile(`^nameserver\[\d+\]\s*:\s*(\S+)`)
	ifIndexLine    = regexp.MustCompile(`^if_index\s*:\s*\d+\s*\(([^)]+)\)`)
)

type scutilResolver struct {
	scoped      bool
	iface       string
	nameservers []netip.Addr
}

// parseScutilDNS parses `scutil --dns` into resolvers.
func parseScutilDNS(out string) []scutilResolver {
	var resolvers []scutilResolver
	var cur *scutilResolver
	scoped := false
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "DNS configuration"):
			scoped = strings.Contains(line, "scoped")
			cur = nil
		case resolverHeader.MatchString(line):
			resolvers = append(resolvers, scutilResolver{scoped: scoped})
			cur = &resolvers[len(resolvers)-1]
		case cur != nil:
			if m := nameserverLine.FindStringSubmatch(line); m != nil {
				addr, err := netip.ParseAddr(m[1])
				if err == nil {
					cur.nameservers = append(cur.nameservers, addr)
				}
			} else if m := ifIndexLine.FindStringSubmatch(line); m != nil {
				cur.iface = m[1]
			}
		}
	}
	return resolvers
}

// pickSystemResolvers chooses the resolvers for direct lookups: the scoped
// resolver of iface if there is one, else the first default resolver with
// nameservers. Addresses in exclude (the CLI's own DNS address) are dropped.
func pickSystemResolvers(resolvers []scutilResolver, iface string, exclude netip.Addr) []netip.Addr {
	filter := func(addrs []netip.Addr) []netip.Addr {
		var out []netip.Addr
		for _, a := range addrs {
			if a != exclude {
				out = append(out, a)
			}
		}
		return out
	}
	for _, r := range resolvers {
		if r.scoped && r.iface == iface {
			if addrs := filter(r.nameservers); len(addrs) > 0 {
				return addrs
			}
		}
	}
	for _, r := range resolvers {
		if !r.scoped {
			if addrs := filter(r.nameservers); len(addrs) > 0 {
				return addrs
			}
		}
	}
	return nil
}

// IPv6Mode is a network service's IPv6 configuration method.
type IPv6Mode string

const (
	IPv6Automatic IPv6Mode = "Automatic"
	IPv6Manual    IPv6Mode = "Manual"
	IPv6Off       IPv6Mode = "Off"
	// IPv6Unknown is any other value. The CLI never changes IPv6 it can't restore.
	IPv6Unknown IPv6Mode = "Unknown"
)

// IPv6Config is a service's IPv6 setting, as needed to restore it.
type IPv6Config struct {
	Mode IPv6Mode `json:"mode"`
	// Raw is the mode as networksetup printed it.
	Raw string `json:"raw,omitempty"`
	// For Manual only.
	Address      string `json:"address,omitempty"`
	PrefixLength int    `json:"prefixLength,omitempty"`
	Router       string `json:"router,omitempty"`
}

// Restorable reports whether the CLI can put this setting back exactly.
func (c IPv6Config) Restorable() bool {
	switch c.Mode {
	case IPv6Automatic, IPv6Off:
		return true
	case IPv6Manual:
		_, addrErr := netip.ParseAddr(c.Address)
		_, routerErr := netip.ParseAddr(c.Router)
		return addrErr == nil && routerErr == nil && c.PrefixLength > 0 && c.PrefixLength <= 128
	default:
		return false
	}
}

// parseIPv6Info parses the IPv6 lines of `networksetup -getinfo SERVICE`.
func parseIPv6Info(out string) (IPv6Config, error) {
	var cfg IPv6Config
	found := false
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch strings.ToLower(key) {
		case "ipv6":
			found = true
			cfg.Raw = value
			switch strings.ToLower(value) {
			case "automatic":
				cfg.Mode = IPv6Automatic
			case "manual":
				cfg.Mode = IPv6Manual
			case "off":
				cfg.Mode = IPv6Off
			default:
				cfg.Mode = IPv6Unknown
			}
		case "ipv6 ip address":
			cfg.Address = value
		case "ipv6 router":
			cfg.Router = value
		case "ipv6 prefix length":
			if n, err := strconv.Atoi(value); err == nil {
				cfg.PrefixLength = n
			}
		}
	}
	if !found {
		return IPv6Config{}, fmt.Errorf("no IPv6 line in networksetup -getinfo output")
	}
	return cfg, nil
}

// routeGetResult is the matched route reported by `route -n get`.
type routeGetResult struct {
	destination netip.Addr
	bits        int // -1 if no mask was printed (a host route)
	// cloned is true for a route the kernel cloned (flag WASCLONED): a
	// per-destination cache entry, not configuration.
	cloned bool
}

// parseRouteGet parses `route -n get ...`.
func parseRouteGet(out string) (routeGetResult, error) {
	res := routeGetResult{bits: -1}
	sawDest := false
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "destination":
			sawDest = true
			if value == "default" {
				res.destination = netip.IPv4Unspecified()
				continue
			}
			addr, err := netip.ParseAddr(value)
			if err != nil {
				// A name such as "localhost" can't be one of our routes.
				res.destination = netip.Addr{}
				continue
			}
			res.destination = addr
		case "mask":
			if value == "default" {
				res.bits = 0
				continue
			}
			mask, err := netip.ParseAddr(value)
			if err != nil || !mask.Is4() {
				return res, fmt.Errorf("unexpected mask %q in route output", value)
			}
			res.bits = maskBits(mask)
		case "flags":
			res.cloned = strings.Contains(value, "WASCLONED")
		}
	}
	if !sawDest {
		return res, fmt.Errorf("no destination in route output")
	}
	return res, nil
}

// maskBits counts the leading ones of an IPv4 netmask, or returns -1 if the
// mask isn't contiguous.
func maskBits(mask netip.Addr) int {
	b := mask.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := 0
	for v&0x80000000 != 0 {
		n++
		v <<= 1
	}
	if v != 0 {
		return -1
	}
	return n
}

// matches reports whether the route found is exactly dst.
func (r routeGetResult) matches(dst netip.Prefix) bool {
	if !r.destination.IsValid() || r.destination != dst.Addr() {
		return false
	}
	bits := r.bits
	if bits == -1 {
		bits = 32
	}
	return bits == dst.Bits()
}

var dhcpDNSLine = regexp.MustCompile(`^domain_name_server\s*\([^)]*\)\s*:\s*\{([^}]*)\}`)

// parseDHCPResolvers parses the DNS servers from `ipconfig getpacket IFACE`,
// for example "domain_name_server (ip_mult): {172.20.10.1, 8.8.8.8}".
func parseDHCPResolvers(out string) []netip.Addr {
	var addrs []netip.Addr
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		m := dhcpDNSLine.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
		if m == nil {
			continue
		}
		for _, field := range strings.Split(m[1], ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(field)); err == nil {
				addrs = append(addrs, a)
			}
		}
	}
	return addrs
}

// parseInetAddrs returns the IPv4 addresses ("inet A.B.C.D netmask ...")
// from `ifconfig IFACE`.
func parseInetAddrs(out string) []netip.Addr {
	var addrs []netip.Addr
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "inet" {
			continue
		}
		if a, err := netip.ParseAddr(fields[1]); err == nil && a.Is4() {
			addrs = append(addrs, a)
		}
	}
	return addrs
}
