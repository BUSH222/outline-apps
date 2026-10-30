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
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"localhost/client/go/outline/macoscli/internal/sysexec"

	"github.com/stretchr/testify/require"
)

// Fixtures follow the documented macOS output formats. Addresses are from
// private and documentation ranges; MAC addresses are fake.

const netstatFixture = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            10.20.0.1          UGScIg                en7
default            link#22            UCSIg               utun3
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#6             UCS                   en0      !
192.168.1          link#6             UCS                   en0      !
192.168.1.1/32     link#6             UCS                   en0      !
192.168.1.1        02:00:00:00:00:01  UHLWIir               en0   1175

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::1%en0                             UGcg                  en0
`

func TestParseNetstatDefaults(t *testing.T) {
	routes, err := parseNetstatDefaults(netstatFixture)
	require.NoError(t, err)
	require.Equal(t, []DefaultRoute{
		{Interface: "en0", Gateway: netip.MustParseAddr("192.168.1.1")},
		{Interface: "en7", Gateway: netip.MustParseAddr("10.20.0.1"), Scoped: true},
		{Interface: "utun3", Scoped: true},
	}, routes)

	primary, ok := PrimaryDefault(routes, "")
	require.True(t, ok)
	require.Equal(t, "en0", primary.Interface)
	require.Equal(t, []string{"en0", "en7"}, ActiveInterfaces(routes, "utun3"))
}

func TestParseNetstatDefaults_LinkRouteAndOurUTun(t *testing.T) {
	out := "Internet:\nDestination Gateway Flags Netif Expire\n" +
		"default link#9 UCSg utun9\n" +
		"default link#14 UCSg ppp0\n"
	routes, err := parseNetstatDefaults(out)
	require.NoError(t, err)
	primary, ok := PrimaryDefault(routes, "utun9")
	require.True(t, ok)
	require.Equal(t, DefaultRoute{Interface: "ppp0"}, primary)
	require.False(t, primary.Gateway.IsValid())
}

func TestParseNetstatDefaults_Errors(t *testing.T) {
	_, err := parseNetstatDefaults("garbage")
	require.ErrorContains(t, err, "no IPv4 routing table")
	_, err = parseNetstatDefaults("Internet:\nDestination Gateway Flags Netif\ndefault weird UGS en0\n")
	require.ErrorContains(t, err, "unexpected default gateway")

	routes, err := parseNetstatDefaults("Internet:\nDestination Gateway Flags Netif\n")
	require.NoError(t, err)
	_, ok := PrimaryDefault(routes, "")
	require.False(t, ok, "offline: no default route")
}

const serviceOrderFixture = `An asterisk (*) denotes that a network service is disabled.
(1) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) Old Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(3) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(4) Some VPN
(Hardware Port: com.example.vpn, Device: )
`

func TestParseServiceForDevice(t *testing.T) {
	svc, err := parseServiceForDevice(serviceOrderFixture, "en0")
	require.NoError(t, err)
	require.Equal(t, "Wi-Fi", svc)
	svc, err = parseServiceForDevice(serviceOrderFixture, "en7")
	require.NoError(t, err)
	require.Equal(t, "USB 10/100/1000 LAN", svc)
	_, err = parseServiceForDevice(serviceOrderFixture, "en9")
	require.ErrorContains(t, err, "no enabled network service")
}

func TestParseServiceForDevice_DisabledOnly(t *testing.T) {
	out := "(*) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n"
	_, err := parseServiceForDevice(out, "en0")
	require.Error(t, err)
}

func TestParseDNSServers(t *testing.T) {
	servers, err := parseDNSServers("There aren't any DNS Servers set on Wi-Fi.\n")
	require.NoError(t, err)
	require.Nil(t, servers)

	servers, err = parseDNSServers("1.1.1.1\n2606:4700:4700::1111\n")
	require.NoError(t, err)
	require.Equal(t, []string{"1.1.1.1", "2606:4700:4700::1111"}, servers)

	_, err = parseDNSServers("Wi-Fi is not a recognized network service.\n")
	require.ErrorContains(t, err, "unexpected DNS server line")
}

const scutilFixture = `DNS configuration

resolver #1
  search domain[0] : home.example
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  if_index : 6 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  nameserver[0] : 10.20.0.53
  if_index : 14 (en7)
  flags    : Scoped, Request A records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
`

func TestPickSystemResolvers(t *testing.T) {
	resolvers := parseScutilDNS(scutilFixture)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.1")},
		pickSystemResolvers(resolvers, "en0", OutlineDNS))
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.20.0.53")},
		pickSystemResolvers(resolvers, "en7", OutlineDNS))
	// No scoped resolver for the interface: use the default resolver.
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("fe80::1%en0")},
		pickSystemResolvers(resolvers, "en9", OutlineDNS))
}

func TestPickSystemResolvers_SkipsOutlineDNS(t *testing.T) {
	// While connected, the service resolver is ours; it must never be used for direct lookups.
	out := strings.ReplaceAll(scutilFixture, "192.168.1.1", "169.254.113.53")
	out = strings.ReplaceAll(out, "fe80::1%en0", "169.254.113.53")
	require.Nil(t, pickSystemResolvers(parseScutilDNS(out), "en0", OutlineDNS))
}

func TestParseIPv6Info(t *testing.T) {
	auto, err := parseIPv6Info("DHCP Configuration\nIP address: 192.168.1.23\nRouter: 192.168.1.1\nClient ID: \nIPv6: Automatic\nIPv6 IP address: none\nIPv6 Router: none\nWi-Fi ID: 02:00:00:00:00:02\n")
	require.NoError(t, err)
	require.Equal(t, IPv6Automatic, auto.Mode)
	require.True(t, auto.Restorable())

	off, err := parseIPv6Info("IPv6: Off\n")
	require.NoError(t, err)
	require.Equal(t, IPv6Off, off.Mode)

	manual, err := parseIPv6Info("IPv6: Manual\nIPv6 IP address: 2001:db8::5\nIPv6 Prefix Length: 64\nIPv6 Router: 2001:db8::1\n")
	require.NoError(t, err)
	require.Equal(t, IPv6Config{Mode: IPv6Manual, Raw: "Manual", Address: "2001:db8::5", PrefixLength: 64, Router: "2001:db8::1"}, manual)
	require.True(t, manual.Restorable())

	// Manual without a prefix length can't be restored exactly, so it must be left alone.
	partial, err := parseIPv6Info("IPv6: Manual\nIPv6 IP address: 2001:db8::5\nIPv6 Router: 2001:db8::1\n")
	require.NoError(t, err)
	require.False(t, partial.Restorable())

	odd, err := parseIPv6Info("IPv6: Link-local only\n")
	require.NoError(t, err)
	require.Equal(t, IPv6Unknown, odd.Mode)
	require.False(t, odd.Restorable())

	_, err = parseIPv6Info("Wi-Fi is not a recognized network service.\n")
	require.Error(t, err)
}

func TestParseRouteGet(t *testing.T) {
	exact := "   route to: 10.0.0.0\ndestination: 10.0.0.0\n       mask: 255.0.0.0\n    gateway: 192.168.1.1\n  interface: en0\n"
	res, err := parseRouteGet(exact)
	require.NoError(t, err)
	require.True(t, res.matches(netip.MustParsePrefix("10.0.0.0/8")))
	require.False(t, res.matches(netip.MustParsePrefix("10.0.0.0/9")))

	fallback := "   route to: 0.0.0.0\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n"
	res, err = parseRouteGet(fallback)
	require.NoError(t, err)
	require.False(t, res.matches(netip.MustParsePrefix("0.0.0.0/1")))
	require.True(t, res.matches(netip.MustParsePrefix("0.0.0.0/0")))

	host := "   route to: 169.254.113.53\ndestination: 169.254.113.53\n  interface: utun5\n      flags: <UP,HOST,DONE,STATIC>\n"
	res, err = parseRouteGet(host)
	require.NoError(t, err)
	require.True(t, res.matches(netip.MustParsePrefix("169.254.113.53/32")))

	linkLocal := "   route to: 169.254.0.0\ndestination: 169.254.0.0\n       mask: 255.255.0.0\n  interface: en0\n"
	res, err = parseRouteGet(linkLocal)
	require.NoError(t, err)
	require.True(t, res.matches(netip.MustParsePrefix("169.254.0.0/16")))
	require.False(t, res.matches(netip.MustParsePrefix("169.254.113.53/32")))

	_, err = parseRouteGet("garbage")
	require.Error(t, err)
}

func TestMaskBits(t *testing.T) {
	require.Equal(t, 8, maskBits(netip.MustParseAddr("255.0.0.0")))
	require.Equal(t, 1, maskBits(netip.MustParseAddr("128.0.0.0")))
	require.Equal(t, 32, maskBits(netip.MustParseAddr("255.255.255.255")))
	require.Equal(t, -1, maskBits(netip.MustParseAddr("255.0.255.0")))
}

func TestIsReadOnly(t *testing.T) {
	readOnly := []sysexec.Call{
		sysexec.Cmd("netstat", "-rn", "-f", "inet"),
		sysexec.Cmd("scutil", "--dns"),
		sysexec.Cmd("route", "-n", "get", "-net", "10.0.0.0/8"),
		sysexec.Cmd("networksetup", "-listnetworkserviceorder"),
		sysexec.Cmd("networksetup", "-getdnsservers", "Wi-Fi"),
		sysexec.Cmd("networksetup", "-getinfo", "Wi-Fi"),
		sysexec.Cmd("pfctl", "-s", "info"),
		sysexec.Cmd("pfctl", "-s", "rules"),
		sysexec.Cmd("pfctl", "-a", "com.apple/outline-cli", "-s", "rules"),
	}
	mutating := []sysexec.Call{
		sysexec.Cmd("route", "-n", "add", "-net", "0.0.0.0/1", "-interface", "utun5"),
		sysexec.Cmd("route", "-n", "delete", "-net", "0.0.0.0/1", "-interface", "utun5"),
		sysexec.Cmd("route", "get"),
		sysexec.Cmd("networksetup", "-setdnsservers", "Wi-Fi", "169.254.113.53"),
		sysexec.Cmd("networksetup", "-setv6off", "Wi-Fi"),
		sysexec.Cmd("networksetup"),
		sysexec.Cmd("scutil"),
		sysexec.Cmd("scutil", "--set", "HostName", "x"),
		sysexec.Cmd("ifconfig", "utun5", "inet", "10.111.222.1", "10.111.222.2"),
		sysexec.Cmd("dscacheutil", "-flushcache"),
		sysexec.Cmd("killall", "-HUP", "mDNSResponder"),
		sysexec.Cmd("pfctl", "-E"),
		sysexec.Cmd("pfctl", "-X", "123"),
		sysexec.Cmd("pfctl", "-f", "/etc/pf.conf"),
		sysexec.Cmd("pfctl", "-a", "com.apple/outline-cli", "-f", "/var/db/outline-cli/anchor.conf"),
		sysexec.Cmd("pfctl", "-a", "com.apple/outline-cli", "-F", "all"),
		sysexec.Cmd("pfctl", "-a", "com.apple/outline-cli", "-s", "rules", "-F", "all"),
		sysexec.Cmd("pfctl", "-s", "rules", "-f", "/tmp/x"),
	}
	for _, c := range readOnly {
		require.True(t, IsReadOnly(c), c.String())
	}
	for _, c := range mutating {
		require.False(t, IsReadOnly(c), c.String())
	}
}

// --- Router: exact commands ---

func newRouter(handler func(sysexec.Call) ([]byte, error)) (*Router, *sysexec.Fake) {
	f := &sysexec.Fake{Handler: handler}
	return &Router{Exec: f}, f
}

func cmdErr(c sysexec.Call, out string) error {
	return &sysexec.CommandError{Call: c, ExitCode: 1, Output: out, Err: errors.New("exit status 1")}
}

func TestRouter_RouteCommands(t *testing.T) {
	ctx := context.Background()
	r, f := newRouter(nil)
	added, err := r.AddRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun5"})
	require.NoError(t, err)
	require.True(t, added)
	_, err = r.AddRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("192.168.1.1")})
	require.NoError(t, err)
	_, err = r.AddRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("169.254.113.53/32"), Interface: "utun5"})
	require.NoError(t, err)
	require.NoError(t, r.DeleteRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("128.0.0.0/1"), Interface: "utun5"}))

	var got []string
	for _, c := range f.Calls() {
		got = append(got, c.String())
	}
	require.Equal(t, []string{
		"route -n add -net 0.0.0.0/1 -interface utun5",
		"route -n add -net 10.0.0.0/8 192.168.1.1",
		"route -n add -host 169.254.113.53 -interface utun5",
		"route -n delete -net 128.0.0.0/1 -interface utun5",
	}, got)
}

func TestRouter_RouteSpecValidation(t *testing.T) {
	r, f := newRouter(nil)
	ctx := context.Background()
	_, err := r.AddRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("10.0.0.0/8")})
	require.Error(t, err)
	_, err = r.AddRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("192.168.1.1"), Interface: "en0"})
	require.Error(t, err)
	_, err = r.AddRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("::/1"), Interface: "utun5"})
	require.Error(t, err)
	require.Empty(t, f.Calls(), "invalid routes must not reach the system")
}

func TestRouter_AddExistingAndDeleteMissing(t *testing.T) {
	ctx := context.Background()
	r, _ := newRouter(func(c sysexec.Call) ([]byte, error) {
		switch c.Args[1] {
		case "add":
			return nil, cmdErr(c, "route: writing to routing socket: File exists\nadd net 169.254.0.0: gateway 192.168.1.1: File exists\n")
		case "delete":
			return nil, cmdErr(c, "route: writing to routing socket: not in table\ndelete net 10.0.0.0: not in table\n")
		}
		return nil, nil
	})
	added, err := r.AddRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("169.254.0.0/16"), Gateway: netip.MustParseAddr("192.168.1.1")})
	require.NoError(t, err)
	require.False(t, added)
	require.NoError(t, r.DeleteRoute(ctx, RouteSpec{Dst: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("192.168.1.1")}))
}

func TestRouter_OtherRouteErrorsPropagate(t *testing.T) {
	r, _ := newRouter(func(c sysexec.Call) ([]byte, error) {
		return nil, cmdErr(c, "route: must be root to alter routing table\n")
	})
	_, err := r.AddRoute(context.Background(), RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun5"})
	require.ErrorContains(t, err, "must be root")
	require.ErrorContains(t, r.DeleteRoute(context.Background(), RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun5"}), "must be root")
}

func TestRouter_LookupRoute(t *testing.T) {
	r, f := newRouter(func(c sysexec.Call) ([]byte, error) {
		switch c.Args[len(c.Args)-1] {
		case "169.254.0.0/16":
			return []byte("destination: 169.254.0.0\n       mask: 255.255.0.0\n      flags: <UP,DONE,CLONING,STATIC>\n"), nil
		case "0.0.0.0/1":
			return []byte("destination: default\n       mask: default\n"), nil
		case "203.0.113.50":
			// What macOS reports for a host contacted moments ago (for
			// example the server a dynamic key was fetched from).
			return []byte("   route to: 203.0.113.50\ndestination: 203.0.113.50\n    gateway: 192.168.1.254\n  interface: en1\n      flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF>\n"), nil
		default:
			return nil, cmdErr(c, "route: writing to routing socket: not in table\n")
		}
	})
	ctx := context.Background()
	for dst, want := range map[string]RouteStatus{
		"169.254.0.0/16":  RoutePresent,
		"0.0.0.0/1":       RouteAbsent,
		"203.0.113.0/24":  RouteAbsent,
		"203.0.113.50/32": RouteCloned,
	} {
		got, err := r.LookupRoute(ctx, netip.MustParsePrefix(dst))
		require.NoError(t, err, dst)
		require.Equal(t, want, got, dst)
	}
	var calls []string
	for _, c := range f.Calls() {
		calls = append(calls, c.String())
	}
	require.Contains(t, calls, "route -n get -net 169.254.0.0/16")
	require.Contains(t, calls, "route -n get -host 203.0.113.50")
}

func TestRouter_DeleteClonedRoute(t *testing.T) {
	r, f := newRouter(func(c sysexec.Call) ([]byte, error) {
		if c.Args[len(c.Args)-1] == "203.0.113.9" {
			return nil, cmdErr(c, "route: writing to routing socket: not in table\n")
		}
		return nil, nil
	})
	ctx := context.Background()
	require.NoError(t, r.DeleteClonedRoute(ctx, netip.MustParsePrefix("203.0.113.50/32")))
	require.NoError(t, r.DeleteClonedRoute(ctx, netip.MustParsePrefix("203.0.113.9/32")), "already gone is fine")
	require.Equal(t, "route -n delete -host 203.0.113.50", f.Calls()[0].String())
}

func TestRouter_DNSAndIPv6Commands(t *testing.T) {
	ctx := context.Background()
	r, f := newRouter(nil)
	require.NoError(t, r.SetDNS(ctx, "USB 10/100/1000 LAN", []string{"169.254.113.53"}))
	require.NoError(t, r.SetDNS(ctx, "Wi-Fi", nil))
	require.NoError(t, r.SetDNS(ctx, "Wi-Fi", []string{"1.1.1.1", "9.9.9.9"}))
	require.NoError(t, r.SetIPv6(ctx, "Wi-Fi", IPv6Config{Mode: IPv6Off}))
	require.NoError(t, r.SetIPv6(ctx, "Wi-Fi", IPv6Config{Mode: IPv6Automatic}))
	require.NoError(t, r.SetIPv6(ctx, "Wi-Fi", IPv6Config{Mode: IPv6Manual, Address: "2001:db8::5", PrefixLength: 64, Router: "2001:db8::1"}))
	require.Error(t, r.SetIPv6(ctx, "Wi-Fi", IPv6Config{Mode: IPv6Manual, Address: "2001:db8::5"}))
	require.Error(t, r.SetIPv6(ctx, "Wi-Fi", IPv6Config{Mode: IPv6Unknown, Raw: "Link-local only"}))
	require.NoError(t, r.ConfigureUTun(ctx, "utun5", netip.MustParseAddr("10.111.222.1"), netip.MustParseAddr("10.111.222.2")))
	require.NoError(t, r.FlushDNSCache(ctx))

	var got []string
	for _, c := range f.Calls() {
		got = append(got, c.String())
	}
	require.Equal(t, []string{
		"networksetup -setdnsservers 'USB 10/100/1000 LAN' 169.254.113.53",
		"networksetup -setdnsservers Wi-Fi empty",
		"networksetup -setdnsservers Wi-Fi 1.1.1.1 9.9.9.9",
		"networksetup -setv6off Wi-Fi",
		"networksetup -setv6automatic Wi-Fi",
		"networksetup -setv6manual Wi-Fi 2001:db8::5 64 2001:db8::1",
		"ifconfig utun5 inet 10.111.222.1 10.111.222.2 netmask 255.255.255.255 mtu 1500 up",
		"dscacheutil -flushcache",
		"killall -HUP mDNSResponder",
	}, got)
}

func TestRouter_Reads(t *testing.T) {
	r, _ := newRouter(func(c sysexec.Call) ([]byte, error) {
		switch {
		case c.Name == "netstat":
			return []byte(netstatFixture), nil
		case c.Name == "scutil":
			return []byte(scutilFixture), nil
		case len(c.Args) > 0 && c.Args[0] == "-listnetworkserviceorder":
			return []byte(serviceOrderFixture), nil
		case len(c.Args) > 0 && c.Args[0] == "-getdnsservers":
			return []byte("There aren't any DNS Servers set on Wi-Fi.\n"), nil
		case len(c.Args) > 0 && c.Args[0] == "-getinfo":
			return []byte("IPv6: Automatic\n"), nil
		}
		return nil, errors.New("unexpected")
	})
	ctx := context.Background()
	routes, err := r.DefaultRoutes(ctx)
	require.NoError(t, err)
	require.Len(t, routes, 3)
	svc, err := r.ServiceForInterface(ctx, "en0")
	require.NoError(t, err)
	require.Equal(t, "Wi-Fi", svc)
	dns, err := r.DNSServers(ctx, svc)
	require.NoError(t, err)
	require.Nil(t, dns)
	res, err := r.SystemResolvers(ctx, "en0")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.1")}, res)
	v6, err := r.IPv6(ctx, svc)
	require.NoError(t, err)
	require.Equal(t, IPv6Automatic, v6.Mode)
}

func TestRouter_LookupRouteErrorShowsTheOutput(t *testing.T) {
	r, _ := newRouter(func(sysexec.Call) ([]byte, error) {
		return []byte("   route to: 10.0.0.0\n  something unexpected\n"), nil
	})
	_, err := r.LookupRoute(context.Background(), netip.MustParsePrefix("10.0.0.0/8"))
	require.ErrorContains(t, err, "no destination in route output")
	require.ErrorContains(t, err, "something unexpected")
}

// The documented `ipconfig getpacket` format; values are from a typical
// iPhone hotspot.
const getpacketFixture = `op = BOOTREPLY
htype = 1
flags = 0
hlen = 6
hops = 0
xid = 0x5a1b2c3d
ciaddr = 0.0.0.0
yiaddr = 172.20.10.4
siaddr = 172.20.10.1
giaddr = 0.0.0.0
chaddr = 02:00:00:00:00:03
sname = 
file = 
options:
Options count is 8
dhcp_message_type (uint8): ACK 0x5
server_identifier (ip): 172.20.10.1
lease_time (uint32): 0x15180
subnet_mask (ip): 255.255.255.240
router (ip_mult): {172.20.10.1}
domain_name_server (ip_mult): {172.20.10.1, 8.8.8.8}
end (none): 
`

func TestParseDHCPResolvers(t *testing.T) {
	require.Equal(t, []netip.Addr{netip.MustParseAddr("172.20.10.1"), netip.MustParseAddr("8.8.8.8")},
		parseDHCPResolvers(getpacketFixture))
	require.Nil(t, parseDHCPResolvers("op = BOOTREPLY\nrouter (ip_mult): {172.20.10.1}\n"))
	require.Nil(t, parseDHCPResolvers(""))
}

func TestRouter_DHCPResolvers(t *testing.T) {
	r, f := newRouter(func(c sysexec.Call) ([]byte, error) {
		if c.Args[1] == "en1" {
			return []byte(getpacketFixture), nil
		}
		return nil, cmdErr(c, "") // no lease: ipconfig prints nothing and fails
	})
	ctx := context.Background()
	got, err := r.DHCPResolvers(ctx, "en1")
	require.NoError(t, err)
	require.Len(t, got, 2)
	got, err = r.DHCPResolvers(ctx, "en5")
	require.NoError(t, err)
	require.Nil(t, got)
	require.Equal(t, "ipconfig getpacket en1", f.Calls()[0].String())
	require.True(t, IsReadOnly(f.Calls()[0]))
	require.False(t, IsReadOnly(sysexec.Cmd("ipconfig", "set", "en1", "DHCP")))
}

func TestRouter_LookupRouteEmptyOutputMeansAbsent(t *testing.T) {
	// Seen on the developer's Mac right after a disconnect: route exits 0,
	// prints its error on stderr and nothing on stdout.
	r, _ := newRouter(func(sysexec.Call) ([]byte, error) { return nil, nil })
	got, err := r.LookupRoute(context.Background(), netip.MustParsePrefix("10.0.0.0/8"))
	require.NoError(t, err)
	require.Equal(t, RouteAbsent, got)
}

func TestRouter_InterfaceAddrs(t *testing.T) {
	// The format of `ifconfig en1` on macOS (MAC address and IPv6 are fake).
	out := `en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether 02:00:00:00:00:04
	inet6 fe80::1c2b:3a4d:5e6f:7081%en1 prefixlen 64 secured scopeid 0x6
	inet 192.168.1.79 netmask 0xffffff00 broadcast 192.168.1.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
`
	r, f := newRouter(func(sysexec.Call) ([]byte, error) { return []byte(out), nil })
	addrs, err := r.InterfaceAddrs(context.Background(), "en1")
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.79")}, addrs)
	require.Equal(t, "ifconfig en1", f.Calls()[0].String())
	require.True(t, IsReadOnly(f.Calls()[0]))
	require.False(t, IsReadOnly(sysexec.Cmd("ifconfig", "-a")))
	require.Nil(t, parseInetAddrs("en1: flags=8863<UP>\n\tstatus: inactive\n"))
}
