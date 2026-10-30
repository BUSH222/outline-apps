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

package lockdown

import (
	"net/netip"
	"regexp"
	"strings"
)

// Anchor is the pf anchor holding the block rules. The stock /etc/pf.conf
// evaluates every anchor under com.apple/, so no edit to it is needed.
const Anchor = "com.apple/outline-cli"

// Table is the pf table of vpn_only addresses.
const Table = "outline_vpn_only"

// AnchorRules returns the anchor's rules. With utun empty, traffic to the
// table's addresses is blocked everywhere (the disconnected form). With a
// utun, it passes through that utun first (the connected form). If the CLI
// dies, the utun goes away, its pass rule matches nothing, and the block
// applies again: the connected form fails closed too.
//
// The rules don't name the physical interface, which can change while the
// CLI isn't running. With no address family they cover IPv4 and IPv6.
func AnchorRules(addrs []netip.Addr, utun string) string {
	var b strings.Builder
	b.WriteString("# Managed by outline-cli. Remove with: sudo outline-cli unlock\n")
	b.WriteString("table <" + Table + "> persist")
	if len(addrs) > 0 {
		parts := make([]string, len(addrs))
		for i, a := range addrs {
			parts[i] = a.String()
		}
		b.WriteString(" { " + strings.Join(parts, ", ") + " }")
	}
	b.WriteString("\n")
	if utun != "" {
		b.WriteString("pass out quick on " + utun + " from any to <" + Table + ">\n")
	}
	b.WriteString("block drop out quick from any to <" + Table + ">\n")
	return b.String()
}

var tokenRE = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// parseToken finds the reference token in the output of "pfctl -E".
func parseToken(out string) string {
	if m := tokenRE.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// Markers of the CLI's block in /etc/hosts.
const (
	hostsBegin = "# BEGIN outline-cli (managed by outline-cli; remove with: sudo outline-cli unlock)"
	hostsEnd   = "# END outline-cli"
)

// HostsWithBlock returns hosts with the CLI's block (replacing any previous
// one) mapping each name to 0.0.0.0 and ::, so it can't be resolved. With no
// names, the block is only removed. The rest of the file is kept as is.
func HostsWithBlock(hosts string, names []string) string {
	out := HostsWithoutBlock(hosts)
	if len(names) == 0 {
		return out
	}
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	var b strings.Builder
	b.WriteString(out)
	b.WriteString(hostsBegin + "\n")
	for _, n := range names {
		b.WriteString("0.0.0.0 " + n + "\n")
		b.WriteString(":: " + n + "\n")
	}
	b.WriteString(hostsEnd + "\n")
	return b.String()
}

// HostsWithoutBlock returns hosts without the CLI's block. A block whose end
// marker is missing runs to the end of the file.
func HostsWithoutBlock(hosts string) string {
	lines := strings.SplitAfter(hosts, "\n")
	var b strings.Builder
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case !inBlock && strings.HasPrefix(trimmed, "# BEGIN outline-cli"):
			inBlock = true
		case inBlock && trimmed == hostsEnd:
			inBlock = false
		case !inBlock:
			b.WriteString(line)
		}
	}
	return b.String()
}

// hostNames returns the entries hosts can block: those without "*." (hosts
// has no wildcards).
func hostNames(entries []string) []string {
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e, "*.") {
			out = append(out, e)
		}
	}
	return out
}
