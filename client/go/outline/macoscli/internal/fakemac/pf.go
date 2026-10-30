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

package fakemac

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// StockPFRules is what "pfctl -s rules" shows once /etc/pf.conf is loaded.
const StockPFRules = `scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all`

// pf is the simulated packet filter.
type pf struct {
	enabled   bool
	tokens    map[uint64]bool
	nextToken uint64
	// mainRules is the main ruleset ("" until /etc/pf.conf is loaded).
	mainRules string
	anchors   map[string]string
}

func newPF() pf {
	return pf{tokens: map[uint64]bool{}, nextToken: 7000, mainRules: StockPFRules, anchors: map[string]string{}}
}

// SetPFMainRules replaces the main ruleset ("" = nothing loaded).
func (m *Mac) SetPFMainRules(rules string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pf.mainRules = rules
}

// Reboot clears what a reboot clears: pf is disabled with no references,
// rules and anchors gone, and every route the Mac didn't set up itself.
// (DNS and IPv6 settings and files persist.)
func (m *Mac) Reboot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pf = newPF()
	m.pf.mainRules = ""
	for dst, r := range m.routes {
		if r.Interface != "en0" || r.Gateway.IsValid() {
			delete(m.routes, dst)
		}
	}
	m.utuns = map[string]string{}
}

// PFAnchor returns the rules loaded into an anchor.
func (m *Mac) PFAnchor(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pf.anchors[name]
}

// PFEnabled reports whether pf is enabled, and how many references hold it.
func (m *Mac) PFEnabled() (bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pf.enabled, len(m.pf.tokens)
}

func (m *Mac) pfSummary() string {
	var anchors []string
	for name, rules := range m.pf.anchors {
		anchors = append(anchors, name+"="+rules)
	}
	sort.Strings(anchors)
	return fmt.Sprintf("enabled=%v refs=%d main=%q anchors=%q", m.pf.enabled, len(m.pf.tokens), m.pf.mainRules, anchors)
}

func (m *Mac) pfctl(a []string) (string, string) {
	anchor := ""
	if len(a) >= 2 && a[0] == "-a" {
		anchor, a = a[1], a[2:]
	}
	p := &m.pf
	switch {
	case len(a) == 2 && a[0] == "-s" && a[1] == "info":
		status := "Disabled"
		if p.enabled {
			status = "Enabled for 0 days 00:01:02"
		}
		return fmt.Sprintf("Status: %s           Debug: Urgent\n\nState Table                          Total             Rate\n", status), ""
	case len(a) == 2 && a[0] == "-s" && a[1] == "rules":
		rules := p.mainRules
		if anchor != "" {
			rules = p.anchors[anchor]
		}
		if rules == "" {
			return "", ""
		}
		return rules + "\n", ""
	case len(a) == 1 && a[0] == "-E" && anchor == "":
		p.nextToken++
		p.tokens[p.nextToken] = true
		p.enabled = true
		return fmt.Sprintf("No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : %d\n", p.nextToken), ""
	case len(a) == 2 && a[0] == "-X" && anchor == "":
		token, err := strconv.ParseUint(a[1], 10, 64)
		if err != nil || !p.tokens[token] {
			return "", "pfctl: DIOCSTOPREF: Invalid argument\n"
		}
		delete(p.tokens, token)
		if len(p.tokens) > 0 {
			return "pf not disabled\n", ""
		}
		p.enabled = false
		return "pf disabled\n", ""
	case len(a) == 2 && a[0] == "-f":
		data, err := os.ReadFile(a[1])
		if err != nil {
			return "", fmt.Sprintf("pfctl: %v\n", err)
		}
		if anchor == "" {
			// Like the stock /etc/pf.conf: shown as StockPFRules once loaded.
			p.mainRules = strings.TrimSpace(string(data))
			if strings.Contains(p.mainRules, `anchor "com.apple/*"`) {
				p.mainRules = StockPFRules
			}
			return "", ""
		}
		p.anchors[anchor] = strings.TrimSpace(string(data))
		// Real pfctl also warns about ALTQ on standard error, and succeeds.
		return "", ""
	case len(a) == 2 && a[0] == "-F" && a[1] == "all" && anchor != "":
		delete(p.anchors, anchor)
		return "", ""
	}
	return "", fmt.Sprintf("fakemac: unexpected pfctl arguments %q\n", a)
}
