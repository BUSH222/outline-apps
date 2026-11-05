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

// Package lockdown keeps vpn_only domains unreachable while the VPN is off.
//
// "outline-cli lockdown" installs two things that stay in place when the CLI
// isn't running, until "outline-cli unlock":
//   - a pf anchor (com.apple/outline-cli) that blocks the addresses learned
//     for vpn_only domains while connected. While connected, the anchor lets
//     them through the utun only;
//   - a block in /etc/hosts that maps the vpn_only names to 0.0.0.0 and ::.
//     It is removed while connected, so the names resolve through the tunnel.
//
// Addresses are only ever learned through the tunnel; lockdown never looks
// a vpn_only name up itself, since that would send the lookup outside the VPN.
package lockdown

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"localhost/client/go/outline/macoscli/internal/rules"
	"localhost/client/go/outline/macoscli/internal/sysexec"
	"localhost/client/go/outline/macoscli/internal/sysrouter"
)

// Default system paths.
const (
	DefaultHostsPath  = "/etc/hosts"
	DefaultPFConfPath = "/etc/pf.conf"
)

// Files in the state directory.
const (
	stateName       = "lockdown.json"
	learnedName     = "vpn_only.json"
	anchorFileName  = "anchor.conf"
	hostsBackupName = "hosts.backup"
)

// learnedMaxAge drops addresses not seen for this long.
const learnedMaxAge = 30 * 24 * time.Hour

// learnedRefresh is how stale a last-seen time may get before it is saved
// again; new addresses are always saved at once.
const learnedRefresh = 24 * time.Hour

// State is lockdown.json. Its existence means lockdown is active; it is
// written before anything is installed, so cleanup can finish an interrupted
// lockdown.
type State struct {
	Version int `json:"version"`
	// Entries are the vpn_only entries locked down, normalized.
	Entries []string `json:"entries"`
	// Token is the pf reference that keeps pf enabled ("pfctl -E").
	Token    string    `json:"token,omitempty"`
	LockedAt time.Time `json:"lockedAt"`
}

// learnedFile is vpn_only.json: the addresses learned for vpn_only domains
// while connected, kept across sessions.
type learnedFile struct {
	Addrs map[netip.Addr]learnedAddr `json:"addrs"`
	// FirstHops are the server's addresses, which are never blocked: the
	// block must never cut the tunnel itself.
	FirstHops []netip.Addr `json:"firstHops,omitempty"`
}

type learnedAddr struct {
	Domain   string    `json:"domain"`
	LastSeen time.Time `json:"lastSeen"`
}

// Manager installs and removes the lockdown. It is safe for concurrent use.
type Manager struct {
	Exec sysexec.Executor
	// Dir is the state directory (/var/db/outline-cli).
	Dir string
	// HostsPath and PFConfPath are the system files (DefaultHostsPath and
	// DefaultPFConfPath). They must be set; there is deliberately no default,
	// so a test can't edit the real /etc/hosts by leaving them out.
	HostsPath  string
	PFConfPath string
	Log        *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu sync.Mutex
	// utun is set while a session is connected.
	utun string
}

func (m *Manager) log() *slog.Logger {
	if m.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return m.Log
}

func (m *Manager) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}

func (m *Manager) hostsPath() string  { return m.HostsPath }
func (m *Manager) pfConfPath() string { return m.PFConfPath }

// Status returns the lockdown state, or nil if lockdown isn't active.
func (m *Manager) Status() (*State, error) {
	var st State
	if err := readJSON(filepath.Join(m.Dir, stateName), &st); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &st, nil
}

// Lock installs (or refreshes) the lockdown for the given vpn_only entries,
// in the disconnected form. The caller holds the instance lock, so no
// session is running.
func (m *Manager) Lock(ctx context.Context, entries []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := rules.FromLists(nil, entries)
	if err != nil {
		return err
	}
	if len(r.VPNOnly) == 0 {
		return errors.New("there are no vpn_only entries to lock down")
	}
	st, err := m.Status()
	if err != nil {
		return err
	}
	if st == nil {
		st = &State{Version: 1}
	}
	st.Entries = r.VPNOnly
	st.LockedAt = m.now().UTC()
	// Recorded first: if anything below is interrupted, cleanup finishes it.
	if err := m.saveState(st); err != nil {
		return err
	}
	if err := m.backupHosts(); err != nil {
		return err
	}
	return m.applyDisconnected(ctx, st)
}

// Unlock removes the lockdown. It reports whether one was active.
func (m *Manager) Unlock(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.Status()
	if err != nil || st == nil {
		return false, err
	}
	if err := m.writeHosts(nil); err != nil {
		return true, err
	}
	m.flushDNS(ctx)
	if _, err := m.run(ctx, sysexec.Cmd("pfctl", "-a", Anchor, "-F", "all")); err != nil {
		return true, fmt.Errorf("removing the pf rules: %w", err)
	}
	if st.Token != "" {
		if _, err := m.run(ctx, sysexec.Cmd("pfctl", "-X", st.Token)); err != nil {
			// A reboot invalidates the token; pf may be enabled by someone else.
			m.log().Warn("releasing the pf reference failed; pf stays as it is", "err", err)
		}
	}
	os.Remove(filepath.Join(m.Dir, anchorFileName))
	if err := os.Remove(filepath.Join(m.Dir, stateName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return true, err
	}
	return true, nil
}

// Connected switches an active lockdown to the connected form: vpn_only
// addresses pass through utun, and the hosts block is removed so the names
// resolve through the tunnel. Without lockdown it does nothing.
func (m *Manager) Connected(ctx context.Context, utun string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, err := m.Status()
	if err != nil || st == nil {
		return err
	}
	m.utun = utun
	if err := m.loadAnchor(ctx, st, utun); err != nil {
		return err
	}
	if err := m.writeHosts(nil); err != nil {
		return err
	}
	m.flushDNS(ctx)
	m.log().Info("lockdown: vpn_only domains are reachable through the tunnel", "utun", utun)
	return nil
}

// Disconnected puts an active lockdown back in the disconnected form (after
// a session, or by cleanup after a crash). Without lockdown it does nothing.
func (m *Manager) Disconnected(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.utun = ""
	st, err := m.Status()
	if err != nil || st == nil {
		return err
	}
	return m.applyDisconnected(ctx, st)
}

func (m *Manager) applyDisconnected(ctx context.Context, st *State) error {
	if err := m.ensurePF(ctx, st); err != nil {
		return err
	}
	if err := m.loadAnchor(ctx, st, ""); err != nil {
		return err
	}
	if err := m.writeHosts(hostNames(st.Entries)); err != nil {
		return err
	}
	m.flushDNS(ctx)
	return nil
}

// SetFirstHops records the server's addresses, which are never blocked.
func (m *Manager) SetFirstHops(hops []netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lf, err := m.loadLearned()
	if err != nil {
		return err
	}
	lf.FirstHops = nil
	for _, h := range hops {
		h = h.Unmap()
		lf.FirstHops = append(lf.FirstHops, h)
		delete(lf.Addrs, h)
	}
	return m.saveLearned(lf)
}

// Learn records addresses learned for vpn_only domains (address -> domain).
// While a locked-down session is connected, new addresses go into the pf
// table at once.
func (m *Manager) Learn(ctx context.Context, learned map[netip.Addr]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	lf, err := m.loadLearned()
	if err != nil {
		return err
	}
	now := m.now().UTC()
	added, changed := false, false
	for addr, domain := range learned {
		addr = addr.Unmap()
		if slices.Contains(lf.FirstHops, addr) {
			continue
		}
		old, ok := lf.Addrs[addr]
		if !ok {
			added = true
		}
		if !ok || old.Domain != domain || now.Sub(old.LastSeen) > learnedRefresh {
			lf.Addrs[addr] = learnedAddr{Domain: domain, LastSeen: now}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := m.saveLearned(lf); err != nil {
		return err
	}
	if !added || m.utun == "" {
		return nil
	}
	st, err := m.Status()
	if err != nil || st == nil {
		return err
	}
	return m.loadAnchor(ctx, st, m.utun)
}

// TableAddrs returns the addresses the pf table would hold: those learned for
// domains the lockdown covers, without the server's.
func (m *Manager) TableAddrs(st *State) ([]netip.Addr, error) {
	lf, err := m.loadLearned()
	if err != nil {
		return nil, err
	}
	r, err := rules.FromLists(nil, st.Entries)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for addr, l := range lf.Addrs {
		if c, _ := r.Match(l.Domain); c == rules.VPNOnly && !slices.Contains(lf.FirstHops, addr) {
			out = append(out, addr)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out, nil
}

// ensurePF makes sure pf is enabled (holding a reference of its own) and
// evaluates the com.apple anchors. If the main ruleset is empty (nothing
// loaded since boot), the stock /etc/pf.conf is loaded; a main ruleset
// without the anchor is someone else's setup and is left alone.
func (m *Manager) ensurePF(ctx context.Context, st *State) error {
	info, err := m.run(ctx, sysexec.Cmd("pfctl", "-s", "info"))
	if err != nil {
		return fmt.Errorf("reading pf's status: %w", err)
	}
	if st.Token == "" || !strings.Contains(info, "Status: Enabled") {
		c := sysexec.Cmd("pfctl", "-E")
		c.CombinedOutput = true
		out, err := m.run(ctx, c)
		if err != nil {
			return fmt.Errorf("enabling pf: %w", err)
		}
		token := parseToken(out)
		if token == "" {
			return fmt.Errorf("enabling pf: no reference token in its output: %q", strings.TrimSpace(out))
		}
		st.Token = token
		if err := m.saveState(st); err != nil {
			return err
		}
	}

	main, err := m.run(ctx, sysexec.Cmd("pfctl", "-s", "rules"))
	if err != nil {
		return fmt.Errorf("reading pf's rules: %w", err)
	}
	if strings.Contains(main, `anchor "com.apple/*"`) {
		return nil
	}
	if strings.TrimSpace(main) != "" {
		return errors.New(`pf's main ruleset doesn't evaluate the "com.apple/*" anchors, so the block rules wouldn't apply; add anchor "com.apple/*" to it`)
	}
	conf, err := os.ReadFile(m.pfConfPath())
	if err != nil {
		return fmt.Errorf("pf has no rules loaded and %s can't be read: %w", m.pfConfPath(), err)
	}
	if !strings.Contains(string(conf), `anchor "com.apple/*"`) {
		return fmt.Errorf(`pf has no rules loaded and %s doesn't evaluate the "com.apple/*" anchors`, m.pfConfPath())
	}
	if _, err := m.run(ctx, sysexec.Cmd("pfctl", "-f", m.pfConfPath())); err != nil {
		return fmt.Errorf("loading %s: %w", m.pfConfPath(), err)
	}
	m.log().Info("pf had no rules loaded; loaded the system's default ruleset", "file", m.pfConfPath())
	return nil
}

func (m *Manager) loadAnchor(ctx context.Context, st *State, utun string) error {
	addrs, err := m.TableAddrs(st)
	if err != nil {
		return err
	}
	path := filepath.Join(m.Dir, anchorFileName)
	if err := writeFileAtomic(path, []byte(AnchorRules(addrs, utun)), 0o600); err != nil {
		return err
	}
	if _, err := m.run(ctx, sysexec.Cmd("pfctl", "-a", Anchor, "-f", path)); err != nil {
		return fmt.Errorf("loading the pf rules: %w", err)
	}
	m.log().Debug("lockdown: pf rules loaded", "addresses", len(addrs), "connected", utun != "")
	return nil
}

// writeHosts replaces the CLI's block in the hosts file (none for no names).
func (m *Manager) writeHosts(names []string) error {
	path := m.hostsPath()
	if path == "" {
		return errors.New("lockdown: no hosts file path set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	updated := HostsWithBlock(string(data), names)
	if updated == string(data) {
		return nil
	}
	mode := fs.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := writeFileAtomic(path, []byte(updated), mode); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// backupHosts copies the hosts file once, before the first change.
func (m *Manager) backupHosts() error {
	backup := filepath.Join(m.Dir, hostsBackupName)
	if _, err := os.Stat(backup); err == nil {
		return nil
	}
	data, err := os.ReadFile(m.hostsPath())
	if err != nil {
		return fmt.Errorf("reading %s: %w", m.hostsPath(), err)
	}
	return writeFileAtomic(backup, data, 0o600)
}

func (m *Manager) flushDNS(ctx context.Context) {
	if err := (&sysrouter.Router{Exec: m.Exec}).FlushDNSCache(ctx); err != nil {
		m.log().Warn("flushing the DNS cache failed", "err", err)
	}
}

func (m *Manager) run(ctx context.Context, c sysexec.Call) (string, error) {
	out, err := m.Exec.Run(ctx, c)
	return string(out), err
}

func (m *Manager) saveState(st *State) error {
	return writeJSON(filepath.Join(m.Dir, stateName), st)
}

func (m *Manager) loadLearned() (*learnedFile, error) {
	lf := &learnedFile{}
	if err := readJSON(filepath.Join(m.Dir, learnedName), lf); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if lf.Addrs == nil {
		lf.Addrs = map[netip.Addr]learnedAddr{}
	}
	cutoff := m.now().Add(-learnedMaxAge)
	for addr, l := range lf.Addrs {
		if l.LastSeen.Before(cutoff) {
			delete(lf.Addrs, addr)
		}
	}
	return lf, nil
}

func (m *Manager) saveLearned(lf *learnedFile) error {
	return writeJSON(filepath.Join(m.Dir, learnedName), lf)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s is corrupt: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0o600)
}

// writeFileAtomic writes data to a temporary file next to path and renames
// it into place, so readers see the old or the new content, never a mix.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
