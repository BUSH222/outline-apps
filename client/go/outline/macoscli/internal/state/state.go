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

// Package state persists what the CLI changed on the system, so every change
// can be undone from the state file alone, even after kill -9. The file is
// written before each change it describes.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"localhost/client/go/outline/macoscli/internal/sysrouter"
)

// DefaultDir is where the state file and lock live.
const DefaultDir = "/var/db/outline-cli"

const (
	fileName = "state.json"
	lockName = "lock"
	// CurrentVersion is the state file format version.
	CurrentVersion = 1
)

// Route is a route the CLI added (or is about to add).
type Route struct {
	sysrouter.RouteSpec
	// Purpose says why the route exists: "exclude", "first-hop", "bypass", "dns" or "default".
	Purpose string `json:"purpose"`
}

// SavedDNS is a service's DNS setting before the CLI changed it.
type SavedDNS struct {
	// Servers are the manual servers; nil means DHCP-provided ("empty").
	Servers []string `json:"servers"`
}

// State describes every system change of one session.
type State struct {
	Version   int       `json:"version"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"startedAt"`

	// The physical network when the session started (or last changed).
	Interface string `json:"interface"`
	Gateway   string `json:"gateway,omitempty"`
	Service   string `json:"service"`

	// PrevDNS is set before the service's DNS is changed. nil: DNS untouched.
	PrevDNS *SavedDNS `json:"prevDNS,omitempty"`
	// PrevIPv6 is set before the service's IPv6 is changed. nil: IPv6 untouched.
	PrevIPv6 *sysrouter.IPv6Config `json:"prevIPv6,omitempty"`
	// SystemResolvers are the resolvers in effect before DNS was changed.
	SystemResolvers []string `json:"systemResolvers,omitempty"`

	UTun string `json:"utun,omitempty"`
	// Routes are journaled before they are added.
	Routes []Route `json:"routes,omitempty"`
}

// Clone returns a deep copy.
func (s *State) Clone() *State {
	if s == nil {
		return nil
	}
	c := *s
	if s.PrevDNS != nil {
		dns := SavedDNS{Servers: append([]string(nil), s.PrevDNS.Servers...)}
		if s.PrevDNS.Servers == nil {
			dns.Servers = nil
		}
		c.PrevDNS = &dns
	}
	if s.PrevIPv6 != nil {
		v6 := *s.PrevIPv6
		c.PrevIPv6 = &v6
	}
	c.SystemResolvers = append([]string(nil), s.SystemResolvers...)
	c.Routes = append([]Route(nil), s.Routes...)
	return &c
}

// Empty reports whether nothing remains to be undone.
func (s *State) Empty() bool {
	return s.PrevDNS == nil && s.PrevIPv6 == nil && len(s.Routes) == 0
}

// Store loads and saves the state.
type Store interface {
	Load() (*State, error)
	Save(*State) error
	Remove() error
}

// FileStore keeps the state in Dir/state.json.
type FileStore struct {
	Dir string
}

// Path returns the state file path.
func (f FileStore) Path() string { return filepath.Join(f.Dir, fileName) }

// Load returns the saved state, or nil if there is none.
func (f FileStore) Load() (*State, error) {
	data, err := os.ReadFile(f.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state file: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("state file %s is corrupt: %w", f.Path(), err)
	}
	if s.Version != CurrentVersion {
		return nil, fmt.Errorf("state file %s has version %d; this build understands %d", f.Path(), s.Version, CurrentVersion)
	}
	return &s, nil
}

// Save writes the state atomically: a temp file in the same directory is
// synced and renamed over the old one, then the directory is synced. The
// directory is created with mode 0700 and the file has mode 0600.
func (f FileStore) Save(s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	tmp, err := os.CreateTemp(f.Dir, fileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("writing state file: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("writing state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("writing state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.Path()); err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}
	return syncDir(f.Dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Some file systems don't support syncing a directory; the rename is still done.
	_ = d.Sync()
	return nil
}

// Remove deletes the state file. A missing file is not an error.
func (f FileStore) Remove() error {
	err := os.Remove(f.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err == nil {
		err = syncDir(f.Dir)
	}
	return err
}

// MemStore keeps the state in memory, for dry runs and tests.
type MemStore struct {
	mu    sync.Mutex
	state *State
	// Saves counts Save calls.
	Saves int
	// OnSave, if set, is called with a copy of every saved state.
	OnSave func(*State)
}

// NewMemStore returns a store holding s (which may be nil).
func NewMemStore(s *State) *MemStore { return &MemStore{state: s.Clone()} }

func (m *MemStore) Load() (*State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Clone(), nil
}

func (m *MemStore) Save(s *State) error {
	m.mu.Lock()
	m.state = s.Clone()
	m.Saves++
	onSave := m.OnSave
	m.mu.Unlock()
	if onSave != nil {
		onSave(s.Clone())
	}
	return nil
}

func (m *MemStore) Remove() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = nil
	return nil
}
