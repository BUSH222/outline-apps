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

package state

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"localhost/client/go/outline/macoscli/internal/sysrouter"

	"github.com/stretchr/testify/require"
)

func sample() *State {
	return &State{
		Version:         CurrentVersion,
		PID:             4242,
		StartedAt:       time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		Interface:       "en0",
		Gateway:         "192.168.1.1",
		Service:         "Wi-Fi",
		PrevDNS:         &SavedDNS{Servers: nil},
		PrevIPv6:        &sysrouter.IPv6Config{Mode: sysrouter.IPv6Manual, Raw: "Manual", Address: "2001:db8::5", PrefixLength: 64, Router: "2001:db8::1"},
		SystemResolvers: []string{"192.168.1.1"},
		UTun:            "utun7",
		Routes: []Route{
			{RouteSpec: sysrouter.RouteSpec{Dst: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("192.168.1.1")}, Purpose: "exclude"},
			{RouteSpec: sysrouter.RouteSpec{Dst: netip.MustParsePrefix("0.0.0.0/1"), Interface: "utun7"}, Purpose: "default"},
		},
	}
}

func TestFileStore_RoundTrip(t *testing.T) {
	store := FileStore{Dir: filepath.Join(t.TempDir(), "outline-cli")}
	got, err := store.Load()
	require.NoError(t, err)
	require.Nil(t, got, "no state file yet")

	want := sample()
	require.NoError(t, store.Save(want))
	got, err = store.Load()
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Nil(t, got.PrevDNS.Servers, "DHCP DNS (nil) must survive the round trip")

	dirInfo, err := os.Stat(store.Dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	fileInfo, err := os.Stat(store.Path())
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())

	require.NoError(t, store.Remove())
	require.NoError(t, store.Remove(), "removing twice is fine")
	got, err = store.Load()
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestFileStore_AtomicReplaceLeavesNoTempFiles(t *testing.T) {
	store := FileStore{Dir: t.TempDir()}
	s := sample()
	for i := 0; i < 5; i++ {
		s.PID = i
		require.NoError(t, store.Save(s))
	}
	entries, err := os.ReadDir(store.Dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	got, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, 4, got.PID)
}

func TestFileStore_IgnoresLeftoverTempFile(t *testing.T) {
	// A crash between writing the temp file and renaming it leaves the old state intact.
	store := FileStore{Dir: t.TempDir()}
	require.NoError(t, store.Save(sample()))
	require.NoError(t, os.WriteFile(filepath.Join(store.Dir, fileName+".tmp-123"), []byte("{partial"), 0o600))
	got, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, sample(), got)
}

func TestFileStore_CorruptAndVersion(t *testing.T) {
	store := FileStore{Dir: t.TempDir()}
	require.NoError(t, os.WriteFile(store.Path(), []byte("{not json"), 0o600))
	_, err := store.Load()
	require.ErrorContains(t, err, "corrupt")

	require.NoError(t, os.WriteFile(store.Path(), []byte(`{"version": 99}`), 0o600))
	_, err = store.Load()
	require.ErrorContains(t, err, "version 99")
}

func TestFileStore_Lock(t *testing.T) {
	store := FileStore{Dir: t.TempDir()}
	unlock, err := store.Lock()
	require.NoError(t, err)
	_, err = store.Lock()
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, unlock())
	unlock, err = store.Lock()
	require.NoError(t, err)
	require.NoError(t, unlock())
}

func TestMemStore(t *testing.T) {
	var saved []*State
	m := NewMemStore(nil)
	m.OnSave = func(s *State) { saved = append(saved, s) }
	s := sample()
	require.NoError(t, m.Save(s))
	s.PID = 1 // the store must hold a copy
	got, err := m.Load()
	require.NoError(t, err)
	require.Equal(t, 4242, got.PID)
	require.Len(t, saved, 1)
	require.NoError(t, m.Remove())
	got, err = m.Load()
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestEmptyAndClone(t *testing.T) {
	s := sample()
	require.False(t, s.Empty())
	c := s.Clone()
	c.Routes[0].Purpose = "changed"
	c.PrevIPv6.Address = "changed"
	require.Equal(t, "exclude", s.Routes[0].Purpose)
	require.Equal(t, "2001:db8::5", s.PrevIPv6.Address)
	require.True(t, (&State{Version: 1, UTun: "utun1"}).Empty())
}
