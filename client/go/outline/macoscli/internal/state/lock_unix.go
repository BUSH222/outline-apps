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

//go:build unix

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ErrLocked means another outline-cli process holds the lock.
var ErrLocked = errors.New("another outline-cli is running")

// Lock takes an exclusive, non-blocking lock on Dir/lock. The kernel releases
// it when the process exits, however it exits, so a state file whose lock can
// be taken was left behind by a process that is gone.
func (f FileStore) Lock() (unlock func() error, err error) {
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}
	file, err := os.OpenFile(filepath.Join(f.Dir, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("locking %s: %w", file.Name(), err)
	}
	return func() error {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return file.Close()
	}, nil
}
