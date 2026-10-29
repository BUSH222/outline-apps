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

//go:build darwin

package tunnel

import "github.com/songgao/water"

// OpenUTun opens the next free utun device. It needs root. The kernel destroys
// the device, and routes that point at it, when the process exits.
//
// water handles the 4-byte address-family header that utun adds to packets.
// The device is configured through sysrouter (ifconfig), not here.
func OpenUTun() (TUN, error) {
	return water.New(water.Config{DeviceType: water.TUN})
}
