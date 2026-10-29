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

package sysexec

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCallString(t *testing.T) {
	require.Equal(t, "route -n add -net 0.0.0.0/1 -interface utun5",
		Cmd("route", "-n", "add", "-net", "0.0.0.0/1", "-interface", "utun5").String())
	require.Equal(t, "networksetup -setdnsservers 'USB 10/100/1000 LAN' empty",
		Cmd("networksetup", "-setdnsservers", "USB 10/100/1000 LAN", "empty").String())
	require.Equal(t, `echo 'it'\''s' ''`, Cmd("echo", "it's", "").String())
}

// The Real executor runs only harmless shell builtins here.
func TestReal_Success(t *testing.T) {
	out, err := Real{}.Run(context.Background(), Cmd("sh", "-c", "echo out; echo err >&2"))
	require.NoError(t, err)
	require.Equal(t, "out\n", string(out))
}

func TestReal_Failure(t *testing.T) {
	_, err := Real{}.Run(context.Background(), Cmd("sh", "-c", "echo out; echo err >&2; exit 3"))
	var ce *CommandError
	require.ErrorAs(t, err, &ce)
	require.Equal(t, 3, ce.ExitCode)
	require.Contains(t, ce.Output, "out")
	require.Contains(t, ce.Output, "err")
	require.Contains(t, OutputOf(err), "err")
	require.Contains(t, err.Error(), "sh -c")
}

func TestReal_LocaleAndPathArePinned(t *testing.T) {
	out, err := Real{}.Run(context.Background(), Cmd("sh", "-c", `echo "$LC_ALL|$PATH"`))
	require.NoError(t, err)
	require.Equal(t, "C|/usr/sbin:/usr/bin:/sbin:/bin\n", string(out))
}

func TestFake(t *testing.T) {
	f := &Fake{Handler: func(c Call) ([]byte, error) {
		if c.Name == "fail" {
			return nil, errors.New("boom")
		}
		return []byte("ok"), nil
	}}
	out, err := f.Run(context.Background(), Cmd("a", "1"))
	require.NoError(t, err)
	require.Equal(t, "ok", string(out))
	_, err = f.Run(context.Background(), Cmd("fail"))
	require.Error(t, err)
	require.Equal(t, []Call{Cmd("a", "1"), Cmd("fail")}, f.Calls())
}

func TestDryRun_NeverRunsMutatingCalls(t *testing.T) {
	next := &Fake{Handler: func(c Call) ([]byte, error) {
		if c.Name != "read" {
			t.Fatalf("dry run passed a mutating call through: %s", c)
		}
		return []byte("state"), nil
	}}
	var out bytes.Buffer
	d := &DryRun{Next: next, IsReadOnly: func(c Call) bool { return c.Name == "read" }, Out: &out}

	got, err := d.Run(context.Background(), Cmd("read"))
	require.NoError(t, err)
	require.Equal(t, "state", string(got))
	got, err = d.Run(context.Background(), Cmd("write", "x y"))
	require.NoError(t, err)
	require.Empty(t, got)

	require.Equal(t, []Call{Cmd("read")}, next.Calls())
	require.Equal(t, []Call{Cmd("write", "x y")}, d.Skipped())
	require.Equal(t, "    write 'x y'\n", out.String())
}

func TestDryRun_NilPredicateSkipsEverything(t *testing.T) {
	next := &Fake{}
	d := &DryRun{Next: next}
	_, err := d.Run(context.Background(), Cmd("read"))
	require.NoError(t, err)
	require.Empty(t, next.Calls())
}
