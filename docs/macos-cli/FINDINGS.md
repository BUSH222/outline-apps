# macOS CLI: M0 findings

Results of milestone M0: checking the spec's assumptions against the code, plus
the first local build. Paths are relative to the repo root. "Verified" here
means verified by reading source or by a local build; **no VPN behavior has been
tested**.

Build host: Intel Mac (i5-8500), macOS 15.6 (Darwin 24.6), Go 1.25.14, Xcode
Command Line Tools only (Apple clang 17, MacOSX 15.5 SDK). No full Xcode.

## 1. Spec §3 `[unverified]` items

| # | Assumption | Result | Evidence |
|---|---|---|---|
| A1 | lwIP/go-tun2socks cgo compiles on darwin arm64 and amd64 with the CLT alone | **Verified (local build)** | `go-tun2socks@v1.16.11/core` only needs `#cgo CFLAGS: -I./c/include` and no Apple frameworks. `./client/go/outline/electron` (which links `lwip2transport`) builds natively for amd64 and cross-builds for arm64 with `GOARCH=arm64 CGO_ENABLED=1 CC="clang -arch arm64"`. `go vet` passes for both. See section 3. |
| A2 | `ParseTunnelConfig` accepts what dynamic keys return; the `-client` format | **Verified (source)** | `client/go/outline/parse.go:78-182` accepts: a YAML scalar string (an `ss://` URL); legacy Shadowsocks JSON (`server`, `server_port`, `method`, `password`); YAML/JSON with `transport:` (and optional `reporter:`); and `error: {message, details}`, which becomes a `ProviderError`. The result is JSON `{client, firstHop, connectionType}`, where `client` is a JSON string `{"transport": …}` in the `ProviderClientConfig` shape that `-client` and `ClientConfig.New` consume (`client.go:84-87,132`). On darwin, parsing does no network I/O: hostname pre-resolution only runs on linux and windows (`configregistry/config_dial_endpoint.go:60`). |
| A3 | `golang.org/x/net/dns/dnsmessage` is usable | **Verified (source)** | `go.mod` already lists `golang.org/x/net v0.44.0 // indirect`, and `go.sum` has its `h1:` hash. The pinned SDK's own `dns` package imports `dnsmessage`. Using it moves x/net to the direct block of `go.mod`. The module zip is not in the local module cache yet, so it is first fetched from `proxy.golang.org` in M4. |
| A4 | `IP_BOUND_IF` / `IPV6_BOUND_IF` in the pinned `golang.org/x/sys` | **Verified (source)** | `golang.org/x/sys@v0.36.0/unix/zerrors_darwin_{amd64,arm64}.go`: `IP_BOUND_IF = 0x19`, `IPV6_BOUND_IF = 0x7d`. |
| A5 | Pinned SDK `v0.1.0-rc1` matches SDK master | **Moot** | The CLI compiles only against the pinned version. Every API the plan uses exists in `golang.getoutline.org/sdk@v0.1.0-rc1`: `lwip2transport.ConfigureDeviceWithRelay`, the `packetrelay` interfaces and `NewPacketRelayFromPacketListener`, `dnsintercept`, `dns.NewUDPResolver` / `dns.NewTCPResolver`, and `transport.UDPListener{ListenConfig}`. |

## 2. New assumptions (cannot be checked without root or a real network)

| # | Assumption | How it will be checked | Fallback |
|---|---|---|---|
| N1 | A socket with `IP_BOUND_IF` ignores the `0/1` and `128/1` utun routes and uses the physical interface's scoped default route | M3: a local darwin test with short timeouts binds sockets to `lo0`'s index and checks that loopback works and that a TEST-NET address (`192.0.2.1`) is unreachable. Real routing is checked in `MANUAL_TEST.md`. | Gateway host routes for the server, already planned as defense in depth |
| N2 | `IPV6_BOUND_IF` on a dual-stack `AF_INET6` socket (Go's wildcard `ListenPacket("udp")`) also scopes IPv4-mapped traffic | Same M3 probe on a `"udp"` wildcard listener | Use `udp4` listeners while IPv6 is off; set both options and ignore EINVAL on the one that doesn't apply |
| N3 | When the process dies, the kernel destroys the utun and the routes that point at it | `MANUAL_TEST.md` (`kill -9`, then `netstat -rn`) | `cleanup` deletes every recorded route either way |
| N4 | A pf anchor loads under the stock `anchor "com.apple/*"` without editing `/etc/pf.conf` | `MANUAL_TEST.md` (`pfctl -a com.apple/outline-cli -sr`) | A guarded edit of `/etc/pf.conf` |
| N5 | A host route for the link-local `169.254.113.53` via `-interface utunN` is accepted and wins over the on-link `169.254/16` route | `MANUAL_TEST.md` (`route -n get 169.254.113.53` shows the utun) | Pick a non-link-local DNS address for the intercept (needs the address to be configurable; upstream hard-codes it) |
| N6 | The parsers match real output of `netstat -rn -f inet`, `networksetup -listnetworkserviceorder / -getdnsservers / -getinfo`, `scutil --dns` and `route -n get` on macOS 15 (fixtures follow the documented formats; no real output was captured). Manual IPv6 restore needs `networksetup -getinfo` to print a prefix length; if it doesn't, IPv6 is left alone with a warning | `connect --dry-run` on the developer's Mac runs exactly these read-only queries | Fix the parser from the pasted output |
| N7 | `route -n get -net X` reports the matching route itself when an exact route exists (used to avoid recording routes the CLI didn't add) | `MANUAL_TEST.md` | Compare against `netstat -rn` instead |

## 3. Findings that change the design

1. **No `client.go` hook is needed.** `vpn.ConnectRemoteDevice(ctx, sd, pr)` (`client/go/outline/vpn/device.go`) takes a plain `transport.StreamDialer` and `packetrelay.PacketRelay`. `outline.ProviderClientConfig`, `outline.NewReporterParser`, `configregistry.NewDefaultTransportProvider` and `configregistry.PacketRelay.NotifyNetworkChanged` are all exported. So the CLI decodes the client config, parses the transport, wraps the resulting `*TransportPair` with the domain rules, and passes it to `ConnectRemoteDevice`. Wrapping the `TypeParser` instead would not work: `configyaml.TypeParser.Parse` rejects any `$type` it has no subparser for.
2. **`NotifyNetworkChanged()` must be called once at start.** In the app, `Client.StartSession` does it. Without it, the UDP connectivity check never runs and DNS stays in "truncate" mode, which forces every query onto TCP (`configregistry/outline_dns_intercept.go:83-98`).
3. **No edit to the electron package is needed.** The interface-bound dialers live in the CLI's own package, so `electron/dialer_others.go` stays untouched.
4. **Some transport sockets are not interface-bound and would loop into the utun:**
   - `basic-access` hardcodes `&transport.TCPDialer{}` and `&transport.UDPListener{}` (`configregistry/config_proxyless.go:59,64`).
   - `tcpudp` with `udp: null` or `$type: direct` uses the unbound `directWrappedPL` (`configregistry/registry.go:76`).
   - Decision D7: the CLI refuses to connect when the parsed stream dialer or packet relay is `ConnTypeDirect`. TCP `direct` and `iptable` entries use the injected (bound) dialer, so they are fine.
5. **Hostname first hops resolve at dial time on darwin** through the system resolver. Once connected, that resolver points at `169.254.113.53`, which is inside the tunnel. The bound dialers therefore carry their own `net.Resolver{PreferGo: true}` that queries the resolvers captured before the change, over interface-bound sockets. First-hop IPs are also resolved before any change and get gateway host routes.
6. **`tun.OpenTunDevice` on darwin** ignores the requested name, does not return the chosen `utunN` (which the routes need), and runs `ifconfig` itself. The CLI opens the utun with `github.com/songgao/water` instead. It is already a direct dependency, handles the 4-byte address-family header (`syscalls_darwin.go:224-266`), and exposes `Name()`. `ifconfig` then goes through the CLI's single command executor.
7. **`fetchResource` leaks the URL:** it puts the full URL in the error's `Details` (`client/go/outline/fetch.go:40,59`), which would expose an `ssconf` secret in logs. It also can't take an injected HTTP client, so it can't be tested against a TLS `httptest` server. The CLI uses its own small fetcher with the same 10 s timeout and non-2xx rule, plus redaction. `ParseTunnelConfig` still goes through `outline.InvokeMethod`.
8. **The exclusion list overlaps the DNS address.** `kExcludedSubnets` in `PacketTunnelProvider.swift` includes `169.254.0.0/16`, which contains `169.254.113.53`. The `/32` route into the utun is more specific, so it wins. macOS already has a `169.254` link route, so adding the exclusion fails with EEXIST. The CLI only records and removes routes it actually added.
9. **cgo objects default to the host's macOS version (15.0)** as their minimum. A binary built on macOS 15 would refuse to run on 12–14. Setting `MACOSX_DEPLOYMENT_TARGET` alone is not enough, because it isn't part of Go's build cache key: cached objects built for 15.0 get reused, and the linker warns. `build-local.sh` passes `-mmacosx-version-min=12.0` in `CGO_CFLAGS` and `CGO_LDFLAGS`, and checks every slice's `LC_BUILD_VERSION minos`.
10. **`lipo` drops the signature.** After `lipo -create`, `codesign --verify` reports "code object is not signed at all". Re-signing with `codesign --force --sign -` fixes it, as the spec expected.

## 4. Local build results (M0 gate)

Command: `PKG=./client/go/outline/electron NAME=outline-electron-m0 SMOKE_ARGS=-version docs/macos-cli/build-local.sh`

| Check | Result |
|---|---|
| amd64 slice, native build | OK, `minos 12.0` |
| arm64 slice, cross-build (`CC="clang -arch arm64"`) | OK, `minos 12.0`, no linker warnings |
| `go vet ./client/go/outline/electron`, amd64 and arm64 | OK |
| `lipo -create` → `x86_64 arm64` | OK |
| `codesign --force --sign -`, then `codesign --verify --strict` | OK ("valid on disk", "satisfies its Designated Requirement") |
| Smoke test: x86_64 slice runs `-version` | OK (prints the embedded git revision) |
| arm64 slice | Not runnable on an Intel host. Checked with `lipo -archs` and `LC_BUILD_VERSION`; it runs in CI on `macos-15` |

## 5. CI (`.github/workflows/macos_cli.yml`)

- **Runners** (checked Oct 2026): `macos-15` (arm64) and `macos-15-intel` (x86_64, supported until about Aug 2027). Not used: `macos-14` (retiring 2026-11-02) and `macos-latest` (now macOS 26).
- **Jobs:**
  - `build`: per architecture, natively, using `build-local.sh build ARCH`.
  - `universal`: on `macos-15`, using `build-local.sh universal`. It produces the artifact `<NAME>-macos-universal` (the binary plus a SHA-256 file).
- **Permissions:** `contents: read`. No `gh`, no release job, no tag trigger.
- **Action pins** (lightweight tags, so these are commit SHAs, found with `git ls-remote`):
  - `actions/checkout` v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1` (same pin as the repo's other workflows)
  - `actions/setup-go` v7.0.0 `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` (same pin as the repo's other workflows)
  - `actions/upload-artifact` v7.0.2 `cf430e030ddbb5b0abf93d22962f4752f3646cd9`
  - `actions/download-artifact` v8.0.2 `9000827ccba6bdab643e8b6fd33ac0654aef8333`
- **Artifact zips don't keep the executable bit.** After downloading, run `chmod +x`. Also remove the browser quarantine (`xattr -dr com.apple.quarantine <file>`). Both steps will be documented in the README in M6.
- **CLT-only builds are verified locally, not in CI.** GitHub runners ship full Xcode.
- **Not verified yet:** the first CI run. It needs a push and someone to look at the Actions page.

## 6. Repository conventions

- The commitlint `scope-enum` only allows listed scopes. This work uses `client/macos`.
- License headers are checked without npm: `go tool task addlicense -- -check`.

## 7. M2 notes (tunnel manager)

- `connect --dry-run` now prints the exact connect and disconnect command sequences. It runs only read-only queries (`netstat`, `scutil --dns`, `route -n get`, and `networksetup -listnetworkserviceorder`, `-getdnsservers` and `-getinfo`). Tests use a simulated Mac that fails on any change.
- `connect` without `--dry-run` stays disabled until M3. Without interface-bound sockets, the transport's own traffic would loop into the tunnel.
- Crash safety is tested by crashing before each of the 24 system changes of a connect and then running `cleanup` from the state file alone. That is 48 cases: with and without the kernel removing the utun's routes. Every case must restore routes, DNS and IPv6 exactly.
- Routes that already exist (for example macOS's own `169.254/16` link route) are never recorded or removed.
- First-hop host routes are skipped for addresses inside the excluded ranges, which are already off the tunnel. IPv6-only servers are refused, because IPv6 is off during a session.
- The utun subnet avoids the subnets of local interfaces; the candidates mirror `kVpnSubnetCandidates`. The address is chosen in order rather than at random, so it's predictable.

## 8. M3 notes (interface binding, first real connect)

- **N1 and N2 checked locally** (`internal/netbind/probe_darwin_test.go`, no root, every operation has a 2 s deadline):
  - Sockets bound to `lo0` with `IP_BOUND_IF` reach loopback, but get "no route" for `192.0.2.1` instead of leaving through the physical interface. This holds for TCP, a UDP dial, and a UDP listener.
  - `IPV6_BOUND_IF` on a dual-stack socket also scopes IPv4-mapped traffic ("network is unreachable"). The CLI doesn't depend on this, because all its sockets are IPv4.
  - Whether the real interface's scoped route bypasses the utun routes is still checked only in `MANUAL_TEST.md`.
- **The binder fails closed:** it refuses to create any socket until an interface is set, and a failed `setsockopt` fails the dial. Sockets are IPv4-only (`tcp4`/`udp4`), matching IPv6-off.
- **Host-name lookups in the transport** use a Go resolver that sends queries to the resolvers captured before DNS was changed, over bound sockets. The address the system asks for is ignored, because it would be the tunnel's. If no IPv4 resolver was captured, it falls back to `1.1.1.1` (D2).
- **Real `connect` order:**
  1. Root check, lock, and recovery of a crashed session (before the key fetch).
  2. Parse the transport on bound dialers.
  3. Bind to the captured interface (an error aborts before any change).
  4. Open the utun, start lwIP, `NotifyNetworkChanged()`, and wait for the TCP health check.
  5. Routes, DNS and IPv6, then flush the DNS cache.
  6. Poll for network changes every 2 s. Ctrl-C, SIGTERM and SIGHUP restore everything.
- A usage reporter in a key is ignored, with a warning.
- Tests refuse every real socket by default, so they never send traffic out.
- `go test -race` prints `ld: warning: ... malformed LC_DYSYMTAB` with the current Apple linker. This is a known, harmless linker warning for race builds.
- Not handled yet: detecting a dead transport while connected (traffic stops until Ctrl-C).
