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

## 9. Manual test 1 (developer's Mac, 2026-10-30): traffic did not flow

What was observed:
- Connect and disconnect worked: the health checks passed, and DNS, IPv6 and routes were restored afterwards.
- While connected, nothing worked: `dig` through `169.254.113.53` timed out and `curl` got no response.
- `ping 1.1.1.1` answered in 0.36 ms with TTL 64. That reply comes from lwIP, which answers pings itself. So packets did pass between the utun and lwIP, but it says nothing about the server path.

Verified so far:
- **N5 holds:** `route -n get 169.254.113.53` showed `interface: utun4`.
- The parsers read the real Mac correctly: service Wi-Fi on `en1`, gateway `192.168.1.254`, DHCP DNS, IPv6 Automatic.

**Bug found:** the server's host route was never added. The dynamic key is fetched from the server's own IP, so macOS had a kernel-cloned cache route (`WASCLONED`) for it. `route -n get` reported that cache entry as an exact match, and the CLI skipped it as "a route someone else configured". While connected, the server's IP was routed to `utun4`.
- **Fix:** cloned routes are recognized from the `flags` line, deleted, and replaced with the CLI's static host route.

**Open question:** with the host route missing, did the bound sockets still fail? Or does `IP_BOUND_IF` on the primary interface not escape the utun's `/1` routes? That matters for M4, because bypass traffic relies on binding alone.

**Added to answer it:**
- A check after routing, with automatic rollback:
  1. The transport reaches the server with the routes in place.
  2. An ordinary connection (system DNS, default routes) works through the tunnel.
  3. If 2 fails: does DNS at `169.254.113.53` answer?
- Bound-dial failures are now logged with their reason.

## 10. Manual test 2 (developer's Mac, 2026-10-30): traffic flows

**Passed:**
- Both post-routing checks passed.
- `curl -4 https://ifconfig.me` printed the VPN server's IP.
- `dig` works through `169.254.113.53`.
- The server's host route is on `en1` via the router.
- The bound sockets left from `192.168.1.78` on `en1`.

**IPv6:** `curl -6 https://ifconfig.me` succeeded and printed the VPN server's IPv4 address, even though IPv6 is off on Wi-Fi. The request left through the VPN server, so this is not a leak. A leak would show the developer's own ISP address. How an IPv6 connection reached the tunnel is not understood yet; the routing table and utun details have been requested.

**Unclean exit:**
- The test instructions piped the CLI into `tee`. Ctrl-C stopped `tee` too.
- Go's default is to kill a program that writes to a closed stdout or stderr pipe (SIGPIPE). The first log line of the restore therefore killed the process halfway, and the next `connect` correctly reported and restored the leftovers.
- **Fix:** the CLI takes SIGPIPE, so such writes fail with EPIPE and the restore completes. A test with a helper process shows Go's default dies and the fixed process survives. The manual test now uses `tee -i`.

**Reconnect failure:** `route -n get -net 10.0.0.0/8` printed output with no `destination:` line, which aborted the connect. It rolled back before any route was touched. The cause is unknown.
- **Fix:** an unreadable lookup is now logged with the raw output and the route is added anyway. That is safe, because an existing route makes the add fail with "File exists" and is then left alone.

## 11. Manual test 3 (developer's Mac, 2026-10-30): reconnect and network switch

**Passed:**
- Ctrl-C restored everything (with `tee -i`), and an immediate reconnect worked.
- `cleanup --dry-run` afterwards found nothing to clean up.

**IPv6, resolved, no leak:**
- `curl -6 https://ifconfig.me` connected to `::ffff:34.160.111.145`, an IPv4-mapped address. `ifconfig.me` has no IPv6 address, so this was IPv4 through the tunnel.
- `netstat -rn -f inet6` showed no IPv6 default route for Wi-Fi, and the CLI's `utun4` had no IPv6 address. The `utun0`–`utun6` IPv6 routes belong to macOS's own system tunnels.
- The manual test now uses an IPv6-only host.

**`route -n get` printing nothing:**
- On a reconnect, every lookup of a route that doesn't exist printed nothing on stdout and exited 0; the "not in table" error goes to stderr.
- Empty output now simply means "no such route". Non-empty unexpected output is still logged.

**Bug, hotspot switch (same Wi-Fi service, new network):**
- The transport resolves its server's host name through the direct resolvers. Those were only refreshed when the network *service* changed.
- A hotspot over Wi-Fi keeps the service and the interface, so lookups kept going to the old router `192.168.1.254` ("can't assign requested address"), and the tunnel stayed down.
- The Go resolver also kept retrying the first server, never the others.

**Fixes:**
- The direct resolvers are recomputed on every network change: the user's manual DNS if set, else the new DHCP servers from `ipconfig getpacket` (`scutil` only shows the tunnel's DNS while connected), then the gateway, then `1.1.1.1`.
- Lookups try each resolver in turn, with a 3 s limit each.
- Tests reproduce the hotspot case, and a fake DNS server on loopback shows the fallback to the next resolver.

## 12. Manual test 4 (developer's Mac, 2026-10-30): IPv6 passes, hotspot switch still stuck

**IPv6 passed:** `curl -6 https://ipv6.icanhazip.com` failed with exit 6, the same as with the stock client.

**Hotspot switch:**
- The CLI logged `the network is gone` and never `the network changed`.
- Afterwards, the bound sockets on `en1` failed with `can't assign requested address` (no IPv4 address on `en1`) and `network is unreachable` (no route on `en1`), even for `1.1.1.1`.
- So the new network was never configured as far as the CLI could see, and the CLI never switched to it.
- The earlier run showed the same state for over 40 s. After Ctrl-C, which restores DNS and routes, the network works.
- **Working hypothesis:** something in the connected state keeps macOS from finishing the new network's IPv4 setup (DHCP, or the default route).
- **Added to find out:** while offline, the CLI now logs the default routes it sees (including scoped ones) each time they change, and how long it has been waiting.

## 13. Manual test 5 (developer's Mac, 2026-10-30): switching between a router's 2.4 GHz and 5 GHz networks

Baseline without the VPN: about 6 s to switch.

**With the VPN:**
- The CLI saw the drop and logged `the network is back after 4s`, with the same router (`192.168.1.254`) on the same interface (`en1`).
- After that, every connection to the server failed with `can't assign requested address` for minutes, although `en1` was up (`BOUND`, `RouterARPVerified`) with a new address: `192.168.1.79` instead of `192.168.1.78`.

**Cause:**
- macOS stores the interface address in a gateway route when the route is added, and keeps using it after that address is gone.
- The CLI's own gateway routes (the server host route and the exclusions, visible as `192.168/16` and `172.16/12` via `192.168.1.254`) still used `.78`.
- The CLI decided "network changed" by interface and gateway only, so with the same router it never re-created them.
- This most likely also explains the hotspot runs (manual tests 3 and 4), where the address changed as well.

**Fix:**
- The interface's IPv4 addresses (`ifconfig IFACE`, read-only) are now part of the network's identity.
- Any change of interface, gateway or address, and any return from offline, deletes and re-adds the gateway routes, refreshes the direct resolvers, and notifies the transport.
- A default route on an interface without an address counts as "not yet online".
- The simulated Mac now models routes that keep their old source address, and tests reproduce the failure: same router with a new address, an address change without a gap, a return with the same address, and waiting for an address.

## 14. Manual test 6 (developer's Mac, 2026-10-30): network switch recovers

With commit `bd37e0bf`, switching between the router's 2.4 GHz and 5 GHz networks while connected recovers: the routes are re-created with the new address, and traffic flows through the tunnel again. **M3 is confirmed on the developer's Mac** for connect, checks, disconnect, crash recovery, an IPv6 leak check and a same-router network switch. A later quick test with the same build showed that switching to a phone hotspot (a different router) recovers too.

## 15. M4 notes (bypass list)

**Step 0: does binding alone escape the tunnel?** Bypass traffic goes to arbitrary addresses with no host route, so this had to be checked before relying on it.
- A plain bound `connect` can't tell: lwIP accepts every TCP connection itself, so a socket that wrongly entered the utun would also "connect".
- Instead, a third post-routing check (log-only, never fatal) asks `1.1.1.1` for `whoami.cloudflare` (class CH, type TXT, over TCP), which answers with the asker's public address. It asks once through a bound socket and once through the tunnel, and only says whether the two differ; the addresses aren't logged.
- **Answered by manual test 7 (section 16): binding alone does not work.** The check was then removed again (it would only warn on every connect), and bypass addresses get host routes.

**Dependency:** `golang.org/x/net v0.44.0` was already in the local module cache by M4, so nothing was fetched. `go mod tidy` only moved it from the indirect block to the direct one; `go.sum` is unchanged.

**Design as built:**
- `internal/rules`: strict YAML (unknown or duplicate keys are errors, so a typo can't silently drop a rule). `example.com` covers the domain and its subdomains; `*.example.com` covers only subdomains. Names are lowercased and converted to punycode with `idna.Lookup`. IP addresses, URLs, ports and other wildcards are refused. `direct_dns` (IPv4 only) is supported as in SPEC 6.2. A bypass entry that a `vpn_only` entry covers triggers a warning.
- `internal/ipcache`: one expiry per class per address, so a bypass answer never hides a vpn_only one; vpn_only wins while both are valid. TTLs are clamped to `[min_ttl, max_ttl]`.
- `internal/dnsrelay`:
  - A query goes direct only if every question is a bypass name; any vpn_only question sends it through the tunnel. Malformed messages go through the tunnel untouched.
  - Every answer (direct or through the tunnel) is read on the way back. The CNAME chain is followed from the question name; its class is the strongest of any name in it, and its TTL the smallest.
  - Direct resolvers are the binder's (manual DNS, else DHCP, then the gateway, then `1.1.1.1`), or `direct_dns`. Each is tried for 3 s; SERVFAIL and REFUSED move on to the next. If all fail, the query goes through the tunnel (D2).
  - **TCP:** queries are read from the 2-byte-framed stream; replies are written back as they arrive. **Deviation from the plan:** replies on the shared tunnel connection are not matched by ID. Each reply carries its own question (that is what is learned from), replies go back on the same client connection, and RFC 7766 lets them arrive out of order; the client matches IDs itself.
  - Truncated (TC) replies are passed on unchanged; the client retries over TCP, which takes the same path.
- `internal/route`: wraps the parsed `TransportPair`, keeping its connection type, first hop and `NotifyNetworkChanged`.
  - Bypass addresses use the binder's dialer, or a direct UDP relay on the binder's listener (30 s idle timeout), with **no fallback** to the tunnel. Since manual test 7 this path only carries connections lwIP already had before an address's host route existed; new connections follow the route and never enter the utun.
  - vpn_only and unknown addresses use the transport; vpn_only never goes direct, even when the tunnel fails.
  - Host names (only from the transport's own checks) go through the transport.
  - UDP associations are modeled on the SDK's `dnsintercept`: sub-associations are created on first use and replaced if they end; the association closes itself once nothing is active, so lwIP releases the app's socket, as upstream does.
- **Wiring:** with an empty or missing rules file, the transport isn't wrapped at all, so M3 behavior is unchanged. With rules, lwIP gets the router; the post-routing checks use the bare transport.
- **Pre-resolution:** names listed without `*.` (and not overridden by vpn_only) are resolved directly once connected, and again at 80% of their clamped TTL; failures retry after 30 s.

**Limits found:**
- The pinned `dnsmessage` has no SVCB/HTTPS record type, so `ipv4hint` addresses in HTTPS records aren't learned. Writing a parser for them was ruled out (no hand-written DNS parsing).
- The others (DoH, connections opened before a mapping exists, shared CDN addresses, OS and app DNS caches) are listed in `MANUAL_TEST.md` section 7.

**vpn_only in M4:** such addresses are already kept off the direct path. Refusing a transport that isn't fully tunneled (D8) and `lockdown`/`unlock` come in M5.

## 16. Manual test 7 (developer's Mac, 2026-10-30): bypass blocked the domain

**What happened:**
- The VPN itself worked as before (the server's IP from `ifconfig.me`, DNS over UDP and TCP).
- `curl -4 https://ipv4.icanhazip.com` printed nothing, and the site didn't load in Firefox either.
- The log shows every step up to the connect working: the name was resolved ahead of time and again through the relay, its addresses were learned as bypass, and the connection was routed to the direct path. Then: `dial tcp4 <address>:443: connect: network is unreachable` from the socket bound to `en1`.

**Cause:** on macOS, a socket bound to the primary interface with `IP_BOUND_IF` doesn't fall back to that interface's unscoped `default` route when a more specific route on another interface matches. Here the utun's `0/1` and `128/1` match every address, so the kernel refuses the connection. It only worked so far for destinations with a route on `en1` of their own: the server's host route, and the router's DNS inside the excluded `192.168/16`. This answers the open question from manual test 1 (N1 holds only with a matching route on the physical interface).

**Fix:** every address learned for a bypass domain gets a host route via the physical gateway (`route -n add -host ADDR GATEWAY`, purpose `bypass`):
- added **before the DNS answer is passed to the app** (the relay's `OnLearn` hook runs synchronously), so the app's first connection already uses it;
- journaled in the state file like every other route, so `cleanup` and crash recovery remove it;
- moved to the new gateway on every network change, and added once the network is back if it was learned while offline;
- removed at once if the address is later learned for a `vpn_only` domain;
- otherwise kept until disconnect, not expired with the DNS TTL, so long-lived connections aren't cut.

With the route in place, apps' connections to bypass addresses don't enter the utun at all, and the CLI's own bound sockets reach them too.

**Same cause, not fixed (known gaps):**
- The direct resolvers are reachable only if they are inside an excluded range (a home router, a phone hotspot) or have a host route. A public DHCP or manual resolver (for example `8.8.8.8`) and the `1.1.1.1` fallback get "network is unreachable" too. Bypass lookups then fall back to the tunnel (D2), which still works. But the transport's own host-name lookups after a network change would fail on such a network. Giving those resolvers host routes would also send apps' own traffic to them around the tunnel; that trade-off is for the developer to decide.

## 17. Manual test 8 (developer's Mac, 2026-10-30): bypass works

With commit `1c059d3e` and `bypass: [icanhazip.com]`:
- `curl -4 https://ipv4.icanhazip.com` printed the developer's own public IP; `curl -4 https://ifconfig.me` printed the server's.
- The log showed both addresses learned (ahead of time for `icanhazip.com`, and again through the relay for `ipv4.icanhazip.com`), each followed by `added a direct route for a bypass address`.
- `route -n get` for both addresses: the router, on `en1`.
- DNS over UDP and TCP worked for the bypass name and for other names.

**M4 is confirmed on the developer's Mac** for a bypass subdomain over TCP.

**Developer's decision on DNS outside the tunnel (2026-10-30):** lookups for bypass names may leave outside the VPN; lookups for vpn_only or ordinary names, and other traffic, may not. Therefore the direct resolvers do **not** get plain host routes (a host route applies to every app, so apps' own DNS to that resolver would skip the tunnel). The gap from section 16 stays open; see CHECKPOINT section 7 for the proposed fix.

## 18. After M4: server name lookups on networks with a public DNS server

Approved by the developer: when the binder can't look up a first-hop host name (a public DHCP resolver isn't reachable from bound sockets, section 16), it dials the addresses resolved when the session started (`Binder.SetKnownAddrs`). They have host routes via the gateway, so no new route is needed and nothing else leaves the tunnel.

## 19. M5 notes (VPN-only list and lockdown)

**Part A (connected):**
- `connect` refuses `vpn_only` entries with a transport whose TCP or UDP isn't `tunneled` (for example an `iptable` with direct entries), per D8.
- vpn_only addresses never go direct (the router since M4), and lose a bypass host route at once if one exists (shared addresses).
- Names listed without `*.` are looked up ahead of time **through the tunnel only** (DNS over TCP to `169.254.113.53`, which the transport forwards to its resolver), for A and AAAA, and again at 80% of the TTL. This follows the developer's rule: vpn_only lookups never leave the VPN.
- Every address learned for a vpn_only domain is kept in `/var/db/outline-cli/vpn_only.json` (0600), with its domain and when it was last seen; entries unseen for 30 days are dropped. The server's addresses are never kept.

**Part B (`lockdown`/`unlock`), D1:**
- **pf:** anchor `com.apple/outline-cli`, loaded from `/var/db/outline-cli/anchor.conf` with `pfctl -a com.apple/outline-cli -f FILE`. The table is written inline (`table <outline_vpn_only> persist { ... }`), not from a separate file as planned: the anchor file already holds everything and is reloaded on every change.
  - Disconnected form: `block drop out quick from any to <outline_vpn_only>`.
  - Connected form: `pass out quick on utunN from any to <outline_vpn_only>` first. No address family, so both IPv4 and IPv6 are covered. No physical interface is named.
  - pf is enabled with `pfctl -E`; its reference token (printed on standard error, hence `Call.CombinedOutput`) is kept in `lockdown.json` and released by `unlock` with `pfctl -X`.
  - If `pfctl -s rules` shows no `anchor "com.apple/*"`: with an empty main ruleset (nothing loaded since boot), `/etc/pf.conf` is loaded, provided it has that anchor; a non-empty main ruleset without it is someone else's setup, and lockdown fails with an error instead of changing it. N4 was confirmed by manual test 9 (section 20).
- **hosts:** a block between `# BEGIN outline-cli ...` and `# END outline-cli` with `0.0.0.0 NAME` and `:: NAME` for each entry without `*.`. It's a pure text transform (golden-tested), written atomically, keeping the file's mode; a one-time backup goes to `hosts.backup`.
- `lockdown.json` is written **before** anything is installed, so an interrupted lockdown is finished by `cleanup`.
- **Lifecycle:**
  - `connect`: after the routes are up, the connected form, then the hosts block is removed. If that fails, the vpn_only domains stay blocked (fails closed) and a warning is logged.
  - Disconnect: the disconnected form and the hosts block, even if restoring the network failed.
  - `cleanup`: re-installs both whenever lockdown is on (including after a reboot, which re-enables pf with a new token). It never removes them.
  - A connect that recovers a crashed session re-installs them before fetching the key.
  - `lockdown` and `unlock` take the instance lock, so they refuse while `connect` runs.
- `lockdown` never resolves names itself (that would leak the lookups); the table holds what sessions learned.
- `pfctl` reads (`-s info`, `-s rules`, `-a ANCHOR -s rules`) are on the dry-run allowlist; every other `pfctl` call counts as a change. The simulated Mac models pf (enable references, main ruleset, anchors, reboot).
- Tests never touch `/etc/hosts` or `/etc/pf.conf`: the lockdown manager has no default paths, and the test environment always passes temporary files.

## 20. Manual test 9 (developer's Mac, 2026-10-30): VPN-only and lockdown work; crash cleanup failed

**Passed:**
- Connect, the bypass list and the vpn_only list worked as before; while connected, the vpn_only site showed the server's IP.
- `lockdown --dry-run` listed the IPv4 and IPv6 address learned through the tunnel; `lockdown` installed them.
- While disconnected: the site was blocked by name (`dscacheutil` gave `0.0.0.0` and `::`) and by address (`curl --resolve` to the learned address timed out, exit 28); other sites worked.
- **N4 holds:** the anchor loaded under the stock main ruleset (`pfctl -s rules` shows `anchor "com.apple/*" all`), its table held the addresses, and pf applied the block. `/etc/pf.conf` was not touched.
- Reconnecting made the site reachable through the tunnel again.
- After `kill -9` while connected, the site stayed blocked (the pass rule names a utun that no longer exists), and `cleanup` re-installed the lockdown.

**Bug: `cleanup` failed after the crash, and so did every later `cleanup` and `connect`:**
- `route -n delete -net 0.0.0.0/1 -interface utun4` failed with `route: bad address: utun4` (exit 68). The kernel had already removed the utun **and** its routes (N3), but `route` resolves the interface name before it looks at the routing table, so for a missing interface it never gets to "not in table" (the error the CLI accepted as "already gone").
- `cleanup` had restored DNS, IPv6 and the gateway routes on its first run; only the three utun routes stayed in the state file, and each retry failed the same way. `connect` runs the same recovery first, so it refused to start.
- The simulated Mac answered "not in table" in this case, so the 48 crash tests never saw it.

**Fix:** when deleting an interface route fails with "bad address" and `ifconfig IFACE` (read-only) says the interface doesn't exist, the route counts as deleted. The simulated Mac now answers like the real `route` (an interface that doesn't exist is "bad address", for add and delete), and with the old code the crash tests fail with exactly the error from this test.

Also seen: `ifconfig.me` now has an IPv6 address (the AAAA lookup through the tunnel found one), unlike in manual test 3 (section 11). The IPv6 leak check in `MANUAL_TEST.md` uses `ipv6.icanhazip.com` anyway.

Also seen: after the crash, `netstat` showed `169.254.113.53 link#7 UHRLSW en1 !`. That is macOS's own entry, cloned from the on-link `169.254/16` route when something kept querying the old DNS address; it isn't the CLI's and expires by itself.

## 21. Manual test 10 (developer's Mac, 2026-10-30): crash cleanup fixed

With commit `e825d82c`, `cleanup` after `kill -9` restores everything, the lockdown included, and so does a plain `connect` after a crash (it runs the same recovery first).

Between the crash and the recovery, nothing that needs DNS works (DNS still points at the dead tunnel's address; plain `curl` to a host name hung, and one later attempt went through once a cached answer was used). The developer accepted this as intended; it's documented in `README.md` and `MANUAL_TEST.md` section 5.

## 22. M6 notes

- `docs/macos-cli/README.md`: recovery first, then install (CI artifact with `chmod +x`, `xattr -dr com.apple.quarantine` and the SHA-256 check; or `build-local.sh`), the key file, connect, rules, lockdown, limits, what the CLI changes on the Mac, and pointers for developers.
- `MANUAL_TEST.md`: scope finalized; the lockdown checks fill in the learned address with a command, because the developer twice hit zsh reading a leftover `<address>` placeholder as a redirect.
- CI already builds, signs and uploads the universal artifact `outline-cli-macos-universal`; the developer has been testing with downloads of it.
