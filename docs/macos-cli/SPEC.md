# Outline macOS CLI: Specification

Target location in the repo: `docs/macos-cli/SPEC.md`

Status: draft for planning. Statements marked **[verified]** were confirmed by reading the source of `OutlineFoundation/outline-apps` (master) and `OutlineFoundation/outline-sdk` (master) during research. Statements marked **[unverified]** are assumptions the agent must check before relying on them.

---

## 1. Goal

Build a **command-line Outline VPN client for macOS (Apple Silicon and Intel)** that:

1. Runs as a root process (`sudo`) and **does not use Apple's Network Extension**, so it needs no Apple Developer account, no entitlements and no provisioning profile.
2. Accepts the same access keys as the Outline app, including **dynamic `ssconf://` keys** and advanced YAML/JSON transport configs.
3. Adds two features the stock client lacks:
   - **Bypass list:** traffic to listed domains never goes through the VPN.
   - **VPN-only list:** listed domains are blocked unless the VPN is up; when it is up they work normally.
4. Is built by **GitHub Actions** on macOS runners. The developer has Go, Node 22 and the Xcode command line tools locally, but not full Xcode.

This is for personal use. Distribution, notarization and a GUI are out of scope.

## 2. Non-goals

- No GUI, menu-bar item, Electron app, Cordova app or Network Extension.
- No Windows or Linux work. Do not break the existing Linux/Windows builds, but do not extend them.
- No changes to the Outline server or server manager.
- No always-on or at-boot operation in the first version (a LaunchDaemon is a possible later step).

## 3. Background (verified facts)

- **[verified]** macOS in the stock repo is a Cordova/Mac Catalyst app. The VPN is a `NEPacketTunnelProvider` (`client/src/cordova/apple/OutlineLib/VpnExtension`). The Electron client targets only Windows and Linux. Do not try to port either.
- **[verified]** The Go module is named `localhost`. Packages import each other as `localhost/client/go/...`. The Go version is pinned in `go.mod` (1.25.0 at research time).
- **[verified]** `client/go/outline/electron/main.go` (package `main`) is a CLI-like binary used by Electron on Windows/Linux. It takes `-client` (a JSON/YAML client config), `-tunName`, `-tunAddr`, `-tunGw`, `-tunMask`, `-tunDNS`, `-adapterIndex` and others. It opens a TUN device with `github.com/eycorsican/go-tun2socks/tun`, connects a remote device through `vpn.ConnectRemoteDevice`, and relays traffic with `vpn.RelayTraffic`. It does not set routes or system DNS, and does not fetch `ssconf://` keys.
- **[verified]** `go-tun2socks` v1.16.11 has `tun/tun_darwin.go`. It opens a `utun` through `github.com/songgao/water` and configures it with `ifconfig`. It needs root and no entitlement.
- **[verified]** Traffic from the TUN is terminated in userspace by lwIP (`golang.getoutline.org/sdk/network/lwip2transport`). The Go code sees only IP:port destinations: `DialStream(ctx, "1.2.3.4:443")` for TCP and `NewAssociation()` / `SendPacket(p, dst netip.AddrPort)` for UDP. Hostnames are not visible at this layer.
- **[verified]** DNS: the OS resolver is pointed at the link-local address `169.254.113.53`. `client/go/outline/configregistry/outline_dns_intercept.go` (`wrapTransportPairWithOutlineDNS`) intercepts TCP and UDP to that address and forwards to a randomly chosen public resolver (1.1.1.1, 9.9.9.9, 208.67.222.222, 208.67.220.220). It is applied in the `shadowsocks`, `tcpudp` and `basic-access` (proxyless) transports. The address is an unexported constant `linkLocalDNS`. The Apple extension sets the same address in `PacketTunnelProvider.swift`.
- **[verified]** `configregistry` already has `direct`, `block` and `iptable` stream dialers. `iptable` routes TCP by destination IP only. There is no UDP equivalent and nothing domain-aware.
- **[verified]** Dynamic keys: `client/web/app/outline_server_repository/config.ts` rewrites `ssconf://` to `https://`, fetches it through the Go method `FetchResource` (plain HTTP GET, 10 s timeout, in `go/outline/fetch.go`), passes the body to the Go method `ParseTunnelConfig`, and uses the result (client config and first-hop address). Both methods are reachable through the exported `outline.InvokeMethod(method, input string) *InvokeMethodResult` in `go/outline/method_channel.go`.
- **[verified]** The Windows build passes a physical-adapter-bound base dialer into `configregistry.NewDefaultTransportProvider(tcp, udp)` via `newBaseDialersWithAdapter(nicIdx)` in `electron/dialer_windows.go`. `electron/dialer_others.go` (`//go:build !windows`) is a stub returning `errors.ErrUnsupported`. A darwin implementation belongs here.
- **[verified]** The repo enforces Apache-2.0 license headers (`license.yml`, `npm run addlicense:check`) and Conventional Commits (`commitlint.config.js`).
- **[verified]** `outline-sdk/x/examples/outline-cli` exists but is Linux-only, accepts only `ss://`, and has no `ssconf://` support. Do not base the work on it.
- **[unverified]** The `lwip2transport`/`go-tun2socks` core needs cgo and compiles on darwin arm64 and amd64 with the command line tools alone.
- **[unverified]** `ParseTunnelConfig` accepts the same YAML/JSON forms that dynamic keys return. The `-client` flag format expected by `main.go`.
- **[unverified]** `golang.org/x/net/dns/dnsmessage` is usable here (it is not a direct dependency in `go.mod` today).
- **[unverified]** `IP_BOUND_IF` / `IPV6_BOUND_IF` constants exist in the pinned `golang.org/x/sys/unix` for darwin.
- **[unverified]** The pinned SDK (`v0.1.0-rc1`) matches SDK master for the APIs used here.

## 4. Architecture decisions

1. **Base the CLI on `client/go/outline/electron/main.go`.** Create a new package `main` in a new directory (suggested: `client/go/outline/macoscli/`) that reuses the app's own `outline`, `configregistry` and `vpn` packages. This gives the app's full config registry (`shadowsocks`, `websocket`, `first-supported`, `tcpudp`, `basic-access`, `dial`, `iptable`).
2. **No Network Extension.** Use a `utun` device plus the system routing table and DNS settings, applied by shelling out to `route`, `ifconfig`, `networksetup`, `scutil`, `pfctl`.
3. **Loop prevention by interface binding, not host routes.** All of the transport's own sockets, and all direct (bypass) sockets, are bound to the physical interface with `IP_BOUND_IF` (and `IPV6_BOUND_IF`). Pass the bound dialers into `NewDefaultTransportProvider`, exactly as the Windows path does. A host route for the server IP may be added as defense in depth, but must not be the only mechanism, because first hops can be hostnames, CDNs, or multiple endpoints.
4. **All system mutation goes through one interface** (suggested name `SystemRouter`) with a real implementation that executes commands and a fake for tests. Nothing else in the codebase runs `exec.Command`.
5. **Domain rules wrap the transport, with minimal edits to upstream files.** The preferred design wraps the `TransportPair` after parsing, so the wrapper sees DNS traffic addressed to `169.254.113.53:53` before the built-in intercept does. This likely needs one small optional hook in `client.go` (for example `ClientConfig.WrapTransport func(*configregistry.TransportPair) (*configregistry.TransportPair, error)`) or an equivalent new file in package `outline`. The agent must justify its choice in the plan.
6. **Fail closed for VPN-only domains; fail safe for the system.** If the CLI crashes, routes and DNS must be recoverable (see section 7), and VPN-only block rules must stay in place.

## 5. CLI interface

```
sudo outline-cli connect  --key <ss://… | ssconf://… | https://… | /path/to/config.yaml>
                          [--key-file PATH] [--rules PATH] [--log-level LEVEL]
                          [--dry-run]            # resolve key + print plan; no root needed
sudo outline-cli cleanup                         # restore routes/DNS/IPv6 from the state file
sudo outline-cli lockdown                        # install VPN-only block rules (persistent)
sudo outline-cli unlock                          # remove VPN-only block rules
outline-cli version
```

- Keys must also be readable from the environment (`OUTLINE_KEY`) or `--key-file`, so they stay out of shell history.
- Under `sudo`, `$HOME` may be root's. Resolve the invoking user's config via `SUDO_USER`, or require an explicit `--rules`.
- Key resolution: for `ssconf://` and `https://`, swap the scheme to `https`, fetch **before** any route or DNS change (the fetch must go out directly), then call `ParseTunnelConfig` via `outline.InvokeMethod`. Ignore the `#fragment` (display name only). Re-fetch on every `connect`.

## 6. Features

### 6.1 Tunnel manager (macOS)

On `connect`:
1. Capture current state first: active interface and gateway (`route -n get default`), the network service name for that interface, current DNS servers, IPv6 setting. Write the **state file** before changing anything.
2. Open a `utun` via go-tun2socks and assign an address (avoid collisions with existing local subnets, as `selectVpnAddress` does in `PacketTunnelProvider.swift`).
3. Routes: `0.0.0.0/1` and `128.0.0.0/1` via the utun. Keep local and private ranges off the tunnel; mirror the exclusion list `kExcludedSubnets` from `PacketTunnelProvider.swift` as a documented, overridable list. Add a host route for `169.254.113.53/32` into the utun.
4. DNS: `networksetup -setdnsservers <service> 169.254.113.53`. Flush caches (`dscacheutil -flushcache; killall -HUP mDNSResponder`).
5. IPv6: the stock Apple path appears to be IPv4-only, so IPv6 would leak. Disable IPv6 on the active service for the session (`networksetup -setv6off`) and restore the previous setting on exit.
6. Poll for network changes (gateway or interface change, for example switching Wi-Fi), update the bound interface index, re-apply what is needed, and call `client.NotifyNetworkChanged()`.

On exit (SIGINT, SIGTERM, SIGHUP) or `cleanup`: restore everything from the state file. At startup, if a stale state file exists, restore it first.

### 6.2 Bypass list ("never route these domains through the VPN")

Rules file (YAML), suggested schema:

```yaml
bypass:                 # matches the domain and all subdomains
  - lichess.org
vpn_only:               # see 6.3
  - example.com
direct_dns: []          # optional; default = the system resolvers captured before DNS was overridden
min_ttl: 60s            # floor for learned IP mappings
max_ttl: 1h             # ceiling
```

Behavior:
1. **Matcher:** suffix match on labels (`lichess.org` covers `www.lichess.org`; it must not cover `notlichess.org`). Case-insensitive; trailing dots normalized.
2. **DNS-aware relay:** parse intercepted UDP and TCP (2-byte length framing) DNS queries to `169.254.113.53:53`. For queries whose name matches a bypass domain, resolve through a **direct** resolver, bound to the physical interface, instead of the remote resolver, so CDNs return answers near the user. Snoop the response: record A/AAAA answers and follow the CNAME chain, and store `IP → domain` with TTL (clamped to `min_ttl`/`max_ttl`). Non-matching queries follow the existing path unchanged.
3. **Routing wrappers:** a `StreamDialer` and a `PacketRelay` that check the destination IP against the learned bypass set. Hits dial **directly**, bound to the physical interface. Misses use the tunnel. Must work for TCP and UDP (QUIC).
4. **Pre-resolution:** at start, resolve every exact (non-wildcard) bypass hostname directly and seed the set; refresh periodically before TTL expiry.
5. Known limits to document in the CLI README: DoH/DoT in browsers bypasses system DNS (name never seen); connections opened before a mapping exists stay on the tunnel; shared CDN IPs can pull other domains onto the direct path; OS DNS caching can hide queries. TLS SNI sniffing is **out of scope** (it would require patching the SDK's `lwip2transport`).

### 6.3 VPN-only list ("blocked unless going through the VPN")

Interpretation: when the VPN is **on**, these domains are reachable normally (always through the tunnel, never direct); when the VPN is **off**, they are blocked.

- **Part A (VPN on):** domains in `vpn_only` never take the bypass path, always use the tunnel, and **fail closed**: if the tunnel transport fails, do not fall back to direct. If a domain appears in both lists, `vpn_only` wins and a warning is logged.
- **Part B (VPN off):** the CLI cannot enforce anything when it is not running, so enforcement lives in persistent system state, installed by `lockdown` and removed by `unlock`:
  - a **`pf` anchor** that blocks outbound traffic on the physical interface to the learned IPs of `vpn_only` domains (tunnel traffic exits to the proxy server's IP, so it is unaffected); the IP set is persisted and refreshed while connected;
  - **`/etc/hosts` entries** mapping those domains to `0.0.0.0`, removed on `connect` and restored on disconnect.
  - If the CLI crashes, the block rules stay (fail closed). `cleanup` restores routes and DNS but must **not** remove the block rules; only `unlock` does.
  - Both need root. IPv4 and IPv6 must be covered.
- Document the limits: DoH in browsers, hardcoded IPs, CDN IP churn, not surviving reboot unless a LaunchDaemon is added later. The agent should present these trade-offs and the alternatives (a NetworkExtension content filter is out of scope; `includeAllNetworks` is whole-device, not per-domain) in its plan.

## 7. Safety and state

- State file (root-owned, mode 0600), suggested path `/var/db/outline-cli/state.json`, written **before** mutation, containing the service name, previous DNS, previous IPv6 setting, added routes, and the utun name.
- Every system change must be reversible by `cleanup` from the state file alone, even after `kill -9`.
- `--dry-run` prints the exact commands that would be run and touches nothing.
- Never log full access keys; redact secrets and the `ssconf` URL path/query.

## 8. Repository rules

- New code in new files and directories. Edits to existing upstream files are limited to: `client/go/outline/electron/dialer_others.go` (build tag change to exclude darwin, so a new `dialer_darwin.go` can be added), one small hook in `client/go/outline/client.go` if needed, and `go.mod`/`go.sum` for new dependencies. Anything else needs a stated reason in the plan.
- Every new file gets the Apache-2.0 license header used elsewhere in the repo.
- Conventional Commits; one commit (or small series) per milestone.
- Never commit real access keys. Use obviously fake keys in tests and docs.
- Do not run `npm ci` or the `npm run action` tooling. The CLI is Go only.
- Keep the upstream CI workflows untouched; add a new workflow file instead.

## 9. Testing strategy

The agent works in a Linux sandbox that **cannot** create a `utun`, change routes or run macOS tools. Therefore:

- Pure logic must be unit-tested on Linux: domain matcher, DNS packet parse/build (UDP and TCP framing, CNAME chains, A/AAAA, truncation), TTL cache and clamping, routing wrappers with fake dialers/relays, `ssconf://` resolution against `httptest`, state-file round trips, cleanup from a state file, and the command sequences produced by the `SystemRouter` implementation (compare against expected commands using a fake executor).
- Darwin-specific code (`IP_BOUND_IF`, `utun`) sits behind `//go:build darwin` and is compiled and vetted in CI on macOS runners.
- The agent must write `docs/macos-cli/MANUAL_TEST.md`: the exact steps the human runs on a real Mac (what to run with `sudo`, what to observe, how to recover). The agent must never claim end-to-end VPN behavior is verified.

## 10. CI (GitHub Actions)

New workflow file `.github/workflows/macos_cli.yml`:

- Runs on a macOS runner (`macos-15`, arm64). Check which Intel runner label is currently available; otherwise build `amd64` on the arm64 runner with `GOARCH=amd64 CGO_ENABLED=1` and clang's `-arch x86_64`.
- `actions/setup-go` with `go-version-file: go.mod`.
- Steps: `go vet` and `go test` for the packages owned by this work, then build `arm64` and `amd64` binaries, combine with `lipo -create`, and **re-sign ad hoc** (`codesign -s - -f`), because `lipo` invalidates the signature and Apple Silicon will not run unsigned binaries. Upload the universal binary as an artifact.
- No step may alter runner routes or DNS. At most, a smoke test that the binary starts and prints `version`.
- On a version tag, attach the binary to a GitHub release (optional, last milestone).
- The agent should use `gh run watch` and `gh run view --log-failed` to iterate on CI failures.
- Note for the README: browser-downloaded binaries are quarantined by Gatekeeper; fetch with `gh run download` / `curl`, or run `xattr -d com.apple.quarantine <file>`.

## 11. Milestones and acceptance gates

| # | Milestone | Gate |
|---|---|---|
| M0 | **Baseline and verification.** Resolve every **[unverified]** item in section 3 by reading code or building in CI. Add the workflow with a build-only job for `./client/go/outline/electron` on macOS arm64 and amd64. | CI green; a short findings note committed; plan updated if an assumption failed. |
| M1 | **CLI skeleton and key resolution.** Subcommands, flag/env/file key input, `ssconf://`/`https://` fetch + `ParseTunnelConfig`, `--dry-run`, redacted logging. | Unit tests pass (Linux + macOS); dry-run prints the resolved transport and first hop for static and dynamic fake keys. |
| M2 | **Tunnel manager.** `SystemRouter` interface and implementations, state file, routes, DNS, IPv6, signal handling, `cleanup`, stale-state recovery, network-change polling. | Fake-executor tests cover connect, disconnect, crash recovery and network change; `--dry-run` shows the command sequence. |
| M3 | **Interface-bound dialers.** `dialer_darwin.go` with `IP_BOUND_IF`/`IPV6_BOUND_IF`, wired into `NewDefaultTransportProvider`. | Builds and vets on macOS CI; logic around interface selection is unit-tested with an injectable control function. |
| M4 | **Domain bypass.** Matcher, DNS relay (UDP + TCP), TTL cache, routing dialer/relay, pre-resolution, rules-file loading. | Unit tests: wildcard/suffix rules, CNAME chains, TTL expiry and clamping, TCP DNS framing, IPv6, direct-vs-tunnel decisions for TCP and UDP. |
| M5 | **VPN-only.** Part A in the router (fail closed, conflict handling) and Part B (`lockdown`/`unlock`, pf anchor and hosts management, persistence of learned IPs). | Fake-executor tests of the exact `pfctl`/hosts operations; documented limitations; plan decision recorded. |
| M6 | **Release and docs.** Universal binary artifact, CLI README, `MANUAL_TEST.md`. | CI produces and signs the universal binary; docs complete. |

## 12. Decisions for the human (the agent should ask, not assume)

1. Mechanism for VPN-off blocking (hosts + pf as specified, or something lighter or stricter).
2. Default direct resolver for bypass domains: system resolvers captured at start, or a fixed public resolver.
3. Whether to disable IPv6 on the service for the session or attempt to tunnel IPv6.
4. Whether a LaunchDaemon for always-on behavior should be planned now or deferred.

## 13. Definition of done

- `connect` works with static and dynamic keys on a real Mac (verified by the human using `MANUAL_TEST.md`).
- Bypass and VPN-only rules behave as specified, with documented limits.
- `cleanup` and crash recovery restore the network, and VPN-only rules persist until `unlock`.
- CI builds a universal binary; unit tests pass; no secrets are committed; license headers and commit format pass the repo's checks.
