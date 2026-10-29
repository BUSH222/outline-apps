# Outline macOS CLI: Specification

Target location in the repo: `docs/macos-cli/SPEC.md`

Status: approved plan; corrected in M0 against the code. Statements marked **[verified]** were confirmed by reading the source of `OutlineFoundation/outline-apps` (master) and the pinned `golang.getoutline.org/sdk@v0.1.0-rc1`, or by a local build. Statements marked **[unverified]** are assumptions that must be checked before relying on them. Evidence is in [`FINDINGS.md`](FINDINGS.md).

---

## 1. Goal

Build a **command-line Outline VPN client for macOS (Apple Silicon and Intel)** that:

1. Runs as a root process (`sudo`) and **does not use Apple's Network Extension**, so it needs no Apple Developer account, no entitlements and no provisioning profile.
2. Accepts the same access keys as the Outline app, including **dynamic `ssconf://` keys** and advanced YAML/JSON transport configs.
3. Adds two features the stock client lacks:
   - **Bypass list:** traffic to listed domains never goes through the VPN.
   - **VPN-only list:** listed domains are blocked unless the VPN is up; when it is up they work normally.
4. Is built locally with Go and the Xcode command line tools (the developer has no full Xcode). **GitHub Actions** on macOS runners also produces a downloadable universal binary.

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
- **[verified]** `go-tun2socks` v1.16.11 has `tun/tun_darwin.go`. It opens a `utun` through `github.com/songgao/water` and configures it with `ifconfig`. It needs root and no entitlement. **However:** `OpenTunDevice` ignores the requested name, does not return the chosen `utunN` (which the routes need), and runs `ifconfig` itself, which breaks decision 4.4. The CLI opens the utun with `water` directly instead (`water` is already a direct dependency, handles the 4-byte address-family header, and exposes `Name()`).
- **[verified]** `vpn.ConnectRemoteDevice(ctx, sd transport.StreamDialer, pr packetrelay.PacketRelay)` does not need `outline.Client`. `outline.ProviderClientConfig`, `outline.NewReporterParser`, `configregistry.NewDefaultTransportProvider` and `configregistry.PacketRelay.NotifyNetworkChanged` are exported. `NotifyNetworkChanged()` must be called once at start (in the app, `Client.StartSession` does it); otherwise UDP DNS stays in truncate mode.
- **[verified]** Traffic from the TUN is terminated in userspace by lwIP (`golang.getoutline.org/sdk/network/lwip2transport`). The Go code sees only IP:port destinations: `DialStream(ctx, "1.2.3.4:443")` for TCP and `NewAssociation()` / `SendPacket(p, dst netip.AddrPort)` for UDP. Hostnames are not visible at this layer.
- **[verified]** DNS: the OS resolver is pointed at the link-local address `169.254.113.53`. `client/go/outline/configregistry/outline_dns_intercept.go` (`wrapTransportPairWithOutlineDNS`) intercepts TCP and UDP to that address and forwards to a randomly chosen public resolver (1.1.1.1, 9.9.9.9, 208.67.222.222, 208.67.220.220). It is applied in the `shadowsocks`, `tcpudp` and `basic-access` (proxyless) transports. The address is an unexported constant `linkLocalDNS`. The Apple extension sets the same address in `PacketTunnelProvider.swift`.
- **[verified]** `configregistry` already has `direct`, `block` and `iptable` stream dialers. `iptable` routes TCP by destination IP only. There is no UDP equivalent and nothing domain-aware.
- **[verified]** Dynamic keys: `client/web/app/outline_server_repository/config.ts` rewrites `ssconf://` to `https://`, fetches it through the Go method `FetchResource` (plain HTTP GET, 10 s timeout, in `go/outline/fetch.go`), passes the body to the Go method `ParseTunnelConfig`, and uses the result (client config and first-hop address). Both methods are reachable through the exported `outline.InvokeMethod(method, input string) *InvokeMethodResult` in `go/outline/method_channel.go`. **However:** `fetchResource` puts the full URL in the error's `Details` (`fetch.go:40,59`), which leaks the `ssconf` secret, and it can't take an injected HTTP client. The CLI uses its own fetcher (same 10 s timeout and non-2xx rule, with redaction) and calls only `ParseTunnelConfig` through `InvokeMethod`.
- **[verified]** The Windows build passes a physical-adapter-bound base dialer into `configregistry.NewDefaultTransportProvider(tcp, udp)` via `newBaseDialersWithAdapter(nicIdx)` in `electron/dialer_windows.go`. `electron/dialer_others.go` (`//go:build !windows`) is a stub returning `errors.ErrUnsupported`. **Correction:** the darwin bound dialers live in the CLI's own package, so the electron package stays untouched.
- **[verified]** Not every transport socket goes through the injected base dialers. `basic-access` hardcodes `&transport.TCPDialer{}` and `&transport.UDPListener{}` (`config_proxyless.go:59,64`). A `tcpudp` config with `udp: null` or `$type: direct` uses an unbound `&transport.UDPListener{}` (`registry.go:76`). Hostname first hops are resolved at dial time on darwin through the system resolver (pre-resolution only runs on linux and windows, `config_dial_endpoint.go:60`).
- **[verified]** The repo enforces Apache-2.0 license headers (`license.yml`; check without npm with `go tool task addlicense -- -check`) and Conventional Commits (`commitlint.config.js`, whose `scope-enum` requires a listed scope; this work uses `client/macos`).
- **[verified]** `outline-sdk/x/examples/outline-cli` exists but is Linux-only, accepts only `ss://`, and has no `ssconf://` support. Do not base the work on it.
- **[verified, local build]** The `lwip2transport`/`go-tun2socks` core needs cgo and compiles on darwin arm64 and amd64 with the command line tools alone (amd64 native, arm64 cross-built with `CC="clang -arch arm64"`). cgo objects default to the host's macOS version as their minimum, so builds pass `-mmacosx-version-min=12.0` in `CGO_CFLAGS`/`CGO_LDFLAGS`. See `FINDINGS.md`.
- **[verified]** `ParseTunnelConfig` (`parse.go:78-182`) accepts an `ss://` string, legacy Shadowsocks JSON, YAML/JSON with `transport:`, and a provider `error:`. Its `client` output is the `ProviderClientConfig` JSON that `-client` and `ClientConfig.New` consume.
- **[verified]** `golang.org/x/net/dns/dnsmessage` is usable: `golang.org/x/net v0.44.0` is already an indirect dependency with a `go.sum` hash, and the pinned SDK imports `dnsmessage`. Using it only moves x/net to the direct block of `go.mod`.
- **[verified]** `IP_BOUND_IF = 0x19` and `IPV6_BOUND_IF = 0x7d` exist in `golang.org/x/sys@v0.36.0/unix` for darwin amd64 and arm64.
- **[verified]** All SDK APIs used here are present in the pinned `golang.getoutline.org/sdk@v0.1.0-rc1`. SDK master is irrelevant, because the CLI compiles only against the pinned version.
- **[unverified]** `IP_BOUND_IF` sockets ignore the utun routes and use the physical interface's scoped default route; `IPV6_BOUND_IF` also scopes IPv4-mapped traffic on dual-stack sockets; the kernel removes utun routes when the process dies; a pf anchor loads under `com.apple/*` without editing `/etc/pf.conf`. The first two are probed by a local, root-free test in M3; all four are checked in `MANUAL_TEST.md`.

## 4. Architecture decisions

1. **Base the CLI on `client/go/outline/electron/main.go`.** Create a new package `main` in a new directory (suggested: `client/go/outline/macoscli/`) that reuses the app's own `outline`, `configregistry` and `vpn` packages. This gives the app's full config registry (`shadowsocks`, `websocket`, `first-supported`, `tcpudp`, `basic-access`, `dial`, `iptable`).
2. **No Network Extension.** Use a `utun` device plus the system routing table and DNS settings, applied by shelling out to `route`, `ifconfig`, `networksetup`, `scutil`, `pfctl`.
3. **Loop prevention by interface binding, not host routes.** All of the transport's own sockets, and all direct (bypass) sockets, are bound to the physical interface with `IP_BOUND_IF` (and `IPV6_BOUND_IF`). Pass the bound dialers into `NewDefaultTransportProvider`, exactly as the Windows path does. A host route for the server IP may be added as defense in depth, but must not be the only mechanism, because first hops can be hostnames, CDNs, or multiple endpoints. In addition:
   - The bound dialers carry their own `net.Resolver{PreferGo: true}` that queries the resolvers captured before DNS was changed, over bound sockets, so hostname first hops never resolve through the tunnel.
   - The CLI **refuses** configs whose parsed stream dialer or packet relay is `ConnTypeDirect` (`basic-access`, `udp: null` / `direct`), because upstream builds those with unbound sockets that would loop into the utun.
4. **All system mutation goes through one interface** (suggested name `SystemRouter`) with a real implementation that executes commands and a fake for tests. Nothing else in the codebase runs `exec.Command`.
5. **Domain rules wrap the transport, with no edits to upstream Go files.** The CLI parses the transport itself with `NewDefaultTransportProvider(boundTCP, boundUDP).Parse`, wraps the resulting `TransportPair`, and passes the wrapped dialer and relay to `vpn.ConnectRemoteDevice`. The wrapper is therefore outermost and sees DNS traffic addressed to `169.254.113.53:53` before the built-in intercept does. No `client.go` hook is needed. (Wrapping the `TypeParser` would not work, because it rejects any `$type` it has no subparser for.)
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
- `sudo` resets the environment by default (`env_reset`), so `OUTLINE_KEY=… sudo outline-cli` loses the key. Recommended: `--key-file PATH`; the CLI warns if the file is readable by group or others (it should be mode 0600). The alternative, `sudo env OUTLINE_KEY=… outline-cli connect`, briefly shows the key in the process list. `--key` works but lands in shell history.
- Rules file lookup, in order:
  1. `--rules PATH` if given.
  2. Otherwise, if `SUDO_USER` is set: that user's home directory, found with `user.Lookup` (not `$HOME`, which may be root's), plus `/.config/outline-cli/rules.yaml`.
  3. Otherwise: `$HOME/.config/outline-cli/rules.yaml`.
  - A missing file means no rules (logged).
  - An invalid file is an error.
  - `--dry-run` prints the resolved path.
- The only invocations safe to run on a development machine without root are `version` and `connect --dry-run`.
- Key resolution: for `ssconf://` and `https://`, swap the scheme to `https`, fetch **before** any route or DNS change (the fetch must go out directly; any stale state is restored first), then call `ParseTunnelConfig` via `outline.InvokeMethod`. Ignore the `#fragment` (display name only). Re-fetch on every `connect`.

## 6. Features

### 6.1 Tunnel manager (macOS)

On `connect`:
1. Capture current state first:
   - active interface and gateway (`route -n get default`)
   - the network service name for that interface
   - the configured DNS servers (`networksetup -getdnsservers`; "There aren't any DNS Servers set" means DHCP, restored with `empty`)
   - the effective system resolvers (`scutil --dns`, used for direct lookups)
   - the IPv6 setting (`networksetup -getinfo`: Automatic, Manual with address/prefix/router, LinkLocal, or Off)

   Write the **state file** before changing anything.
2. Open a `utun` with `water` and assign an address through the command executor. Avoid collisions with existing local subnets, as `selectVpnAddress` does in `PacketTunnelProvider.swift`.
3. Connect the transport and **wait for the TCP health check before touching any route**. If it fails, tear down; nothing system-wide was changed.
4. Routes. Each route is recorded in the state file before it is added. Only routes this run actually added are removed later (EEXIST means "not ours").
   - Keep local and private ranges off the tunnel: mirror the exclusion list `kExcludedSubnets` from `PacketTunnelProvider.swift` as a documented, overridable list, routed via the gateway. That list contains `169.254.0.0/16`, which macOS already routes on-link, so that one is skipped.
   - Add gateway host routes for the resolved first-hop IPs (defense in depth).
   - Add a host route for `169.254.113.53/32` into the utun (more specific than the exclusion).
   - Add `0.0.0.0/1` and `128.0.0.0/1` via the utun.

   Gateway routes do not disappear with the utun, so they must be in the state file.
5. DNS: `networksetup -setdnsservers <service> 169.254.113.53`. This setting **persists across reboot**, so a crash leaves name resolution broken until `cleanup` runs. The recovery command is documented at the top of the README.
6. IPv6: the stock Apple path appears to be IPv4-only, so IPv6 would leak. Disable IPv6 on the active service for the session (`networksetup -setv6off`) and restore the exact previous setting on exit, including Manual address, prefix and router. This only covers the active service; the CLI warns if others are active.
7. If lockdown is active (6.3): remove the hosts block and load the pf anchor's "connected" form.
8. **Last:** flush caches (`dscacheutil -flushcache; killall -HUP mDNSResponder`), after both the DNS and hosts changes.
9. Poll for network changes (gateway or interface change, for example switching Wi-Fi). On a change: update the bound interface index and resolvers, re-apply what is needed, and call `NotifyNetworkChanged()` on the transport's packet relay.

On exit (SIGINT, SIGTERM, SIGHUP) or `cleanup`, restore everything from the state file in this order:
1. DNS and IPv6.
2. Routes.
3. Close the utun.
4. If lockdown is active: re-install the hosts block and the pf "disconnected" form.
5. Flush caches.
6. Delete the state file.

Each step is idempotent. At startup, if a stale state file exists (its owner is dead), restore it first, before any key fetch.

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
  - a **`pf` anchor** (`com.apple/outline-cli`) with a persisted table of the learned IPs of `vpn_only` domains, refreshed while connected.
    - The rule is **not tied to the physical interface**, because that interface changes and the CLI isn't running when the VPN is off.
    - Disconnected form: `block drop out quick to <table>`.
    - Connected form: a `pass out quick on utunN to <table>` rule comes first. If the CLI crashes, that pass rule matches a dead interface, so the block still applies.
    - Tunnel traffic exits to the proxy server's IP, so it is unaffected. First-hop IPs are never added to the table.
  - **`/etc/hosts` entries** (a marked block) mapping those domains to `0.0.0.0` and `::`, removed on `connect` and restored on disconnect. Hosts entries have no wildcards, so only listed names are covered.
  - If the CLI crashes, the pf block stays (fail closed). After a `kill -9` while connected, the hosts block is missing until `cleanup` runs.
  - `cleanup` restores routes and DNS and **re-installs** the block rules (hosts and the pf disconnected form). It must never remove them; only `unlock` does.
  - Both need root. IPv4 and IPv6 must be covered.
- Document the limits: DoH in browsers, hardcoded IPs, CDN IP churn, not surviving reboot unless a LaunchDaemon is added later. The agent should present these trade-offs and the alternatives (a NetworkExtension content filter is out of scope; `includeAllNetworks` is whole-device, not per-domain) in its plan.

## 7. Safety and state

- State file (root-owned, mode 0600), suggested path `/var/db/outline-cli/state.json`, written **before** mutation, containing the service name, previous DNS, previous IPv6 setting, added routes, and the utun name.
- Every system change must be reversible by `cleanup` from the state file alone, even after `kill -9`.
- `--dry-run` prints the exact commands that would be run and touches nothing.
- Never log full access keys; redact secrets and the `ssconf` URL path/query.

## 8. Repository rules

- New code in new files and directories. Edits to existing upstream files are limited to `go.mod`/`go.sum` for new dependencies (expected: moving `golang.org/x/net` from indirect to direct). The design needs no change to `client/go/outline/client.go` or `client/go/outline/electron/dialer_others.go` (see 4.3 and 4.5). Anything else needs a stated reason in the plan.
- Every new file gets the Apache-2.0 license header used elsewhere in the repo.
- Conventional Commits; one commit (or small series) per milestone.
- Never commit real access keys. Use obviously fake keys in tests and docs.
- Do not run `npm ci` or the `npm run action` tooling. The CLI is Go only.
- Keep the upstream CI workflows untouched; add a new workflow file instead.

## 9. Testing strategy

The agent works on the developer's **real Intel Mac** (Go and the command line tools only). It must never use `sudo`, create a `utun`, or change routes, DNS, IPv6, `/etc/hosts` or pf there. The only CLI invocations it may run are `version` and `connect --dry-run`. Therefore:

- Pure logic is unit-tested locally and stays free of build tags, so it is OS-independent: domain matcher, DNS packet parse/build (UDP and TCP framing, CNAME chains, A/AAAA, truncation), TTL cache and clamping, routing wrappers with fake dialers/relays, `ssconf://` resolution against `httptest`, state-file round trips, cleanup from a state file, and the command sequences produced by the `SystemRouter` implementation (compared against expected commands using a fake executor). Tests assert that the dry-run executor never runs a mutating command.
- Darwin-specific code (`IP_BOUND_IF`, `utun`) sits behind `//go:build darwin`.
  - It is compiled and vetted locally for amd64 (native) and arm64 (cross-compiled with `CC="clang -arch arm64"`).
  - A root-free local test with short timeouts binds sockets to `lo0` to show that `IP_BOUND_IF`/`IPV6_BOUND_IF` take effect.
- Local builds are the main feedback loop; CI is secondary.
- The agent must write `docs/macos-cli/MANUAL_TEST.md`: the exact steps the human runs on a real Mac (what to run with `sudo`, what to observe, how to recover). The agent must never claim end-to-end VPN behavior is verified.

## 10. CI (GitHub Actions)

CI is secondary. Its job is to produce a universal binary the developer downloads from the run's Actions page. **`gh` is not used anywhere.**

New workflow file `.github/workflows/macos_cli.yml`:

- **Runners:** native builds on `macos-15` (arm64) and `macos-15-intel` (x86_64, supported until about Aug 2027). Do not use `macos-14` (retiring 2026-11-02) or `macos-latest` (now macOS 26). If the Intel label goes away, build `amd64` on the arm64 runner with `GOARCH=amd64 CGO_ENABLED=1 CC="clang -arch x86_64"`.
- `actions/setup-go` with `go-version-file: go.mod`. All actions are pinned by commit SHA.
- **Permissions:** `contents: read`. No tag trigger, no release job, no `contents: write`.
- **Steps:**
  - `go vet` and `go test` for the packages owned by this work.
  - Build `arm64` and `amd64` slices with `docs/macos-cli/build-local.sh` (minimum macOS 12.0).
  - Combine them with `lipo -create` and **re-sign ad hoc** (`codesign --force --sign -`), because `lipo` invalidates the signature and Apple Silicon will not run unsigned binaries.
  - Upload the universal binary and its SHA-256 as an artifact.
- No step may alter runner routes or DNS. At most, a smoke test that the binary starts and prints `version`.
- **Failures:** the developer pastes the failing log; the agent reproduces it locally where possible.
- **CLT-only buildability** is verified locally, because GitHub runners ship full Xcode.
- **Notes for the README:**
  - A binary downloaded through a browser is quarantined by Gatekeeper: run `xattr -dr com.apple.quarantine outline-cli`. A binary built locally with `build-local.sh` is not quarantined and needs no such step.
  - Artifact zips do not keep the executable bit: run `chmod +x outline-cli`.

## 11. Milestones and acceptance gates

| # | Milestone | Gate |
|---|---|---|
| M0 | **Baseline and verification.** Resolve every **[unverified]** item in section 3 by reading code or building locally. Add `build-local.sh` and the workflow with a build-only job for `./client/go/outline/electron` on macOS arm64 and amd64. | Local amd64 + arm64 (cross) builds, lipo and ad hoc signing succeed; `FINDINGS.md` committed; branch pushed (the developer checks the CI run). |
| M1 | **CLI skeleton and key resolution.** Subcommands, flag/env/file key input, `ssconf://`/`https://` fetch + `ParseTunnelConfig`, `--dry-run`, redacted logging. | Unit tests pass (Linux + macOS); dry-run prints the resolved transport and first hop for static and dynamic fake keys. |
| M2 | **Tunnel manager.** `SystemRouter` interface and implementations, state file, routes, DNS, IPv6, signal handling, `cleanup`, stale-state recovery, network-change polling. | Fake-executor tests cover connect, disconnect, crash recovery and network change; `--dry-run` shows the command sequence. |
| M3 | **Interface-bound dialers.** `dialer_darwin.go` with `IP_BOUND_IF`/`IPV6_BOUND_IF`, wired into `NewDefaultTransportProvider`. | Builds and vets on macOS CI; logic around interface selection is unit-tested with an injectable control function. |
| M4 | **Domain bypass.** Matcher, DNS relay (UDP + TCP), TTL cache, routing dialer/relay, pre-resolution, rules-file loading. | Unit tests: wildcard/suffix rules, CNAME chains, TTL expiry and clamping, TCP DNS framing, IPv6, direct-vs-tunnel decisions for TCP and UDP. |
| M5 | **VPN-only.** Part A in the router (fail closed, conflict handling) and Part B (`lockdown`/`unlock`, pf anchor and hosts management, persistence of learned IPs). | Fake-executor tests of the exact `pfctl`/hosts operations; documented limitations; plan decision recorded. |
| M6 | **Release and docs.** Universal binary artifact, CLI README, `MANUAL_TEST.md`. | CI produces and signs the universal binary; docs complete. |

## 12. Decisions (answered by the developer)

1. **VPN-off blocking:** pf anchor plus `/etc/hosts`, as specified in 6.3.
2. **Direct resolver for bypass domains:** the system resolvers captured at start (`scutil --dns`), over bound sockets. If none are usable, fall back to 1.1.1.1 (direct, bound). If a direct lookup fails, fall back to the tunnel resolver.
3. **IPv6:** disabled on the active service for the session (`-setv6off`) and restored exactly. The CLI warns if other services are active.
4. **LaunchDaemon:** deferred. Lockdown state stays self-contained so a later daemon can re-apply it at boot.
5. **DNS override mechanism:** `networksetup` (persists across reboot; the recovery command is documented).
6. **Working environment:** local `go build`/`vet`/`test`, `go tool task addlicense -- -check`, `lipo` and ad hoc `codesign` are allowed. No `sudo`, nothing that touches network configuration, no `gh`. The feature branch is pushed to `origin` with plain git at each gate.
7. **Configs that would loop** (`basic-access`, UDP `null`/`direct`): refused with a clear error.
8. **`vpn_only` with a transport that isn't fully tunneled** (for example a `Partial` `iptable` config): refused.

## 13. Definition of done

- `connect` works with static and dynamic keys on a real Mac (verified by the human using `MANUAL_TEST.md`).
- Bypass and VPN-only rules behave as specified, with documented limits.
- `cleanup` and crash recovery restore the network, and VPN-only rules persist until `unlock`.
- CI builds a universal binary; unit tests pass; no secrets are committed; license headers and commit format pass the repo's checks.
