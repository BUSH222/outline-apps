# macOS CLI: checkpoint (2026-10-30, end of M3)

Read this first if you are picking up this work. It says where things stand, which rules apply, what was learned the hard way, and what comes next. Details live in:

- [`SPEC.md`](SPEC.md): goals and design. It has been corrected against the code; where the spec and the code disagree, the code wins, and you propose a spec fix.
- [`FINDINGS.md`](FINDINGS.md): evidence for every assumption, plus a numbered log of each manual test and what it changed.
- [`MANUAL_TEST.md`](MANUAL_TEST.md): what the developer runs on the real Mac. It starts with recovery steps.
- The approved plan, outside the repo: `~/.claude/plans/pasted-content-id-7507-you-are-curried-trinket.md`. It has the original milestone plan and the developer's answers to decisions D1–D8.

## 1. What this is

`outline-cli` is a root-run Outline VPN client for macOS that doesn't use the Network Extension. It accepts static (`ss://`) and dynamic (`ssconf://`, `https://`) keys. Traffic goes into a `utun` through the app's own Go transport (`configregistry` + `vpn.ConnectRemoteDevice` / lwIP). Two features are still to come:

- a bypass list (domains that never use the VPN, M4);
- a VPN-only list (domains blocked unless the VPN is up, M5).

Code: `client/go/outline/macoscli/`. Branch: `feat/macos-cli` on `origin` (the developer's fork `BUSH222/outline-apps`). `master` is untouched.

## 2. Rules (set by the developer; follow them exactly)

**Environment:** you run on the developer's real Intel Mac (macOS 15.6, Go 1.25.14, Xcode Command Line Tools only). It is not a sandbox.

**Allowed locally:**
- `go build`, `go vet`, `go test` (with `-race`), and `go tool task addlicense -- -check`;
- `docs/macos-cli/build-local.sh` (it runs `lipo` and an ad hoc `codesign`);
- `git` commit, and `git push origin feat/macos-cli` at each gate.

**Allowed CLI invocations:** only `outline-cli version` and `outline-cli connect --dry-run`.

**Never, locally:**
- `sudo`;
- anything that changes routes, DNS, IPv6, pf or `/etc/hosts`;
- running `connect` (without `--dry-run`), `cleanup`, `lockdown` or `unlock`.

The auto-mode permission check also blocked running `networksetup`/`netstat`/`scutil` directly, so ask the developer for real outputs instead. (In M2 I broke this rule once by running `cleanup` and `connect` to check that they refuse; don't.)

**No `gh`.** The developer checks CI on the Actions page and pastes failing logs.

**Tests must never use the real network.** In the main package the test environment refuses every bound socket by default (`env.bind`), and every system command goes to the simulated Mac (`internal/fakemac`). Keep it that way. One slow test once sent a real SYN; that is how this was found.

**Repository rules:**
- New code only in new files. The only upstream file allowed to change is `go.mod`/`go.sum`, which M4 will need (see section 6). No change to `client.go` or the electron package is needed.
- Every new file gets the Apache-2.0 header ("Copyright 2026 The Outline Authors").
- Conventional Commits with the scope `client/macos` (commitlint `scope-enum`), ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Never commit real keys or anything from the developer's real key or server: host names, public IPs.
  - **This was violated once:** a test copied the developer's server IP from a pasted `route get` output. The branch history was rewritten and force-pushed (with the developer's approval) to remove it. Never copy values from the developer's pasted output into the repo.
  - Use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or obviously fake values in tests and docs.
- Leave the upstream CI workflows alone. Ours is `.github/workflows/macos_cli.yml`.

**Way of working:**
- Go milestone by milestone, commit at each gate, then stop and report.
- Never claim VPN behavior is verified end to end; only the developer's manual tests count.
- Keep replies short and plain.

## 3. Decisions already made (from the plan)

| # | Decision |
|---|---|
| D1 | VPN-off blocking: pf anchor + `/etc/hosts` |
| D2 | Direct resolver for bypass domains: the captured system resolvers, with fallbacks (now: the user's manual DNS, else DHCP DNS, then the gateway, then `1.1.1.1`) |
| D3 | IPv6 off on the primary service during a session; restored exactly |
| D4 | LaunchDaemon deferred |
| D5 | DNS override via `networksetup` (persists across reboot; the recovery command is documented) |
| D6 | Local builds are the main feedback loop; no `gh`; plain-git push at gates |
| D7 | Refuse configs that would loop: `basic-access`, UDP `direct`/missing |
| D8 | Refuse `vpn_only` rules when the transport isn't fully tunneled |

## 4. Status

| Milestone | State |
|---|---|
| M0 Baseline, CI, findings | Done |
| M1 CLI skeleton, key resolution, redaction, dry run | Done |
| M2 Tunnel manager, state file, cleanup, crash safety | Done |
| M3 Interface binding, real `connect` | **Done and confirmed on the real Mac** (manual tests 1–6: connect, both post-routing checks, disconnect, crash recovery, IPv6 leak check, a 2.4/5 GHz network switch, and a quick phone-hotspot switch) |
| M4 Bypass list | **Next** |
| M5 VPN-only list | Not started |
| M6 Universal artifact, README, final `MANUAL_TEST.md` | Partly done (CI already produces the signed universal artifact; README not written) |

## 5. How the code fits together

```
main.go            subcommands, env (everything injectable), surviveBrokenPipes (SIGPIPE)
connect.go         key -> resolve -> parse (bound dialers for real, plain for dry run) -> loop check -> first hops
                   -> dry run: print the plan via sysexec.DryRun | real: runSession
session.go         prepareSession (root, lock, recover a crashed session BEFORE the key fetch), runSession,
                   startRemoteDevice (lwIP + NotifyNetworkChanged + TCP health check + relays)
verify.go          post-routing checks: 1) the transport reaches the server with routes in place;
                   2) an ordinary HTTP request works through the tunnel (if not, probe DNS at 169.254.113.53)
cleanup.go         cleanup [--dry-run]
firsthop.go        resolve the transport's first hops to IPv4 (refuses IPv6-only servers)
rules_path.go      --rules, else SUDO_USER's home (user.Lookup), else $HOME; .config/outline-cli/rules.yaml

internal/redact    secret scrubbing for logs, errors and output; also the slog ReplaceAttr hook
internal/keys      Read (flag/file/env), Resolver (ss/ssconf/https/config file), Fetcher (https only,
                   no URL in errors), ParseTunnelConfig (via outline.InvokeMethod), ParseClientConfig, CheckLoopSafe
internal/sysexec   the ONLY place that runs commands: Real (LC_ALL=C, fixed PATH), Fake, DryRun (read-only passthrough)
internal/sysrouter builds macOS commands and parses netstat, networksetup, scutil, route get, ipconfig getpacket, ifconfig;
                   IsReadOnly is the dry-run allowlist
internal/state     state.json in /var/db/outline-cli (atomic, 0600), flock instance lock, MemStore
internal/tunnel    Up / Down / Cleanup / CheckNetwork / Watch: the whole system-change sequence
internal/netbind   IP_BOUND_IF sockets (IPv4 only, fail closed), LookupIPv4 with resolver failover, dial logging
internal/fakemac   simulated Mac for tests: routes (incl. cloned ones and stale source addresses), DNS, IPv6,
                   services, networks, failure and crash injection
```

**Connect order** (`tunnel.Up`):
1. Capture the default routes, service, DNS, scutil resolvers, IPv6 and interface addresses. **Write the state file.**
2. `OnNetwork` binds the binder to the interface.
3. Open and configure the utun.
4. Start the transport and **wait for the health check**.
5. Add routes, each journaled before it is added: the exclusions via the gateway, the first-hop host routes, `169.254.113.53/32` via the utun, then `0/1` and `128/1` via the utun.
6. Set DNS to `169.254.113.53`, turn IPv6 off, and flush the DNS cache.
7. Run `Verify`. If it fails, everything is rolled back.

**Teardown:** DNS and IPv6, then routes (newest first), close the utun, then flush the DNS cache (only if something was undone), then delete the state file. Every step is saved as it completes, so a failed or interrupted teardown can be resumed.

**Network watch:** every 2 s. The network's identity is interface + gateway + **the interface's IPv4 addresses**. On any change, and on every return from offline:
- re-create the gateway routes;
- move DNS and IPv6 if the service changed;
- recompute the direct resolvers;
- call `OnNetwork`, which re-binds the binder, sets the resolvers and notifies the transport.

## 6. Hard-won lessons (all in FINDINGS.md with evidence)

1. **`ping` proves nothing.** lwIP answers pings to any address itself in under 1 ms (TTL 64). Use `curl` or `dig`.
2. **macOS caches routes.** After contacting a host, `route -n get` reports a cloned route (`flags: ...WASCLONED...`) as if it were an exact match. Delete it and add the real route; never treat it as someone else's route.
3. **`route -n get` for a missing route** may print nothing on stdout and exit 0 (the error goes to stderr). Empty output means "absent".
4. **Gateway routes keep the source address** they captured when they were added. After the Mac's address changes (even with the same router), connections over them fail with `can't assign requested address`. Re-create routes on any address change or return from offline.
5. **The same service can be a different network** (another Wi-Fi network, a hotspot). Refresh the direct resolvers on every change. While connected, `scutil --dns` only shows `169.254.113.53`; read DHCP DNS with `ipconfig getpacket IFACE`.
6. **Go's resolver retries only the first server** when `Dial` ignores the address. `netbind.LookupIPv4` tries each resolver in turn, 3 s each.
7. **Go dies on SIGPIPE** when writing to a closed stdout or stderr. `connect | tee` plus Ctrl-C killed the restore halfway. `surviveBrokenPipes()` fixes it; the docs use `tee -i`.
8. **`curl -6` to a host without an AAAA record** uses an IPv4-mapped address, so it goes through the IPv4 tunnel and looks like a "leak". Test IPv6 with `ipv6.icanhazip.com`.
9. **cgo objects default to the host macOS as their minimum version.** `build-local.sh` passes `-mmacosx-version-min=12.0` in `CGO_CFLAGS`/`CGO_LDFLAGS` (`MACOSX_DEPLOYMENT_TARGET` alone isn't in Go's cache key).
10. `go test -race` prints `ld: warning: ... malformed LC_DYSYMTAB`. It is harmless.
11. Upstream's "Go Backend Test" runs `go test ./client/...` on Ubuntu, which includes these packages. Keep darwin-only code behind build tags with stubs. Our workflow's `linux-tests` job guards this.

## 7. Next: M4 (bypass list)

**Goal (SPEC 6.2):** domains in `bypass:` (a suffix match on labels) never use the VPN. The rules file is YAML at the path from `rules_path.go`:

```yaml
bypass: [example.com]
vpn_only: []        # M5; if a domain is in both lists, vpn_only wins (fail closed)
min_ttl: 60s
max_ttl: 1h
```

**Step 0: settle one open question before building on it.**
- So far, bound sockets have only been proven to escape the utun routes **together with** the server's host route. Before that route existed (manual test 1), traffic failed, and it was never isolated why.
- Bypass traffic will go to arbitrary IPs with **binding alone**.
- Add a third post-routing check, log-only and never fatal: a bound TCP connect to a public IP that has no host route (for example `1.1.1.1:80`), reporting success or the error. Ask the developer to run it.
- If it fails, bypass must add `/32` host routes via the gateway for learned IPs (journaled like the others) instead of relying on binding.

**Packages to add** (as in the plan; all pure Go, no build tags):
- `internal/rules`: YAML loading and validation; the label-suffix matcher (lowercase, trailing dot, IDN via `x/net/idna`); any `vpn_only` match wins.
- `internal/ipcache`: IP → {class, domain, expiry}, with TTL clamped to `[min_ttl, max_ttl]` and an injectable clock. VPN-only beats bypass for a shared IP.
- `internal/dnsrelay`: intercept DNS to `169.254.113.53:53` before the upstream intercept sees it.
  - UDP: model it on the SDK's `dnsintercept` association.
  - TCP: 2-byte length framing; replies on the shared inner connection are matched by ID.
  - Bypass queries go to the direct resolvers over bound sockets. Others pass through unchanged.
  - Snoop answers (follow the CNAME chain; TTL = minimum along the chain) and learn the IPs.
  - Pass TC replies through; malformed packets go to the tunnel.
- `internal/route`: a `transport.StreamDialer` + `packetrelay.PacketRelay` wrapper around the parsed `*configregistry.TransportPair`:
  - bypass IP → `binder.StreamDialer()` / a direct relay on `binder.PacketListener()`, with no fallback to the tunnel;
  - anything else → the inner pair.
  - Wire it in `session.go` around `pair` before `startRemoteDevice`. `verifyTunnel` keeps using the inner pair for check 1.
- Pre-resolution: resolve the exact bypass hosts at start, and refresh them at 80 % of their TTL.

**Dependency:** using `golang.org/x/net/dns/dnsmessage` and `idna` moves `golang.org/x/net v0.44.0` from indirect to direct in `go.mod`. `go.sum` already has the hash, but the module isn't in the local module cache, so the first build fetches it from `proxy.golang.org`. If that is blocked, stop and tell the developer what to allow. Don't write a DNS parser yourself.

**Tests to write** (SPEC section 9 and the plan's test list):
- matcher: `lichess.org` covers `www.lichess.org` but not `notlichess.org`;
- CNAME chains;
- TTL clamping and expiry;
- TCP framing (a split length prefix, several queries in one segment);
- TC replies; NXDOMAIN;
- direct-vs-tunnel decisions for TCP and UDP;
- vpn_only never goes direct, even when the tunnel fails.

**Docs:** add a bypass section to `MANUAL_TEST.md` (`curl -4 https://ifconfig.me` through a bypass domain shows the developer's own IP; any other domain shows the server's IP), and document the limits (DoH, connections opened before a mapping exists, shared CDN IPs, OS DNS caching).

**Gate:** all tests pass locally (and on Linux in CI); then commit, push, and ask for the manual bypass test.

## 8. After M4

- **M5 (VPN-only):**
  - Part A: `vpn_only` IPs always go through the tunnel and fail closed; refuse non-tunneled transports (D8).
  - Part B: `lockdown`/`unlock` with a pf anchor `com.apple/outline-cli`. Rules: `block drop out quick to <table>`, plus `pass out quick on utunN to <table>` while connected. First-hop IPs never go in the table.
  - Plus a marked `/etc/hosts` block. `cleanup` re-installs both; only `unlock` removes them.
  - Fake-executor tests of the exact `pfctl` invocations; golden tests for the hosts edits.
- **M6:**
  - `docs/macos-cli/README.md`: install (`chmod +x`, `xattr -dr com.apple.quarantine` for the CI download; not needed for local builds), the sudo key/rules guidance, recovery, and limits.
  - Finish `MANUAL_TEST.md`.
- **Known gaps to mention or fix:**
  - A dead transport isn't detected while connected (traffic stops until Ctrl-C).
  - Only the primary service's DNS/IPv6 are changed (the CLI warns when several interfaces are active).
  - A usage reporter in a key is ignored with a warning.

## 9. Gate checklist (run before every commit)

```sh
gofmt -l client/go/outline/macoscli                      # must print nothing
go vet ./client/go/outline/macoscli/...
go test -race -count=1 ./client/go/outline/macoscli/...
GOARCH=arm64 CGO_ENABLED=1 CC="clang -arch arm64" \
  CGO_CFLAGS="-O2 -g -mmacosx-version-min=12.0" CGO_LDFLAGS="-mmacosx-version-min=12.0" \
  go vet ./client/go/outline/macoscli/...                # arm64 cross-check
go tool task addlicense -- -check                        # exit 0
docs/macos-cli/build-local.sh                            # universal build + signature + version smoke test
```

Then commit with the `client/macos` scope and run `git push origin feat/macos-cli`. Report to the developer with the outcome first; give them exact commands to run on the Mac and say what to send back.

## 10. History rewrite (done 2026-10-30)

The branch was rewritten with `git filter-branch` to remove the developer's server IP from a test file, and force-pushed. As a result:
- Commit hashes from before 2026-10-30 evening, as quoted in older chat logs, no longer exist. The rewritten branch starts with the same commit messages.
- `master` was not touched.
- GitHub may still serve the old commits by their exact hashes until it garbage-collects them. Because the repository is a fork, that includes the upstream network. Purging them for good needs a request to GitHub Support; the developer was told.
