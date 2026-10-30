# outline-cli: an Outline VPN client for macOS, on the command line

`outline-cli` connects a Mac to an Outline server without the Outline app and without Apple's Network Extension, so it needs no Apple Developer account. It runs as root in a terminal and works on Apple Silicon and Intel Macs with macOS 12 or later.

- It takes the same access keys as the Outline app: `ss://`, dynamic `ssconf://` and `https://` keys, and YAML/JSON transport configs.
- A **bypass list** keeps chosen domains off the VPN.
- A **VPN-only list** sends chosen domains through the VPN only, and with `lockdown` blocks them while the VPN is off.

It is meant for personal use: it changes system network settings while it runs, and it has no GUI.

## If your network breaks

Run these in order; each is safe to repeat.

1. If `outline-cli connect` is still running, press **Ctrl-C** and wait for `disconnected: routes, DNS and IPv6 are restored`.
2. Run `sudo outline-cli cleanup`. It restores routes, DNS and IPv6 from `/var/db/outline-cli/state.json`. (`sudo outline-cli connect ...` does the same before it connects.)
3. If that fails, restore by hand. Replace `Wi-Fi` with your service (`networksetup -listnetworkserviceorder`):
   ```sh
   sudo networksetup -setdnsservers Wi-Fi empty     # DNS back to automatic (DHCP)
   sudo networksetup -setv6automatic Wi-Fi          # IPv6 back on
   sudo route -n delete -net 0.0.0.0/1
   sudo route -n delete -net 128.0.0.0/1
   sudo route -n delete -host 169.254.113.53
   sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
   sudo rm /var/db/outline-cli/state.json
   ```
   If you had set DNS servers or a manual IPv6 address yourself, the old values are in the state file (`prevDNS`, `prevIPv6`); read it with `sudo cat` before deleting it.
4. **A site stays blocked:** that's the lockdown. Run `sudo outline-cli unlock`. By hand: `sudo pfctl -a com.apple/outline-cli -F all`, and delete the lines from `# BEGIN outline-cli` to `# END outline-cli` in `/etc/hosts` (a copy from before the first lockdown is in `/var/db/outline-cli/hosts.backup`).

A reboot clears the routes and the lockdown's pf rules, but **not** the DNS setting or the hosts block, so step 3's `networksetup` line (or `cleanup`) is still needed.

After `kill -9` or a crash, nothing that needs DNS works until `cleanup` (or the next `connect`) runs: DNS still points at the tunnel's address. That's expected.

## Install

**From a CI build:** open a run of the "macOS CLI" workflow on the repository's Actions page, download the `outline-cli-macos-universal` artifact, then:

```sh
unzip outline-cli-macos-universal.zip
chmod +x outline-cli                          # artifact zips drop the executable bit
xattr -dr com.apple.quarantine outline-cli    # downloads are quarantined by Gatekeeper
shasum -a 256 -c outline-cli.sha256           # optional: check the download
./outline-cli version
```

**Built locally** (needs Go, see `go.mod` for the version, and the Xcode Command Line Tools; full Xcode isn't needed):

```sh
docs/macos-cli/build-local.sh     # writes output/macos-cli/outline-cli (universal, signed ad hoc)
```

A local build isn't quarantined, so `chmod` and `xattr` aren't needed. Copy it into a folder of its own, since its key and rules files go next to it:

```sh
mkdir -p ~/Applications/outline-cli && cp output/macos-cli/outline-cli ~/Applications/outline-cli/
```

(If you put it somewhere on your `PATH` instead, such as `/usr/local/bin`, the files go there too; or pass `--key-file` and `--rules`.)

## Start it with a double-click

Keep `outline-cli` in a folder of its own (for example `~/Applications/outline-cli/`). Next to it, it uses two files:

- `access-key.txt`: your access key (`ss://`, `ssconf://` or `https://`, or a transport config);
- `rules.yaml`: the bypass and VPN-only rules (see below).

**Double-click `outline-cli` in Finder.** A Terminal window opens and asks for your Mac password (it changes network settings, so it runs itself through `sudo`). Then it connects. **Press Ctrl-C in that window to disconnect** (closing the window works too).

The first time, it creates both files, owned by you: `access-key.txt` empty (mode 600, readable only by you) and `rules.yaml` with only comments (no rules). It then stops and asks for the key: paste the key into `access-key.txt`, save, and double-click again. If either file goes missing later, it is created again the same way.

From a terminal, `./outline-cli` with no arguments does the same as a double-click, and `sudo ./outline-cli connect` does it without the restart through `sudo`.

## Other ways to pass the key

The key and rules files can live elsewhere: `--key-file PATH` and `--rules PATH` override the files next to the program. Then:

- `--key KEY` puts the key in your shell history.
- `OUTLINE_KEY=...` is dropped by `sudo`; `sudo env OUTLINE_KEY=... outline-cli connect` works but shows the key in the process list while it starts.
- `--key /path/to/config.yaml` takes an advanced transport config file.

The CLI warns if the key file is readable by others, and never prints or logs the key (secrets are shown as `<redacted>`). A dynamic key is fetched again on every connect, directly, before anything changes.

Not every config works: configs that would send traffic around the server without going through the CLI (`basic-access`, or `udp` set to `direct` or missing) are refused, because their sockets would loop back into the tunnel.

## Connect from a terminal

```sh
./outline-cli connect --dry-run       # no root: shows the plan, changes nothing (and creates no files)
sudo ./outline-cli connect            # connect; Ctrl-C disconnects
```

On connect it checks that the server answers, routes all IPv4 traffic and DNS into the tunnel, turns IPv6 off on the active network service, and checks that traffic flows. If a check fails, it undoes everything itself. `Ctrl-C`, `SIGTERM` and `SIGHUP` (closing the window) restore everything.

While connected it follows network changes (another Wi-Fi network, a hotspot, Ethernet) every 2 seconds.

Useful flags: `--log-level debug` (what it does and why), `--key-file PATH`, `--rules PATH`. To keep a log, use `tee -i` (plain `tee` stops on Ctrl-C):

```sh
sudo ./outline-cli connect --log-level debug 2>&1 | tee -i /tmp/outline-cli.log
```

## Rules: bypass and VPN-only

The rules file is `rules.yaml` next to `outline-cli`, or the file given with `--rules`. With no rules, all traffic goes through the VPN.

```yaml
bypass:              # never through the VPN
  - lichess.org      # the domain and all its subdomains
  - "*.example.org"  # only subdomains (quote entries that start with *)
vpn_only:            # only ever through the VPN; blocked while it's off after "lockdown"
  - example.com
direct_dns: []       # optional: IPv4 DNS servers for bypass names (default: your network's)
min_ttl: 60s         # learned addresses are kept at least this long
max_ttl: 1h          # and at most this long
```

- Entries match whole labels: `lichess.org` covers `www.lichess.org`, not `notlichess.org`. Names are case-insensitive; Unicode names are fine.
- If a name matches both lists, `vpn_only` wins.
- Unknown keys, IP addresses and URLs are errors, so a typo can't silently drop a rule. `connect --dry-run` shows the rules it would apply.

**How bypass works:** DNS questions for bypass names are answered by your network's own DNS server, outside the VPN; everything else is answered through the VPN. Each address in such an answer gets a route via your router (before the app sees the answer) for the rest of the session, so connections to it skip the VPN, from every app.

**How VPN-only works:** vpn_only names are only ever looked up through the VPN, and their addresses never take the bypass path. If the rules have vpn_only entries, `connect` refuses a key whose transport sends some traffic directly (for example an `iptable` config with direct entries). The addresses learned for them are remembered for `lockdown`.

## Lockdown: block VPN-only domains while the VPN is off

```sh
sudo outline-cli lockdown --dry-run    # shows what it would install
sudo outline-cli lockdown              # block vpn_only domains while disconnected
sudo outline-cli unlock                # remove the block
```

`lockdown` installs two things that stay when the CLI isn't running:

- **pf rules** (anchor `com.apple/outline-cli`) that block the vpn_only addresses learned while connected. While you're connected, they let them through the tunnel only. If the CLI crashes, they keep blocking.
- **An `/etc/hosts` block** that resolves the vpn_only names to nothing. It's taken out while you're connected, so the names work through the VPN.

It reads the same `rules.yaml` (or `--rules PATH`). `connect` and `cleanup` put both back after a session or a crash; only `unlock` removes them. `lockdown` and `unlock` refuse to run while `connect` is running. After editing `vpn_only`, run `lockdown` again.

`lockdown` never looks the names up itself, since that would send the lookups outside the VPN. Connect once first: the CLI looks the listed names up through the VPN by itself, and also learns the addresses of the subdomains you use.

## Limits

Bypass:
- Apps with their own DNS (browsers with "secure DNS"/DNS-over-HTTPS, hard-coded resolvers) don't use the CLI's DNS, so their connections to bypass domains still use the VPN. Safari and curl use the system resolver.
- Connections opened before a name was resolved through the CLI stay on the VPN; apps that cache DNS (browsers keep names for about a minute) may use the VPN at first.
- A bypass address shared with other sites (content networks) takes those sites off the VPN too, until you disconnect. A vpn_only entry always wins.
- Addresses inside HTTPS-type DNS records (address hints) aren't learned.
- On a network whose DNS server is on the internet rather than your router, bypass lookups go through the VPN instead (they still bypass; content networks may pick a server near the VPN server).

VPN-only and lockdown:
- Addresses are only learned while connected. Until then, only the exact names in the hosts file are blocked; the hosts file has no wildcards, so `example.com` there doesn't block `www.example.com` (its addresses are blocked once learned).
- Browsers with DNS-over-HTTPS skip the hosts file; known addresses are still blocked by pf.
- Content networks change addresses; a shared address blocks other sites on it while you're disconnected.
- **A reboot clears the pf rules** (the hosts block stays). Run `sudo outline-cli cleanup` after rebooting. (Doing it at boot automatically would need a LaunchDaemon, which isn't included.)

General:
- IPv6 is turned off on the active network service during a session (traffic only goes through the tunnel over IPv4). Servers that only have IPv6 addresses aren't supported.
- Only the primary network service's DNS and IPv6 are changed. With several active interfaces (Wi-Fi and Ethernet), the CLI warns that the others may leak.
- If the server stops answering while you're connected, traffic just stops; the CLI doesn't notice. Ctrl-C restores the network.
- A usage reporter in a dynamic key is ignored (with a warning).
- The DNS setting it changes survives a reboot (see "If your network breaks").

## What it changes on your Mac

| What | When | Undone by |
|---|---|---|
| A `utun` interface with routes `0/1`, `128/1` and `169.254.113.53` | connect | disconnect; the kernel removes them if the process dies |
| Routes via your router: local ranges, the server's addresses, bypass addresses | connect, and while connected | disconnect, `cleanup` |
| DNS of the active service set to `169.254.113.53` | connect | disconnect, `cleanup` |
| IPv6 of the active service turned off | connect | disconnect, `cleanup` (the exact previous setting) |
| pf anchor `com.apple/outline-cli`, pf enabled | `lockdown` | `unlock` |
| A marked block in `/etc/hosts` | `lockdown` (out while connected) | `unlock` |
| `access-key.txt` and `rules.yaml` next to the program, if missing | connect | never (they are your files) |
| `/var/db/outline-cli/`: `state.json` (what to undo), `lock`, `lockdown.json`, `vpn_only.json` (learned addresses), `anchor.conf`, `hosts.backup` | as above | the session's and lockdown's files are removed when undone |

Every change is recorded in `state.json` before it's made, so `cleanup` can undo a session even after `kill -9`.

## Problems

- Run with `--log-level debug` and look for warnings; `connect --dry-run` shows what it would do.
- [`MANUAL_TEST.md`](MANUAL_TEST.md) has step-by-step checks for every feature, and the commands to run when traffic doesn't flow.
- Logs are redacted, but they include your network's addresses and the domains you use; check before sharing them.

## For developers

- Code: `client/go/outline/macoscli/` (package `main` plus `internal/...`). It reuses the app's own Go transport (`configregistry`, `vpn`), so every key type the app accepts works here.
- Design and decisions: [`SPEC.md`](SPEC.md); evidence and the log of every manual test: [`FINDINGS.md`](FINDINGS.md); where things stand: [`CHECKPOINT.md`](CHECKPOINT.md).
- Tests never touch the real network or system settings: system commands go to a simulated Mac (`internal/fakemac`), sockets are refused, and lockdown tests use temporary files.
  ```sh
  go vet ./client/go/outline/macoscli/...
  go test -race ./client/go/outline/macoscli/...
  ```
- CI (`.github/workflows/macos_cli.yml`) tests on Linux and macOS and builds the signed universal artifact.
