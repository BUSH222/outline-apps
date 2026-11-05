# outline-cli: manual test on a real Mac

This is the only end-to-end check of the VPN. Unit tests and CI cover the logic and the build, but they never touch a real network. Run the steps in order and note the result of each one.

It covers connect, disconnect, crash recovery, network changes, the bypass list (section 7) and the VPN-only list with lockdown (section 8). For installing and everyday use, see [`README.md`](README.md).

Commands with `<...>` need that part filled in by hand first; in zsh a leftover `<` is read as a file redirect.

## 0. If your network breaks: recovery

Try these in order. Each step is safe to repeat.

1. If `outline-cli` is still running in a terminal, press **Ctrl-C** and wait for `disconnected: routes, DNS and IPv6 are restored`.
2. Run:
   ```sh
   sudo outline-cli cleanup
   ```
   It restores routes, DNS and IPv6 from `/var/db/outline-cli/state.json`. Run `sudo outline-cli cleanup --dry-run` first if you want to see what it will do.
3. If `cleanup` fails, restore by hand. Replace `Wi-Fi` with your service name from `networksetup -listnetworkserviceorder`:
   ```sh
   sudo networksetup -setdnsservers Wi-Fi empty     # DNS back to DHCP
   sudo networksetup -setv6automatic Wi-Fi          # IPv6 back on
   sudo route -n delete -net 0.0.0.0/1
   sudo route -n delete -net 128.0.0.0/1
   sudo route -n delete -host 169.254.113.53
   sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
   ```
   Host routes for bypass addresses (`netstat -rn -f inet` shows them as single addresses via your router, flags `UGHS`) are harmless if left over, and a reboot clears them; `cleanup` removes them too.
   If `cleanup` (from a build older than this fix) keeps failing with `route: bad address: utunN` after a crash: macOS already removed those routes with the utun. Check that `netstat -rn -f inet | grep -E 'utun|^0/1|^128.0/1'` prints nothing, then delete the stale state file: `sudo rm /var/db/outline-cli/state.json`.
   If you had set DNS servers or a manual IPv6 address yourself before connecting, the previous values are in the state file: `sudo cat /var/db/outline-cli/state.json` (see `prevDNS` and `prevIPv6`).
4. **A site stays blocked** although you ran `unlock`, or `outline-cli` is gone: remove the lockdown by hand.
   ```sh
   sudo outline-cli unlock                          # first choice
   sudo pfctl -a com.apple/outline-cli -F all       # by hand: the pf rules
   sudo nano /etc/hosts                             # and delete the lines from "# BEGIN outline-cli" to "# END outline-cli"
   sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
   ```
   A copy of `/etc/hosts` from before the first lockdown is in `/var/db/outline-cli/hosts.backup`.
5. Last resort: reboot. Routes are cleared by a reboot, but **the DNS setting is not**, so still run the `networksetup -setdnsservers` line from step 3.

## 1. Before you start

- Build with `docs/macos-cli/build-local.sh`, or download the `outline-cli-macos-universal` artifact from a CI run. For the artifact:
  ```sh
  unzip outline-cli-macos-universal.zip && chmod +x outline-cli
  xattr -dr com.apple.quarantine outline-cli
  ```
- Put your key in a file only you can read:
  ```sh
  pbpaste > access-key.txt && chmod 600 access-key.txt   # in the folder with outline-cli, after copying the key
  ```
- Run every `./outline-cli` command from the folder that holds `outline-cli`: its key (`access-key.txt`) and rules (`rules.yaml`) are read from there.
- Keep a second terminal open for checks.
- Record the baseline, so you can compare after disconnecting:
  ```sh
  networksetup -getdnsservers Wi-Fi > /tmp/before-dns.txt
  networksetup -getinfo Wi-Fi | grep IPv6 > /tmp/before-ipv6.txt
  netstat -rn -f inet > /tmp/before-routes.txt
  curl -4 -s https://ifconfig.me; echo    # your normal public IP
  ```

## 2. Dry run (no root)

```sh
./outline-cli connect --dry-run
```

Expected: the key is shown redacted, the first-hop IP(s) are listed, and the connect list includes `route -n add -host <first hop IP> <your router>`. If macOS has a cached route for the server (it usually does right after the key is fetched), a `route -n delete -host <first hop IP>` comes just before it. Nothing changes on the system.

## 3. Connect and check

Before connecting, save the routes that matter for the diagnosis:

```sh
netstat -rn -f inet | grep -E '^default|^<first hop IP>' > /tmp/before-defaults.txt
```

Then connect:

```sh
sudo ./outline-cli connect --log-level debug 2>&1 | tee -i /tmp/outline-cli.log
```

Expected, in order:
1. `the server is reachable`
2. `check 1/2 passed: the server is reachable with the tunnel routes in place`
3. `check 2/2 passed: traffic flows through the tunnel`
4. `connected: traffic goes through the tunnel (bound to en1)`

(`tee -i` keeps capturing when you press Ctrl-C, so the disconnect messages are logged too.)

These two checks run automatically once traffic is routed into the tunnel. If either fails, the CLI rolls every change back by itself and prints which check failed. Your network is then as before; no `cleanup` is needed.

Note: **`ping` proves nothing here.** The CLI's network stack answers pings to any address itself, in under a millisecond. Use `curl` or `dig`.

In the second terminal:

| Check | Command | Expected |
|---|---|---|
| Public IP is the server's (no `ping`: see the note above) | `curl -4 -s https://ifconfig.me; echo` | The server's exit IP, not your normal one |
| Tunnel routes | `netstat -rn -f inet \| grep utun` | `0/1`, `128.0/1` and `169.254.113.53` on a `utunN` |
| **N5:** DNS address goes into the tunnel | `route -n get 169.254.113.53` | `interface: utunN` (not en0) |
| Server route stays physical | `route -n get <first hop IP from the dry run>` | `interface: en1` (your Wi-Fi), gateway = your router, **not** utunN |
| DNS points at the tunnel | `scutil --dns \| grep -m2 nameserver` | `169.254.113.53` |
| Names resolve | `dig +short example.com` | Addresses (answered through the tunnel) |
| IPv6 is off on the service | `networksetup -getinfo Wi-Fi \| grep IPv6` | `IPv6: Off` |
| No IPv6 leak | `curl -6 -s -m 5 https://ipv6.icanhazip.com; echo " exit=$?"` | Fails (non-zero exit). `ipv6.icanhazip.com` only has an IPv6 address; printing one would be a leak. (`ifconfig.me` has no IPv6 address, so `curl -6` to it falls back to IPv4 through the tunnel and proves nothing.) |
| Local network still works | `ping -c 2 <your router IP>` | Replies |
| State file exists | `sudo cat /var/db/outline-cli/state.json` | Lists the routes, `prevDNS` and `prevIPv6` |

### Double-click

1. Disconnect (Ctrl-C) if connected. Move `access-key.txt` and `rules.yaml` away from the folder (or test with a copy of `outline-cli` in an empty folder).
2. Double-click `outline-cli` in Finder. Expected: a Terminal window says it needs administrator rights and asks for your password, then prints `created .../access-key.txt: paste your access key into it`, `created .../rules.yaml: ...`, and stops with `no access key yet: paste your Outline access key into ...`. Nothing on the system changed. Both new files belong to you (`ls -l`), and `access-key.txt` has mode `-rw-------`.
3. Paste the key into `access-key.txt` (any editor), save, and double-click again. Expected: it connects (`connected: ...`). `curl -4 -s https://ifconfig.me` shows the server's IP.
4. Press Ctrl-C in that window. Expected: `disconnected: routes, DNS and IPv6 are restored`.
5. Optional: connect again by double-click and close the Terminal window instead (confirm "Terminate"). The network should be restored the same way (check as in section 4).

## 4. Disconnect

Press Ctrl-C in the first terminal. Expected: `disconnected: routes, DNS and IPv6 are restored`. Then:

```sh
diff <(networksetup -getdnsservers Wi-Fi) /tmp/before-dns.txt && echo DNS ok
diff <(networksetup -getinfo Wi-Fi | grep IPv6) /tmp/before-ipv6.txt && echo IPv6 ok
netstat -rn -f inet | grep -c utun          # expected: 0
sudo ls /var/db/outline-cli/                # expected: only "lock", no state.json
curl -4 -s https://ifconfig.me; echo        # your normal IP again
```

## 5. Crash recovery (kill -9)

1. Connect as in step 3.
2. In the second terminal: `sudo pkill -9 -f 'outline-cli connect'`. From now until step 4, nothing that needs DNS works: DNS still points at the dead tunnel's address. That's expected.
3. **N3:** check what the kernel removed:
   ```sh
   netstat -rn -f inet | grep -E 'utun|^0/1|^128.0/1|169.254.113.53'   # expected: nothing (they died with the utun)
   networksetup -getdnsservers Wi-Fi                                     # expected: still 169.254.113.53, so DNS is broken
   ```
4. Run `sudo ./outline-cli cleanup --dry-run`, then `sudo ./outline-cli cleanup`. Expected: `restored the network: ...`.
5. Repeat the checks from step 4. All should be back to the baseline.
6. Also check that `connect` recovers by itself: crash again (steps 1–2), then run `sudo ./outline-cli connect` directly. Expected: a warning `restored the network left behind by a previous session`, and then it connects normally.

## 6. Network change

While connected:

1. Switch networks, for example from Wi-Fi to an iPhone hotspot or Ethernet, or turn Wi-Fi off and on.
2. Within a few seconds of the new network coming up, the log shows `the network changed` (a short `the network is gone` before it is normal). Check:
   - `curl -4 -s https://ifconfig.me` shows the server's IP again within a few seconds.
   - The log shows no repeated `a connection from the physical interface failed` after the change. Such warnings naming the *old* network's DNS server were the hotspot bug of manual test 3.
   - `networksetup -getdnsservers <new service>` shows `169.254.113.53`, and the old service is back to its own setting.
3. Disconnect (Ctrl-C) and check that both services are restored.

## 7. Bypass list

Domains under `bypass:` never use the VPN. Each entry covers the domain and all its subdomains (`icanhazip.com` covers `ipv4.icanhazip.com`, but not `noticanhazip.com`). The rules file is `rules.yaml` next to `outline-cli`; `--rules PATH` overrides it.

1. Write the rules file (as yourself, not with sudo):
   ```sh
   cat > rules.yaml <<'EOF'
   bypass:
     - icanhazip.com
   EOF
   ```
2. Dry run: `./outline-cli connect --dry-run`. Expected: `rules file: ... (found: 1 bypass, 0 vpn_only)` and `bypass: icanhazip.com`.
3. Connect as in step 3, with `--log-level debug`. Expected, before the checks: `domain rules are on bypass=1 vpn_only=0`. Within a second or two after `connected:`, the log shows `learned an address domain=icanhazip.com ... class=bypass` (the name is resolved ahead of time through your network's DNS), each followed by `added a direct route for a bypass address`.
4. In the second terminal:

| Check | Command | Expected |
|---|---|---|
| A bypass subdomain goes direct | `curl -4 -s https://ipv4.icanhazip.com` | **Your normal public IP** (from the baseline in step 1) |
| Everything else stays on the VPN | `curl -4 -s https://ifconfig.me; echo` | The server's IP |
| The log shows why | `grep -E 'learned an address\|direct route' /tmp/outline-cli.log \| tail -6` | `learned an address domain=ipv4.icanhazip.com ... class=bypass` and `added a direct route for a bypass address addr=<address>` |
| The bypass addresses have routes | `for a in $(dig +short ipv4.icanhazip.com); do route -n get $a \| grep -E 'gateway\|interface'; done` | Your router and `en1` for each address, **not** utunN |
| DNS over UDP for a bypass name | `dig +short ipv4.icanhazip.com` | Addresses (answered by your network's DNS) |
| DNS over TCP for a bypass name | `dig +tcp +short ipv4.icanhazip.com` | The same kind of answer |
| DNS for other names still works | `dig +short example.com` | Addresses (answered through the tunnel) |

5. Optional: switch networks as in section 6, then repeat the first two checks and the route check. The bypass check should show the **new** network's public IP, and the routes the new router.
6. Disconnect (Ctrl-C) and run the checks from section 4. Also: `grep -c UGHS /tmp/before-routes.txt` and `netstat -rn -f inet | grep -c UGHS` should print the same number (the server's and the bypass host routes are gone).

If the bypass check fails, send the `grep` output and the route check.

### Limits of the bypass list

- **The CLI only sees DNS that goes to the system resolver.** Browsers with DNS-over-HTTPS ("secure DNS") or apps with a hard-coded resolver resolve the name themselves, so their connections to bypass domains still use the VPN. curl and Safari use the system resolver.
- **Only connections opened after the name was resolved through the CLI go direct.** The CLI flushes the macOS DNS cache when it connects, but apps with their own cache (browsers keep names for about a minute) may connect through the VPN at first. Connections that were open before connecting stay where they are.
- **Shared addresses:** if a bypass domain shares a content network address with another site, connections to that other site go direct too. A `vpn_only` entry always wins over this.
- **Each bypass address gets a host route via your router until you disconnect**, so every connection to it skips the VPN, from any app, even after the DNS answer expires. That keeps long-lived connections (a game's socket, for example) from being cut. An address later learned for a `vpn_only` domain loses its route at once.
- Names written without `*.` are looked up again by the CLI before their answers expire, so new addresses get routes too. (`min_ttl` and `max_ttl` bound how long the CLI's own address list keeps an answer.)
- Addresses that appear only as hints inside HTTPS (type 65) DNS records aren't learned.
- `vpn_only` entries are already kept off the direct path while connected, but blocking them while disconnected (`lockdown`) comes in M5.

## 8. VPN-only list and lockdown

Domains under `vpn_only:` only ever go through the VPN. After `sudo outline-cli lockdown` they are also blocked while the VPN is off, until `sudo outline-cli unlock`. This test uses `ifconfig.me`, which shows whose address a request comes from.

1. Add a `vpn_only` entry to the rules file:
   ```sh
   cat > rules.yaml <<'EOF'
   bypass:
     - icanhazip.com
   vpn_only:
     - ifconfig.me
   EOF
   ```
2. **While connected (part A).** Connect as in step 3 (`--log-level debug`). Expected soon after `connected:`: `learned an address domain=ifconfig.me ... class=vpn_only` for its IPv4 address (and IPv6, if it has one). The name is looked up through the tunnel only. Then:
   - `curl -4 -s https://ifconfig.me; echo` prints the **server's** IP.
   - Disconnect (Ctrl-C). `sudo ls /var/db/outline-cli` lists `vpn_only.json` (the learned addresses).
3. **Lock down.**
   ```sh
   sudo ./outline-cli lockdown --dry-run     # shows the hosts lines and the pf rules, with the learned address(es)
   sudo ./outline-cli lockdown
   ```
   Expected: `lockdown is on: while the VPN is off, ifconfig.me are blocked (N learned address(es) in pf, ...)`, with N at least 1. Keep one learned IPv4 address for the checks below:
   ```sh
   ADDR=$(sudo pfctl -a com.apple/outline-cli -t outline_vpn_only -T show 2>/dev/null | grep -m1 -E '^ *[0-9]+\.' | tr -d ' '); echo "$ADDR"
   ```
4. **While disconnected:**

| Check | Command | Expected |
|---|---|---|
| The site is blocked | `curl -4 -s -m 5 https://ifconfig.me; echo " exit=$?"` | Fails (non-zero exit) |
| By name (hosts) | `dscacheutil -q host -a name ifconfig.me` | `ip_address: 0.0.0.0` |
| By address (pf), even with the name resolved by hand | `curl -4 -s -m 5 --resolve ifconfig.me:443:$ADDR https://ifconfig.me; echo " exit=$?"` | Fails (non-zero exit, usually 28) |
| **N4:** the anchor is loaded | `sudo pfctl -a com.apple/outline-cli -s rules` | `block drop out quick from any to <outline_vpn_only>` |
| The table holds the address | `sudo pfctl -a com.apple/outline-cli -t outline_vpn_only -T show` | The address(es) from the dry run |
| pf evaluates the anchor | `sudo pfctl -s rules 2>/dev/null \| grep com.apple` | `anchor "com.apple/*" all` |
| Other sites still work | `curl -4 -s https://ipv4.icanhazip.com` | Your normal IP |

5. **Connect again** (as in step 3). Expected: `lockdown: vpn_only domains are reachable through the tunnel utun=utunN`. Then:
   - `curl -4 -s https://ifconfig.me; echo` prints the server's IP;
   - `grep -c outline-cli /etc/hosts` prints `0` (the hosts block is out while connected);
   - `sudo pfctl -a com.apple/outline-cli -s rules` shows `pass out quick on utunN ...` before the block.
6. **Crash while connected:** `sudo pkill -9 -f 'outline-cli connect'`. Then:
   - `curl -4 -s -m 5 --resolve ifconfig.me:443:$ADDR https://ifconfig.me; echo " exit=$?"` still fails: the pass rule names a utun that no longer exists. (Everything else fails too until `cleanup`, because DNS still points at the dead tunnel; see section 5.)
   - `sudo ./outline-cli cleanup` prints `lockdown re-installed: ifconfig.me are blocked while the VPN is off`, and `grep -c outline-cli /etc/hosts` is back to `2` (the two marker lines).
7. **Unlock:** `sudo ./outline-cli unlock`. Expected: `lockdown is off ...`; `curl -4 -s https://ifconfig.me` prints your normal IP; `grep -c outline-cli /etc/hosts` prints `0`; `sudo pfctl -a com.apple/outline-cli -s rules` prints nothing.
8. Optional, reboot: lock down, reboot, and repeat the checks of step 4. Expected: the name check still blocks (the hosts file survives), but **the address check passes**: a reboot clears pf. `sudo ./outline-cli cleanup` puts the pf rules back.

### Limits of the VPN-only list

- **Addresses are only learned while connected**, from DNS answers through the tunnel. Until a domain has been used (or looked up ahead of time) in a session, pf has nothing to block for it; only the hosts entry stops it.
- **The hosts block only covers the names exactly as listed:** `example.com` blocks `example.com`, not `www.example.com` (hosts has no wildcards). Subdomains are blocked by address once their addresses were learned. `*.example.com` entries only work through learned addresses.
- **Browsers with DNS-over-HTTPS** skip the hosts file; the pf block still applies to known addresses.
- **Content networks change addresses**, and a shared address blocks other sites on it too while the VPN is off. `unlock` removes everything.
- **A reboot clears the pf rules** (the hosts block stays). Run `sudo outline-cli cleanup` (or `lockdown`) after a reboot. Doing this at boot automatically is a possible later addition (a LaunchDaemon).
- `lockdown` and `unlock` refuse to run while `connect` is running. After editing `vpn_only`, run `lockdown` again.
- A `vpn_only` entry makes `connect` refuse a key whose transport sends some traffic directly (for example an `iptable` config with direct entries).

## 9. Things to note (not failures)

- If the server goes down while you're connected, traffic just stops. The CLI doesn't detect a dead transport yet. Ctrl-C restores the network.
- Only the primary service's DNS and IPv6 are changed. With several active interfaces the CLI warns that the others may leak.
- A server given as a host name is resolved before connecting, using your normal DNS.

## 10. If connect fails or traffic doesn't flow

Send back:
- `/tmp/outline-cli.log` (it is redacted, but check it before sending)
- `/tmp/before-defaults.txt`

If the session stays up but traffic fails, also run these in the second terminal while it is connected:

```sh
netstat -rn -f inet | grep -E '^default|^<first hop IP>|utun'
route -n get <first hop IP>
curl -4 -sv -m 10 http://1.1.1.1/ 2>&1 | tail -3         # TCP through the tunnel, no DNS needed
dig +short +time=3 +tries=1 example.com @169.254.113.53  # DNS through the tunnel, UDP
dig +short +time=3 +tries=1 +tcp example.com @169.254.113.53
sudo tcpdump -ni en1 -c 10 host <first hop IP>            # run curl again meanwhile: do packets to the server leave on Wi-Fi?
sudo tcpdump -ni utunN -c 10                              # and what enters the tunnel (utunN from the log)
```

## 11. What to send back

For each step: pass or fail, and for failures the terminal output (use `--log-level debug`) plus the output of the check that failed. Mask anything you consider private (your public IP, network names).
