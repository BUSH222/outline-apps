# outline-cli: manual test on a real Mac

This is the only end-to-end check of the VPN. Unit tests and CI cover the logic and the build, but they never touch a real network. Run the steps in order and note the result of each one.

Scope so far (M4): connect, disconnect, crash recovery, network changes, and the bypass list (section 7). VPN-only blocking comes in M5, and this document will grow with it.

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
   If you had set DNS servers or a manual IPv6 address yourself before connecting, the previous values are in the state file: `sudo cat /var/db/outline-cli/state.json` (see `prevDNS` and `prevIPv6`).
4. Last resort: reboot. Routes are cleared by a reboot, but **the DNS setting is not**, so still run the `networksetup -setdnsservers` line from step 3.

## 1. Before you start

- Build with `docs/macos-cli/build-local.sh`, or download the `outline-cli-macos-universal` artifact from a CI run. For the artifact:
  ```sh
  unzip outline-cli-macos-universal.zip && chmod +x outline-cli
  xattr -dr com.apple.quarantine outline-cli
  ```
- Put your key in a file only you can read:
  ```sh
  install -m 600 /dev/null ~/.outline-key && pbpaste > ~/.outline-key
  ```
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
./outline-cli connect --dry-run --key-file ~/.outline-key
```

Expected: the key is shown redacted, the first-hop IP(s) are listed, and the connect list includes `route -n add -host <first hop IP> <your router>`. If macOS has a cached route for the server (it usually does right after the key is fetched), a `route -n delete -host <first hop IP>` comes just before it. Nothing changes on the system.

## 3. Connect and check

Before connecting, save the routes that matter for the diagnosis:

```sh
netstat -rn -f inet | grep -E '^default|^<first hop IP>' > /tmp/before-defaults.txt
```

Then connect:

```sh
sudo ./outline-cli connect --key-file ~/.outline-key --log-level debug 2>&1 | tee -i /tmp/outline-cli.log
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
2. In the second terminal: `sudo pkill -9 -f 'outline-cli connect'`.
3. **N3:** check what the kernel removed:
   ```sh
   netstat -rn -f inet | grep -E 'utun|^0/1|^128.0/1|169.254.113.53'   # expected: nothing (they died with the utun)
   networksetup -getdnsservers Wi-Fi                                     # expected: still 169.254.113.53, so DNS is broken
   ```
4. Run `sudo ./outline-cli cleanup --dry-run`, then `sudo ./outline-cli cleanup`. Expected: `restored the network: ...`.
5. Repeat the checks from step 4. All should be back to the baseline.
6. Also check that `connect` recovers by itself: crash again (steps 1–2), then run `sudo ./outline-cli connect --key-file ~/.outline-key` directly. Expected: a warning `restored the network left behind by a previous session`, and then it connects normally.

## 6. Network change

While connected:

1. Switch networks, for example from Wi-Fi to an iPhone hotspot or Ethernet, or turn Wi-Fi off and on.
2. Within a few seconds of the new network coming up, the log shows `the network changed` (a short `the network is gone` before it is normal). Check:
   - `curl -4 -s https://ifconfig.me` shows the server's IP again within a few seconds.
   - The log shows no repeated `a connection from the physical interface failed` after the change. Such warnings naming the *old* network's DNS server were the hotspot bug of manual test 3.
   - `networksetup -getdnsservers <new service>` shows `169.254.113.53`, and the old service is back to its own setting.
3. Disconnect (Ctrl-C) and check that both services are restored.

## 7. Bypass list

Domains under `bypass:` never use the VPN. Each entry covers the domain and all its subdomains (`icanhazip.com` covers `ipv4.icanhazip.com`, but not `noticanhazip.com`). The rules file is `~/.config/outline-cli/rules.yaml` of the user who runs `sudo`; `--rules PATH` overrides it.

1. Create the rules file (as yourself, not with sudo):
   ```sh
   mkdir -p ~/.config/outline-cli
   cat > ~/.config/outline-cli/rules.yaml <<'EOF'
   bypass:
     - icanhazip.com
   EOF
   ```
2. Dry run: `./outline-cli connect --dry-run --key-file ~/.outline-key`. Expected: `rules file: ... (found: 1 bypass, 0 vpn_only)` and `bypass: icanhazip.com`.
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

## 8. Things to note (not failures)

- If the server goes down while you're connected, traffic just stops. The CLI doesn't detect a dead transport yet. Ctrl-C restores the network.
- Only the primary service's DNS and IPv6 are changed. With several active interfaces the CLI warns that the others may leak.
- A server given as a host name is resolved before connecting, using your normal DNS.

## 9. If connect fails or traffic doesn't flow

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

## 10. What to send back

For each step: pass or fail, and for failures the terminal output (use `--log-level debug`) plus the output of the check that failed. Mask anything you consider private (your public IP, network names).
