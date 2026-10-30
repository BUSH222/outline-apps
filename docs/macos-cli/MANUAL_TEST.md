# outline-cli: manual test on a real Mac

This is the only end-to-end check of the VPN. Unit tests and CI cover the logic and the build, but they never touch a real network. Run the steps in order and note the result of each one.

Scope so far (M3): connect, disconnect, crash recovery, network changes. Bypass and VPN-only rules come in M4 and M5, and this document will grow with them.

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
| No IPv6 leak | `curl -6 -s -m 5 https://ifconfig.me; echo` | Fails, **or** prints the VPN server's address. A leak is your own ISP address (IPv4 or IPv6) |
| How IPv6 is handled (diagnostic) | `curl -6 -sv -m 5 https://ifconfig.me 2>&1 \| grep -E 'Trying\|Connected'`, `netstat -rn -f inet6 \| grep -E '^default\|utun'`, `ifconfig utunN` | Send the output back |
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
2. Within a few seconds the log shows `the network changed`. Check:
   - `curl -4 -s https://ifconfig.me` still shows the server's IP.
   - `networksetup -getdnsservers <new service>` shows `169.254.113.53`, and the old service is back to its own setting.
3. Disconnect (Ctrl-C) and check that both services are restored.

## 7. Things to note (not failures)

- If the server goes down while you're connected, traffic just stops. The CLI doesn't detect a dead transport yet. Ctrl-C restores the network.
- Only the primary service's DNS and IPv6 are changed. With several active interfaces the CLI warns that the others may leak.
- A server given as a host name is resolved before connecting, using your normal DNS.

## 8. If connect fails or traffic doesn't flow

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

## 9. What to send back

For each step: pass or fail, and for failures the terminal output (use `--log-level debug`) plus the output of the check that failed. Mask anything you consider private (your public IP, network names).
