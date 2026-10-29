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

Expected: the key is shown redacted, the first-hop IP(s) are listed, and the connect and disconnect command lists match what you saw in M2. Nothing changes on the system.

## 3. Connect and check

```sh
sudo ./outline-cli connect --key-file ~/.outline-key
```

Expected: `the server is reachable`, then `connected: traffic goes through the tunnel (bound to en0)`.

In the second terminal:

| Check | Command | Expected |
|---|---|---|
| Public IP is the server's | `curl -4 -s https://ifconfig.me; echo` | The server's exit IP, not your normal one |
| Tunnel routes | `netstat -rn -f inet \| grep utun` | `0/1`, `128.0/1` and `169.254.113.53` on a `utunN` |
| **N5:** DNS address goes into the tunnel | `route -n get 169.254.113.53` | `interface: utunN` (not en0) |
| Server route stays physical | `route -n get <first hop IP from the dry run>` | `interface: en0`, gateway = your router |
| DNS points at the tunnel | `scutil --dns \| grep -m2 nameserver` | `169.254.113.53` |
| Names resolve | `dig +short example.com` | Addresses (answered through the tunnel) |
| IPv6 is off on the service | `networksetup -getinfo Wi-Fi \| grep IPv6` | `IPv6: Off` |
| No IPv6 leak | `curl -6 -s -m 5 https://ifconfig.me; echo $?` | Fails (non-zero exit) |
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

## 8. What to send back

For each step: pass or fail, and for failures the terminal output (use `--log-level debug`) plus the output of the check that failed. Mask anything you consider private (your public IP, network names).
