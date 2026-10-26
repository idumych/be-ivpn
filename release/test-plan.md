# Test plan: Be IVPN

Be IVPN is a network client: its peer is IVPN itself. There is no fake
server; the tests use a real IVPN account, logged in once in the test VM by
the human (never type an account ID: ask them to log in through the window).
The login is kept in `~/config/settings/IVPN/daemon/account.json`, so a
reinstall doesn't need a new one.

## Fixtures

- A logged-in IVPN account in the VM (see above).
- **The VM's clock must be right** (`date -u` against the host's). V2Ray and
  obfs4 servers silently ignore a client whose clock is off; VirtualBox
  Haiku guests often run hours off. Fix with
  `ssh <vm> "date -u -s '$(date -u '+%Y-%m-%d %H:%M:%S')'"`.
- IVPN's own check of where traffic leaves:
  `curl -sS -m 15 https://api.ivpn.net/v4/geo-lookup` prints
  `"isIvpnServer":true` when it goes through IVPN.

## Fresh state

Keep `~/config/settings/IVPN/daemon/account.json` (the login). Delete
`~/config/settings/IVPN/settings.json` (window settings) and
`~/config/settings/IVPN/daemon/firewall.json`, and make sure no tunnel or
firewall is left from an earlier run: `route` shows the network's default
route(s) and no `tun/` interface.

Screenshots of the main window show the account's plan and ID: take them
with `redactshot.py`, blacking out the "Account" line.

## Feature checks

### connect
Steps: in the main window, choose **Protocol: WireGuard** and
**Obfuscation: Off**. Click **Connect**. Wait until the status header shows
**Protected**. Run the geo lookup in the guest, saving its output to
`dist/V/evidence/{p}-geo-connect.txt`. Save the OCR text of a screenshot of
the window to `{p}-screen.txt`. Click **Disconnect**.
PASS when: `{p}-screen.txt` has `Protected` and `{p}-geo-connect.txt` has
`"isIvpnServer":true`.

### obfuscation
Steps: choose **Obfuscation: V2Ray (QUIC)**. Click **Connect**, wait for
**Protected**, run the geo lookup into `{p}-geo-v2ray.txt`, click
**Disconnect**, and set **Obfuscation** back to **Off**.
PASS when: `{p}-geo-v2ray.txt` has `"isIvpnServer":true`.

### firewall
Steps: tick **Firewall (block traffic outside the VPN)**. The status detail
says the internet is blocked. In the guest, run
`curl -sS -m 8 -o /dev/null -w '%{http_code}' http://1.1.1.1/` and write
`disconnected with the firewall on: internet blocked` to `{p}-firewall.txt`
only if curl got no answer (`000`). Untick the firewall and check the same
curl answers again (`301`); add `firewall off: internet back` to the file.
PASS when: `{p}-firewall.txt` has both lines.
