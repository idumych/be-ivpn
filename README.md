# Be IVPN

A native IVPN client for **Haiku** and **Renku OS**, written against the
Haiku API. IVPN's own service doesn't exist for these systems, so Be IVPN
brings its own, **ivpnd**: it logs in and fetches the server list from
IVPN's API, and runs the tunnels with code from [Sotoportego](https://github.com/atomozero/Sotoportego)
by [atomozero](https://github.com/atomozero) (MIT), a native VPN client for
Haiku: WireGuard built in (Haiku has no `wg`), and OpenVPN through the
`openvpn` package. For obfuscation it runs the same helpers as IVPN's own
app, [V2Ray](https://github.com/v2fly/v2ray-core) and
[obfs4proxy](https://gitlab.com/yawning/obfs4), built for Haiku. The window
starts ivpnd when needed.

## What it does

- Log in with your account ID, including 2FA and "too many devices"
- Connect or disconnect, with a live status (green / amber / red) and time connected
- Choose a location from a searchable list with latency, or Fastest / Random
- Protocol (WireGuard or OpenVPN) and port
- Obfuscation, for networks that block VPNs: V2Ray (QUIC or TCP) for
  WireGuard and OpenVPN; obfs3 or obfs4 (with IAT modes) for OpenVPN
- Firewall (kill switch): nothing leaves outside the VPN, also while it
  connects or after it drops; or "firewall on connect", only while connected
- A Deskbar item that shows the connection status (right-click it to
  connect, disconnect or open the app; **Be IVPN → Show in Deskbar** turns
  it on or off)
- AntiTracker and Hardcore mode
- Desktop notifications when the connection comes up or drops
- Changing location, protocol, port or AntiTracker while connected
  reconnects automatically, like the official app

Closing the window does **not** disconnect the VPN; ivpnd keeps running.

Not included yet: multi-hop, split tunnel, custom DNS, captcha logins and
Enhanced App Authentication.

## Install (Haiku R1/beta6 or newer, or Renku OS; x86_64)

Download `be_ivpn-<version>-1-x86_64.hpkg` from the
[latest release](https://github.com/idumych/be-ivpn/releases/latest)
and, in Terminal, in the folder where you saved it:

```sh
pkgman install ./be_ivpn-*.hpkg
```

This also installs `openvpn`, and replaces the older `ivpn_haiku` package
if you have it. Open it from the Deskbar: **Applications → Be IVPN**.

Tested on Haiku R1/beta6 (x86_64, in VirtualBox): logging in, WireGuard
and OpenVPN connections (IVPN's own check confirms the traffic leaves from an
IVPN server), AntiTracker, reconnecting when settings change while connected,
and disconnecting, which puts the routes and DNS back as they were. The same
package installs on Renku OS, but it is not tested there yet.

Good to know:

- **IPv4 only**: Haiku's tunnel driver has no IPv6. On a network with IPv6,
  IPv6 traffic does not go through the VPN, unless the firewall is on: it
  blocks IPv6 too.
- **How the firewall works:** Haiku has no packet filter, so it works on
  routes. While it is on, your network's default route stays out of the
  routing table (ivpnd takes it out again when DHCP puts it back), so
  traffic can only leave through the VPN. Your local network and IVPN's API
  (for logging in) stay reachable; other internet access is blocked until
  you connect. It stays on until you turn it off, also when ivpnd restarts,
  but after a reboot it comes back only when the app (and so ivpnd) starts.
  If you remove the app while it is on, restart to get your connection back.
- While connected, ivpnd points `/boot/system/settings/network/resolv.conf`
  at IVPN's DNS (or AntiTracker) and puts the original back when you
  disconnect.
- ivpnd keeps its files in `~/config/settings/IVPN/daemon/` (the session is
  in `account.json`, readable only by you).

## If something goes wrong

- **"The IVPN service is not reachable":** ivpnd normally starts by itself.
  If it doesn't, run `/boot/system/apps/BeIVPN/ivpnd` in Terminal to see
  why. The app retries every few seconds.
- **Settings** are saved in `~/config/settings/IVPN/settings.json`. Delete
  that file to reset them.

## Build it yourself

On Haiku R1/beta6 (the package then installs on newer Haiku and Renku OS):

```sh
pkgman install gcc haiku_devel curl_devel openssl3_devel golang git
sh packaging/haiku/build-hpkg.sh
```

This also builds V2Ray and obfs4proxy with HaikuPorts' Go
(`packaging/haiku/build-helpers.sh`, which patches V2Ray's Haiku gaps).

The result is `be_ivpn-<version>-1-x86_64.hpkg` in this folder.

## How it is built (for developers)

```
src/core/   protocol + data model, plain C++17, no Haiku API
            DaemonConnection  TCP to 127.0.0.1, port/secret from port.txt,
                              newline-delimited JSON, Hello handshake
            Model             server list, pings, settings, Connect params
            Requests.h        every request the app sends
src/ui/     Haiku API window, location picker, status header
src/deskbar/ the Deskbar item (BeIVPNDeskbar.so)
src/ivpnd/  ivpnd, the IVPN service (the same JSON protocol as IVPN's
            official ivpn-service)
            KillSwitch        the firewall, on routes
            Proxy             runs V2Ray / obfs4proxy for obfuscation
            DaemonLogic       API answers -> responses, tunnel configs
                              (no Haiku API; tests/daemon_logic_test.cpp)
            Daemon            the background app: clients, workers, tunnels
third_party/sotoportego/      WireGuard + OpenVPN backends (MIT), see its README
tests/      core tests against a fake daemon (on Linux: tests/run_tests.sh)
            gocheck/: decodes every request with the real daemon's Go
            types (unknown fields rejected)
third_party/json.hpp   nlohmann/json 3.11.3 (MIT)
```

## Credits

- **[Sotoportego](https://github.com/atomozero/Sotoportego) by
  [atomozero](https://github.com/atomozero)**: the service (ivpnd)
  runs its tunnels with Sotoportego's WireGuard backend, written from
  scratch for Haiku, and its OpenVPN backend, with its tun, routing and DNS
  handling. Used under the MIT License (`third_party/sotoportego/LICENSE`);
  what was changed is listed in `third_party/sotoportego/README.md`.
- **[IVPN desktop-app](https://github.com/ivpn/desktop-app)** (GPL v3):
  the protocol, API and OpenVPN settings ivpnd follows, and the OpenVPN CA
  and TLS key in `resources/openvpn/`.
- **[V2Ray](https://github.com/v2fly/v2ray-core)** (MIT) and
  **[obfs4proxy](https://gitlab.com/yawning/obfs4)** (BSD 2-clause), built
  for Haiku and shipped in the package as ivpnd's obfuscation helpers.
- **[nlohmann/json](https://github.com/nlohmann/json)** (MIT).

License: GPL v3, the same as IVPN's desktop-app. IVPN is a trademark of
Privatus Limited; this is not an official IVPN product.
