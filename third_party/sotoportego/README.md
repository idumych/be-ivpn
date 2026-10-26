# Sotoportego tunnel code (MIT)

The WireGuard and OpenVPN backends of [Sotoportego](https://github.com/atomozero/Sotoportego),
a native VPN client for Haiku by atomozero, used by `ivpnd` (`src/ivpnd`) to
run IVPN's tunnels on Haiku. Copied from commit
`d864eaa680f03693e5ae599ec2cb4c19043a45fc` (`src/backend/` and
`src/common/`), under the MIT License in `LICENSE`.

Only Haiku builds use it. Changes from upstream, all marked `IVPN:` or
listed here:

- `OpenVPNBackend.cpp`: crash-recovery file in `~/config/settings/IVPN/daemon/`
  instead of `.../Sotoportego/`, and the management password file named
  `/tmp/ivpnd.mgmtXXXXXX`, so a Sotoportego install and this app never act on
  each other's files.
- `OpenVPNBackend.cpp`: reports Disconnected when its reader thread exits,
  also after an error, so `ivpnd` knows when openvpn is really gone.
- `OpenVPNBackend.cpp`: the echoed openvpn log hides the management
  `username` command, which openvpn prints in clear.
- `OpenVPNBackend.h`, `WireGuardBackend.h`: an `IsIdle()` accessor (no
  process, thread or tun slot left).
- `WireGuardBackend.cpp`: resolv.conf backup named `resolv.conf.ivpn-wg`
  (unused: `ivpnd` sets DNS itself and gives the backend no `DNS =` line).
- `TunDevice.cpp/.h`: a held default route for the kill switch
  (`SetDefaultRouteHeld()`, `RestoreDefaultRoute()`); `DefaultGateway()`
  skips tun defaults and falls back to the held gateway. Both backends put
  the carrier default back through `RestoreDefaultRoute()`.
- `OpenVPNBackend.cpp`: uses `TunDevice::DefaultGateway()` when openvpn
  reports no `ROUTE_GATEWAY` (none exists while the kill switch holds it).
- `OpenVPNBackend.cpp`, `WireGuardBackend.cpp`: never pin a loopback
  endpoint (a tunnel through a local V2Ray or obfs4 proxy) to the gateway.
