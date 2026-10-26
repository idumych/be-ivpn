/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TUN_DEVICE_H
#define TUN_DEVICE_H


#include <String.h>


// Shared helpers for Haiku's tunnel device, used by every backend that runs
// over tun/N (OpenVPN today, WireGuard next). Route and DNS management stay
// with the daemon; this is only the device plumbing.
namespace TunDevice {

// Synchronously run `ifconfig <args...>` (argv NULL-terminated) and wait for
// it. Returns true on a zero exit status. When `quiet`, the child's stderr is
// redirected to /dev/null -- what the slot probe wants, since a missing or
// stuck slot is an expected outcome there, not a failure to surface.
bool	RunIfconfig(const char* const argv[], bool quiet = false);

// Find the first free tun/N slot and bring it up with a plain `up` (no
// address). On success fills `outInterface` ("tun/N", for ifconfig/route) and
// `outNode` ("/dev/tun/N", for openvpn's --dev-node) and returns true.
//
// A previous session can leave a slot in a state where `ifconfig up` fails
// until reboot, so we delete-then-up each slot and scan upward until one
// takes. Callers that need an address on the interface assign it afterwards.
bool	ProbeFreeSlot(BString& outInterface, BString& outNode);

// Synchronously run `route <args...>` (argv NULL-terminated). Logs the command
// and its outcome; returns true on a zero exit. Used to install and remove the
// routes that steer traffic into a tunnel.
bool	RunRoute(const char* const argv[]);

// Read the current IPv4 default route. On success fills `gateway` (the next-hop
// IP) and `iface` (the physical interface it leaves on) and returns true.
// Needed to pin a VPN server / WireGuard endpoint to the carrier so its own
// packets don't loop back into the tunnel they carry.
// IVPN: defaults through a tun/N interface are skipped, and while the
// default route is held (below) the held gateway is returned when the table
// has no carrier default.
bool	DefaultGateway(BString& gateway, BString& iface);

// IVPN: kill switch support. While held, the carrier's default route stays
// out of the routing table: RestoreDefaultRoute() only remembers the gateway
// instead of adding it back, so nothing leaves outside the tunnel.
void	SetDefaultRouteHeld(bool held);
bool	DefaultRouteHeld();
void	SetHeldGateway(const BString& gateway, const BString& iface);
bool	HeldGateway(BString& gateway, BString& iface);

// IVPN: puts the carrier default route back after a tunnel, or just
// remembers it while the default route is held.
bool	RestoreDefaultRoute(const BString& gateway, const BString& iface);

// IVPN: true for 127.0.0.0/8, which must never be pinned to a gateway (the
// endpoint of a tunnel that runs through a local obfuscation proxy).
bool	IsLoopback(const BString& ip);

}	// namespace TunDevice


#endif	// TUN_DEVICE_H
