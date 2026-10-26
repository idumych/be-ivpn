/*
 * ivpnd - the kill switch ("firewall").
 *
 * Haiku has no packet filter, so this works on routes instead: while it is
 * on, the carrier's default routes (IPv4 and IPv6) stay out of the routing
 * table. Traffic can then only leave through the tunnel's own default route,
 * or to hosts pinned to the carrier: IVPN's API (so logging in and updating
 * the server list still work) and, pinned by the daemon while it connects,
 * the VPN or proxy server. The local network keeps working through its
 * on-link route.
 *
 * A DHCP renewal puts the default route back, so Check() runs every few
 * seconds and takes it out again. The state is saved, so ivpnd keeps it
 * after a restart (until the user turns it off).
 *
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPND_KILL_SWITCH_H
#define IVPND_KILL_SWITCH_H

#include <map>
#include <string>
#include <vector>

#include "DaemonLogic.h"

namespace ivpnd {

class KillSwitch {
public:
						KillSwitch(const std::string& statePath);

			// At startup: turns it back on if it was on.
			void		Load();

			bool		IsEnabled() const { return fEnabled; }
			void		Enable();
			// 'tunnelUp': the tunnel's default route is in place; the
			// carrier's comes back when the tunnel goes down.
			void		Disable(bool tunnelUp);

			// IVPN's API servers, reachable while it is on.
			void		SetApiHosts(const std::vector<std::string>& ips);
			const std::vector<std::string>& ApiHosts() const
							{ return fApiHosts; }

			// Takes out a default route that came back (DHCP), and pins
			// the API once the carrier's gateway is known.
			void		Check();

private:
			void		_Save() const;
			void		_PinAll();
			void		_UnpinAll();
			void		_RemoveCarrierDefaults();

			std::string	fStatePath;
			bool		fEnabled;
			std::vector<std::string> fApiHosts;
			// API host -> the "iface gateway" it is pinned through
			std::map<std::string, std::string> fPinned;
			// IPv6 defaults taken out, put back when it is turned off
			std::vector<DefaultRoute> fHeldV6;
};

// The `route` command's output, for ParseDefaultRoutes().
std::string	RouteTable();

// Pins 'ip' to the carrier's gateway (the held one while the kill switch is
// on), so its traffic doesn't go into the tunnel. Fills 'via' with the
// "iface gateway" used. False when there is no carrier gateway.
bool		PinToCarrier(const std::string& ip, std::string& via);
void		UnpinFromCarrier(const std::string& ip, const std::string& via);

}	// namespace ivpnd

#endif	// IVPND_KILL_SWITCH_H
