/*
 * ivpnd - the kill switch ("firewall").
 * Distributed under the terms of the GNU GPL v3.
 */
#include "KillSwitch.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#include "../../third_party/sotoportego/TunDevice.h"

using nlohmann::json;

namespace ivpnd {

namespace {

bool
IsTun(const std::string& iface)
{
	return iface.rfind("tun/", 0) == 0;
}


void
Route(const char* command, const DefaultRoute& r)
{
	if (r.v6) {
		const char* const argv[] = {"route", command, r.iface.c_str(),
			"inet6", "default", "gw", r.gateway.c_str(), NULL};
		TunDevice::RunRoute(argv);
	} else {
		const char* const argv[] = {"route", command, r.iface.c_str(),
			"inet", "0.0.0.0", "gw", r.gateway.c_str(), "netmask", "0.0.0.0",
			NULL};
		TunDevice::RunRoute(argv);
	}
}

}	// namespace


std::string
RouteTable()
{
	std::string out;
	FILE* fp = popen("route", "r");
	if (fp == NULL)
		return out;
	char buffer[1024];
	size_t n;
	while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0)
		out.append(buffer, n);
	pclose(fp);
	return out;
}


bool
PinToCarrier(const std::string& ip, std::string& via)
{
	BString gateway, iface;
	if (ip.empty() || !TunDevice::DefaultGateway(gateway, iface))
		return false;
	const char* const argv[] = {"route", "add", iface.String(), "inet",
		ip.c_str(), "gw", gateway.String(), "netmask", "255.255.255.255",
		NULL};
	// Already there (a backend pinned it) is fine, but then it isn't ours
	// to take out again.
	if (!TunDevice::RunRoute(argv))
		return false;
	via = std::string(iface.String()) + " " + gateway.String();
	return true;
}


void
UnpinFromCarrier(const std::string& ip, const std::string& via)
{
	size_t space = via.find(' ');
	if (ip.empty() || space == std::string::npos)
		return;
	std::string iface = via.substr(0, space);
	std::string gateway = via.substr(space + 1);
	const char* const argv[] = {"route", "delete", iface.c_str(), "inet",
		ip.c_str(), "gw", gateway.c_str(), "netmask", "255.255.255.255",
		NULL};
	TunDevice::RunRoute(argv);
}


KillSwitch::KillSwitch(const std::string& statePath)
	:
	fStatePath(statePath),
	fEnabled(false),
	fTunnelUp(false)
{
}


void
KillSwitch::Load()
{
	std::ifstream in(fStatePath);
	std::stringstream ss;
	ss << in.rdbuf();
	json state = json::parse(ss.str(), nullptr, false);
	if (!state.is_object())
		return;
	if (state.contains("held") && state["held"].is_array()) {
		for (const json& r : state["held"]) {
			DefaultRoute route;
			route.v6 = r.value("v6", false);
			route.gateway = r.value("gateway", "");
			route.iface = r.value("iface", "");
			if (!route.gateway.empty() && !route.iface.empty())
				fHeld.push_back(route);
		}
	}

	if (!state.value("enabled", false)) {
		// A previous run died with a tunnel up: put back what it held
		_RestoreHeld();
		_Save();
		return;
	}
	// After a restart with the kill switch on, the carrier default is no
	// longer in the table: the saved gateway is the only record of it.
	std::string gateway = state.value("gateway", "");
	std::string iface = state.value("iface", "");
	if (!gateway.empty() && !iface.empty())
		TunDevice::SetHeldGateway(gateway.c_str(), iface.c_str());
	Enable();
}


void
KillSwitch::Enable()
{
	if (!fEnabled)
		printf("ivpnd: kill switch on\n");
	fEnabled = true;
	TunDevice::SetDefaultRouteHeld(true);
	_RemoveCarrierDefaults();
	if (!fTunnelUp)
		_PinAll();
	_Save();
}


void
KillSwitch::Disable()
{
	if (!fEnabled)
		return;
	printf("ivpnd: kill switch off\n");
	fEnabled = false;
	_UnpinAll();

	BString gateway, iface;
	bool known = TunDevice::HeldGateway(gateway, iface);
	TunDevice::SetDefaultRouteHeld(false);
	TunDevice::SetHeldGateway("", "");
	// With a tunnel up the defaults stay out until it goes down (and its
	// backend puts its own carrier default back then)
	if (!fTunnelUp) {
		if (known) {
			// the default a tunnel left with the kill switch
			DefaultRoute r;
			r.gateway = gateway.String();
			r.iface = iface.String();
			bool listed = false;
			for (const DefaultRoute& h : fHeld)
				listed = listed || h == r;
			if (!listed)
				fHeld.push_back(r);
		}
		_RestoreHeld();
	}
	_Save();
}


void
KillSwitch::SetTunnelUp(bool up)
{
	fTunnelUp = up;
	if (up) {
		// The API goes through the tunnel like everything else
		_UnpinAll();
		_RemoveCarrierDefaults();
	} else if (!fEnabled)
		_RestoreHeld();
	else
		_PinAll();
	_Save();
}


void
KillSwitch::SetApiHosts(const std::vector<std::string>& ips)
{
	if (ips == fApiHosts)
		return;
	_UnpinAll();
	fApiHosts = ips;
	if (fEnabled && !fTunnelUp)
		_PinAll();
}


void
KillSwitch::Check()
{
	if (!fEnabled && !fTunnelUp)
		return;
	_RemoveCarrierDefaults();
	if (fEnabled && !fTunnelUp)
		_PinAll();
}


void
KillSwitch::_RemoveCarrierDefaults()
{
	for (const DefaultRoute& r : ParseDefaultRoutes(RouteTable())) {
		if (IsTun(r.iface))
			continue;
		bool known = false;
		for (const DefaultRoute& h : fHeld)
			known = known || h == r;
		if (!known)
			fHeld.push_back(r);
		if (!r.v6 && fEnabled) {
			// The first carrier is the one tunnels and API pins use; a new
			// network (or DHCP) can bring a new gateway, and the pins must
			// follow it.
			BString oldGateway, oldIface;
			bool hadOld = TunDevice::HeldGateway(oldGateway, oldIface);
			bool oldStillHeld = false;
			for (const DefaultRoute& h : fHeld) {
				oldStillHeld = oldStillHeld || (hadOld && !h.v6
					&& h.gateway == oldGateway.String()
					&& h.iface == oldIface.String() && !(h == r));
			}
			if (!hadOld || (!oldStillHeld && (r.gateway != oldGateway.String()
					|| r.iface != oldIface.String()))) {
				_UnpinAll();
				TunDevice::SetHeldGateway(r.gateway.c_str(), r.iface.c_str());
			}
		}
		printf("ivpnd: %s takes out the default route via %s %s\n",
			fEnabled ? "kill switch" : "tunnel", r.iface.c_str(),
			r.gateway.c_str());
		Route("delete", r);
		_Save();
	}
}


void
KillSwitch::_RestoreHeld()
{
	std::vector<DefaultRoute> present = ParseDefaultRoutes(RouteTable());
	for (const DefaultRoute& r : fHeld) {
		bool there = false;
		for (const DefaultRoute& p : present)
			there = there || p == r;
		if (!there)
			Route("add", r);
	}
	fHeld.clear();
}


void
KillSwitch::_PinAll()
{
	for (const std::string& ip : fApiHosts) {
		if (fPinned.count(ip) != 0)
			continue;
		std::string via;
		if (PinToCarrier(ip, via))
			fPinned[ip] = via;
	}
}


void
KillSwitch::_UnpinAll()
{
	for (const auto& p : fPinned)
		UnpinFromCarrier(p.first, p.second);
	fPinned.clear();
}


void
KillSwitch::_Save() const
{
	json state = {{"enabled", fEnabled}};
	BString gateway, iface;
	if (fEnabled && TunDevice::HeldGateway(gateway, iface)) {
		state["gateway"] = gateway.String();
		state["iface"] = iface.String();
	}
	json held = json::array();
	for (const DefaultRoute& r : fHeld)
		held.push_back({{"v6", r.v6}, {"gateway", r.gateway},
			{"iface", r.iface}});
	state["held"] = held;
	std::ofstream out(fStatePath, std::ios::trunc);
	out << state.dump(1, '\t') << "\n";
}

}	// namespace ivpnd
