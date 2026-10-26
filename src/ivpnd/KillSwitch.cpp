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
	fEnabled(false)
{
}


void
KillSwitch::Load()
{
	std::ifstream in(fStatePath);
	std::stringstream ss;
	ss << in.rdbuf();
	json state = json::parse(ss.str(), nullptr, false);
	if (!state.is_object() || !state.value("enabled", false))
		return;

	// After a restart with the kill switch on, the carrier default is no
	// longer in the table: the saved gateway is the only record of it.
	std::string gateway = state.value("gateway", "");
	std::string iface = state.value("iface", "");
	if (!gateway.empty() && !iface.empty())
		TunDevice::SetHeldGateway(gateway.c_str(), iface.c_str());
	if (state.contains("v6") && state["v6"].is_array()) {
		for (const json& r : state["v6"]) {
			DefaultRoute route;
			route.v6 = true;
			route.gateway = r.value("gateway", "");
			route.iface = r.value("iface", "");
			if (!route.gateway.empty() && !route.iface.empty())
				fHeldV6.push_back(route);
		}
	}
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
	_PinAll();
	_Save();
}


void
KillSwitch::Disable(bool tunnelUp)
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
	// With the tunnel up, its backend puts the carrier default back when
	// it goes down; without one, nothing would.
	if (!tunnelUp && known) {
		bool present = false;
		for (const DefaultRoute& r : ParseDefaultRoutes(RouteTable()))
			present = present || (!r.v6 && !IsTun(r.iface));
		if (!present)
			TunDevice::RestoreDefaultRoute(gateway, iface);
	}
	for (const DefaultRoute& r : fHeldV6)
		Route("add", r);
	fHeldV6.clear();
	_Save();
}


void
KillSwitch::SetApiHosts(const std::vector<std::string>& ips)
{
	if (ips == fApiHosts)
		return;
	_UnpinAll();
	fApiHosts = ips;
	if (fEnabled)
		_PinAll();
}


void
KillSwitch::Check()
{
	if (!fEnabled)
		return;
	_RemoveCarrierDefaults();
	_PinAll();
}


void
KillSwitch::_RemoveCarrierDefaults()
{
	for (const DefaultRoute& r : ParseDefaultRoutes(RouteTable())) {
		if (IsTun(r.iface))
			continue;
		if (r.v6) {
			bool known = false;
			for (const DefaultRoute& h : fHeldV6)
				known = known || h == r;
			if (!known)
				fHeldV6.push_back(r);
		} else {
			// A new network (or DHCP) brings a new gateway: the API pins
			// must follow it.
			BString oldGateway, oldIface;
			bool hadOld = TunDevice::HeldGateway(oldGateway, oldIface);
			if (!hadOld || r.gateway != oldGateway.String()
				|| r.iface != oldIface.String()) {
				_UnpinAll();
				TunDevice::SetHeldGateway(r.gateway.c_str(), r.iface.c_str());
			}
		}
		printf("ivpnd: kill switch takes out the default route via %s %s\n",
			r.iface.c_str(), r.gateway.c_str());
		Route("delete", r);
		_Save();
	}
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
	json v6 = json::array();
	for (const DefaultRoute& r : fHeldV6)
		v6.push_back({{"gateway", r.gateway}, {"iface", r.iface}});
	state["v6"] = v6;
	std::ofstream out(fStatePath, std::ios::trunc);
	out << state.dump(1, '\t') << "\n";
}

}	// namespace ivpnd
