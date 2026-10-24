/*
 * IVPN for Vitruvian - data model.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "Model.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <sys/stat.h>

using nlohmann::json;

namespace ivpn {

namespace {

std::string
Str(const json& j, const char* key)
{
	if (!j.is_object())
		return std::string();
	auto it = j.find(key);
	if (it == j.end() || !it->is_string())
		return std::string();
	return it->get<std::string>();
}


int
Int(const json& j, const char* key, int fallback = 0)
{
	if (!j.is_object())
		return fallback;
	auto it = j.find(key);
	if (it == j.end() || !it->is_number())
		return fallback;
	return it->get<int>();
}


bool
Bool(const json& j, const char* key, bool fallback)
{
	if (!j.is_object())
		return fallback;
	auto it = j.find(key);
	if (it == j.end() || !it->is_boolean())
		return fallback;
	return it->get<bool>();
}


std::string
Lower(std::string s)
{
	for (char& c : s)
		c = (char)tolower((unsigned char)c);
	return s;
}


std::vector<Server>
ParseServers(const json& list)
{
	std::vector<Server> result;
	if (!list.is_array())
		return result;

	for (const json& s : list) {
		Server server;
		server.gateway = Str(s, "gateway");
		server.countryCode = Str(s, "country_code");
		server.country = Str(s, "country");
		server.city = Str(s, "city");
		server.isp = Str(s, "isp");
		auto hosts = s.find("hosts");
		if (hosts != s.end() && hosts->is_array())
			server.hosts = *hosts;
		else
			server.hosts = json::array();

		if (server.gateway.empty() || server.hosts.empty())
			continue;
		result.push_back(std::move(server));
	}

	std::sort(result.begin(), result.end(),
		[](const Server& a, const Server& b) {
			if (a.country != b.country)
				return a.country < b.country;
			return a.city < b.city;
		});
	return result;
}


std::vector<Port>
ParsePorts(const json& list, bool allowTcp)
{
	std::vector<Port> result;
	if (list.is_array()) {
		for (const json& p : list) {
			int port = Int(p, "port");
			if (port <= 0)
				continue;	// ranges are not offered in this UI
			bool tcp = Lower(Str(p, "type")) == "tcp";
			if (tcp && !allowTcp)
				continue;
			Port entry;
			entry.port = port;
			entry.tcp = tcp;
			if (std::find(result.begin(), result.end(), entry) == result.end())
				result.push_back(entry);
		}
	}

	Port def;	// UDP 2049 is IVPN's default for both protocols
	if (std::find(result.begin(), result.end(), def) == result.end())
		result.push_back(def);

	std::sort(result.begin(), result.end(), [](const Port& a, const Port& b) {
		if (a.tcp != b.tcp)
			return !a.tcp;	// UDP first
		return a.port < b.port;
	});
	return result;
}

}	// namespace


// #pragma mark - Port / Server


std::string
Port::Label() const
{
	return std::string(tcp ? "TCP " : "UDP ") + std::to_string(port);
}


// #pragma mark - Obfuscation


std::string
Obfuscation::Label() const
{
	switch (v2ray) {
		case V2Ray::QUIC:	return "V2Ray (QUIC)";
		case V2Ray::TCP:	return "V2Ray (TCP)";
		case V2Ray::None:	break;
	}
	if (obfsVersion == 3)
		return "obfs3";
	if (obfsVersion == 4) {
		if (obfsIat == 0)
			return "obfs4";
		return "obfs4 (IAT " + std::to_string(obfsIat)
			+ (obfsIat == 2 ? ", paranoid)" : ")");
	}
	return "Off";
}


std::vector<Obfuscation>
ObfuscationChoices(VpnType type)
{
	std::vector<Obfuscation> choices;
	choices.push_back(Obfuscation());
	if (type == VpnType::OpenVPN) {
		Obfuscation o;
		o.obfsVersion = 3;
		choices.push_back(o);
		o.obfsVersion = 4;
		for (int iat = 0; iat <= 2; iat++) {
			o.obfsIat = iat;
			choices.push_back(o);
		}
	}
	Obfuscation v;
	v.v2ray = V2Ray::QUIC;
	choices.push_back(v);
	v.v2ray = V2Ray::TCP;
	choices.push_back(v);
	return choices;
}


std::vector<Port>
AllowedPorts(const std::vector<Port>& ports, VpnType type,
	const Obfuscation& obfs)
{
	bool needTcp = false;
	bool any = false;
	if (obfs.v2ray == V2Ray::QUIC)
		needTcp = false;
	else if (obfs.v2ray == V2Ray::TCP || obfs.UsesObfsproxy())
		needTcp = true;
	else if (type == VpnType::WireGuard)
		needTcp = false;
	else
		any = true;	// plain OpenVPN: UDP and TCP

	std::vector<Port> result;
	for (const Port& p : ports) {
		if (any || p.tcp == needTcp)
			result.push_back(p);
	}

	if (result.empty() && needTcp && type == VpnType::WireGuard) {
		// IVPN lists no TCP ports for WireGuard; V2Ray (TCP) uses the
		// WireGuard port numbers over TCP (as the official app does).
		for (const Port& p : ports) {
			Port tcp{p.port, true};
			if (std::find(result.begin(), result.end(), tcp) == result.end())
				result.push_back(tcp);
		}
	}
	if (result.empty())
		result.push_back(Port{needTcp ? 443 : 2049, needTcp});
	return result;
}


Port
PickPort(const std::vector<Port>& allowed, const Port& current,
	const Obfuscation& obfs, const Port* chosen)
{
	if (chosen != nullptr
		&& std::find(allowed.begin(), allowed.end(), *chosen) != allowed.end())
		return *chosen;
	if (std::find(allowed.begin(), allowed.end(), current) != allowed.end())
		return current;

	Port recommended;
	if (obfs.v2ray == V2Ray::QUIC)
		recommended = Port{443, false};
	else if (obfs.v2ray == V2Ray::TCP)
		recommended = Port{80, true};
	if (obfs.v2ray != V2Ray::None
		&& std::find(allowed.begin(), allowed.end(), recommended)
			!= allowed.end())
		return recommended;
	return allowed.front();
}


Obfuscation
ConnectedObfuscation(const json& m)
{
	Obfuscation o;
	int v2ray = Int(m, "V2RayProxy");
	if (v2ray == (int)V2Ray::QUIC || v2ray == (int)V2Ray::TCP)
		o.v2ray = (V2Ray)v2ray;
	if (m.is_object() && m.contains("Obfsproxy")) {
		const json& obfs = m["Obfsproxy"];
		int version = Int(obfs, "Version");
		if (version == 3 || version == 4) {
			o.obfsVersion = version;
			o.obfsIat = version == 4 ? Int(obfs, "Obfs4Iat") : 0;
		}
	}
	return o;
}


std::string
Server::GatewayId() const
{
	size_t dot = gateway.find('.');
	return dot == std::string::npos ? gateway : gateway.substr(0, dot);
}


std::string
Server::DisplayName() const
{
	if (city.empty())
		return country;
	if (country.empty())
		return city;
	return city + ", " + country;
}


bool
Server::HasHost(const std::string& hostIp) const
{
	if (hostIp.empty())
		return false;
	for (const json& h : hosts) {
		if (Str(h, "host") == hostIp)
			return true;
		auto v6 = h.find("ipv6");
		if (v6 != h.end() && Str(*v6, "host") == hostIp)
			return true;
	}
	return false;
}


std::string
Server::HostnameFor(const std::string& hostIp) const
{
	for (const json& h : hosts) {
		if (Str(h, "host") == hostIp)
			return Str(h, "hostname");
	}
	return std::string();
}


const Server*
ServerLists::FindByGatewayId(VpnType type, const std::string& id) const
{
	for (const Server& s : For(type)) {
		if (s.GatewayId() == id)
			return &s;
	}
	return nullptr;
}


const Server*
ServerLists::FindByHost(const std::string& hostIp) const
{
	for (const Server& s : wireguard) {
		if (s.HasHost(hostIp))
			return &s;
	}
	for (const Server& s : openvpn) {
		if (s.HasHost(hostIp))
			return &s;
	}
	return nullptr;
}


ServerLists
ParseServerList(const json& vpnServers)
{
	ServerLists lists;
	if (!vpnServers.is_object())
		return lists;

	if (vpnServers.contains("wireguard"))
		lists.wireguard = ParseServers(vpnServers["wireguard"]);
	if (vpnServers.contains("openvpn"))
		lists.openvpn = ParseServers(vpnServers["openvpn"]);

	json ports;
	if (vpnServers.contains("config") && vpnServers["config"].is_object()
		&& vpnServers["config"].contains("ports"))
		ports = vpnServers["config"]["ports"];

	// TCP ports are kept for WireGuard too: V2Ray (TCP) uses them
	lists.wireguardPorts = ParsePorts(
		ports.is_object() && ports.contains("wireguard")
			? ports["wireguard"] : json(), true);
	lists.openvpnPorts = ParsePorts(
		ports.is_object() && ports.contains("openvpn")
			? ports["openvpn"] : json(), true);
	return lists;
}


// #pragma mark - pings


void
UpdatePings(PingMap& pings, const json& pingResults)
{
	if (!pingResults.is_array())
		return;
	for (const json& r : pingResults) {
		std::string host = Str(r, "Host");
		int ping = Int(r, "Ping", -1);
		if (host.empty())
			continue;
		if (ping > 0)
			pings[host] = ping;
		else
			pings.erase(host);
	}
}


int
ServerPing(const Server& server, const PingMap& pings)
{
	int best = -1;
	for (const json& h : server.hosts) {
		auto it = pings.find(Str(h, "host"));
		if (it == pings.end() || it->second <= 0)
			continue;
		if (best < 0 || it->second < best)
			best = it->second;
	}
	return best;
}


const Server*
FindFastest(const std::vector<Server>& servers, const PingMap& pings)
{
	const Server* best = nullptr;
	int bestPing = -1;
	for (const Server& s : servers) {
		int p = ServerPing(s, pings);
		if (p > 0 && (bestPing < 0 || p < bestPing)) {
			best = &s;
			bestPing = p;
		}
	}
	return best;
}


// #pragma mark - Settings


static json
PortToJson(const Port& p)
{
	return json{{"port", p.port}, {"tcp", p.tcp}};
}


static json
ObfsToJson(const Obfuscation& o)
{
	return json{{"v2ray", (int)o.v2ray}, {"obfsVersion", o.obfsVersion},
		{"obfsIat", o.obfsIat}};
}


static Obfuscation
ObfsFromJson(const json& j, VpnType type)
{
	Obfuscation o;
	int v2ray = Int(j, "v2ray");
	if (v2ray == (int)V2Ray::QUIC || v2ray == (int)V2Ray::TCP)
		o.v2ray = (V2Ray)v2ray;
	int version = Int(j, "obfsVersion");
	if (type == VpnType::OpenVPN && (version == 3 || version == 4)) {
		o.obfsVersion = version;
		int iat = Int(j, "obfsIat");
		if (version == 4 && iat >= 0 && iat <= 2)
			o.obfsIat = iat;
	}
	return o;
}


static Port
PortFromJson(const json& j, Port fallback)
{
	if (!j.is_object())
		return fallback;
	Port p;
	p.port = Int(j, "port", fallback.port);
	p.tcp = Bool(j, "tcp", fallback.tcp);
	if (p.port <= 0 || p.port > 65535)
		return fallback;
	return p;
}


json
Settings::ToJson() const
{
	return json{
		{"version", 1},
		{"vpnType", (int)vpnType},
		{"selection", (int)selection},
		{"gatewayId", gatewayId},
		{"wireguardPort", PortToJson(wireguardPort)},
		{"openvpnPort", PortToJson(openvpnPort)},
		{"wireguardChosenPort", PortToJson(wireguardChosenPort)},
		{"openvpnChosenPort", PortToJson(openvpnChosenPort)},
		{"wireguardObfuscation", ObfsToJson(wireguardObfs)},
		{"openvpnObfuscation", ObfsToJson(openvpnObfs)},
		{"firewallOnConnect", firewallOnConnect},
		{"antiTracker", antiTracker},
		{"antiTrackerHardcore", antiTrackerHardcore},
		{"notifications", notifications},
		{"deskbarOffered", deskbarOffered},
	};
}


Settings
Settings::FromJson(const json& j)
{
	Settings s;
	if (!j.is_object())
		return s;

	int type = Int(j, "vpnType", (int)s.vpnType);
	if (type == (int)VpnType::OpenVPN || type == (int)VpnType::WireGuard)
		s.vpnType = (VpnType)type;

	int sel = Int(j, "selection", (int)s.selection);
	if (sel >= 0 && sel <= 2)
		s.selection = (ServerSelection)sel;

	s.gatewayId = Str(j, "gatewayId");
	if (j.contains("wireguardPort"))
		s.wireguardPort = PortFromJson(j["wireguardPort"], s.wireguardPort);
	if (j.contains("openvpnPort"))
		s.openvpnPort = PortFromJson(j["openvpnPort"], s.openvpnPort);
	// settings from 1.0.1 and earlier: the saved port is the best guess
	s.wireguardChosenPort = j.contains("wireguardChosenPort")
		? PortFromJson(j["wireguardChosenPort"], s.wireguardPort)
		: s.wireguardPort;
	s.openvpnChosenPort = j.contains("openvpnChosenPort")
		? PortFromJson(j["openvpnChosenPort"], s.openvpnPort)
		: s.openvpnPort;
	if (j.contains("wireguardObfuscation"))
		s.wireguardObfs = ObfsFromJson(j["wireguardObfuscation"],
			VpnType::WireGuard);
	if (j.contains("openvpnObfuscation"))
		s.openvpnObfs = ObfsFromJson(j["openvpnObfuscation"], VpnType::OpenVPN);
	// WireGuard runs over TCP only inside V2Ray (TCP)
	if (s.wireguardObfs.v2ray != V2Ray::TCP)
		s.wireguardPort.tcp = false;
	s.firewallOnConnect = Bool(j, "firewallOnConnect", s.firewallOnConnect);
	s.antiTracker = Bool(j, "antiTracker", s.antiTracker);
	s.antiTrackerHardcore = Bool(j, "antiTrackerHardcore",
		s.antiTrackerHardcore);
	s.notifications = Bool(j, "notifications", s.notifications);
	s.deskbarOffered = Bool(j, "deskbarOffered", s.deskbarOffered);

	if (s.selection == ServerSelection::Manual && s.gatewayId.empty())
		s.selection = ServerSelection::Fastest;
	return s;
}


bool
Settings::Load(const std::string& path)
{
	std::ifstream file(path);
	if (!file.good())
		return false;
	json j = json::parse(file, nullptr, false);
	if (j.is_discarded())
		return false;
	*this = FromJson(j);
	return true;
}


bool
Settings::Save(const std::string& path) const
{
	size_t slash = path.rfind('/');
	if (slash != std::string::npos && slash > 0)
		mkdir(path.substr(0, slash).c_str(), 0755);	// may already exist

	std::string tmp = path + ".tmp";
	{
		std::ofstream file(tmp, std::ios::trunc);
		if (!file.good())
			return false;
		file << ToJson().dump(2) << "\n";
		if (!file.good())
			return false;
	}
	return rename(tmp.c_str(), path.c_str()) == 0;
}


// #pragma mark - Connect request


json
BuildConnectParams(const Settings& settings, const ServerLists& servers,
	const PingMap& pings, unsigned randomSeed, const Server** chosenOut,
	std::string& error)
{
	const std::vector<Server>& list = servers.For(settings.vpnType);
	if (list.empty()) {
		error = "The server list is not loaded yet.";
		return json();
	}

	const Server* chosen = nullptr;
	switch (settings.selection) {
		case ServerSelection::Manual:
			chosen = servers.FindByGatewayId(settings.vpnType,
				settings.gatewayId);
			if (chosen == nullptr) {
				error = "The selected location is not available for this "
					"protocol. Please choose another location.";
				return json();
			}
			break;
		case ServerSelection::Random:
			chosen = &list[randomSeed % list.size()];
			break;
		case ServerSelection::Fastest:
			chosen = FindFastest(list, pings);
			if (chosen == nullptr)
				chosen = &list.front();	// no ping results yet
			break;
	}

	// A stale saved port (e.g. UDP after switching to obfs4) is corrected
	// here, so the daemon never gets a combination it can't use.
	const Obfuscation& obfs = settings.ObfsFor(settings.vpnType);
	Port port = PickPort(AllowedPorts(servers.PortsFor(settings.vpnType),
		settings.vpnType, obfs), settings.PortFor(settings.vpnType), obfs);
	json portJson = {
		{"Protocol", port.tcp ? 1 : 0},	// 0 = UDP
		{"Port", port.port},
	};

	json params = {
		{"Metadata", {
			{"ServerSelectionEntry", (int)settings.selection},
			{"ServerSelectionExit", 0},
			{"AntiTracker", {
				{"Enabled", settings.antiTracker},
				{"Hardcore", settings.antiTracker
					&& settings.antiTrackerHardcore},
				{"AntiTrackerBlockListName", ""},	// daemon default
			}},
		}},
		{"VpnType", (int)settings.vpnType},
		{"FirewallOn", settings.firewallOnConnect},
		{"IPv6", false},
		{"IPv6Only", false},
	};

	json vpnParams = {
		{"Port", portJson},
		{"EntryVpnServer", {{"Hosts", chosen->hosts}}},
		{"V2RayProxy", (int)obfs.v2ray},
	};
	if (settings.vpnType == VpnType::OpenVPN) {
		vpnParams["Obfs4proxy"] = {
			{"Version", obfs.UsesObfsproxy() ? obfs.obfsVersion : 0},
			{"Obfs4Iat", obfs.UsesObfsproxy() && obfs.obfsVersion == 4
				? obfs.obfsIat : 0},
		};
	}
	if (settings.vpnType == VpnType::WireGuard)
		params["WireGuardParameters"] = vpnParams;
	else
		params["OpenVpnParameters"] = vpnParams;

	if (chosenOut != nullptr)
		*chosenOut = chosen;
	return params;
}


std::string
StateDescription(int stateVal)
{
	switch (stateVal) {
		case kStateDisconnected:	return "Disconnected";
		case kStateConnecting:		return "Connecting";
		case kStateWait:			return "Waiting for server";
		case kStateAuth:			return "Authenticating";
		case kStateGetConfig:		return "Getting configuration";
		case kStateAssignIP:		return "Assigning IP address";
		case kStateAddRoutes:		return "Adding routes";
		case kStateConnected:		return "Connected";
		case kStateReconnecting:	return "Reconnecting";
		case kStateTcpConnect:		return "TCP connect";
		case kStateExiting:			return "Disconnecting";
		case kStateInitialised:		return "Waiting for handshake";
		default:					return "Working";
	}
}

}	// namespace ivpn
