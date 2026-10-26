/*
 * ivpnd - the IVPN service for Haiku: the parts that need no Haiku API.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "DaemonLogic.h"

#include <cctype>
#include <cstdlib>
#include <random>
#include <sstream>

using nlohmann::json;

namespace ivpnd {

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


int64_t
Int(const json& j, const char* key, int64_t fallback = 0)
{
	if (!j.is_object())
		return fallback;
	auto it = j.find(key);
	if (it == j.end() || !it->is_number())
		return fallback;
	return it->get<int64_t>();
}


bool
Bool(const json& j, const char* key)
{
	if (!j.is_object())
		return false;
	auto it = j.find(key);
	return it != j.end() && it->is_boolean() && it->get<bool>();
}


const json&
Obj(const json& j, const char* key)
{
	static const json empty = json::object();
	if (!j.is_object())
		return empty;
	auto it = j.find(key);
	if (it == j.end() || !it->is_object())
		return empty;
	return *it;
}


// "172.16.0.1/12" -> "172.16.0.1"
std::string
StripMask(const std::string& cidr)
{
	return cidr.substr(0, cidr.find('/'));
}


// A random UDP port from a servers.json port list ([{"type":"UDP",
// "port":N}, ...]), or 0.
int
RandomUdpPort(const json& ports)
{
	std::vector<int> udp;
	if (ports.is_array()) {
		for (const json& p : ports) {
			std::string type = Str(p, "type");
			int port = (int)Int(p, "port");
			if (port > 0 && (type == "UDP" || type == "udp" || type.empty()))
				udp.push_back(port);
		}
	}
	if (udp.empty())
		return 0;
	std::random_device rd;
	return udp[std::uniform_int_distribution<size_t>(0, udp.size() - 1)(rd)];
}

}	// namespace


json
Session::ToJson() const
{
	return {
		{"accountId", accountId},
		{"token", token},
		{"deviceName", deviceName},
		{"vpnUsername", vpnUsername},
		{"vpnPassword", vpnPassword},
		{"wgPrivateKey", wgPrivateKey},
		{"wgPublicKey", wgPublicKey},
		{"wgLocalIp", wgLocalIp},
		{"wgKeyGenerated", wgKeyGenerated},
		{"account", account.is_object() ? account : json::object()},
	};
}


Session
Session::FromJson(const json& j)
{
	Session s;
	s.accountId = Str(j, "accountId");
	s.token = Str(j, "token");
	s.deviceName = Str(j, "deviceName");
	s.vpnUsername = Str(j, "vpnUsername");
	s.vpnPassword = Str(j, "vpnPassword");
	s.wgPrivateKey = Str(j, "wgPrivateKey");
	s.wgPublicKey = Str(j, "wgPublicKey");
	s.wgLocalIp = Str(j, "wgLocalIp");
	s.wgKeyGenerated = Int(j, "wgKeyGenerated");
	s.account = Obj(j, "account");
	return s;
}


bool
ValidAccountId(const std::string& id)
{
	// Same rule as ivpn-service: "i-....-....-...." or "ivpn" + 7-8
	// letters and digits
	if (id.size() == 16 && id.compare(0, 2, "i-") == 0 && id[6] == '-'
		&& id[11] == '-')
		return true;
	if ((id.size() == 11 || id.size() == 12) && id.compare(0, 4, "ivpn") == 0) {
		for (size_t i = 4; i < id.size(); i++) {
			if (!isalnum((unsigned char)id[i]))
				return false;
		}
		return true;
	}
	return false;
}


json
AccountFromServiceStatus(const json& ss)
{
	json caps = json::array();
	if (ss.is_object() && ss.contains("capabilities")
		&& ss["capabilities"].is_array())
		caps = ss["capabilities"];
	return {
		{"Active", Bool(ss, "is_active")},
		{"ActiveUntil", Int(ss, "active_until")},
		{"CurrentPlan", Str(ss, "current_plan")},
		{"PaymentMethod", Str(ss, "payment_method")},
		{"IsRenewable", Bool(ss, "is_renewable")},
		{"WillAutoRebill", Bool(ss, "will_auto_rebill")},
		{"IsFreeTrial", Bool(ss, "is_on_free_trial")},
		{"Capabilities", caps},
		{"Upgradable", Bool(ss, "upgradable")},
		{"UpgradeToPlan", Str(ss, "upgrade_to_plan")},
		{"UpgradeToURL", Str(ss, "upgrade_to_url")},
		{"DeviceManagement", Bool(ss, "device_management")},
		{"DeviceManagementURL", Str(ss, "device_management_url")},
		{"Limit", Int(ss, "limit")},
	};
}


json
SessionResp(const Session& s)
{
	if (!s.LoggedIn())
		return {{"AccountID", ""}, {"Session", ""}, {"DeviceName", ""},
			{"WgPublicKey", ""}, {"WgLocalIP", ""}, {"WgKeyGenerated", 0},
			{"WgKeysRegenInerval", 0}, {"WgUsePresharedKey", false}};
	return {
		{"AccountID", s.accountId},
		{"Session", s.token},
		{"DeviceName", s.deviceName},
		{"WgPublicKey", s.wgPublicKey},
		{"WgLocalIP", s.wgLocalIp},
		{"WgKeyGenerated", s.wgKeyGenerated},
		{"WgKeysRegenInerval", kWgKeyRotationSeconds},
		{"WgUsePresharedKey", false},
	};
}


int
ApiStatus(const json& body)
{
	return (int)Int(body, "status");
}


std::string
ApiMessage(const json& body)
{
	return Str(body, "message");
}


bool
HandleSessionNew(const json& body, const std::string& accountId,
	Session& session, json& resp)
{
	if (!body.is_object()) {
		resp = {
			{"Command", "ErrorResp"},
			{"ErrorMessage", "Could not reach the IVPN server. Check your "
				"internet connection and try again."},
		};
		return false;
	}

	int status = ApiStatus(body);
	resp = {
		{"Command", "SessionNewResp"},
		{"APIStatus", status},
		{"APIErrorMessage", ApiMessage(body)},
		{"Session", SessionResp(Session())},
		{"Account", json::object()},
		{"RawResponse", ""},
	};

	if (status != 200) {
		// "too many devices" carries the account in "data"
		if (body.contains("data") && body["data"].is_object())
			resp["Account"] = AccountFromServiceStatus(body["data"]);
		return false;
	}

	std::string token = Str(body, "token");
	if (token.empty()) {
		resp["APIStatus"] = 0;
		resp["APIErrorMessage"] = "The IVPN server sent an incomplete answer.";
		return false;
	}

	session.accountId = accountId;
	session.token = token;
	session.deviceName = Str(body, "device_name");
	session.vpnUsername = Str(body, "vpn_username");
	session.vpnPassword = Str(body, "vpn_password");
	session.account = AccountFromServiceStatus(Obj(body, "service_status"));
	const json& wg = Obj(body, "wireguard");
	if (Int(wg, "status") == 200 && !Str(wg, "ip_address").empty())
		session.wgLocalIp = Str(wg, "ip_address");
	else
		session.wgLocalIp.clear();	// register the key before connecting

	resp["Session"] = SessionResp(session);
	resp["Account"] = session.account;
	return true;
}


bool
PlanConnect(const json& params, const Pings& pings,
	const json& serversConfig, ConnectPlan& plan, std::string& error)
{
	plan = ConnectPlan();
	plan.vpnType = (int)Int(params, "VpnType", 1);
	if (plan.vpnType != 0 && plan.vpnType != 1) {
		error = "Unknown VPN protocol.";
		return false;
	}

	const json& vpn = Obj(params, plan.vpnType == 1
		? "WireGuardParameters" : "OpenVpnParameters");
	const json& port = Obj(vpn, "Port");
	plan.port = (int)Int(port, "Port", 2049);
	plan.tcp = Int(port, "Protocol") == 1;
	if (plan.port <= 0 || plan.port > 65535) {
		error = "Invalid port.";
		return false;
	}
	plan.v2ray = (int)Int(vpn, "V2RayProxy");
	if (plan.v2ray < 0 || plan.v2ray > 2) {
		error = "Unknown V2Ray transport.";
		return false;
	}
	if (plan.v2ray == 0 && plan.vpnType == 0) {
		const json& obfs = Obj(vpn, "Obfs4proxy");
		plan.obfsVersion = (int)Int(obfs, "Version");
		plan.obfsIat = plan.obfsVersion == 4 ? (int)Int(obfs, "Obfs4Iat") : 0;
		if ((plan.obfsVersion != 0 && plan.obfsVersion != 3
				&& plan.obfsVersion != 4) || plan.obfsIat < 0
			|| plan.obfsIat > 2) {
			error = "Unknown obfsproxy setting.";
			return false;
		}
	}
	// With V2Ray the chosen port is the V2Ray server's: UDP for QUIC, TCP
	// for TCP. The tunnel itself runs over UDP behind the local proxy.
	if (plan.v2ray == 1 && plan.tcp) {
		error = "V2Ray (QUIC) needs a UDP port.";
		return false;
	}
	if (plan.v2ray == 2 && !plan.tcp) {
		error = "V2Ray (TCP) needs a TCP port.";
		return false;
	}
	if (plan.vpnType == 1 && plan.tcp && plan.v2ray == 0) {
		error = "WireGuard works over UDP only.";
		return false;
	}

	const json& entry = Obj(vpn, "EntryVpnServer");
	auto hostsIt = entry.find("Hosts");
	if (hostsIt == entry.end() || !hostsIt->is_array() || hostsIt->empty()) {
		error = "The chosen location has no servers.";
		return false;
	}

	// Lowest known latency wins; unknown hosts keep the list order.
	const json* best = nullptr;
	int bestPing = -1;
	for (const json& h : *hostsIt) {
		if (Str(h, "host").empty())
			continue;
		if (plan.vpnType == 1 && Str(h, "public_key").empty())
			continue;
		if (plan.v2ray != 0 && Str(h, "v2ray").empty())
			continue;
		if (plan.obfsVersion == 4 && Str(Obj(h, "obfs"), "obfs4_key").empty())
			continue;
		auto p = pings.find(Str(h, "host"));
		int ping = p != pings.end() && p->second > 0 ? p->second : -1;
		if (best == nullptr || (ping >= 0 && (bestPing < 0 || ping < bestPing))) {
			best = &h;
			bestPing = ping;
		}
	}
	if (best == nullptr) {
		error = plan.v2ray != 0 || plan.obfsVersion != 0
			? "The chosen location has no servers for this obfuscation."
			: "The chosen location has no usable servers.";
		return false;
	}
	plan.hostIp = Str(*best, "host");
	plan.hostname = Str(*best, "hostname");
	plan.publicKey = Str(*best, "public_key");
	plan.hostLocalIp = StripMask(Str(*best, "local_ip"));

	const json& ports = Obj(serversConfig, "ports");
	if (plan.v2ray != 0) {
		const json& v2 = Obj(ports, "v2ray");
		plan.v2rayServer = Str(*best, "v2ray");
		plan.v2rayPort = plan.port;
		plan.v2rayUserId = Str(v2, "id");
		auto list = v2.find(plan.vpnType == 1 ? "wireguard" : "openvpn");
		plan.v2rayInboundPort = list != v2.end() ? RandomUdpPort(*list) : 0;
		// ivpn-service: the host's DNS name under IVPN's other domain
		std::string dnsName = Str(*best, "dns_name");
		size_t at = dnsName.find("ivpn.net");
		if (at != std::string::npos)
			dnsName.replace(at, 8, "inet-telecom.com");
		plan.v2rayTlsName = dnsName;
		if (plan.v2rayUserId.empty() || plan.v2rayInboundPort == 0
			|| (plan.v2ray == 1 && plan.v2rayTlsName.empty())) {
			error = "The server list has no V2Ray settings. Update it and "
				"try again.";
			return false;
		}
	} else if (plan.obfsVersion != 0) {
		plan.obfsPort = (int)Int(Obj(ports,
			plan.obfsVersion == 4 ? "obfs4" : "obfs3"), "port",
			plan.obfsVersion == 4 ? 5146 : 5145);
		plan.obfs4Key = Str(Obj(*best, "obfs"), "obfs4_key");
	}

	const json& at = Obj(Obj(params, "Metadata"), "AntiTracker");
	plan.antiTracker = Bool(at, "Enabled");
	plan.hardcore = plan.antiTracker && Bool(at, "Hardcore");

	if (plan.antiTracker) {
		const json& cfg = Obj(Obj(serversConfig, "antitracker"),
			plan.hardcore ? "hardcore" : "default");
		plan.dns = Str(cfg, "ip");
		if (plan.dns.empty())
			plan.dns = plan.hardcore ? "10.0.254.3" : "10.0.254.2";
	} else if (plan.vpnType == 1) {
		plan.dns = plan.hostLocalIp.empty() ? "172.16.0.1" : plan.hostLocalIp;
	} else {
		plan.dns = "10.0.254.1";	// what IVPN's OpenVPN servers push
	}
	return true;
}


std::string
WireGuardConf(const ConnectPlan& plan, const Session& session, int localPort)
{
	std::ostringstream out;
	out << "[Interface]\n"
		<< "PrivateKey = " << session.wgPrivateKey << "\n"
		<< "Address = " << StripMask(session.wgLocalIp) << "/32\n";
	// Room for V2Ray's own headers inside the carrier's 1500 bytes
	if (localPort > 0)
		out << "MTU = 1280\n";
	out << "\n[Peer]\n"
		<< "PublicKey = " << plan.publicKey << "\n";
	if (localPort > 0)
		out << "Endpoint = 127.0.0.1:" << localPort << "\n";
	else
		out << "Endpoint = " << plan.hostIp << ":" << plan.port << "\n";
	out
		<< "AllowedIPs = 0.0.0.0/0\n"
		<< "PersistentKeepalive = 25\n";
	return out.str();
}


std::string
OpenVpnConf(const ConnectPlan& plan, const std::string& ca,
	const std::string& tlsAuth, int localPort,
	const std::string& socksAuthFile)
{
	// Same options as ivpn-service (daemon/vpn/openvpn/config.go). Haiku's
	// tun driver has no IPv6, so pushed IPv6 settings are dropped.
	std::ostringstream out;
	out << "client\n"
		<< "dev tun\n";
	if (plan.UsesV2Ray() && localPort > 0) {
		// the local V2Ray proxy forwards UDP to the server's V2Ray port
		out << "proto udp\n"
			<< "remote 127.0.0.1 " << localPort << "\n";
	} else if (plan.UsesObfsproxy() && localPort > 0) {
		// openvpn asks obfs4proxy (SOCKS) for the server's obfs port
		out << "proto tcp-client\n"
			<< "remote " << plan.hostIp << " " << plan.obfsPort << "\n"
			<< "socks-proxy 127.0.0.1 " << localPort;
		if (!socksAuthFile.empty())
			out << " \"" << socksAuthFile << "\"";
		out << "\n";
	} else {
		out << "proto " << (plan.tcp ? "tcp-client" : "udp") << "\n"
			<< "remote " << plan.hostIp << " " << plan.port << "\n";
	}
	out << "resolv-retry infinite\n"
		<< "nobind\n"
		<< "persist-key\n"
		<< "auth-user-pass\n"
		<< "auth-nocache\n"
		<< "hand-window 6\n"
		<< "keepalive 8 30\n"
		<< "connect-retry 2 6\n"
		// IVPN's servers negotiate an AEAD cipher; AES-256-CBC is the
		// fallback ivpn-service uses ("cipher" alone is deprecated in 2.6)
		<< "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:"
			"AES-256-CBC\n"
		<< "data-ciphers-fallback AES-256-CBC\n"
		<< "remote-cert-tls server\n"
		<< "pull-filter ignore \"ifconfig-ipv6\"\n"
		<< "pull-filter ignore \"route-ipv6\"\n"
		<< "<ca>\n" << ca << (ca.empty() || ca.back() == '\n' ? "" : "\n")
		<< "</ca>\n"
		<< "key-direction 1\n"
		<< "<tls-auth>\n" << tlsAuth
		<< (tlsAuth.empty() || tlsAuth.back() == '\n' ? "" : "\n")
		<< "</tls-auth>\n";
	return out.str();
}


json
ConnectedResp(const ConnectPlan& plan, const std::string& clientIp,
	int64_t since)
{
	return {
		{"Command", "ConnectedResp"},
		{"TimeSecFrom1970", since},
		{"ClientIP", StripMask(clientIp)},
		{"ClientIPv6", ""},
		{"ServerIP", plan.hostIp},
		{"ServerPort", plan.port},
		{"IsTCP", plan.tcp},
		{"Mtu", 0},
		{"IsPaused", false},
		{"PausedTill", ""},
		{"VpnType", plan.vpnType},
		{"ExitHostname", ""},
		{"V2RayProxy", plan.v2ray},
		{"Obfsproxy", {{"Version", plan.UsesObfsproxy() ? plan.obfsVersion : 0},
			{"Obfs4Iat", plan.UsesObfsproxy() ? plan.obfsIat : 0}}},
	};
}


json
V2RayConfig(const ConnectPlan& plan, int localPort)
{
	json stream;
	if (plan.v2ray == 1) {
		stream = {
			{"network", "quic"},
			{"security", "tls"},
			{"quicSettings", {{"security", ""}, {"key", ""},
				{"header", {{"type", "srtp"}}}}},
			{"tlsSettings", {{"serverName", plan.v2rayTlsName}}},
		};
	} else {
		stream = {
			{"network", "tcp"},
			{"tcpSettings", {{"header", {
				{"type", "http"},
				{"request", {
					{"version", "1.1"},
					{"method", "GET"},
					{"path", {"/"}},
					{"headers", {
						{"Host", {"www.inet-telecom.com"}},
						{"User-Agent", {
							"Mozilla/5.0 (Windows NT 10.0; WOW64) "
							"AppleWebKit/537.36 (KHTML, like Gecko) "
							"Chrome/55.0.2883.75 Safari/537.36",
							"Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac "
							"OS X) AppleWebKit/601.1 (KHTML, like Gecko) "
							"CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"}},
						{"Accept-Encoding", {"gzip, deflate"}},
						{"Connection", {"keep-alive"}},
						{"Pragma", "no-cache"},
					}},
				}},
			}}}},
		};
	}
	return {
		{"log", {{"loglevel", "warning"}}},
		{"inbounds", {{
			{"port", std::to_string(localPort)},
			{"listen", "127.0.0.1"},
			{"protocol", "dokodemo-door"},
			{"settings", {{"address", plan.hostIp},
				{"port", plan.v2rayInboundPort}, {"network", "udp"}}},
		}}},
		{"outbounds", {{
			{"tag", "proxy"},
			{"protocol", "vmess"},
			{"settings", {{"vnext", {{
				{"address", plan.v2rayServer},
				{"port", plan.v2rayPort},
				{"users", {{{"id", plan.v2rayUserId}, {"alterId", 0},
					{"security", "none"}}}},
			}}}}},
			{"streamSettings", stream},
		}}},
	};
}


std::string
Obfs4AuthFile(const ConnectPlan& plan)
{
	if (!plan.UsesObfsproxy() || plan.obfsVersion != 4)
		return std::string();
	return "cert=" + plan.obfs4Key + ";\niat-mode="
		+ std::to_string(plan.obfsIat);
}


int
ObfsproxySocksPort(const std::string& line, int version)
{
	std::string method = "CMETHOD obfs" + std::to_string(version) + " ";
	if (line.rfind(method, 0) != 0)
		return 0;
	size_t colon = line.rfind(':');
	if (colon == std::string::npos)
		return 0;
	int port = atoi(line.c_str() + colon + 1);
	return port > 0 && port <= 65535 ? port : 0;
}


std::vector<DefaultRoute>
ParseDefaultRoutes(const std::string& output)
{
	// Haiku's `route` prints one table per family:
	//   IPv4 routing table:
	//   Destination Netmask Gateway Flags Interface
	//       0.0.0.0 0.0.0.0 10.0.2.2 D----- /dev/net/ipro1000/0
	//   IPv6 routing table:
	//   Destination     Gateway Flags Interface
	//          ::/0     fe80::1 D----- /dev/net/ipro1000/0
	std::vector<DefaultRoute> routes;
	std::istringstream in(output);
	std::string line;
	bool v6 = false;
	while (std::getline(in, line)) {
		if (line.find("IPv4 routing table") != std::string::npos) {
			v6 = false;
			continue;
		}
		if (line.find("IPv6 routing table") != std::string::npos) {
			v6 = true;
			continue;
		}
		std::istringstream fields(line);
		std::vector<std::string> t;
		std::string f;
		while (fields >> f)
			t.push_back(f);
		DefaultRoute r;
		r.v6 = v6;
		if (!v6 && t.size() >= 5 && t[0] == "0.0.0.0" && t[1] == "0.0.0.0"
			&& t[2] != "-" && t[2] != "0.0.0.0") {
			r.gateway = t[2];
		} else if (v6 && t.size() >= 4 && t[0] == "::/0"
			&& t[1] != "-") {
			r.gateway = t[1];
		} else
			continue;
		r.iface = t.back();
		routes.push_back(r);
	}
	return routes;
}


json
DisconnectedResp(bool failure, const std::string& reason, bool stateInfo)
{
	return {
		{"Command", "DisconnectedResp"},
		{"Failure", failure},
		{"Reason", failure ? 1 : 0},
		{"ReasonDescription", reason},
		{"IsStateInfo", stateInfo},
	};
}


json
VpnStateResp(int stateVal)
{
	static const char* names[] = {"DISCONNECTED", "CONNECTING", "WAIT",
		"AUTH", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "CONNECTED",
		"RECONNECTING", "TCP_CONNECT", "EXITING", "INITIALISED"};
	std::string name = stateVal >= 0 && stateVal < 12 ? names[stateVal]
		: "CONNECTING";
	return {{"Command", "VpnStateResp"}, {"StateVal", stateVal},
		{"State", name}};
}


json
PingServersResp(const Pings& pings)
{
	json results = json::array();
	for (const auto& p : pings)
		results.push_back({{"Host", p.first}, {"Ping", p.second}});
	return {{"Command", "PingServersResp"}, {"PingResults", results}};
}


std::map<std::string, bool>
HostsOf(const json& servers, const std::string& which)
{
	std::map<std::string, bool> hosts;
	for (const char* type : {"wireguard", "openvpn"}) {
		if (!which.empty() && which != type)
			continue;
		if (!servers.is_object() || !servers.contains(type)
			|| !servers[type].is_array())
			continue;
		for (const json& server : servers[type]) {
			if (!server.is_object() || !server.contains("hosts")
				|| !server["hosts"].is_array())
				continue;
			for (const json& h : server["hosts"]) {
				std::string ip = Str(h, "host");
				if (!ip.empty())
					hosts[ip] = true;
			}
		}
	}
	return hosts;
}

}	// namespace ivpnd
