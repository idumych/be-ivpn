/*
 * ivpnd - the IVPN service for Haiku: the parts that need no Haiku API.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "DaemonLogic.h"

#include <cctype>
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
	if (plan.vpnType == 1 && plan.tcp) {
		error = "WireGuard works over UDP only.";
		return false;
	}
	if (Int(vpn, "V2RayProxy") != 0
		|| Int(Obj(vpn, "Obfs4proxy"), "Version") != 0) {
		error = "Obfuscation is not available on Haiku yet.";
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
		auto p = pings.find(Str(h, "host"));
		int ping = p != pings.end() && p->second > 0 ? p->second : -1;
		if (best == nullptr || (ping >= 0 && (bestPing < 0 || ping < bestPing))) {
			best = &h;
			bestPing = ping;
		}
	}
	if (best == nullptr) {
		error = "The chosen location has no usable servers.";
		return false;
	}
	plan.hostIp = Str(*best, "host");
	plan.hostname = Str(*best, "hostname");
	plan.publicKey = Str(*best, "public_key");
	plan.hostLocalIp = StripMask(Str(*best, "local_ip"));

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
WireGuardConf(const ConnectPlan& plan, const Session& session)
{
	std::ostringstream out;
	out << "[Interface]\n"
		<< "PrivateKey = " << session.wgPrivateKey << "\n"
		<< "Address = " << StripMask(session.wgLocalIp) << "/32\n"
		<< "\n[Peer]\n"
		<< "PublicKey = " << plan.publicKey << "\n"
		<< "Endpoint = " << plan.hostIp << ":" << plan.port << "\n"
		<< "AllowedIPs = 0.0.0.0/0\n"
		<< "PersistentKeepalive = 25\n";
	return out.str();
}


std::string
OpenVpnConf(const ConnectPlan& plan, const std::string& ca,
	const std::string& tlsAuth)
{
	// Same options as ivpn-service (daemon/vpn/openvpn/config.go). Haiku's
	// tun driver has no IPv6, so pushed IPv6 settings are dropped.
	std::ostringstream out;
	out << "client\n"
		<< "dev tun\n"
		<< "proto " << (plan.tcp ? "tcp-client" : "udp") << "\n"
		<< "remote " << plan.hostIp << " " << plan.port << "\n"
		<< "resolv-retry infinite\n"
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
		{"V2RayProxy", 0},
		{"Obfsproxy", {{"Version", 0}, {"Obfs4Iat", 0}}},
	};
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
