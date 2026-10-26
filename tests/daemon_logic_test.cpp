// Unit tests for ivpnd's platform-independent logic (runs on any Linux).
// Build: see tests/run_tests.sh
#include <iostream>

#include "../src/core/Model.h"
#include "../src/ivpnd/DaemonLogic.h"

using nlohmann::json;
using namespace ivpnd;

static int gFailures = 0;
#define CHECK(cond) do { if (!(cond)) { \
	std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; \
	gFailures++; } } while (0)

static bool
Contains(const std::string& text, const std::string& part)
{
	return text.find(part) != std::string::npos;
}


static json
Servers()
{
	return json::parse(R"({
	"wireguard": [
		{"gateway":"nl.wg.ivpn.net","country_code":"NL","country":"Netherlands",
		 "city":"Amsterdam","hosts":[
		  {"hostname":"nl3.wg.ivpn.net","host":"185.102.218.104",
		   "public_key":"AsMT2FqpkZbjzWeDch6GwufF5odl259W/hIkGytVfWo=",
		   "local_ip":"172.16.0.1/12","dns_name":"nl3.gw.ivpn.net",
		   "v2ray":"185.102.218.110"},
		  {"hostname":"nl4.wg.ivpn.net","host":"185.102.218.105",
		   "public_key":"BsMT2FqpkZbjzWeDch6GwufF5odl259W/hIkGytVfWo=",
		   "local_ip":"172.16.0.1/12"}]}
	],
	"openvpn": [
		{"gateway":"nl.gw.ivpn.net","country_code":"NL","country":"Netherlands",
		 "city":"Amsterdam","hosts":[{"hostname":"nl3.gw.ivpn.net",
		   "host":"185.102.218.100","obfs":{"obfs4_key":"k"},
		   "dns_name":"nl3.gw.ivpn.net","v2ray":"185.102.218.111"}]}
	],
	"config": {
	  "antitracker": {"default":{"ip":"10.0.254.2"},
	                  "hardcore":{"ip":"10.0.254.3"}},
	  "ports": {
		"wireguard":[{"type":"UDP","port":2049},{"type":"UDP","port":53},
		             {"type":"UDP","port":443}],
		"openvpn":[{"type":"UDP","port":2049},{"type":"TCP","port":443},
		           {"type":"TCP","port":80}],
		"v2ray":{"id":"27de860d-5601-412d-8b71-baa048a94b98",
		         "openvpn":[{"type":"UDP","port":20501},{"type":"TCP","port":1443}],
		         "wireguard":[{"type":"UDP","port":15351}]},
		"obfs3":{"port":5145},
		"obfs4":{"port":5146}
	}}
	})");
}


static void
TestAccountId()
{
	CHECK(ValidAccountId("i-ABCD-EFGH-IJKL"));
	CHECK(ValidAccountId("ivpnAbc1234"));
	CHECK(ValidAccountId("ivpnAbc12345"));
	CHECK(!ValidAccountId("ivpnAb"));
	CHECK(!ValidAccountId("i-ABCD-EFGH-IJKL-extra"));
	CHECK(!ValidAccountId(""));
}


static void
TestSessionNew()
{
	Session s;
	s.wgPrivateKey = "keep";
	json resp;

	// success
	json ok = {{"status", 200}, {"token", "tok"}, {"vpn_username", "ivpnU"},
		{"vpn_password", "pw"}, {"device_name", "brave-fox"},
		{"service_status", {{"is_active", true}, {"active_until", 1900000000},
			{"current_plan", "IVPN Pro"}, {"capabilities", {"multihop"}}}},
		{"wireguard", {{"status", 200}, {"ip_address", "172.27.1.2"}}}};
	CHECK(HandleSessionNew(ok, "i-AAAA-BBBB-CCCC", s, resp));
	CHECK(resp["Command"] == "SessionNewResp");
	CHECK(resp["APIStatus"] == 200);
	CHECK(resp["Session"]["AccountID"] == "i-AAAA-BBBB-CCCC");
	CHECK(resp["Account"]["Active"] == true);
	CHECK(resp["Account"]["CurrentPlan"] == "IVPN Pro");
	CHECK(resp["Account"]["ActiveUntil"] == 1900000000);
	CHECK(s.token == "tok" && s.vpnUsername == "ivpnU" && s.vpnPassword == "pw");
	CHECK(s.wgLocalIp == "172.27.1.2");
	CHECK(s.wgPrivateKey == "keep");
	CHECK(s.LoggedIn());

	// round trip through account.json
	Session back = Session::FromJson(json::parse(s.ToJson().dump()));
	CHECK(back.token == "tok" && back.wgLocalIp == "172.27.1.2");
	CHECK(back.account["CurrentPlan"] == "IVPN Pro");

	// WireGuard key not accepted: no address, register before connecting
	Session s2;
	json okNoWg = ok;
	okNoWg["wireguard"] = {{"status", 424}, {"message", "no key"}};
	CHECK(HandleSessionNew(okNoWg, "i-AAAA-BBBB-CCCC", s2, resp));
	CHECK(s2.wgLocalIp.empty());

	// too many devices
	Session s3;
	json limit = {{"status", 602}, {"message", "Session limit"},
		{"data", {{"limit", 7}, {"current_plan", "IVPN Standard"}}}};
	CHECK(!HandleSessionNew(limit, "i-AAAA-BBBB-CCCC", s3, resp));
	CHECK(resp["Command"] == "SessionNewResp");
	CHECK(resp["APIStatus"] == 602);
	CHECK(resp["APIErrorMessage"] == "Session limit");
	CHECK(resp["Account"]["Limit"] == 7);
	CHECK(resp["Session"]["AccountID"] == "");
	CHECK(!s3.LoggedIn());

	// 2FA needed
	CHECK(!HandleSessionNew({{"status", 70011}, {"message", "2FA"}},
		"i-AAAA-BBBB-CCCC", s3, resp));
	CHECK(resp["APIStatus"] == 70011);

	// network failure -> ErrorResp, which the window shows on the login card
	CHECK(!HandleSessionNew(json(), "i-AAAA-BBBB-CCCC", s3, resp));
	CHECK(resp["Command"] == "ErrorResp");

	// 200 without a token is not a login
	CHECK(!HandleSessionNew({{"status", 200}}, "i-AAAA-BBBB-CCCC", s3, resp));
	CHECK(!s3.LoggedIn());
}


// The window builds "Connect" with the app's own Model code; ivpnd must read
// back exactly what it means.
static json
AppConnectParams(ivpn::VpnType type, bool antiTracker, bool hardcore,
	ivpn::Port port, ivpn::Obfuscation obfs = ivpn::Obfuscation())
{
	ivpn::Settings settings;
	settings.vpnType = type;
	settings.ObfsFor(type) = obfs;
	settings.selection = ivpn::ServerSelection::Manual;
	settings.gatewayId = "nl";
	settings.antiTracker = antiTracker;
	settings.antiTrackerHardcore = hardcore;
	settings.PortFor(type) = port;
	ivpn::ServerLists lists = ivpn::ParseServerList(Servers());
	std::string error;
	json params = ivpn::BuildConnectParams(settings, lists, ivpn::PingMap(),
		0, nullptr, error);
	CHECK(!params.is_null());
	return json::parse(params.dump());	// as sent over the wire
}


static void
TestPlanConnect()
{
	json config = Servers()["config"];
	ConnectPlan plan;
	std::string error;

	// WireGuard, no pings: first host, gateway as DNS
	json wg = AppConnectParams(ivpn::VpnType::WireGuard, false, false,
		{2049, false});
	CHECK(PlanConnect(wg, Pings(), config, plan, error));
	CHECK(plan.vpnType == 1);
	CHECK(plan.hostIp == "185.102.218.104");
	CHECK(plan.hostname == "nl3.wg.ivpn.net");
	CHECK(plan.port == 2049 && !plan.tcp);
	CHECK(plan.hostLocalIp == "172.16.0.1");
	CHECK(plan.dns == "172.16.0.1");

	// the faster host wins
	Pings pings = {{"185.102.218.104", 80}, {"185.102.218.105", 20}};
	CHECK(PlanConnect(wg, pings, config, plan, error));
	CHECK(plan.hostIp == "185.102.218.105");
	CHECK(plan.publicKey == "BsMT2FqpkZbjzWeDch6GwufF5odl259W/hIkGytVfWo=");

	// a host that answered beats one that didn't
	pings = {{"185.102.218.105", 300}};
	CHECK(PlanConnect(wg, pings, config, plan, error));
	CHECK(plan.hostIp == "185.102.218.105");

	// AntiTracker resolvers
	json at = AppConnectParams(ivpn::VpnType::WireGuard, true, false,
		{2049, false});
	CHECK(PlanConnect(at, Pings(), config, plan, error));
	CHECK(plan.antiTracker && !plan.hardcore && plan.dns == "10.0.254.2");
	json hard = AppConnectParams(ivpn::VpnType::WireGuard, true, true,
		{53, false});
	CHECK(PlanConnect(hard, Pings(), config, plan, error));
	CHECK(plan.hardcore && plan.dns == "10.0.254.3" && plan.port == 53);

	// OpenVPN over TCP
	json ovpn = AppConnectParams(ivpn::VpnType::OpenVPN, false, false,
		{443, true});
	CHECK(PlanConnect(ovpn, Pings(), config, plan, error));
	CHECK(plan.vpnType == 0 && plan.tcp && plan.port == 443);
	CHECK(plan.hostIp == "185.102.218.100");
	CHECK(plan.dns == "10.0.254.1");

	// what ivpnd can't do is refused, not silently changed
	json wgTcp = wg;
	wgTcp["WireGuardParameters"]["Port"]["Protocol"] = 1;
	CHECK(!PlanConnect(wgTcp, Pings(), config, plan, error));
	json noHosts = wg;
	noHosts["WireGuardParameters"]["EntryVpnServer"]["Hosts"] = json::array();
	CHECK(!PlanConnect(noHosts, Pings(), config, plan, error));
	// empty params: WireGuard without any hosts
	CHECK(!PlanConnect(json::object(), Pings(), config, plan, error));
}


static void
TestConfigs()
{
	json config = Servers()["config"];
	ConnectPlan plan;
	std::string error;
	CHECK(PlanConnect(AppConnectParams(ivpn::VpnType::WireGuard, false, false,
		{2049, false}), Pings(), config, plan, error));
	Session s;
	s.wgPrivateKey = "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=";
	s.wgLocalIp = "172.27.1.2";
	std::string conf = WireGuardConf(plan, s);
	CHECK(Contains(conf, "[Interface]\nPrivateKey = " + s.wgPrivateKey));
	CHECK(Contains(conf, "Address = 172.27.1.2/32\n"));
	CHECK(Contains(conf, "PublicKey = AsMT2FqpkZbjzWeDch6GwufF5odl259W"));
	CHECK(Contains(conf, "Endpoint = 185.102.218.104:2049\n"));
	CHECK(Contains(conf, "AllowedIPs = 0.0.0.0/0\n"));
	CHECK(!Contains(conf, "DNS"));

	CHECK(PlanConnect(AppConnectParams(ivpn::VpnType::OpenVPN, false, false,
		{443, true}), Pings(), config, plan, error));
	std::string ovpn = OpenVpnConf(plan, "-----CA-----", "-----TA-----\n");
	CHECK(Contains(ovpn, "proto tcp-client\n"));
	CHECK(Contains(ovpn, "remote 185.102.218.100 443\n"));
	CHECK(Contains(ovpn, "auth-user-pass\n"));
	CHECK(Contains(ovpn, "<ca>\n-----CA-----\n</ca>\n"));
	CHECK(Contains(ovpn, "key-direction 1\n<tls-auth>\n-----TA-----\n</tls-auth>"));
	// the backend owns these; a second copy would break openvpn's start
	CHECK(!Contains(ovpn, "management"));
	CHECK(!Contains(ovpn, "dev-node"));
}


static void
TestObfuscation()
{
	json config = Servers()["config"];
	ConnectPlan plan;
	std::string error;
	Session s;
	s.wgPrivateKey = "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=";
	s.wgLocalIp = "172.27.1.2";

	// WireGuard over V2Ray (QUIC): the chosen UDP port is the V2Ray server's
	ivpn::Obfuscation quic;
	quic.v2ray = ivpn::V2Ray::QUIC;
	json wgQuic = AppConnectParams(ivpn::VpnType::WireGuard, false, false,
		{2049, false}, quic);
	CHECK(PlanConnect(wgQuic, Pings(), config, plan, error));
	CHECK(plan.UsesV2Ray() && plan.v2ray == 1 && !plan.UsesObfsproxy());
	CHECK(plan.port == 2049 && !plan.tcp);
	CHECK(plan.v2rayServer == "185.102.218.110");
	CHECK(plan.v2rayPort == 2049);
	CHECK(plan.v2rayInboundPort == 15351);
	CHECK(plan.v2rayTlsName == "nl3.gw.inet-telecom.com");
	CHECK(plan.v2rayUserId == "27de860d-5601-412d-8b71-baa048a94b98");
	CHECK(plan.ProxyServer() == "185.102.218.110");
	std::string conf = WireGuardConf(plan, s, 40000);
	CHECK(Contains(conf, "Endpoint = 127.0.0.1:40000\n"));
	CHECK(Contains(conf, "MTU = 1280\n"));
	json v2 = V2RayConfig(plan, 40000);
	CHECK(v2["inbounds"][0]["port"] == "40000");
	CHECK(v2["inbounds"][0]["listen"] == "127.0.0.1");
	CHECK(v2["inbounds"][0]["protocol"] == "dokodemo-door");
	CHECK(v2["inbounds"][0]["settings"]["address"] == "185.102.218.104");
	CHECK(v2["inbounds"][0]["settings"]["port"] == 15351);
	CHECK(v2["inbounds"][0]["settings"]["network"] == "udp");
	const json& out = v2["outbounds"][0];
	CHECK(out["protocol"] == "vmess");
	CHECK(out["settings"]["vnext"][0]["address"] == "185.102.218.110");
	CHECK(out["settings"]["vnext"][0]["port"] == 2049);
	CHECK(out["settings"]["vnext"][0]["users"][0]["id"]
		== "27de860d-5601-412d-8b71-baa048a94b98");
	CHECK(out["settings"]["vnext"][0]["users"][0]["security"] == "none");
	CHECK(out["streamSettings"]["network"] == "quic");
	CHECK(out["streamSettings"]["security"] == "tls");
	CHECK(out["streamSettings"]["tlsSettings"]["serverName"]
		== "nl3.gw.inet-telecom.com");
	CHECK(out["streamSettings"]["quicSettings"]["header"]["type"] == "srtp");
	json c = ConnectedResp(plan, "172.27.1.2", 1);
	CHECK(ivpn::ConnectedObfuscation(c).v2ray == ivpn::V2Ray::QUIC);

	// WireGuard over V2Ray (TCP) needs a TCP port, which the app picks
	ivpn::Obfuscation tcp;
	tcp.v2ray = ivpn::V2Ray::TCP;
	json wgTcp = AppConnectParams(ivpn::VpnType::WireGuard, false, false,
		{2049, false}, tcp);
	CHECK(PlanConnect(wgTcp, Pings(), config, plan, error));
	CHECK(plan.v2ray == 2 && plan.tcp && plan.v2rayPort == plan.port);
	v2 = V2RayConfig(plan, 40001);
	CHECK(v2["outbounds"][0]["streamSettings"]["network"] == "tcp");
	CHECK(!v2["outbounds"][0]["streamSettings"].contains("security"));
	CHECK(v2["outbounds"][0]["streamSettings"]["tcpSettings"]["header"]["type"]
		== "http");
	// ... and QUIC a UDP one
	json bad = wgQuic;
	bad["WireGuardParameters"]["Port"]["Protocol"] = 1;
	CHECK(!PlanConnect(bad, Pings(), config, plan, error));

	// OpenVPN over V2Ray: UDP to the local proxy
	json ovQuic = AppConnectParams(ivpn::VpnType::OpenVPN, false, false,
		{2049, false}, quic);
	CHECK(PlanConnect(ovQuic, Pings(), config, plan, error));
	CHECK(plan.v2rayServer == "185.102.218.111");
	CHECK(plan.v2rayInboundPort == 20501);	// UDP only
	std::string ovpn = OpenVpnConf(plan, "CA", "TA", 40002);
	CHECK(Contains(ovpn, "proto udp\nremote 127.0.0.1 40002\n"));
	CHECK(!Contains(ovpn, "socks-proxy"));

	// OpenVPN with obfs4 (IAT 1): SOCKS to obfs4proxy, server's obfs4 port
	ivpn::Obfuscation obfs4;
	obfs4.obfsVersion = 4;
	obfs4.obfsIat = 1;
	json ov4 = AppConnectParams(ivpn::VpnType::OpenVPN, false, false,
		{443, true}, obfs4);
	CHECK(PlanConnect(ov4, Pings(), config, plan, error));
	CHECK(plan.UsesObfsproxy() && !plan.UsesV2Ray());
	CHECK(plan.obfsVersion == 4 && plan.obfsIat == 1 && plan.obfsPort == 5146);
	CHECK(plan.obfs4Key == "k");
	CHECK(plan.ProxyServer() == "185.102.218.100");
	CHECK(Obfs4AuthFile(plan) == "cert=k;\niat-mode=1");
	ovpn = OpenVpnConf(plan, "CA", "TA", 41234, "/tmp/auth");
	CHECK(Contains(ovpn, "proto tcp-client\nremote 185.102.218.100 5146\n"
		"socks-proxy 127.0.0.1 41234 \"/tmp/auth\"\n"));
	c = ConnectedResp(plan, "10.0.0.2", 1);
	ivpn::Obfuscation back = ivpn::ConnectedObfuscation(c);
	CHECK(back.obfsVersion == 4 && back.obfsIat == 1);

	// obfs3: no credentials
	ivpn::Obfuscation obfs3;
	obfs3.obfsVersion = 3;
	CHECK(PlanConnect(AppConnectParams(ivpn::VpnType::OpenVPN, false, false,
		{443, true}, obfs3), Pings(), config, plan, error));
	CHECK(plan.obfsPort == 5145 && Obfs4AuthFile(plan).empty());
	ovpn = OpenVpnConf(plan, "CA", "TA", 41235);
	CHECK(Contains(ovpn, "socks-proxy 127.0.0.1 41235\n"));

	// hosts without what the obfuscation needs are skipped
	json noV2 = wgQuic;
	for (json& h : noV2["WireGuardParameters"]["EntryVpnServer"]["Hosts"])
		h.erase("v2ray");
	CHECK(!PlanConnect(noV2, Pings(), config, plan, error));
	CHECK(Contains(error, "obfuscation"));

	CHECK(ObfsproxySocksPort("CMETHOD obfs4 socks5 127.0.0.1:41234", 4)
		== 41234);
	CHECK(ObfsproxySocksPort("CMETHOD obfs3 socks5 127.0.0.1:5000", 4) == 0);
	CHECK(ObfsproxySocksPort("CMETHODS DONE", 4) == 0);
}


static void
TestDefaultRoutes()
{
	std::string out =
		"IPv4 routing table:\n"
		"    Destination         Netmask         Gateway Flags  Interface\n"
		"        0.0.0.0         0.0.0.0        10.0.2.2 D----- /dev/net/ipro1000/0\n"
		"       10.0.2.0   255.255.255.0               - ------ /dev/net/ipro1000/0\n"
		"        0.0.0.0         0.0.0.0     10.11.1.1 D----- tun/0\n"
		"IPv6 routing table:\n"
		"                            Destination                                   Gateway Flags  Interface\n"
		"                                     ::/0                     fe80::1 D----- /dev/net/ipro1000/0\n"
		"                              fe80::/64                                       - ------ /dev/net/ipro1000/0\n";
	std::vector<DefaultRoute> r = ParseDefaultRoutes(out);
	CHECK(r.size() == 3);
	if (r.size() == 3) {
		CHECK(!r[0].v6 && r[0].gateway == "10.0.2.2"
			&& r[0].iface == "/dev/net/ipro1000/0");
		CHECK(!r[1].v6 && r[1].iface == "tun/0");
		CHECK(r[2].v6 && r[2].gateway == "fe80::1"
			&& r[2].iface == "/dev/net/ipro1000/0");
	}
	CHECK(ParseDefaultRoutes("IPv4 routing table:\n").empty());
}


static void
TestResponses()
{
	ConnectPlan plan;
	plan.vpnType = 1;
	plan.hostIp = "1.2.3.4";
	plan.port = 2049;
	json c = ConnectedResp(plan, "172.27.1.2/32", 1700000000);
	CHECK(c["Command"] == "ConnectedResp");
	CHECK(c["ClientIP"] == "172.27.1.2");
	CHECK(c["ServerIP"] == "1.2.3.4");
	CHECK(c["VpnType"] == 1);
	CHECK(c["TimeSecFrom1970"] == 1700000000);
	ivpn::Obfuscation obfs = ivpn::ConnectedObfuscation(c);
	CHECK(obfs.IsOff());

	json d = DisconnectedResp(true, "auth failed");
	CHECK(d["Failure"] == true && d["ReasonDescription"] == "auth failed");
	CHECK(d["IsStateInfo"] == false);
	CHECK(DisconnectedResp(false, "", true)["IsStateInfo"] == true);
	CHECK(VpnStateResp(3)["StateVal"] == 3);
	CHECK(VpnStateResp(3)["State"] == "AUTH");

	// the window reads pings back with its own parser
	json p = json::parse(PingServersResp({{"1.2.3.4", 42}}).dump());
	ivpn::PingMap pm;
	ivpn::UpdatePings(pm, p["PingResults"]);
	CHECK(pm["1.2.3.4"] == 42);

	auto all = HostsOf(Servers(), "");
	CHECK(all.size() == 3);
	CHECK(HostsOf(Servers(), "openvpn").size() == 1);
	CHECK(HostsOf(json(), "").empty());

	Session none;
	CHECK(SessionResp(none)["AccountID"] == "");
}


int
main()
{
	TestAccountId();
	TestSessionNew();
	TestPlanConnect();
	TestConfigs();
	TestObfuscation();
	TestDefaultRoutes();
	TestResponses();
	if (gFailures != 0) {
		std::cerr << gFailures << " daemon logic check(s) failed\n";
		return 1;
	}
	std::cout << "daemon logic tests passed\n";
	return 0;
}
