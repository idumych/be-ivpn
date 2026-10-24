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
		   "local_ip":"172.16.0.1/12"},
		  {"hostname":"nl4.wg.ivpn.net","host":"185.102.218.105",
		   "public_key":"BsMT2FqpkZbjzWeDch6GwufF5odl259W/hIkGytVfWo=",
		   "local_ip":"172.16.0.1/12"}]}
	],
	"openvpn": [
		{"gateway":"nl.gw.ivpn.net","country_code":"NL","country":"Netherlands",
		 "city":"Amsterdam","hosts":[{"hostname":"nl3.gw.ivpn.net",
		   "host":"185.102.218.100","obfs":{"obfs4_key":"k"}}]}
	],
	"config": {
	  "antitracker": {"default":{"ip":"10.0.254.2"},
	                  "hardcore":{"ip":"10.0.254.3"}},
	  "ports": {
		"wireguard":[{"type":"UDP","port":2049},{"type":"UDP","port":53}],
		"openvpn":[{"type":"UDP","port":2049},{"type":"TCP","port":443}]
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
	ivpn::Port port)
{
	ivpn::Settings settings;
	settings.vpnType = type;
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
	json obfs = ovpn;
	obfs["OpenVpnParameters"]["Obfs4proxy"]["Version"] = 4;
	CHECK(!PlanConnect(obfs, Pings(), config, plan, error));
	CHECK(Contains(error, "Obfuscation"));
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
	TestResponses();
	if (gFailures != 0) {
		std::cerr << gFailures << " daemon logic check(s) failed\n";
		return 1;
	}
	std::cout << "daemon logic tests passed\n";
	return 0;
}
