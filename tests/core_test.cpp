// Unit tests for the platform-independent core (runs on any Linux).
// Build: see tests/run_tests.sh
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <unistd.h>

#include "../src/core/DaemonConnection.h"
#include "../src/core/Model.h"
#include "../src/core/Requests.h"

using namespace ivpn;
using nlohmann::json;

static int gFailures = 0;
#define CHECK(cond) do { if (!(cond)) { \
	std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; \
	gFailures++; } } while (0)

static json
SampleServers()
{
	return json::parse(R"({
	"wireguard": [
		{"gateway":"nl.wg.ivpn.net","country_code":"NL","country":"Netherlands",
		 "city":"Amsterdam","isp":"Datapacket",
		 "hosts":[{"hostname":"nl3.wg.ivpn.net","host":"185.102.218.104",
		   "public_key":"AsMT2FqpkZbjzWeDch6GwufF5odl259W/hIkGytVfWo=",
		   "local_ip":"172.16.0.1/12","multihop_port":20003,"load":12.5,
		   "ipv6":{"host":"2a00::1","local_ip":"fd00::1"}},
		  {"hostname":"nl4.wg.ivpn.net","host":"185.102.218.105",
		   "public_key":"x","local_ip":"172.16.0.1/12","load":5}]},
		{"gateway":"us-ca.wg.ivpn.net","country_code":"US","country":"United States",
		 "city":"Los Angeles, CA","hosts":[{"hostname":"us-ca1.wg.ivpn.net",
		   "host":"69.12.80.146","public_key":"y","local_ip":"172.16.0.1/12"}]},
		{"gateway":"broken.wg.ivpn.net","country":"Nowhere","hosts":[]}
	],
	"openvpn": [
		{"gateway":"nl.gw.ivpn.net","country_code":"NL","country":"Netherlands",
		 "city":"Amsterdam","hosts":[{"hostname":"nl3.gw.ivpn.net",
		   "host":"185.102.218.100","obfs":{"obfs4_key":"k"}}]}
	],
	"config": {"ports": {
		"wireguard":[{"type":"UDP","port":2049},{"type":"UDP","port":53},
			{"type":"TCP","port":443},{"type":"UDP","range":{"min":30587,"max":30607}}],
		"openvpn":[{"type":"UDP","port":2049},{"type":"TCP","port":443},
			{"type":"TCP","port":80},{"type":"UDP","port":2049}]
	}}
	})");
}


static void
TestPortFile()
{
	int port = 0;
	uint64_t secret = 0;
	CHECK(DaemonConnection::ParsePortFileContent("51234:ffffffffffffffff",
		port, secret));
	CHECK(port == 51234);
	CHECK(secret == 0xffffffffffffffffULL);
	CHECK(DaemonConnection::ParsePortFileContent(" 80:1a2b\n", port, secret));
	CHECK(port == 80 && secret == 0x1a2b);
	CHECK(!DaemonConnection::ParsePortFileContent("abc:12", port, secret));
	CHECK(!DaemonConnection::ParsePortFileContent("12", port, secret));
	CHECK(!DaemonConnection::ParsePortFileContent("12:zz", port, secret));
	CHECK(!DaemonConnection::ParsePortFileContent("1:2:3", port, secret));
	CHECK(!DaemonConnection::ParsePortFileContent("70000:12", port, secret));

	PortInfo info;
	std::string error;
	CHECK(!DaemonConnection::ReadPortFile(info, error,
		{"/nonexistent/port.txt"}));
	CHECK(error.find("not running") != std::string::npos);
}


static void
TestServerParsing()
{
	ServerLists lists = ParseServerList(SampleServers());
	CHECK(lists.wireguard.size() == 2);	// broken one dropped
	CHECK(lists.openvpn.size() == 1);
	// sorted by country: Netherlands, United States
	CHECK(lists.wireguard[0].GatewayId() == "nl");
	CHECK(lists.wireguard[1].GatewayId() == "us-ca");
	CHECK(lists.wireguard[0].DisplayName() == "Amsterdam, Netherlands");
	CHECK(lists.wireguard[0].hosts.size() == 2);

	// WireGuard: deduped, ranges skipped, UDP first (TCP kept for V2Ray)
	CHECK(lists.wireguardPorts.size() == 3);
	CHECK(lists.wireguardPorts[0].port == 53);
	CHECK(lists.wireguardPorts[1].port == 2049);
	CHECK(lists.wireguardPorts[2].Label() == "TCP 443");
	// OpenVPN: UDP first, then TCP sorted
	CHECK(lists.openvpnPorts.size() == 3);
	CHECK(!lists.openvpnPorts[0].tcp && lists.openvpnPorts[0].port == 2049);
	CHECK(lists.openvpnPorts[1].tcp && lists.openvpnPorts[1].port == 80);
	CHECK(lists.openvpnPorts[2].Label() == "TCP 443");

	CHECK(lists.FindByGatewayId(VpnType::OpenVPN, "nl") != nullptr);
	CHECK(lists.FindByGatewayId(VpnType::OpenVPN, "us-ca") == nullptr);
	const Server* s = lists.FindByHost("69.12.80.146");
	CHECK(s != nullptr && s->city == "Los Angeles, CA");
	CHECK(lists.FindByHost("2a00::1") != nullptr);
	CHECK(s->HostnameFor("69.12.80.146") == "us-ca1.wg.ivpn.net");

	// missing config: still has default port
	ServerLists empty = ParseServerList(json::object());
	CHECK(empty.Empty());
	CHECK(empty.wireguardPorts.size() == 1);
}


static void
TestPings()
{
	ServerLists lists = ParseServerList(SampleServers());
	PingMap pings;
	CHECK(FindFastest(lists.wireguard, pings) == nullptr);

	UpdatePings(pings, json::parse(R"([
		{"Host":"185.102.218.104","Ping":80},
		{"Host":"185.102.218.105","Ping":30},
		{"Host":"69.12.80.146","Ping":45},
		{"Host":"1.2.3.4","Ping":0}])"));
	CHECK(ServerPing(lists.wireguard[0], pings) == 30);
	CHECK(ServerPing(lists.wireguard[1], pings) == 45);
	CHECK(ServerPing(lists.openvpn[0], pings) == -1);
	CHECK(FindFastest(lists.wireguard, pings) == &lists.wireguard[0]);
	CHECK(pings.count("1.2.3.4") == 0);
}


static void
TestObfuscation()
{
	ServerLists lists = ParseServerList(SampleServers());
	const std::vector<Port>& wg = lists.wireguardPorts;
	const std::vector<Port>& ovpn = lists.openvpnPorts;

	CHECK(ObfuscationChoices(VpnType::WireGuard).size() == 3);
	std::vector<Obfuscation> choices = ObfuscationChoices(VpnType::OpenVPN);
	CHECK(choices.size() == 7);
	CHECK(choices[0].IsOff() && choices[0].Label() == "Off");
	CHECK(choices[1].Label() == "obfs3");
	CHECK(choices[2].Label() == "obfs4");
	CHECK(choices[4].Label() == "obfs4 (IAT 2, paranoid)");
	CHECK(choices[6].Label() == "V2Ray (TCP)");

	Obfuscation off, quic, tcp, obfs4;
	quic.v2ray = V2Ray::QUIC;
	tcp.v2ray = V2Ray::TCP;
	obfs4.obfsVersion = 4;
	obfs4.obfsIat = 1;

	// plain WireGuard: UDP only; plain OpenVPN: everything
	std::vector<Port> a = AllowedPorts(wg, VpnType::WireGuard, off);
	CHECK(a.size() == 2 && !a[0].tcp && !a[1].tcp);
	CHECK(AllowedPorts(ovpn, VpnType::OpenVPN, off).size() == 3);
	// V2Ray QUIC: UDP; V2Ray TCP and obfsproxy: TCP
	a = AllowedPorts(ovpn, VpnType::OpenVPN, quic);
	CHECK(a.size() == 1 && !a[0].tcp);
	a = AllowedPorts(ovpn, VpnType::OpenVPN, obfs4);
	CHECK(a.size() == 2 && a[0].tcp && a[1].tcp);
	a = AllowedPorts(wg, VpnType::WireGuard, tcp);
	CHECK(a.size() == 1 && a[0] == (Port{443, true}));
	// no TCP ports listed for WireGuard: UDP port numbers over TCP
	std::vector<Port> udpOnly = {Port{2049, false}, Port{53, false}};
	a = AllowedPorts(udpOnly, VpnType::WireGuard, tcp);
	CHECK(a.size() == 2 && a[0] == (Port{2049, true}));

	// keep an allowed port, otherwise the recommended one
	CHECK(PickPort(AllowedPorts(ovpn, VpnType::OpenVPN, tcp), Port{443, true},
		tcp) == (Port{443, true}));
	CHECK(PickPort(AllowedPorts(ovpn, VpnType::OpenVPN, tcp), Port{2049, false},
		tcp) == (Port{80, true}));
	CHECK(PickPort(AllowedPorts(ovpn, VpnType::OpenVPN, obfs4),
		Port{2049, false}, obfs4).tcp);

	// the user's own port wins whenever it is allowed: turning obfs4 off
	// again brings back UDP 2049 instead of keeping the forced TCP port
	Port chosen{2049, false};
	Port forced = PickPort(AllowedPorts(ovpn, VpnType::OpenVPN, obfs4),
		chosen, obfs4, &chosen);
	CHECK(forced.tcp);
	CHECK(PickPort(AllowedPorts(ovpn, VpnType::OpenVPN, off), forced, off,
		&chosen) == chosen);
	CHECK(PickPort(AllowedPorts(wg, VpnType::WireGuard, off), Port{80, true},
		off, &chosen) == chosen);

	Obfuscation fromResp = ConnectedObfuscation(json::parse(
		R"({"V2RayProxy":0,"Obfsproxy":{"Version":4,"Obfs4Iat":2}})"));
	CHECK(fromResp.obfsVersion == 4 && fromResp.obfsIat == 2);
	CHECK(ConnectedObfuscation(json::parse(R"({"V2RayProxy":1})")).v2ray
		== V2Ray::QUIC);
	CHECK(ConnectedObfuscation(json::object()).IsOff());
}


static void
TestSettings()
{
	Settings s;
	s.vpnType = VpnType::OpenVPN;
	s.selection = ServerSelection::Manual;
	s.gatewayId = "nl";
	s.openvpnPort = Port{443, true};
	s.openvpnObfs.obfsVersion = 4;
	s.openvpnObfs.obfsIat = 2;
	s.wireguardObfs.v2ray = V2Ray::TCP;
	s.wireguardPort = Port{443, true};
	s.firewallOnConnect = true;
	s.antiTracker = true;

	char dir[] = "/tmp/ivpntestXXXXXX";
	CHECK(mkdtemp(dir) != nullptr);
	std::string path = std::string(dir) + "/sub/settings.json";
	CHECK(s.Save(path));

	Settings loaded;
	CHECK(loaded.Load(path));
	CHECK(loaded.vpnType == VpnType::OpenVPN);
	CHECK(loaded.selection == ServerSelection::Manual);
	CHECK(loaded.gatewayId == "nl");
	CHECK(loaded.openvpnPort == (Port{443, true}));
	CHECK(loaded.openvpnObfs == s.openvpnObfs);
	CHECK(loaded.wireguardObfs.v2ray == V2Ray::TCP);
	CHECK(loaded.wireguardPort == (Port{443, true}));	// TCP kept for V2Ray
	CHECK(loaded.firewallOnConnect && loaded.antiTracker);

	// the chosen ports round-trip; older settings use the saved port
	s.openvpnChosenPort = Port{2049, false};
	CHECK(s.Save(path));
	CHECK(loaded.Load(path));
	CHECK(loaded.openvpnChosenPort == (Port{2049, false}));
	Settings old = Settings::FromJson(json::parse(
		R"({"openvpnPort":{"port":1194,"tcp":false}})"));
	CHECK(old.openvpnChosenPort == (Port{1194, false}));
	CHECK(old.wireguardChosenPort == old.wireguardPort);

	// garbage / bad values fall back to defaults
	Settings bad = Settings::FromJson(json::parse(
		R"({"vpnType":7,"selection":0,"wireguardPort":{"port":-1,"tcp":true}})"));
	CHECK(bad.vpnType == VpnType::WireGuard);
	CHECK(bad.selection == ServerSelection::Fastest);	// manual w/o gateway
	CHECK(bad.wireguardPort.port == 2049 && !bad.wireguardPort.tcp);
	// obfsproxy is OpenVPN only; unknown values are dropped
	Settings badObfs = Settings::FromJson(json::parse(
		R"({"wireguardObfuscation":{"v2ray":9,"obfsVersion":4},
			"openvpnObfuscation":{"obfsVersion":4,"obfsIat":7}})"));
	CHECK(badObfs.wireguardObfs.IsOff());
	CHECK(badObfs.openvpnObfs.obfsVersion == 4 && badObfs.openvpnObfs.obfsIat == 0);

	std::ofstream(path) << "{ not json";
	Settings junk;
	CHECK(!junk.Load(path));
	if (system((std::string("rm -rf ") + dir).c_str()) != 0) {}
}


static void
TestConnectParams()
{
	ServerLists lists = ParseServerList(SampleServers());
	PingMap pings;
	std::string error;
	const Server* chosen = nullptr;

	Settings s;	// WireGuard, fastest, no pings -> first server
	json p = BuildConnectParams(s, lists, pings, 0, &chosen, error);
	CHECK(!p.is_null());
	CHECK(chosen == &lists.wireguard[0]);
	CHECK(p["VpnType"] == 1);
	CHECK(p["Metadata"]["ServerSelectionEntry"] == 1);
	CHECK(p["WireGuardParameters"]["Port"]["Port"] == 2049);
	CHECK(p["WireGuardParameters"]["Port"]["Protocol"] == 0);
	CHECK(p["WireGuardParameters"]["EntryVpnServer"]["Hosts"].size() == 2);
	CHECK(p["WireGuardParameters"]["EntryVpnServer"]["Hosts"][0]["public_key"]
		== "AsMT2FqpkZbjzWeDch6GwufF5odl259W/hIkGytVfWo=");
	CHECK(!p.contains("OpenVpnParameters"));
	CHECK(p["WireGuardParameters"]["V2RayProxy"] == 0);
	CHECK(!p["WireGuardParameters"].contains("Obfs4proxy"));

	s.vpnType = VpnType::OpenVPN;
	s.selection = ServerSelection::Manual;
	s.gatewayId = "nl";
	s.openvpnPort = Port{443, true};
	s.antiTracker = true;
	s.antiTrackerHardcore = true;
	p = BuildConnectParams(s, lists, pings, 0, &chosen, error);
	CHECK(p["VpnType"] == 0);
	CHECK(p["OpenVpnParameters"]["Port"]["Protocol"] == 1);
	CHECK(p["OpenVpnParameters"]["Port"]["Port"] == 443);
	CHECK(p["Metadata"]["AntiTracker"]["Hardcore"] == true);
	CHECK(chosen->gateway == "nl.gw.ivpn.net");
	CHECK(p["OpenVpnParameters"]["Obfs4proxy"]["Version"] == 0);

	// obfs4 with a saved UDP port: corrected to TCP
	s.openvpnObfs.obfsVersion = 4;
	s.openvpnObfs.obfsIat = 1;
	s.openvpnPort = Port{2049, false};
	p = BuildConnectParams(s, lists, pings, 0, &chosen, error);
	CHECK(p["OpenVpnParameters"]["Obfs4proxy"]["Version"] == 4);
	CHECK(p["OpenVpnParameters"]["Obfs4proxy"]["Obfs4Iat"] == 1);
	CHECK(p["OpenVpnParameters"]["Port"]["Protocol"] == 1);
	CHECK(p["OpenVpnParameters"]["V2RayProxy"] == 0);
	// V2Ray takes precedence: obfsproxy not sent
	s.openvpnObfs.v2ray = V2Ray::QUIC;
	p = BuildConnectParams(s, lists, pings, 0, &chosen, error);
	CHECK(p["OpenVpnParameters"]["V2RayProxy"] == 1);
	CHECK(p["OpenVpnParameters"]["Obfs4proxy"]["Version"] == 0);
	CHECK(p["OpenVpnParameters"]["Port"]["Protocol"] == 0);
	s.openvpnObfs = Obfuscation();

	// WireGuard over V2Ray (TCP) uses a TCP port
	s.vpnType = VpnType::WireGuard;
	s.selection = ServerSelection::Fastest;
	s.wireguardObfs.v2ray = V2Ray::TCP;
	p = BuildConnectParams(s, lists, pings, 0, &chosen, error);
	CHECK(p["WireGuardParameters"]["V2RayProxy"] == 2);
	CHECK(p["WireGuardParameters"]["Port"]["Protocol"] == 1);
	CHECK(p["WireGuardParameters"]["Port"]["Port"] == 443);
	s.wireguardObfs = Obfuscation();
	s.vpnType = VpnType::OpenVPN;
	s.selection = ServerSelection::Manual;

	s.gatewayId = "us-ca";	// no OpenVPN server there
	p = BuildConnectParams(s, lists, pings, 0, &chosen, error);
	CHECK(p.is_null());
	CHECK(!error.empty());

	s.vpnType = VpnType::WireGuard;
	s.selection = ServerSelection::Random;
	p = BuildConnectParams(s, lists, pings, 3, &chosen, error);
	CHECK(chosen == &lists.wireguard[1]);

	// print one for the Go cross-check
	s.selection = ServerSelection::Fastest;
	s.antiTracker = false;
	auto wrap = [](const json& params) {
		return json{{"Command", "Connect"}, {"Idx", 1}, {"ProtocolSecret", ""},
			{"Params", params}}.dump();
	};
	std::ofstream("connect_wg.json")
		<< wrap(BuildConnectParams(s, lists, pings, 0, nullptr, error));
	s.vpnType = VpnType::OpenVPN;
	s.openvpnPort = Port{443, true};
	std::ofstream("connect_ovpn.json")
		<< wrap(BuildConnectParams(s, lists, pings, 0, nullptr, error));
	s.openvpnObfs.obfsVersion = 4;
	s.openvpnObfs.obfsIat = 2;
	std::ofstream("connect_ovpn_obfs4.json")
		<< wrap(BuildConnectParams(s, lists, pings, 0, nullptr, error));
	s.vpnType = VpnType::WireGuard;
	s.wireguardObfs.v2ray = V2Ray::QUIC;
	std::ofstream("connect_wg_v2ray.json")
		<< wrap(BuildConnectParams(s, lists, pings, 0, nullptr, error));
}


// Talks to tests/fake_daemon.py (port given in argv)
static void
TestDaemonConnection(const char* portFile)
{
	PortInfo info;
	std::string error;
	CHECK(DaemonConnection::ReadPortFile(info, error, {portFile}));
	if (info.port == 0) {
		std::cerr << "fake daemon not reachable: " << error << "\n";
		gFailures++;
		return;
	}

	std::mutex lock;
	std::condition_variable cv;
	std::vector<json> received;
	std::string closedReason;
	bool closed = false;

	DaemonConnection conn;
	bool ok = conn.Connect(info,
		[&](const std::string& line) {
			std::lock_guard<std::mutex> l(lock);
			received.push_back(json::parse(line, nullptr, false));
			cv.notify_all();
		},
		[&](const std::string& reason) {
			std::lock_guard<std::mutex> l(lock);
			closedReason = reason;
			closed = true;
			cv.notify_all();
		}, error);
	CHECK(ok);
	if (!ok) {
		std::cerr << error << "\n";
		return;
	}

	uint32_t helloIdx = conn.SendHello("1.0.0:Vitruvian UI");
	CHECK(helloIdx == 1);

	auto waitFor = [&](size_t count) {
		std::unique_lock<std::mutex> l(lock);
		return cv.wait_for(l, std::chrono::seconds(5),
			[&] { return received.size() >= count || closed; });
	};

	CHECK(waitFor(2));
	{
		std::lock_guard<std::mutex> l(lock);
		CHECK(received.size() >= 2);
		if (received.size() >= 2) {
			CHECK(received[0]["Command"] == "HelloResp");
			CHECK(received[0]["Idx"] == helloIdx);
			CHECK(received[1]["Command"] == "ServerListResp");
			// large message split across many TCP segments
			CHECK(received[1]["VpnServers"]["wireguard"].size() == 400);
		}
	}

	uint32_t idx = conn.Send(json{{"Command", "KillSwitchGetStatus"}});
	CHECK(idx == 2);
	CHECK(waitFor(3));
	{
		std::lock_guard<std::mutex> l(lock);
		if (received.size() >= 3) {
			CHECK(received[2]["Command"] == "KillSwitchStatusResp");
			CHECK(received[2]["Idx"] == idx);
		}
	}

	// ask fake daemon to hang up -> closed callback
	conn.Send(json{{"Command", "TestCloseConnection"}});
	{
		std::unique_lock<std::mutex> l(lock);
		cv.wait_for(l, std::chrono::seconds(5), [&] { return closed; });
		CHECK(closed);
	}
	conn.Close();

	// Wrong secret must be rejected by the fake daemon (like the real one)
	PortInfo bad = info;
	bad.secret ^= 1;
	DaemonConnection conn2;
	closed = false;
	received.clear();
	CHECK(conn2.Connect(bad, [&](const std::string& line) {
			std::lock_guard<std::mutex> l(lock);
			received.push_back(json::parse(line, nullptr, false));
			cv.notify_all();
		},
		[&](const std::string&) {
			std::lock_guard<std::mutex> l(lock);
			closed = true;
			cv.notify_all();
		}, error));
	conn2.SendHello("x");
	{
		std::unique_lock<std::mutex> l(lock);
		cv.wait_for(l, std::chrono::seconds(5), [&] { return closed; });
		CHECK(closed);
		// real daemon: ErrorResp "secret verification error", then hang up
		CHECK(received.size() == 1);
		if (received.size() == 1)
			CHECK(received[0]["Command"] == "ErrorResp");
	}
	conn2.Close();
}


// Dump every request so tests/gocheck can decode them with the real types
static void
DumpRequests()
{
	std::vector<json> all = {
		req::Disconnect(), req::GetVPNState(),
		req::Login("i-AAAA-BBBB-CCCC", true, "123456"), req::Logout(),
		req::SessionStatus(), req::SetFirewall(true), req::GetFirewallStatus(),
		req::PingServers(1), req::RefreshServers(),
	};
	for (json& r : all) {
		r["Idx"] = 1;
		r["ProtocolSecret"] = "";
		std::ofstream("req_" + r["Command"].get<std::string>() + ".json")
			<< r.dump();
	}
}


int
main(int argc, char** argv)
{
	DumpRequests();
	TestPortFile();
	TestServerParsing();
	TestPings();
	TestObfuscation();
	TestSettings();
	TestConnectParams();
	if (argc > 1)
		TestDaemonConnection(argv[1]);

	if (gFailures == 0)
		std::cout << "All core tests passed\n";
	return gFailures == 0 ? 0 : 1;
}
