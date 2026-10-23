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

	// WireGuard: UDP only, deduped, ranges skipped, sorted
	CHECK(lists.wireguardPorts.size() == 2);
	CHECK(lists.wireguardPorts[0].port == 53);
	CHECK(lists.wireguardPorts[1].port == 2049);
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
TestSettings()
{
	Settings s;
	s.vpnType = VpnType::OpenVPN;
	s.selection = ServerSelection::Manual;
	s.gatewayId = "nl";
	s.openvpnPort = Port{443, true};
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
	CHECK(loaded.firewallOnConnect && loaded.antiTracker);

	// garbage / bad values fall back to defaults
	Settings bad = Settings::FromJson(json::parse(
		R"({"vpnType":7,"selection":0,"wireguardPort":{"port":-1,"tcp":true}})"));
	CHECK(bad.vpnType == VpnType::WireGuard);
	CHECK(bad.selection == ServerSelection::Fastest);	// manual w/o gateway
	CHECK(bad.wireguardPort.port == 2049 && !bad.wireguardPort.tcp);

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
	TestSettings();
	TestConnectParams();
	if (argc > 1)
		TestDaemonConnection(argv[1]);

	if (gFailures == 0)
		std::cout << "All core tests passed\n";
	return gFailures == 0 ? 0 : 1;
}
