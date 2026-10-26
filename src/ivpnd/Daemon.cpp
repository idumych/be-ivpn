/*
 * ivpnd - the IVPN service for Haiku.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "Daemon.h"

#include <Directory.h>
#include <FindDirectory.h>
#include <Message.h>
#include <MessageRunner.h>
#include <Messenger.h>
#include <Path.h>

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#include "Dns.h"
#include "IvpnApi.h"
#include "Pinger.h"
#include "Proxy.h"

#include "../../third_party/sotoportego/OpenVPNBackend.h"
#include "../../third_party/sotoportego/VPNProfile.h"
#include "../../third_party/sotoportego/VPNProtocol.h"
#include "../../third_party/sotoportego/WireGuardBackend.h"
#include "../../third_party/sotoportego/WireGuardCrypto.h"

using nlohmann::json;

namespace ivpnd {

enum {
	kMsgNewClient		= 'iNew',	// "fd"
	kMsgClientLine		= 'iLin',	// "client", "line"
	kMsgClientGone		= 'iGon',	// "client"
	kMsgWorkDone		= 'iWrk',	// "kind", "client", "idx", "result"
	kMsgDnsCheck		= 'iDns',
	kMsgRefreshServers	= 'iRfs',
	kMsgKillSwitchCheck	= 'iKsw',
	kMsgProxyExited		= 'iPrx',
};

const bigtime_t kDnsCheckInterval = 5000000;
const bigtime_t kKillSwitchCheckInterval = 3000000;
const bigtime_t kServersRefreshInterval = 6LL * 3600 * 1000000;

struct Client {
	int32		id = 0;
	int			fd = -1;
	bool		verified = false;
	std::mutex	sendLock;

	~Client()
	{
		if (fd >= 0)
			close(fd);
	}
};


namespace {

std::string
Str(const json& j, const char* key)
{
	if (!j.is_object())
		return std::string();
	auto it = j.find(key);
	return it != j.end() && it->is_string() ? it->get<std::string>()
		: std::string();
}


int64
Int(const json& j, const char* key, int64 fallback = 0)
{
	if (!j.is_object())
		return fallback;
	auto it = j.find(key);
	return it != j.end() && it->is_number() ? it->get<int64>() : fallback;
}


bool
Bool(const json& j, const char* key)
{
	if (!j.is_object())
		return false;
	auto it = j.find(key);
	return it != j.end() && it->is_boolean() && it->get<bool>();
}


std::string
Base64(const uint8* data, size_t length)
{
	static const char* alphabet =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out;
	for (size_t i = 0; i < length; i += 3) {
		uint32 n = (uint32)data[i] << 16;
		if (i + 1 < length)
			n |= (uint32)data[i + 1] << 8;
		if (i + 2 < length)
			n |= data[i + 2];
		out += alphabet[(n >> 18) & 63];
		out += alphabet[(n >> 12) & 63];
		out += i + 1 < length ? alphabet[(n >> 6) & 63] : '=';
		out += i + 2 < length ? alphabet[n & 63] : '=';
	}
	return out;
}


// A fresh WireGuard key pair, base64. False when OpenSSL can't make one.
bool
NewWireGuardKeys(std::string& privateKey, std::string& publicKey)
{
	uint8 priv[32];
	uint8 pub[32];
	if (!wg::DhGenerate(priv, pub))
		return false;
	privateKey = Base64(priv, sizeof(priv));
	publicKey = Base64(pub, sizeof(pub));
	memset(priv, 0, sizeof(priv));
	return true;
}


std::string
ReadFile(const std::string& path)
{
	std::ifstream in(path);
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str();
}


// Writes 'content' readable only by its owner.
bool
WritePrivateFile(const std::string& path, const std::string& content)
{
	std::string tmp = path + ".tmp";
	int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return false;
	fchmod(fd, 0600);
	size_t done = 0;
	while (done < content.size()) {
		ssize_t n = write(fd, content.data() + done, content.size() - done);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			close(fd);
			unlink(tmp.c_str());
			return false;
		}
		done += (size_t)n;
	}
	close(fd);
	return rename(tmp.c_str(), path.c_str()) == 0;
}

}	// namespace


Daemon::Daemon()
	:
	BApplication(IVPND_SIGNATURE),
	fListenSocket(-1),
	fPort(0),
	fSecret(0),
	fNextClientId(1),
	fPhase(kIdle),
	fActive(NULL),
	fOpenVpn(NULL),
	fWireGuard(NULL),
	fConnected(false),
	fUserStop(false),
	fFailureSent(false),
	fConnectedSince(0),
	fPending(),
	fDnsCheck(NULL),
	fKillSwitch(_DataPath("firewall.json")),
	fFirewallByConnect(false),
	fKillSwitchCheck(NULL)
{
}


Daemon::~Daemon()
{
	delete fDnsCheck;
	delete fKillSwitchCheck;
	if (fProxy)
		fProxy->Stop();
	// The backends' destructors tear down a live tunnel and its routes (a
	// kill switch that is on stays on: firewall.json brings it back).
	if (fOpenVpn != NULL) {
		RemoveHandler(fOpenVpn);
		delete fOpenVpn;
	}
	if (fWireGuard != NULL) {
		RemoveHandler(fWireGuard);
		delete fWireGuard;
	}
	dns::Restore();
	if (fListenSocket >= 0)
		close(fListenSocket);
	unlink(_DataPath("port.txt").c_str());
}


void
Daemon::ReadyToRun()
{
	signal(SIGPIPE, SIG_IGN);

	// A previous run may have died with the tunnel up.
	dns::Restore();

	// Before the backends' crash recovery, which puts the carrier default
	// back: with the kill switch on, it must stay held.
	_LoadState();
	_UpdateApiHosts();
	fKillSwitch.Load();
	_UpdateApiHosts();
	BMessage check(kMsgKillSwitchCheck);
	fKillSwitchCheck = new BMessageRunner(BMessenger(this), &check,
		kKillSwitchCheckInterval);

	fOpenVpn = new OpenVPNBackend();
	fWireGuard = new WireGuardBackend();
	AddHandler(fOpenVpn);
	AddHandler(fWireGuard);
	fOpenVpn->SetObserver(BMessenger(this));
	fWireGuard->SetObserver(BMessenger(this));
	fOpenVpn->RecoverIfCrashed();
	fWireGuard->RecoverIfCrashed();

	if (!_StartListening()) {
		fprintf(stderr, "ivpnd: cannot listen, quitting\n");
		PostMessage(B_QUIT_REQUESTED);
		return;
	}

	_FetchServers(0, 0);
	BMessage refresh(kMsgRefreshServers);
	new BMessageRunner(BMessenger(this), &refresh, kServersRefreshInterval);
}


bool
Daemon::QuitRequested()
{
	// Clients reconnect to a new instance; the destructor tears the tunnel
	// down (Haiku shutdown, or "hey ivpnd quit").
	return true;
}


void
Daemon::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgNewClient:
			_AddClient(message->GetInt32("fd", -1));
			break;

		case kMsgClientLine:
			_HandleLine(message->GetInt32("client", 0),
				message->GetString("line", ""));
			break;

		case kMsgClientGone:
			_RemoveClient(message->GetInt32("client", 0));
			break;

		case kMsgWorkDone:
			_WorkDone(message);
			break;

		case kMsgStatusUpdate:
			_BackendState(message);
			break;

		case kMsgStatsUpdate:
			break;

		case kMsgDnsCheck:
			// DHCP renewals rewrite resolv.conf; keep the VPN's resolver.
			if (fConnected && !dns::IsApplied(fPlan.dns))
				dns::Apply(fPlan.dns);
			break;

		case kMsgRefreshServers:
			_FetchServers(0, 0);
			break;

		case kMsgKillSwitchCheck:
			fKillSwitch.Check();
			break;

		case kMsgProxyExited:
			// The helper died under a live tunnel: nothing gets through.
			if (fPhase == kTunnel && fActive != NULL && !fUserStop) {
				if (!fFailureSent) {
					fFailureSent = true;
					_Broadcast(DisconnectedResp(true, "The obfuscation proxy "
						"stopped."));
				}
				fActive->Disconnect();
			}
			break;

		default:
			BApplication::MessageReceived(message);
			break;
	}
}


// #pragma mark - clients


bool
Daemon::_StartListening()
{
	fListenSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (fListenSocket < 0)
		return false;
	fcntl(fListenSocket, F_SETFD, FD_CLOEXEC);

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(fListenSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0
		|| listen(fListenSocket, 8) != 0)
		return false;
	socklen_t len = sizeof(addr);
	getsockname(fListenSocket, (struct sockaddr*)&addr, &len);
	fPort = ntohs(addr.sin_port);

	uint8 random[8];
	if (!wg::RandomBytes(random, sizeof(random)))
		return false;
	memcpy(&fSecret, random, sizeof(fSecret));
	fSecret |= 1;	// never 0

	char content[64];
	snprintf(content, sizeof(content), "%d:%llx", fPort,
		(unsigned long long)fSecret);
	if (!WritePrivateFile(_DataPath("port.txt"), content))
		return false;

	std::thread(&Daemon::_AcceptLoop, this).detach();
	printf("ivpnd %s listening on 127.0.0.1:%d\n", IVPND_VERSION, fPort);
	return true;
}


void
Daemon::_AcceptLoop()
{
	BMessenger self(this);
	while (true) {
		int fd = accept(fListenSocket, NULL, NULL);
		if (fd < 0) {
			if (errno == EINTR)
				continue;
			return;
		}
		fcntl(fd, F_SETFD, FD_CLOEXEC);
		BMessage msg(kMsgNewClient);
		msg.AddInt32("fd", fd);
		if (self.SendMessage(&msg) != B_OK)
			close(fd);
	}
}


void
Daemon::_AddClient(int fd)
{
	if (fd < 0)
		return;
	std::shared_ptr<Client> client = std::make_shared<Client>();
	client->id = fNextClientId++;
	client->fd = fd;
	fClients[client->id] = client;

	BMessenger self(this);
	std::thread([client, self]() {
		std::string buffer;
		char chunk[4096];
		while (true) {
			ssize_t n = recv(client->fd, chunk, sizeof(chunk), 0);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0 || buffer.size() > 4 * 1024 * 1024)
				break;
			buffer.append(chunk, (size_t)n);
			size_t nl;
			while ((nl = buffer.find('\n')) != std::string::npos) {
				BMessage msg(kMsgClientLine);
				msg.AddInt32("client", client->id);
				msg.AddString("line", buffer.substr(0, nl).c_str());
				buffer.erase(0, nl + 1);
				self.SendMessage(&msg);
			}
		}
		BMessage gone(kMsgClientGone);
		gone.AddInt32("client", client->id);
		self.SendMessage(&gone);
	}).detach();
}


void
Daemon::_RemoveClient(int32 id)
{
	auto it = fClients.find(id);
	if (it == fClients.end())
		return;
	// Wakes the reader, which then drops its reference and the fd closes.
	shutdown(it->second->fd, SHUT_RDWR);
	fClients.erase(it);
}


void
Daemon::_HandleLine(int32 id, const char* line)
{
	auto it = fClients.find(id);
	if (it == fClients.end())
		return;
	std::shared_ptr<Client> client = it->second;

	json request = json::parse(line, nullptr, false);
	if (request.is_discarded() || !request.is_object()) {
		_RemoveClient(id);
		return;
	}

	if (!client->verified) {
		uint32 idx = (uint32)Int(request, "Idx");
		bool secretOk = Str(request, "Command") == "Hello"
			&& request.contains("Secret")
			&& request["Secret"].is_number_unsigned()
			&& request["Secret"].get<uint64>() == fSecret;
		if (!secretOk) {
			_Send(id, {{"Command", "ErrorResp"},
				{"ErrorMessage", "secret verification error"}}, idx);
			_RemoveClient(id);
			return;
		}
		client->verified = true;
	}
	_HandleRequest(*client, request);
}


void
Daemon::_Send(int32 id, json response, uint32 idx)
{
	auto it = fClients.find(id);
	if (it == fClients.end())
		return;
	std::shared_ptr<Client> client = it->second;

	response["Idx"] = idx;
	std::string line = response.dump() + "\n";
	std::lock_guard<std::mutex> lock(client->sendLock);
	size_t done = 0;
	while (done < line.size()) {
		ssize_t n = send(client->fd, line.data() + done, line.size() - done,
			0);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return;	// the reader notices and removes the client
		done += (size_t)n;
	}
}


void
Daemon::_Broadcast(const json& response)
{
	std::vector<int32> ids;
	for (const auto& c : fClients) {
		if (c.second->verified)
			ids.push_back(c.first);
	}
	for (int32 id : ids)
		_Send(id, response, 0);
}


// #pragma mark - requests


void
Daemon::_HandleRequest(Client& client, const json& request)
{
	std::string command = Str(request, "Command");
	uint32 idx = (uint32)Int(request, "Idx");
	int32 id = client.id;

	if (command == "Hello") {
		_Send(id, _HelloResp(), idx);
		if (Bool(request, "GetServersList") && fServers.is_object())
			_Send(id, {{"Command", "ServerListResp"},
				{"VpnServers", fServers}}, 0);
		if (Bool(request, "GetStatus"))
			_SendState(id, 0);
	} else if (command == "GetVPNState") {
		_SendState(id, idx);
	} else if (command == "GetServers") {
		if (Bool(request, "RequestServersUpdate") || !fServers.is_object())
			_FetchServers(id, idx);
		else
			_Send(id, {{"Command", "ServerListResp"},
				{"VpnServers", fServers}}, idx);
	} else if (command == "PingServers") {
		if (!fServers.is_object()) {
			_Send(id, {{"Command", "ErrorResp"},
				{"ErrorMessage", "The server list is not loaded yet."}}, idx);
			return;
		}
		int vpnType = Bool(request, "VpnTypePrioritization")
			? (int)Int(request, "VpnTypePrioritized", -1) : -1;
		std::string which = vpnType == 1 ? "wireguard"
			: vpnType == 0 ? "openvpn" : "";
		std::vector<std::string> hosts;
		for (const auto& h : HostsOf(fServers, which))
			hosts.push_back(h.first);
		int timeout = (int)Int(request, "TimeOutMs", 3000);
		timeout = std::max(500, std::min(timeout, 10000));
		_RunWorker("ping", id, idx, [hosts, timeout]() {
			std::string error;
			std::map<std::string, int> pings = PingHosts(hosts, timeout,
				error);
			json results = json::object();
			for (const auto& p : pings)
				results[p.first] = p.second;
			return json{{"pings", results}, {"error", error}};
		});
	} else if (command == "SessionNew") {
		std::string accountId = Str(request, "AccountID");
		if (!ValidAccountId(accountId)) {
			_Send(id, {{"Command", "ErrorResp"},
				{"ErrorMessage", "Your account ID has to be in "
					"'i-XXXX-XXXX-XXXX' or 'ivpnXXXXXXXX' format."}}, idx);
			return;
		}
		bool force = Bool(request, "ForceLogin");
		std::string code = Str(request, "Confirmation2FA");
		_RunWorker("login", id, idx, [accountId, force, code]() {
			// A new session gets new WireGuard keys, as with ivpn-service.
			std::string priv, pub, error;
			if (!NewWireGuardKeys(priv, pub))
				return json{{"error", "Could not create WireGuard keys."}};
			json body = api::SessionNew(accountId, force, pub, code, error);
			return json{{"body", body}, {"error", error},
				{"accountId", accountId}, {"priv", priv}, {"pub", pub}};
		});
	} else if (command == "SessionStatus") {
		if (!fSession.LoggedIn()) {
			_Send(id, {{"Command", "SessionStatusResp"}, {"APIStatus", 0},
				{"APIErrorMessage", "Not logged in."},
				{"Account", json::object()}}, idx);
			return;
		}
		std::string token = fSession.token;
		_RunWorker("status", id, idx, [token]() {
			std::string error;
			json body = api::SessionStatus(token, error);
			return json{{"body", body}, {"error", error}, {"token", token}};
		});
	} else if (command == "SessionDelete") {
		if (fPhase != kIdle)
			_Disconnect();
		if (Bool(request, "NeedToDisableFirewall") && fKillSwitch.IsEnabled())
			_SetKillSwitch(false);
		std::string token = fSession.token;
		_ForgetSession();
		_Send(id, {{"Command", "EmptyResp"}}, idx);
		_Broadcast(_HelloResp());
		if (!token.empty()) {
			_RunWorker("logout", 0, 0, [token]() {
				std::string error;
				api::SessionDelete(token, error);
				return json::object();
			});
		}
	} else if (command == "KillSwitchGetStatus") {
		_Send(id, _KillSwitchResp(), idx);
	} else if (command == "KillSwitchSetEnabled") {
		fFirewallByConnect = false;
		_SetKillSwitch(Bool(request, "IsEnabled"));
		_Send(id, {{"Command", "EmptyResp"}}, idx);
	} else if (command == "Connect") {
		_Send(id, {{"Command", "EmptyResp"}}, idx);
		const json empty = json::object();
		_Connect(request.contains("Params") ? request["Params"] : empty);
	} else if (command == "Disconnect") {
		if (fPhase == kIdle)
			_Send(id, DisconnectedResp(false, ""), idx);
		else
			_Disconnect();
	} else {
		_Send(id, {{"Command", "ErrorResp"}, {"ErrorMessage",
			"Not supported on Haiku: " + command}}, idx);
	}
}


json
Daemon::_HelloResp() const
{
	std::string v2ray = HelperPath("v2ray");
	std::string obfsproxy = HelperPath("obfs4proxy");
	return {
		{"Command", "HelloResp"},
		{"Version", IVPND_VERSION " (Haiku)"},
		{"ProcessorArch", "amd64"},
		{"Session", SessionResp(fSession)},
		{"Account", fSession.LoggedIn() && fSession.account.is_object()
			? fSession.account : json::object()},
		{"ParanoidMode", {{"IsEnabled", false}}},
		{"DisabledFunctions", {
			{"WireGuardError", ""},
			{"OpenVPNError", ""},
			{"ObfsproxyError", access(obfsproxy.c_str(), X_OK) == 0 ? ""
				: "obfs4proxy is not installed (" + obfsproxy + ")"},
			{"V2RayError", access(v2ray.c_str(), X_OK) == 0 ? ""
				: "V2Ray is not installed (" + v2ray + ")"},
			{"SplitTunnelError", "Not available on Haiku yet"},
			{"FirewallError", ""},
		}},
	};
}


json
Daemon::_KillSwitchResp() const
{
	// Works on routes: the local network stays reachable (on-link), and so
	// does IVPN's API.
	return {{"Command", "KillSwitchStatusResp"},
		{"IsEnabled", fKillSwitch.IsEnabled()}, {"IsPersistent", false},
		{"IsAllowLAN", true}, {"IsAllowMulticast", true},
		{"IsAllowApiServers", true}};
}


void
Daemon::_SetKillSwitch(bool enabled)
{
	if (enabled)
		fKillSwitch.Enable();
	else
		fKillSwitch.Disable(fPhase == kTunnel);
	_UpdateApiHosts();
	_Broadcast(_KillSwitchResp());
}


// IVPN's API addresses from servers.json: pinned to the carrier and used
// instead of DNS while the kill switch is on.
void
Daemon::_UpdateApiHosts()
{
	std::vector<std::string> ips;
	if (fServers.is_object() && fServers.contains("config")) {
		const json& list = fServers["config"].value("api", json::object())
			.value("ips", json::array());
		for (const json& ip : list) {
			if (ip.is_string())
				ips.push_back(ip.get<std::string>());
		}
	}
	fKillSwitch.SetApiHosts(ips);
	api::SetApiAddresses(fKillSwitch.IsEnabled() ? ips
		: std::vector<std::string>());
}


void
Daemon::_SendState(int32 id, uint32 idx)
{
	if (fConnected)
		_Send(id, ConnectedResp(fPlan, fActive != NULL
			? fActive->LocalIP().String() : "", fConnectedSince), idx);
	else if (fPhase == kIdle)
		_Send(id, DisconnectedResp(false, "", true), idx);
	else
		_Send(id, VpnStateResp(1), idx);
}


// #pragma mark - workers


void
Daemon::_RunWorker(const char* kind, int32 client, uint32 idx,
	std::function<json()> work)
{
	BMessenger self(this);
	std::string kindStr = kind;
	std::thread([self, kindStr, client, idx, work]() {
		json result = work();
		BMessage msg(kMsgWorkDone);
		msg.AddString("kind", kindStr.c_str());
		msg.AddInt32("client", client);
		msg.AddUInt32("idx", idx);
		msg.AddString("result", result.dump().c_str());
		self.SendMessage(&msg);
	}).detach();
}


void
Daemon::_FetchServers(int32 client, uint32 idx)
{
	_RunWorker("servers", client, idx, []() {
		std::string error;
		json servers = api::Servers(error);
		return json{{"servers", servers}, {"error", error}};
	});
}


void
Daemon::_WorkDone(BMessage* message)
{
	std::string kind = message->GetString("kind", "");
	int32 client = message->GetInt32("client", 0);
	uint32 idx = message->GetUInt32("idx", 0);
	json result = json::parse(message->GetString("result", "{}"), nullptr,
		false);
	if (!result.is_object())
		return;
	std::string error = Str(result, "error");

	if (kind == "servers") {
		const json& servers = result["servers"];
		if (servers.is_object() && servers.contains("wireguard")) {
			fServers = servers;
			WritePrivateFile(_DataPath("servers.json"), fServers.dump());
			_UpdateApiHosts();
			// Everyone gets the fresh list (the window may have started
			// before there was any).
			_Broadcast({{"Command", "ServerListResp"},
				{"VpnServers", fServers}});
		} else if (client != 0) {
			_Send(client, {{"Command", "ErrorResp"}, {"ErrorMessage",
				error.empty() ? "Could not update the server list." : error}},
				idx);
		} else
			fprintf(stderr, "ivpnd: server list: %s\n", error.c_str());
	} else if (kind == "ping") {
		const json& pings = result["pings"];
		if (pings.is_object()) {
			for (auto it = pings.begin(); it != pings.end(); ++it)
				fPings[it.key()] = it.value().get<int>();
		}
		if (!error.empty() && (!pings.is_object() || pings.empty()))
			_Send(client, {{"Command", "ErrorResp"}, {"ErrorMessage", error}},
				idx);
		else {
			Pings answered;
			if (pings.is_object()) {
				for (auto it = pings.begin(); it != pings.end(); ++it)
					answered[it.key()] = it.value().get<int>();
			}
			_Send(client, PingServersResp(answered), idx);
		}
	} else if (kind == "login") {
		Session session = fSession;
		json resp;
		if (result.contains("body")) {
			if (HandleSessionNew(result["body"], Str(result, "accountId"),
					session, resp)) {
				session.wgPrivateKey = Str(result, "priv");
				session.wgPublicKey = Str(result, "pub");
				session.wgKeyGenerated = time(NULL);
				fSession = session;
				_SaveSession();
				resp["Session"] = SessionResp(fSession);
				_Send(client, resp, idx);
				_Broadcast(_HelloResp());
				return;
			}
			if (Str(resp, "Command") == "ErrorResp" && !error.empty())
				resp["ErrorMessage"] = error;
		} else
			resp = {{"Command", "ErrorResp"}, {"ErrorMessage", error}};
		_Send(client, resp, idx);
	} else if (kind == "status") {
		const json& body = result["body"];
		if (Str(result, "token") != fSession.token)
			return;	// logged out or in again meanwhile
		if (!body.is_object()) {
			_Send(client, {{"Command", "ErrorResp"}, {"ErrorMessage", error}},
				idx);
			return;
		}
		int status = ApiStatus(body);
		if (status == 200) {
			fSession.account = AccountFromServiceStatus(
				body.value("service_status", json::object()));
			if (body.contains("device_name") && body["device_name"].is_string())
				fSession.deviceName = body["device_name"].get<std::string>();
			_SaveSession();
		}
		_Send(client, {{"Command", "SessionStatusResp"},
			{"APIStatus", status}, {"APIErrorMessage", ApiMessage(body)},
			{"SessionToken", fSession.token},
			{"Account", fSession.account}, {"DeviceName", fSession.deviceName}},
			idx);
		if (status == 401 || status == 601) {
			// The session was deleted elsewhere (e.g. "log out all devices")
			if (fPhase != kIdle)
				_Disconnect();
			_ForgetSession();
			_Broadcast(_HelloResp());
		}
	} else if (kind == "wgkey") {
		// Connect step 1 for WireGuard: a registered key.
		if (fPhase != kPreparing)
			return;
		const json& body = result["body"];
		int status = body.is_object() ? ApiStatus(body) : 0;
		std::string ip = body.is_object() ? Str(body, "ip_address") : "";
		if (status == 200 && !ip.empty() && Str(result, "token")
				== fSession.token) {
			fSession.wgPrivateKey = Str(result, "priv");
			fSession.wgPublicKey = Str(result, "pub");
			fSession.wgLocalIp = ip;
			fSession.wgKeyGenerated = time(NULL);
			_SaveSession();
		} else if (status == 401 || status == 601) {
			fPhase = kIdle;
			_ForgetSession();
			_Broadcast(DisconnectedResp(true,
				"Your session has ended. Please log in again."));
			_Broadcast(_HelloResp());
			return;
		}

		if (fUserStop) {
			fPhase = kIdle;
			fUserStop = false;
			_Broadcast(DisconnectedResp(false, ""));
			return;
		}
		if (!fPending.is_null()) {
			json params = fPending;
			fPending = json();
			fPhase = kIdle;
			_Connect(params);
			return;
		}
		if (fSession.wgLocalIp.empty() || fSession.wgPrivateKey.empty()) {
			// Rotation may fail and leave the old key usable; a first
			// registration may not.
			fPhase = kIdle;
			std::string why = body.is_object() ? ApiMessage(body) : error;
			_Broadcast(DisconnectedResp(true,
				"Could not register the WireGuard key"
				+ (why.empty() ? std::string(".") : ": " + why)));
			return;
		}
		_PrepareTunnel();
	} else if (kind == "proxy") {
		// Connect step 2 with obfuscation: the helper is running
		if (fPhase != kPreparing)
			return;
		int port = (int)Int(result, "port");
		if (fUserStop || !fPending.is_null()) {
			_TunnelDown(false, "");
			return;
		}
		if (port <= 0) {
			_TunnelDown(true, error.empty()
				? "Could not start the obfuscation proxy." : error);
			return;
		}
		_StartTunnel(port);
	}
}


// #pragma mark - session


void
Daemon::_LoadState()
{
	json account = json::parse(ReadFile(_DataPath("account.json")), nullptr,
		false);
	if (account.is_object())
		fSession = Session::FromJson(account);
	json servers = json::parse(ReadFile(_DataPath("servers.json")), nullptr,
		false);
	if (servers.is_object() && servers.contains("wireguard"))
		fServers = servers;
}


void
Daemon::_SaveSession() const
{
	if (!WritePrivateFile(_DataPath("account.json"),
			fSession.ToJson().dump(1, '\t')))
		fprintf(stderr, "ivpnd: could not save the session\n");
}


void
Daemon::_ForgetSession()
{
	fSession = Session();
	unlink(_DataPath("account.json").c_str());
}


// #pragma mark - connection


void
Daemon::_Connect(const json& params)
{
	if (fPhase != kIdle) {
		// Like ivpn-service: the newest request wins, after a disconnect.
		fPending = params;
		fUserStop = false;
		if (fPhase == kTunnel && fActive != NULL)
			fActive->Disconnect();
		return;
	}

	if (!fSession.LoggedIn()) {
		_Broadcast(DisconnectedResp(true, "Please log in first."));
		return;
	}

	ConnectPlan plan;
	std::string error;
	json config = fServers.is_object() && fServers.contains("config")
		? fServers["config"] : json::object();
	if (!PlanConnect(params, fPings, config, plan, error)) {
		_Broadcast(DisconnectedResp(true, error));
		return;
	}

	fPlan = plan;
	fConnected = false;
	fUserStop = false;
	fFailureSent = false;
	_Broadcast(VpnStateResp(1));

	// "Firewall on connect": on now, off again after a disconnect
	if (Bool(params, "FirewallOn") && !fKillSwitch.IsEnabled()) {
		fFirewallByConnect = true;
		_SetKillSwitch(true);
	}

	bool needKey = fSession.wgPrivateKey.empty() || fSession.wgLocalIp.empty()
		|| time(NULL) - fSession.wgKeyGenerated > kWgKeyRotationSeconds;
	if (plan.vpnType == 1 && needKey) {
		fPhase = kPreparing;
		std::string token = fSession.token;
		std::string oldPub = fSession.wgPublicKey;
		_RunWorker("wgkey", 0, 0, [token, oldPub]() {
			std::string priv, pub, error;
			if (!NewWireGuardKeys(priv, pub))
				return json{{"error", "Could not create WireGuard keys."}};
			json body = api::WireGuardKeySet(token, pub, oldPub, error);
			return json{{"body", body}, {"error", error}, {"token", token},
				{"priv", priv}, {"pub", pub}};
		});
		return;
	}
	_PrepareTunnel();
}


// Pins what the tunnel talks to outside of it, and starts the obfuscation
// proxy when there is one (on a worker: it takes a few seconds).
void
Daemon::_PrepareTunnel()
{
	// The proxy's server always needs the carrier (the tunnel's default
	// route would swallow it); the VPN server itself needs it before the
	// backend pins it only while the kill switch holds the default route.
	std::string outside = fPlan.ProxyServer();
	if (outside.empty() && fKillSwitch.IsEnabled())
		outside = fPlan.hostIp;
	std::string via;
	if (!outside.empty() && PinToCarrier(outside, via))
		fConnPins.push_back(std::make_pair(outside, via));

	if (fPlan.ProxyServer().empty()) {
		_StartTunnel(0);
		return;
	}

	fPhase = kPreparing;
	std::shared_ptr<ProxyProcess> proxy = std::make_shared<ProxyProcess>();
	fProxy = proxy;
	BMessenger self(this);
	std::function<void()> onExit = [self]() {
		BMessage msg(kMsgProxyExited);
		self.SendMessage(&msg);
	};
	if (fPlan.UsesV2Ray()) {
		int localPort = FreeUdpPort();
		std::string config = _DataPath("v2ray.json");
		if (localPort <= 0 || !WritePrivateFile(config,
				V2RayConfig(fPlan, localPort).dump(1, '\t'))) {
			_TunnelDown(true, "Could not prepare V2Ray.");
			return;
		}
		_RunWorker("proxy", 0, 0, [proxy, config, localPort, onExit]() {
			std::string error;
			bool ok = proxy->StartV2Ray(config, onExit, error);
			return json{{"port", ok ? localPort : 0}, {"error", error}};
		});
	} else {
		int version = fPlan.obfsVersion;
		std::string stateDir = _DataPath("obfs4proxy");
		create_directory(stateDir.c_str(), 0700);
		_RunWorker("proxy", 0, 0, [proxy, version, stateDir, onExit]() {
			std::string error;
			int port = proxy->StartObfsproxy(version, stateDir, onExit, error);
			return json{{"port", port}, {"error", error}};
		});
	}
}


void
Daemon::_StartTunnel(int localPort)
{
	VPNProfile profile;
	profile.fName = "IVPN";
	if (fPlan.UsesV2Ray()) {
		profile.fServer = "127.0.0.1";
		profile.fPort = (uint16)localPort;
		profile.fProtocol = "udp";
	} else if (fPlan.UsesObfsproxy()) {
		profile.fServer = fPlan.hostIp.c_str();
		profile.fPort = (uint16)fPlan.obfsPort;
		profile.fProtocol = "tcp";
	} else {
		profile.fServer = fPlan.hostIp.c_str();
		profile.fPort = (uint16)fPlan.port;
		profile.fProtocol = fPlan.tcp ? "tcp" : "udp";
	}

	std::string path;
	std::string content;
	if (fPlan.vpnType == 1) {
		profile.fBackendType = VPN_BACKEND_WIREGUARD;
		path = _DataPath("wg.conf");
		content = WireGuardConf(fPlan, fSession,
			fPlan.UsesV2Ray() ? localPort : 0);
		fActive = fWireGuard;
	} else {
		profile.fBackendType = VPN_BACKEND_OPENVPN;
		path = _DataPath("ivpn.ovpn");
		BPath data;
		find_directory(B_SYSTEM_DATA_DIRECTORY, &data);
		data.Append("ivpn");
		std::string dir = getenv("IVPND_DATA") != NULL
			? getenv("IVPND_DATA") : data.Path();
		std::string ca = ReadFile(dir + "/ca.crt");
		std::string ta = ReadFile(dir + "/ta.key");
		if (ca.empty() || ta.empty()) {
			_TunnelDown(true, "IVPN's OpenVPN certificate is missing ("
				+ dir + "/ca.crt). Reinstall the app.");
			return;
		}
		std::string authFile;
		std::string auth = Obfs4AuthFile(fPlan);
		if (!auth.empty()) {
			authFile = _DataPath("obfs4.auth");
			if (!WritePrivateFile(authFile, auth)) {
				_TunnelDown(true, "Could not write " + authFile);
				return;
			}
		}
		content = OpenVpnConf(fPlan, ca, ta, localPort, authFile);
		fActive = fOpenVpn;
		fOpenVpn->SetCredentials(fSession.vpnUsername.c_str(),
			fSession.vpnPassword.c_str());
	}
	if (!WritePrivateFile(path, content)) {
		fActive = NULL;
		_TunnelDown(true, "Could not write " + path);
		return;
	}
	profile.fConfigPath = path.c_str();

	fPhase = kTunnel;
	printf("ivpnd: connecting to %s (%s) port %d/%s%s\n",
		fPlan.hostname.c_str(), fPlan.hostIp.c_str(), fPlan.port,
		fPlan.tcp ? "tcp" : "udp", fPlan.UsesV2Ray() ? " over V2Ray"
			: fPlan.UsesObfsproxy() ? " over obfsproxy" : "");
	status_t status = fActive->Connect(profile);
	if (fPlan.vpnType == 1)
		unlink(path.c_str());	// read at Connect(); it holds the private key
	if (status != B_OK) {
		// The backend already cleaned up. Drop a queued reconnect: its
		// late state message could be taken for the new session's.
		fPending = json();
		fFailureSent = true;
		VPNBackend* backend = fActive;
		_TunnelDown(true, "");
		_Broadcast(DisconnectedResp(true, std::string("Could not start the "
			"tunnel (") + backend->BackendName() + ")."));
	}
}


void
Daemon::_Disconnect()
{
	fPending = json();
	fUserStop = true;
	if (fPhase == kTunnel && fActive != NULL)
		fActive->Disconnect();
	// kPreparing: the "wgkey" result sees fUserStop and stops there
}


void
Daemon::_BackendState(BMessage* message)
{
	const char* backend = message->GetString(kFieldBackend, "");
	if (fPhase != kTunnel || fActive == NULL
		|| strcmp(backend, fActive->BackendName()) != 0)
		return;

	VPNState state = (VPNState)message->GetInt32(kFieldState,
		VPN_STATE_DISCONNECTED);
	std::string detail = message->GetString(kFieldDetail, "");
	printf("ivpnd: %s %s %s\n", backend, vpn_state_name(state),
		detail.c_str());

	switch (state) {
		case VPN_STATE_CONNECTING:
			_Broadcast(VpnStateResp(fConnected ? 8 : 1));
			break;
		case VPN_STATE_AUTHENTICATING:
			_Broadcast(VpnStateResp(3));
			break;
		case VPN_STATE_RECONNECTING:
			_Broadcast(VpnStateResp(8));
			break;

		case VPN_STATE_CONNECTED:
		{
			if (!fConnected) {
				fConnected = true;
				fConnectedSince = time(NULL);
				dns::Apply(fPlan.dns);
				delete fDnsCheck;
				BMessage check(kMsgDnsCheck);
				fDnsCheck = new BMessageRunner(BMessenger(this), &check,
					kDnsCheckInterval);
				unlink(_DataPath("ivpn.ovpn").c_str());
			}
			std::string localIp = message->GetString(kFieldLocalIP,
				fActive->LocalIP().String());
			_Broadcast(ConnectedResp(fPlan, localIp, fConnectedSince));
			break;
		}

		case VPN_STATE_ERROR:
			if (!fFailureSent && !fUserStop && fPending.is_null()) {
				fFailureSent = true;
				_Broadcast(DisconnectedResp(true, detail.empty()
					? "The connection failed." : detail));
			}
			// fall through
		case VPN_STATE_DISCONNECTED:
		{
			bool idle = fActive == fOpenVpn ? fOpenVpn->IsIdle()
				: fWireGuard->IsIdle();
			if (!idle) {
				// openvpn is still exiting (after an auth failure it may not
				// even have been told to); its reader reports once it's gone
				if (state == VPN_STATE_ERROR)
					fActive->Disconnect();
				break;
			}
			bool failure = !fUserStop && !fConnected;
			_TunnelDown(failure, failure ? "The connection failed." : "");
			break;
		}
	}
}


void
Daemon::_TunnelDown(bool failure, const std::string& reason)
{
	fPhase = kIdle;
	fActive = NULL;
	fConnected = false;
	delete fDnsCheck;
	fDnsCheck = NULL;
	dns::Restore();
	_RemoveConfigFiles();
	if (fProxy) {
		fProxy->Stop();
		fProxy.reset();
	}
	for (const auto& pin : fConnPins)
		UnpinFromCarrier(pin.first, pin.second);
	fConnPins.clear();

	if (fUserStop && fPending.is_null() && fFirewallByConnect) {
		fFirewallByConnect = false;
		_SetKillSwitch(false);
	}
	// The carrier's gateway is known again: pin the API
	fKillSwitch.Check();

	if (!fPending.is_null()) {
		json params = fPending;
		fPending = json();
		_Broadcast(DisconnectedResp(false, ""));
		_Connect(params);
		return;
	}

	if (!fFailureSent)
		_Broadcast(DisconnectedResp(failure && !fUserStop, reason));
	fUserStop = false;
	fFailureSent = false;
}


void
Daemon::_RemoveConfigFiles()
{
	unlink(_DataPath("wg.conf").c_str());
	unlink(_DataPath("ivpn.ovpn").c_str());
	unlink(_DataPath("v2ray.json").c_str());
	unlink(_DataPath("obfs4.auth").c_str());
}


std::string
Daemon::_DataPath(const char* leaf) const
{
	BPath path;
	find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	path.Append("IVPN/daemon");
	create_directory(path.Path(), 0700);
	path.Append(leaf);
	return path.Path();
}

}	// namespace ivpnd


int
main()
{
	// One line at a time, so a log file shows what happened before a crash
	setvbuf(stdout, NULL, _IOLBF, 0);
	ivpnd::Daemon daemon;
	daemon.Run();
	return 0;
}
