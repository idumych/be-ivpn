/*
 * ivpnd - the IVPN service for Haiku: the parts that need no Haiku API.
 *
 * ivpnd stands in for the official ivpn-service, which does not run on
 * Haiku. It speaks the same JSON protocol (the subset this app uses), so the
 * window and the Deskbar item work unchanged. This file turns IVPN's REST
 * API answers into protocol responses, and a "Connect" request into a
 * WireGuard or OpenVPN configuration.
 *
 * No Be/Haiku API dependency (unit-testable on plain Linux).
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPND_DAEMON_LOGIC_H
#define IVPND_DAEMON_LOGIC_H

#include <cstdint>
#include <map>
#include <string>

#include "../core/Json.h"

namespace ivpnd {

// What we keep after a login (account.json, readable only by its owner).
struct Session {
	std::string	accountId;
	std::string	token;			// session_token for the API
	std::string	deviceName;
	std::string	vpnUsername;	// OpenVPN credentials
	std::string	vpnPassword;
	std::string	wgPrivateKey;	// base64
	std::string	wgPublicKey;	// base64
	std::string	wgLocalIp;		// our address inside the WireGuard tunnel
	int64_t		wgKeyGenerated = 0;	// Unix time
	nlohmann::json account;		// protocol "Account" (AccountStatus)

	bool			LoggedIn() const { return !token.empty(); }
	nlohmann::json	ToJson() const;
	static Session	FromJson(const nlohmann::json& j);
};

// IVPN rotates WireGuard keys weekly by default.
const int64_t kWgKeyRotationSeconds = 7 * 24 * 3600;

bool			ValidAccountId(const std::string& id);

// Protocol "Account" from the API's "service_status".
nlohmann::json	AccountFromServiceStatus(const nlohmann::json& serviceStatus);

// Protocol "Session" (SessionResp) for HelloResp / SessionNewResp.
nlohmann::json	SessionResp(const Session& session);

// Handles the API's answer to POST /v4/session/new. 'httpBody' is the parsed
// body (null when the request failed). On success fills 'session' (keeping
// the WireGuard keys already in it) and returns true. Always fills 'resp'
// with the protocol's SessionNewResp, ready to send.
bool			HandleSessionNew(const nlohmann::json& httpBody,
					const std::string& accountId, Session& session,
					nlohmann::json& resp);

// API error code and message from any API answer.
int				ApiStatus(const nlohmann::json& body);
std::string		ApiMessage(const nlohmann::json& body);

// Everything needed to bring up one tunnel.
struct ConnectPlan {
	int			vpnType = 1;		// 0 = OpenVPN, 1 = WireGuard
	std::string	hostIp;
	std::string	hostname;
	std::string	publicKey;			// WireGuard server key
	std::string	hostLocalIp;		// WireGuard gateway, without "/12"
	int			port = 2049;
	bool		tcp = false;
	bool		antiTracker = false;
	bool		hardcore = false;
	std::string	dns;				// resolver to use while connected
};

// host IP -> latency in ms
typedef std::map<std::string, int> Pings;

// Reads the "Params" of a Connect request. Uses the host with the best
// known latency (else the first). 'serversConfig' is the "config" object of
// servers.json (for the AntiTracker resolvers).
bool			PlanConnect(const nlohmann::json& params, const Pings& pings,
					const nlohmann::json& serversConfig, ConnectPlan& plan,
					std::string& error);

// wg-quick style configuration for the Sotoportego WireGuard backend. No
// DNS line: ivpnd sets the resolver itself for both protocols.
std::string		WireGuardConf(const ConnectPlan& plan, const Session& session);

// OpenVPN client configuration, CA and TLS-auth key inline. Management,
// tun device and routing options are added by the OpenVPN backend.
std::string		OpenVpnConf(const ConnectPlan& plan, const std::string& ca,
					const std::string& tlsAuth);

// Protocol responses for the VPN state.
nlohmann::json	ConnectedResp(const ConnectPlan& plan,
					const std::string& clientIp, int64_t since);
nlohmann::json	DisconnectedResp(bool failure, const std::string& reason,
					bool stateInfo = false);
nlohmann::json	VpnStateResp(int stateVal);

// Protocol PingServersResp from a ping map.
nlohmann::json	PingServersResp(const Pings& pings);

// Every host IP of one protocol in servers.json ("wireguard" or "openvpn";
// empty 'which' = both).
std::map<std::string, bool> HostsOf(const nlohmann::json& servers,
					const std::string& which);

}	// namespace ivpnd

#endif	// IVPND_DAEMON_LOGIC_H
