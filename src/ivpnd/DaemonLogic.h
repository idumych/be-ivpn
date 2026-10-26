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
#include <vector>

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

	// Obfuscation, as ivpn-service does it. V2Ray (VMess over QUIC or TCP)
	// runs a local proxy the tunnel connects to; obfs3/obfs4 (OpenVPN only)
	// run obfs4proxy as a SOCKS proxy for openvpn.
	int			v2ray = 0;			// 0 = off, 1 = QUIC, 2 = TCP
	std::string	v2rayServer;		// the host's V2Ray (VMess) server
	int			v2rayPort = 0;		// its port: the chosen port
	std::string	v2rayTlsName;		// QUIC: TLS server name
	std::string	v2rayUserId;		// VMess user ID (servers.json)
	int			v2rayInboundPort = 0;	// the VPN port behind V2Ray (UDP)
	int			obfsVersion = 0;	// 0 = off, 3 or 4
	int			obfsIat = 0;		// obfs4 IAT mode, 0..2
	int			obfsPort = 0;		// the server's obfs3/obfs4 port (TCP)
	std::string	obfs4Key;			// the host's obfs4 certificate

	bool		UsesV2Ray() const { return v2ray != 0; }
	bool		UsesObfsproxy() const { return v2ray == 0 && obfsVersion != 0; }
	// The address the obfuscation proxy connects to outside the tunnel
	// (empty without obfuscation).
	std::string	ProxyServer() const
		{ return UsesV2Ray() ? v2rayServer : UsesObfsproxy() ? hostIp : ""; }
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
// DNS line: ivpnd sets the resolver itself for both protocols. With V2Ray,
// 'localPort' is the local proxy the endpoint becomes (127.0.0.1).
std::string		WireGuardConf(const ConnectPlan& plan, const Session& session,
					int localPort = 0);

// OpenVPN client configuration, CA and TLS-auth key inline. Management,
// tun device and routing options are added by the OpenVPN backend. With
// V2Ray, 'localPort' is the local proxy; with obfs3/obfs4 it is
// obfs4proxy's SOCKS port and 'socksAuthFile' holds the obfs4 certificate.
std::string		OpenVpnConf(const ConnectPlan& plan, const std::string& ca,
					const std::string& tlsAuth, int localPort = 0,
					const std::string& socksAuthFile = std::string());

// V2Ray client configuration (as ivpn-service writes it): a local
// dokodemo-door on 127.0.0.1:'localPort' (UDP) forwarded over VMess.
nlohmann::json	V2RayConfig(const ConnectPlan& plan, int localPort,
					const std::string& logLevel = "warning");

// obfs4proxy's SOCKS credentials for obfs4 ("cert=...;\niat-mode=N"); empty
// for obfs3.
std::string		Obfs4AuthFile(const ConnectPlan& plan);

// The SOCKS port from obfs4proxy's managed-transport output line
// ("CMETHOD obfs4 socks5 127.0.0.1:41234"), or 0.
int				ObfsproxySocksPort(const std::string& line, int version);

// Default routes in the output of Haiku's `route` command.
struct DefaultRoute {
	bool		v6 = false;
	std::string	gateway;
	std::string	iface;
	bool operator==(const DefaultRoute& o) const
		{ return v6 == o.v6 && gateway == o.gateway && iface == o.iface; }
};
std::vector<DefaultRoute> ParseDefaultRoutes(const std::string& routeOutput);

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
