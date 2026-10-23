/*
 * IVPN for Vitruvian - data model: servers, pings, user settings and
 * building "Connect" requests for the daemon.
 *
 * No Be/Haiku API dependency (unit-testable on plain Linux).
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_MODEL_H
#define IVPN_MODEL_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "Json.h"

namespace ivpn {

// Values match the daemon's vpn.Type
enum class VpnType : int {
	OpenVPN = 0,
	WireGuard = 1,
};

// Values match the daemon's ServerSelectionEnum
enum class ServerSelection : int {
	Manual = 0,
	Fastest = 1,
	Random = 2,
};

// Values match the daemon's vpn.State
enum VpnStateValue {
	kStateDisconnected = 0,
	kStateConnecting,
	kStateWait,
	kStateAuth,
	kStateGetConfig,
	kStateAssignIP,
	kStateAddRoutes,
	kStateConnected,
	kStateReconnecting,
	kStateTcpConnect,
	kStateExiting,
	kStateInitialised,
	kStateTunnelHealth,
};

// IVPN API status codes we react to
enum {
	kApiSuccess = 200,
	kApiSessionLimit = 602,
	kApiCaptchaRequired = 70001,
	kApiCaptchaInvalid = 70002,
	kApi2faRequired = 70011,
	kApi2faInvalid = 70012,
};

struct Port {
	int		port = 2049;
	bool	tcp = false;

	std::string	Label() const;
	bool operator==(const Port& o) const
		{ return port == o.port && tcp == o.tcp; }
};

struct Server {
	std::string		gateway;		// e.g. "nl.wg.ivpn.net"
	std::string		countryCode;	// "NL"
	std::string		country;		// "Netherlands"
	std::string		city;			// "Amsterdam"
	std::string		isp;
	nlohmann::json	hosts;			// passed back to the daemon unchanged

	// "nl" from "nl.wg.ivpn.net" - same for WireGuard and OpenVPN, so a
	// chosen location survives switching protocols.
	std::string		GatewayId() const;
	std::string		DisplayName() const;	// "Amsterdam, Netherlands"
	bool			HasHost(const std::string& hostIp) const;
	std::string		HostnameFor(const std::string& hostIp) const;
};

struct ServerLists {
	std::vector<Server>	wireguard;
	std::vector<Server>	openvpn;
	std::vector<Port>	wireguardPorts;
	std::vector<Port>	openvpnPorts;

	const std::vector<Server>&	For(VpnType type) const
		{ return type == VpnType::WireGuard ? wireguard : openvpn; }
	const std::vector<Port>&	PortsFor(VpnType type) const
		{ return type == VpnType::WireGuard ? wireguardPorts : openvpnPorts; }
	const Server*		FindByGatewayId(VpnType type,
							const std::string& id) const;
	const Server*		FindByHost(const std::string& hostIp) const;
	bool				Empty() const
		{ return wireguard.empty() && openvpn.empty(); }
};

// Parse "VpnServers" object of the daemon's ServerListResp.
ServerLists			ParseServerList(const nlohmann::json& vpnServers);

// host IP -> latency in ms
typedef std::map<std::string, int> PingMap;

void				UpdatePings(PingMap& pings,
						const nlohmann::json& pingResults);
// Best latency of a server's hosts, or -1 when unknown.
int					ServerPing(const Server& server, const PingMap& pings);
const Server*		FindFastest(const std::vector<Server>& servers,
						const PingMap& pings);

struct Settings {
	VpnType			vpnType = VpnType::WireGuard;
	ServerSelection	selection = ServerSelection::Fastest;
	std::string		gatewayId;			// used when selection == Manual
	Port			wireguardPort;		// UDP 2049
	Port			openvpnPort;		// UDP 2049
	bool			firewallOnConnect = false;
	bool			antiTracker = false;
	bool			antiTrackerHardcore = false;
	bool			notifications = true;

	Port&			PortFor(VpnType t)
		{ return t == VpnType::WireGuard ? wireguardPort : openvpnPort; }
	const Port&		PortFor(VpnType t) const
		{ return t == VpnType::WireGuard ? wireguardPort : openvpnPort; }

	nlohmann::json	ToJson() const;
	static Settings	FromJson(const nlohmann::json& j);
	bool			Load(const std::string& path);
	bool			Save(const std::string& path) const;
};

// Build the "Params" object of the daemon's "Connect" request.
// 'randomSeed' picks the server when selection == Random.
// On failure returns null json and fills 'error'.
// 'chosen' receives the server that will be used.
nlohmann::json		BuildConnectParams(const Settings& settings,
						const ServerLists& servers, const PingMap& pings,
						unsigned randomSeed, const Server** chosen,
						std::string& error);

std::string			StateDescription(int stateVal);

}	// namespace ivpn

#endif	// IVPN_MODEL_H
