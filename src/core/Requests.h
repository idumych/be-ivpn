/*
 * IVPN for Vitruvian - every request the app sends to the daemon.
 * Field names mirror daemon/protocol/types/requests.go; tests/gocheck
 * verifies them against the real Go types.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_REQUESTS_H
#define IVPN_REQUESTS_H

#include <string>

#include "Json.h"

namespace ivpn {
namespace req {

inline nlohmann::json
Connect(const nlohmann::json& params)
{
	return {{"Command", "Connect"}, {"Params", params}};
}


inline nlohmann::json
Disconnect()
{
	return {{"Command", "Disconnect"}};
}


inline nlohmann::json
GetVPNState()
{
	return {{"Command", "GetVPNState"}};
}


inline nlohmann::json
Login(const std::string& accountId, bool force,
	const std::string& confirmation2FA = std::string())
{
	return {
		{"Command", "SessionNew"},
		{"AccountID", accountId},
		{"ForceLogin", force},
		{"CaptchaID", ""},
		{"Captcha", ""},
		{"Confirmation2FA", confirmation2FA},
	};
}


inline nlohmann::json
Logout()
{
	return {
		{"Command", "SessionDelete"},
		{"NeedToResetSettings", false},
		{"NeedToDisableFirewall", true},
		{"IsCanDeleteSessionLocally", true},
	};
}


inline nlohmann::json
SessionStatus()
{
	return {{"Command", "SessionStatus"}};
}


inline nlohmann::json
SetFirewall(bool enabled)
{
	return {{"Command", "KillSwitchSetEnabled"}, {"IsEnabled", enabled}};
}


inline nlohmann::json
GetFirewallStatus()
{
	return {{"Command", "KillSwitchGetStatus"}};
}


inline nlohmann::json
PingServers(int vpnType)
{
	return {
		{"Command", "PingServers"},
		{"TimeOutMs", 6000},
		{"VpnTypePrioritization", true},
		{"VpnTypePrioritized", vpnType},
	};
}


inline nlohmann::json
RefreshServers()
{
	return {{"Command", "GetServers"}, {"RequestServersUpdate", true}};
}

}	// namespace req
}	// namespace ivpn

#endif	// IVPN_REQUESTS_H
