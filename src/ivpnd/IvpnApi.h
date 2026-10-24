/*
 * ivpnd - IVPN's REST API (api.ivpn.net) over libcurl, with the same
 * certificate pinning as ivpn-service. Every call blocks: run them off the
 * main looper.
 *
 * No Be/Haiku API dependency.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPND_IVPN_API_H
#define IVPND_IVPN_API_H

#include <string>

#include "../core/Json.h"

namespace ivpnd {
namespace api {

// Each returns the parsed JSON body, or null json when the server could not
// be reached or did not answer with JSON ('error' says why).
nlohmann::json	Servers(std::string& error);
nlohmann::json	SessionNew(const std::string& accountId, bool force,
					const std::string& wgPublicKey,
					const std::string& confirmation2FA, std::string& error);
nlohmann::json	SessionStatus(const std::string& token, std::string& error);
nlohmann::json	SessionDelete(const std::string& token, std::string& error);
nlohmann::json	WireGuardKeySet(const std::string& token,
					const std::string& newPublicKey,
					const std::string& connectedPublicKey,
					std::string& error);

}	// namespace api
}	// namespace ivpnd

#endif	// IVPND_IVPN_API_H
