/*
 * ivpnd - IVPN's REST API over libcurl.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "IvpnApi.h"

#include <curl/curl.h>

#include <mutex>

using nlohmann::json;

namespace ivpnd {
namespace api {

namespace {

const char* kApiBase = "https://api.ivpn.net/";

// SHA-256 of the API certificate's public key, as pinned by ivpn-service
// (daemon/api/api_cert_public_keys.go).
const char* kApiPins = "sha256//g6WEFnt9DyTi70nW/fufsZNw83vFpcmIhMuDPQ1MFcI=;"
	"sha256//KCcpK9y22OrlapwO1/oP8q3LrcDM9Jy9lcfngg2r+Pk=;"
	"sha256//iRHkSbdOY/YD8EE5fpl8W0P8EqmfkBRTADEegR2/Wnc=;"
	"sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";


size_t
Collect(char* data, size_t size, size_t count, void* user)
{
	std::string* body = static_cast<std::string*>(user);
	if (body->size() > 16 * 1024 * 1024)
		return 0;	// no API answer is anywhere near this big
	body->append(data, size * count);
	return size * count;
}


json
Request(const char* method, const std::string& path, const json* payload,
	std::string& error)
{
	static std::once_flag init;
	std::call_once(init, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });

	CURL* curl = curl_easy_init();
	if (curl == nullptr) {
		error = "Could not start an HTTPS request.";
		return json();
	}

	std::string url = std::string(kApiBase) + path;
	std::string body;
	std::string sent;
	struct curl_slist* headers = nullptr;

	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, kApiPins);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "ivpnd (Haiku)");
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Collect);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
	if (payload != nullptr) {
		sent = payload->dump();
		headers = curl_slist_append(headers,
			"Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, sent.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)sent.size());
	}
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);

	CURLcode code = curl_easy_perform(curl);
	long httpStatus = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpStatus);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	if (code != CURLE_OK) {
		error = code == CURLE_SSL_PINNEDPUBKEYNOTMATCH
			? "The IVPN server's certificate is not the expected one."
			: std::string("Could not reach the IVPN server: ")
				+ curl_easy_strerror(code);
		return json();
	}

	json parsed = json::parse(body, nullptr, false);
	if (parsed.is_discarded() || !parsed.is_object()) {
		error = "The IVPN server sent an unexpected answer (HTTP "
			+ std::to_string(httpStatus) + ").";
		return json();
	}
	// servers.json has no "status"; API calls report errors in the body
	if (!parsed.contains("status") && path.rfind("v4/", 0) == 0)
		parsed["status"] = (int)httpStatus;
	return parsed;
}

}	// namespace


json
Servers(std::string& error)
{
	return Request("GET", "v5/servers.json", nullptr, error);
}


json
SessionNew(const std::string& accountId, bool force,
	const std::string& wgPublicKey, const std::string& confirmation2FA,
	std::string& error)
{
	json payload = {
		{"username", accountId},
		{"force", force},
		{"wg_public_key", wgPublicKey},
	};
	if (!confirmation2FA.empty())
		payload["confirmation"] = confirmation2FA;
	return Request("POST", "v4/session/new", &payload, error);
}


json
SessionStatus(const std::string& token, std::string& error)
{
	json payload = {{"session_token", token}};
	return Request("POST", "v4/session/status", &payload, error);
}


json
SessionDelete(const std::string& token, std::string& error)
{
	json payload = {{"session_token", token}};
	return Request("POST", "v4/session/delete", &payload, error);
}


json
WireGuardKeySet(const std::string& token, const std::string& newPublicKey,
	const std::string& connectedPublicKey, std::string& error)
{
	json payload = {
		{"session_token", token},
		{"public_key", newPublicKey},
		{"connected_public_key", connectedPublicKey},
	};
	return Request("POST", "v4/session/wg/set", &payload, error);
}

}	// namespace api
}	// namespace ivpnd
