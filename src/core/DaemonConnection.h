/*
 * IVPN for Vitruvian - connection to the IVPN daemon (ivpn-service).
 *
 * The daemon listens on 127.0.0.1 on a random port. The port and a 64-bit
 * secret are written to "port.txt" as "<port>:<secret-in-hex>".
 * Messages are single-line JSON objects terminated by '\n'.
 * The first request on a new connection must be "Hello" carrying the secret.
 *
 * This class has no dependency on the Be/Haiku API so it can be unit-tested
 * on any Linux system.
 *
 * Distributed under the terms of the GNU GPL v3 (same as IVPN desktop-app).
 */
#ifndef IVPN_DAEMON_CONNECTION_H
#define IVPN_DAEMON_CONNECTION_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "Json.h"

namespace ivpn {

struct PortInfo {
	int			port = 0;
	uint64_t	secret = 0;
	std::string	path;
};

class DaemonConnection {
public:
	using LineCallback = std::function<void(const std::string& line)>;
	using ClosedCallback = std::function<void(const std::string& reason)>;

							DaemonConnection();
							~DaemonConnection();

	// Locations where the daemon may have written its port file.
	static std::vector<std::string> PortFileCandidates();

	// Read port + secret. On failure returns false and fills 'error'.
	static bool				ReadPortFile(PortInfo& info, std::string& error,
								const std::vector<std::string>& candidates
									= PortFileCandidates());

	// Parse "<port>:<hexsecret>" (exposed for tests).
	static bool				ParsePortFileContent(const std::string& content,
								int& port, uint64_t& secret);

	// Connect to 127.0.0.1:port and start the reader thread. Callbacks are
	// invoked from the reader thread.
	bool					Connect(const PortInfo& info, LineCallback onLine,
								ClosedCallback onClosed, std::string& error,
								int timeoutMs = 3000);

	bool					IsConnected() const { return fSocket >= 0; }
	// True once Close() started; lets callbacks stop waiting on a busy UI.
	bool					IsClosing() const { return fClosing; }

	// Builds and sends the "Hello" request. Returns request index or 0.
	// 'clientType' is the daemon's ClientTypeEnum: 0 = the main UI,
	// 3 = other (e.g. the Deskbar item).
	uint32_t				SendHello(const std::string& clientVersion,
								int clientType = 0);

	// Fills "Command"-independent fields (Idx, ProtocolSecret) and sends.
	// 'request' must already contain "Command". Returns request index,
	// 0 on failure.
	uint32_t				Send(nlohmann::json request);

	void					Close();

private:
	void					_ReaderLoop();

	int						fSocket;
	uint64_t				fSecret;
	std::atomic<uint32_t>	fNextIdx;
	std::mutex				fSendLock;
	std::thread				fReader;
	std::atomic<bool>		fClosing;
	LineCallback			fOnLine;
	ClosedCallback			fOnClosed;
};

}	// namespace ivpn

#endif	// IVPN_DAEMON_CONNECTION_H
