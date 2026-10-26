/*
 * ivpnd - the obfuscation proxies: V2Ray and obfs4proxy, the same helper
 * programs ivpn-service runs, built for Haiku and shipped with the app.
 *
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPND_PROXY_H
#define IVPND_PROXY_H

#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <sys/types.h>

namespace ivpnd {

// Where the helpers are installed (IVPND_HELPERS overrides it).
std::string	HelperPath(const char* name);

// A free local UDP port for the V2Ray proxy, or 0.
int			FreeUdpPort();

class ProxyProcess {
public:
						ProxyProcess();
						~ProxyProcess();

			// Runs `v2ray run -config <config>` and waits until it has
			// started. 'onExit' runs (on another thread) if it stops by
			// itself later.
			bool		StartV2Ray(const std::string& config,
							std::function<void()> onExit, std::string& error);

			// Runs obfs4proxy as a managed pluggable transport client for
			// obfs<version> and returns its SOCKS port (0 on failure).
			int			StartObfsproxy(int version,
							const std::string& stateDir,
							std::function<void()> onExit, std::string& error);

			void		Stop();
			bool		IsRunning() const;

private:
			bool		_Spawn(const char* const argv[], const char* name,
							const char* const env[], std::string& error);
			void		_ReadOutput(int fd, std::string name);

	mutable	std::mutex	fLock;
			std::condition_variable fChanged;
			pid_t		fPid;
			bool		fReady;
			bool		fExited;
			bool		fStopping;
			int			fObfsVersion;
			int			fSocksPort;
			std::function<void()> fOnExit;
};

}	// namespace ivpnd

#endif	// IVPND_PROXY_H
