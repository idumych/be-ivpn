/*
 * ivpnd - the IVPN service for Haiku.
 *
 * A background application that does what ivpn-service does on Linux, for
 * the requests this app sends: it listens on 127.0.0.1, writes
 * "<port>:<secret>" to ~/config/settings/IVPN/daemon/port.txt, and answers
 * newline-delimited JSON in the same format. Logins and server lists come
 * from IVPN's API; tunnels are run by Sotoportego's WireGuard and OpenVPN
 * backends (third_party/sotoportego).
 *
 * Threads: an accept thread and one reader per client post every request to
 * the looper; API calls and pings run on worker threads that post their
 * results back. All state lives on the looper.
 *
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPND_DAEMON_H
#define IVPND_DAEMON_H

#include <Application.h>
#include <String.h>

#include <functional>
#include <map>
#include <memory>
#include <string>

#include "../core/Json.h"
#include "../ui/Constants.h"
#include "DaemonLogic.h"

class BMessageRunner;
class VPNBackend;
class OpenVPNBackend;
class WireGuardBackend;

#define IVPND_SIGNATURE	"application/x-vnd.IVPN-Daemon"
#define IVPND_VERSION	IVPN_APP_VERSION

namespace ivpnd {

struct Client;

class Daemon : public BApplication {
public:
								Daemon();
	virtual						~Daemon();

	virtual	void				ReadyToRun();
	virtual	bool				QuitRequested();
	virtual	void				MessageReceived(BMessage* message);

private:
	// clients
			bool				_StartListening();
			void				_AcceptLoop();
			void				_AddClient(int fd);
			void				_RemoveClient(int32 id);
			void				_HandleLine(int32 id, const char* line);
			void				_Send(int32 id, nlohmann::json response,
									uint32 idx);
			void				_Broadcast(const nlohmann::json& response);

	// requests
			void				_HandleRequest(Client& client,
									const nlohmann::json& request);
			nlohmann::json		_HelloResp() const;
			void				_SendState(int32 id, uint32 idx);

	// workers
			void				_RunWorker(const char* kind, int32 client,
									uint32 idx,
									std::function<nlohmann::json()> work);
			void				_WorkDone(BMessage* message);
			void				_FetchServers(int32 client, uint32 idx);

	// session
			void				_LoadState();
			void				_SaveSession() const;
			void				_ForgetSession();

	// connection
			void				_Connect(const nlohmann::json& params);
			void				_StartTunnel();
			void				_Disconnect();
			void				_BackendState(BMessage* message);
			void				_TunnelDown(bool failure,
									const std::string& reason);
			void				_RemoveConfigFiles();

			std::string			_DataPath(const char* leaf) const;

			int					fListenSocket;
			int					fPort;
			uint64				fSecret;
			int32				fNextClientId;
			std::map<int32, std::shared_ptr<Client> > fClients;

			Session				fSession;
			nlohmann::json		fServers;		// servers.json
			Pings				fPings;

			// connection state
			enum Phase { kIdle, kPreparing, kTunnel };
			Phase				fPhase;
			VPNBackend*			fActive;
			OpenVPNBackend*		fOpenVpn;
			WireGuardBackend*	fWireGuard;
			ConnectPlan			fPlan;
			bool				fConnected;
			bool				fUserStop;
			bool				fFailureSent;	// DisconnectedResp already sent
			int64				fConnectedSince;
			nlohmann::json		fPending;		// Connect params to run next
			BMessageRunner*		fDnsCheck;
};

}	// namespace ivpnd

#endif	// IVPND_DAEMON_H
