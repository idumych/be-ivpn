/*
 * IVPN for Vitruvian - bridges DaemonConnection to the Be messaging world.
 * Every line received from the daemon is posted to the target as
 * kMsgDaemonLine; a lost connection is posted as kMsgDaemonClosed.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_DAEMON_CLIENT_H
#define IVPN_DAEMON_CLIENT_H

#include <Messenger.h>
#include <String.h>

#include "../core/DaemonConnection.h"

class DaemonClient {
public:
							DaemonClient(BMessenger target);
							~DaemonClient();

	// Reads port.txt, connects and sends Hello. On failure fills 'error'.
	bool					Connect(BString& error);
	void					Disconnect();
	bool					IsConnected() const
								{ return fConnection.IsConnected(); }

	// Returns the request index, 0 when not sent.
	uint32					Send(const nlohmann::json& request);

private:
	BMessenger				fTarget;
	ivpn::DaemonConnection	fConnection;
};

#endif	// IVPN_DAEMON_CLIENT_H
