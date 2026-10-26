/*
 * Be IVPN - bridges DaemonConnection to the Be messaging world.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "DaemonClient.h"

#include <Message.h>
#include <Entry.h>
#include <InterfaceDefs.h>
#include <Roster.h>

#include "Constants.h"


DaemonClient::DaemonClient(BMessenger target)
	:
	fTarget(target)
{
}


DaemonClient::~DaemonClient()
{
	Disconnect();
}


bool
DaemonClient::Connect(BString& error, const char* clientVersion,
	int clientType)
{
	Disconnect();

	ivpn::PortInfo info;
	std::string err;
	// Our own service; the caller retries in a few seconds.
	if (!be_roster->IsRunning(IVPND_SIGNATURE)) {
		if (be_roster->Launch(IVPND_SIGNATURE) != B_OK) {
			entry_ref ref;
			if (get_ref_for_path(IVPND_PATH, &ref) == B_OK)
				be_roster->Launch(&ref);
		}
		error = "Starting the IVPN service" B_UTF8_ELLIPSIS;
		return false;
	}
	if (!ivpn::DaemonConnection::ReadPortFile(info, err)) {
		error = err.c_str();
		return false;
	}

	// Callbacks run on the reader thread; BMessenger is thread-safe.
	// Never block forever on a full window queue: the window thread may be
	// waiting in Close() for this very thread to finish.
	BMessenger target = fTarget;
	ivpn::DaemonConnection* connection = &fConnection;
	auto post = [target, connection](BMessage& msg) {
		while (target.SendMessage(&msg, (BHandler*)NULL, 250000)
				== B_TIMED_OUT) {
			if (connection->IsClosing())
				return;
		}
	};
	bool ok = fConnection.Connect(info,
		[post](const std::string& line) {
			BMessage msg(kMsgDaemonLine);
			msg.AddString("line", line.c_str());
			post(msg);
		},
		[post](const std::string& reason) {
			BMessage msg(kMsgDaemonClosed);
			msg.AddString("reason", reason.c_str());
			post(msg);
		}, err);

	if (!ok) {
		error = err.c_str();
		return false;
	}

	if (fConnection.SendHello(clientVersion, clientType) == 0) {
		error = "Could not talk to the IVPN service.";
		fConnection.Close();
		return false;
	}
	return true;
}


void
DaemonClient::Disconnect()
{
	fConnection.Close();
}


uint32
DaemonClient::Send(const nlohmann::json& request)
{
	return fConnection.Send(request);
}
