/*
 * Be IVPN - native client for the IVPN service.
 *
 * Talks to ivpnd, its own background service, which keeps the VPN
 * running while the window is closed.
 *
 * Distributed under the terms of the GNU GPL v3.
 */
#include <Alert.h>
#include <Application.h>

#include "Constants.h"
#include "MainWindow.h"


class IVPNApp : public BApplication {
public:
	IVPNApp()
		:
		BApplication(IVPN_APP_SIGNATURE),
		fWindow(NULL),
		fPendingConnect(false)
	{
	}

	virtual void ReadyToRun()
	{
		fWindow = new MainWindow();
		fWindow->Show();
		if (fPendingConnect)
			fWindow->PostMessage(kMsgConnectWhenReady);
	}

	virtual void MessageReceived(BMessage* message)
	{
		switch (message->what) {
			case kMsgConnectWhenReady:
				// from the Deskbar item; may arrive before ReadyToRun()
				if (fWindow == NULL) {
					fPendingConnect = true;
					break;
				}
				fWindow->PostMessage(kMsgConnectWhenReady);
				_ActivateWindow();
				break;
			case B_SILENT_RELAUNCH:
				// launched again (e.g. "Open Be IVPN" in the Deskbar item)
				_ActivateWindow();
				break;
			default:
				BApplication::MessageReceived(message);
		}
	}

	virtual void AboutRequested()
	{
		BAlert* alert = new BAlert("about",
			IVPN_APP_NAME " " IVPN_APP_VERSION "\n\n"
			"Native IVPN client for Haiku.\n"
			"Its service, ivpnd, keeps the VPN running; the tunnels use code "
			"from Sotoportego (MIT).\n\n"
			"Closing this window does not disconnect the VPN.\n\n"
			"GNU GPL v3. IVPN is a trademark of Privatus Limited; this app is "
			"not made by IVPN.",
			"OK");
		alert->Go(NULL);
	}

private:
	void _ActivateWindow()
	{
		if (fWindow != NULL && fWindow->Lock()) {
			fWindow->Activate();
			fWindow->Unlock();
		}
	}

	MainWindow*	fWindow;
	bool		fPendingConnect;
};


int
main()
{
	IVPNApp app;
	app.Run();
	return 0;
}
