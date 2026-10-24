/*
 * IVPN for Vitruvian - native client for the IVPN service.
 *
 * Talks to the same background service (ivpn-service) as the official
 * Linux app and the "ivpn" command, so all of them can be used together.
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
				// launched again (e.g. "Open IVPN" in the Deskbar item)
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
#ifdef IVPN_HAIKU
			"Native IVPN client for Haiku.\n"
			"Its service, ivpnd, keeps the VPN running; the tunnels use code "
			"from Sotoportego (MIT).\n\n"
#else
			"Native IVPN client for Vitruvian.\n"
			"Uses the IVPN service (ivpn-service), the same one used by the "
			"official app and the ivpn command.\n\n"
#endif
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
