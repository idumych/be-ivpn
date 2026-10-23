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
		fWindow(NULL)
	{
	}

	virtual void ReadyToRun()
	{
		fWindow = new MainWindow();
		fWindow->Show();
	}

	virtual void AboutRequested()
	{
		BAlert* alert = new BAlert("about",
			IVPN_APP_NAME " " IVPN_APP_VERSION "\n\n"
			"Native IVPN client for Vitruvian.\n"
			"Uses the IVPN service (ivpn-service), the same one used by the "
			"official app and the ivpn command.\n\n"
			"Closing this window does not disconnect the VPN.\n\n"
			"GNU GPL v3. IVPN is a trademark of Privatus Limited; this app is "
			"not made by IVPN.",
			"OK");
		alert->Go(NULL);
	}

private:
	MainWindow*	fWindow;
};


int
main()
{
	IVPNApp app;
	app.Run();
	return 0;
}
