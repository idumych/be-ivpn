/*
 * IVPN for Vitruvian - the Deskbar item: a lamp in the Deskbar tray that
 * shows the VPN state (green protected, amber connecting, red not
 * protected, grey service not running or not logged in).
 *
 * Built as an add-on library (IVPNDeskbar.so) that Deskbar loads through
 * instantiate_deskbar_item(). It has its own connection to the IVPN
 * service, so it works while the IVPN window is closed.
 *
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_DESKBAR_VIEW_H
#define IVPN_DESKBAR_VIEW_H

#include <String.h>
#include <View.h>

#include <string>

#include "../core/Model.h"

class BMessageRunner;
class DaemonClient;

class DeskbarView : public BView {
public:
							DeskbarView(BRect frame);
	virtual					~DeskbarView();

	virtual void			AttachedToWindow();
	virtual void			DetachedFromWindow();
	virtual void			Draw(BRect updateRect);
	virtual void			MouseDown(BPoint where);
	virtual void			MessageReceived(BMessage* message);

private:
	enum State {
		kNoService,
		kLoggedOut,
		kDisconnected,
		kConnecting,
		kConnected,
	};

	void					_TryConnect();
	void					_ScheduleRetry();
	void					_HandleLine(const char* line);
	void					_SetState(State state);
	BString					_Headline() const;
	BString					_Detail() const;
	void					_ShowMenu(BPoint where);

	DaemonClient*			fDaemon;
	BMessageRunner*			fRetryRunner;
	State					fState;
	bool					fFirewall;
	ivpn::ServerLists		fServers;
	std::string				fServerIp;
	ivpn::VpnType			fType;
	ivpn::Obfuscation		fObfs;
};

#endif	// IVPN_DESKBAR_VIEW_H
