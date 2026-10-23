/*
 * IVPN for Vitruvian - main window.
 *
 * Three cards:
 *   - "service": the IVPN service is not reachable (retries automatically)
 *   - "login":   account ID (+ 2FA code when needed)
 *   - "main":    status, connect button, location, protocol, firewall ...
 *
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_MAIN_WINDOW_H
#define IVPN_MAIN_WINDOW_H

#include <Messenger.h>
#include <String.h>
#include <Window.h>

#include <string>

#include "../core/Model.h"
#include "DaemonClient.h"
#include "ServerListWindow.h"

class BButton;
class BCardLayout;
class BCheckBox;
class BMenuBar;
class BMenuField;
class BMenuItem;
class BMessageRunner;
class BPopUpMenu;
class BStringView;
class BTextControl;
class StatusView;

class MainWindow : public BWindow {
public:
							MainWindow();
	virtual					~MainWindow();

	virtual void			MessageReceived(BMessage* message);
	virtual bool			QuitRequested();

private:
	enum ConnState {
		kDisconnected,
		kConnecting,
		kConnected,
		kDisconnecting,
	};

	BView*					_BuildServiceCard();
	BView*					_BuildLoginCard();
	BView*					_BuildMainCard();
	BMenuBar*				_BuildMenuBar();

	// daemon traffic
	void					_TryConnectDaemon();
	void					_ScheduleDaemonRetry();
	void					_HandleDaemonLine(const char* line);
	void					_HandleHello(const nlohmann::json& m);
	void					_HandleLoginResponse(const nlohmann::json& m);
	void					_HandleConnected(const nlohmann::json& m);
	void					_HandleDisconnected(const nlohmann::json& m);
	void					_HandleError(const nlohmann::json& m);

	// actions
	void					_Connect();
	void					_Disconnect();
	void					_Login();
	void					_OpenServerWindow();
	void					_ApplyChangedSettings();

	// UI state
	void					_ShowCard(int32 index);
	void					_UpdateStatus();
	void					_UpdateLocationButton();
	void					_UpdateProtocolControls();
	void					_UpdateAccountLabel();
	void					_UpdateServerWindow();
	std::vector<ServerEntry> _ServerEntries() const;
	void					_Notify(const char* title, const char* content);
	void					_SaveSettings();
	BString					_SettingsPath() const;

	DaemonClient			fDaemon;
	BMessageRunner*			fRetryRunner;
	BMessageRunner*			fTickRunner;
	bool					fHelloReceived;

	ivpn::Settings			fSettings;
	ivpn::ServerLists		fServers;
	ivpn::PingMap			fPings;
	bool					fPingRequested;
	bool					fWireGuardDisabled;

	// account
	BString					fAccountId;
	nlohmann::json			fAccount;
	uint32					fLoginIdx;
	uint32					fLogoutIdx;
	uint32					fConnectIdx;
	bool					fNeed2fa;
	bool					fForceLogin;

	// connection
	ConnState				fState;
	int						fDaemonStateVal;
	BString					fConnectedServer;	// "Amsterdam, Netherlands"
	BString					fConnectedHost;		// "nl3.wg.ivpn.net"
	BString					fServerIp;
	BString					fClientIp;
	ivpn::VpnType			fConnectedType;
	time_t					fConnectedSince;
	BString					fLastError;
	bool					fFirewallEnabled;
	bool					fFirewallPersistent;
	bool					fUserDisconnect;
	bool					fReconnecting;

	// views
	BCardLayout*			fCards;
	BStringView*			fServiceTitle;
	BStringView*			fServiceDetail;

	BTextControl*			fAccountField;
	BTextControl*			f2faField;
	BButton*				fLoginButton;
	BStringView*			fLoginStatus;

	StatusView*				fStatusView;
	BButton*				fConnectButton;
	BButton*				fLocationButton;
	BPopUpMenu*				fProtocolMenu;
	BMenuField*				fProtocolField;
	BPopUpMenu*				fPortMenu;
	BMenuField*				fPortField;
	BCheckBox*				fFirewallBox;
	BCheckBox*				fFirewallOnConnectBox;
	BCheckBox*				fAntiTrackerBox;
	BCheckBox*				fHardcoreBox;
	BStringView*			fAccountLabel;
	BStringView*			fHintLabel;

	BMenuItem*				fNotifyItem;
	BMessenger				fServerWindow;
};

#endif	// IVPN_MAIN_WINDOW_H
