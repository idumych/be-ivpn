/*
 * IVPN for Vitruvian - main window.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "MainWindow.h"

#include <algorithm>
#include <cstdlib>
#include <ctime>

#include <Alert.h>
#include <Application.h>
#include <Box.h>
#include <Button.h>
#include <CardLayout.h>
#include <CheckBox.h>
#include <ControlLook.h>
#include <Directory.h>
#include <FindDirectory.h>
#include <LayoutBuilder.h>
#include <MenuBar.h>
#include <MenuField.h>
#include <MenuItem.h>
#include <MessageRunner.h>
#include <Notification.h>
#include <Path.h>
#include <PopUpMenu.h>
#include <Roster.h>
#include <Screen.h>
#include <SeparatorView.h>
#include <StringView.h>
#include <TextControl.h>

#include "../core/Requests.h"
#include "Constants.h"
#include "StatusView.h"

using nlohmann::json;
using namespace ivpn;

enum {
	kCardService = 0,
	kCardLogin,
	kCardMain,
};

static const bigtime_t kDaemonRetryDelay = 3000000;	// 3 s


static std::string
JStr(const json& j, const char* key)
{
	if (!j.is_object())
		return std::string();
	auto it = j.find(key);
	return it != j.end() && it->is_string() ? it->get<std::string>()
		: std::string();
}


static int64
JInt(const json& j, const char* key, int64 fallback = 0)
{
	if (!j.is_object())
		return fallback;
	auto it = j.find(key);
	return it != j.end() && it->is_number() ? it->get<int64>() : fallback;
}


static bool
JBool(const json& j, const char* key)
{
	if (!j.is_object())
		return false;
	auto it = j.find(key);
	return it != j.end() && it->is_boolean() && it->get<bool>();
}


static const char*
ProtocolName(VpnType type)
{
	return type == VpnType::WireGuard ? "WireGuard" : "OpenVPN";
}


// #pragma mark -


MainWindow::MainWindow()
	:
	BWindow(BRect(0, 0, 400, 500), IVPN_APP_NAME, B_TITLED_WINDOW,
		B_ASYNCHRONOUS_CONTROLS | B_AUTO_UPDATE_SIZE_LIMITS
			| B_QUIT_ON_WINDOW_CLOSE | B_NOT_ZOOMABLE),
	fDaemon(BMessenger(this)),
	fRetryRunner(NULL),
	fTickRunner(NULL),
	fHelloReceived(false),
	fPingRequested(false),
	fWireGuardDisabled(false),
	fLoginIdx(0),
	fLogoutIdx(0),
	fConnectIdx(0),
	fNeed2fa(false),
	fForceLogin(false),
	fState(kDisconnected),
	fDaemonStateVal(kStateDisconnected),
	fConnectedType(VpnType::WireGuard),
	fConnectedSince(0),
	fFirewallEnabled(false),
	fFirewallPersistent(false),
	fUserDisconnect(false),
	fReconnecting(false),
	fNotifyItem(NULL)
{
	fSettings.Load(_SettingsPath().String());
	srandom((unsigned)time(NULL));

	BView* service = _BuildServiceCard();
	BView* login = _BuildLoginCard();
	BView* main = _BuildMainCard();

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.Add(_BuildMenuBar())
		.AddCards()
			.GetLayout(&fCards)
			.Add(service)
			.Add(login)
			.Add(main)
		.End();

	_ShowCard(kCardService);
	_UpdateProtocolControls();
	_UpdateLocationButton();
	_UpdateStatus();
	CenterOnScreen();

	PostMessage(kMsgTryConnectDaemon);
}


MainWindow::~MainWindow()
{
	delete fRetryRunner;
	delete fTickRunner;
	fDaemon.Disconnect();
}


bool
MainWindow::QuitRequested()
{
	_SaveSettings();
	if (fServerWindow.IsValid())
		fServerWindow.SendMessage(B_QUIT_REQUESTED);
	// The VPN itself keeps running in the IVPN service; closing the window
	// does not disconnect.
	return true;
}


// #pragma mark - building the UI


BMenuBar*
MainWindow::_BuildMenuBar()
{
	BMenuBar* bar = new BMenuBar("menu");

	BMenu* app = new BMenu(IVPN_APP_NAME);
	app->AddItem(new BMenuItem("About IVPN" B_UTF8_ELLIPSIS,
		new BMessage(B_ABOUT_REQUESTED)));
	app->AddSeparatorItem();
	fNotifyItem = new BMenuItem("Show notifications",
		new BMessage(kMsgNotifications));
	fNotifyItem->SetMarked(fSettings.notifications);
	app->AddItem(fNotifyItem);
	app->AddItem(new BMenuItem("Open account page" B_UTF8_ELLIPSIS,
		new BMessage(kMsgOpenAccountPage)));
	app->AddItem(new BMenuItem("Log out", new BMessage(kMsgLogout)));
	app->AddSeparatorItem();
	app->AddItem(new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED), 'Q'));
	bar->AddItem(app);

	BMenu* servers = new BMenu("Servers");
	servers->AddItem(new BMenuItem("Choose location" B_UTF8_ELLIPSIS,
		new BMessage(kMsgChooseServer), 'L'));
	servers->AddItem(new BMenuItem("Test latency again",
		new BMessage(kMsgPingServers)));
	servers->AddItem(new BMenuItem("Update server list",
		new BMessage(kMsgRefreshServers)));
	bar->AddItem(servers);

	return bar;
}


BView*
MainWindow::_BuildServiceCard()
{
	fServiceTitle = new BStringView("serviceTitle",
		"Connecting to the IVPN service" B_UTF8_ELLIPSIS);
	BFont bold(be_bold_font);
	bold.SetSize(be_bold_font->Size() * 1.2f);
	fServiceTitle->SetFont(&bold);
	fServiceDetail = new BStringView("serviceDetail", "");

	BStringView* help = new BStringView("serviceHelp",
		"Make sure the ivpn package is installed and its service is running.");
	BStringView* help2 = new BStringView("serviceHelp2",
		"In Terminal:  sudo systemctl enable --now ivpn-service");
	help2->SetFont(be_fixed_font);

	BView* view = new BView("serviceCard", 0);
	BLayoutBuilder::Group<>(view, B_VERTICAL)
		.SetInsets(B_USE_WINDOW_SPACING)
		.AddGlue()
		.Add(fServiceTitle)
		.Add(fServiceDetail)
		.AddStrut(be_control_look->DefaultItemSpacing())
		.Add(help)
		.Add(help2)
		.AddGroup(B_HORIZONTAL)
			.AddGlue()
			.Add(new BButton("retry", "Try again",
				new BMessage(kMsgRetryDaemon)))
		.End()
		.AddGlue();
	return view;
}


BView*
MainWindow::_BuildLoginCard()
{
	BStringView* title = new BStringView("loginTitle", "Log in to IVPN");
	BFont bold(be_bold_font);
	bold.SetSize(be_bold_font->Size() * 1.4f);
	title->SetFont(&bold);

	BStringView* explain = new BStringView("loginExplain",
		"Enter your account ID (i-XXXX-XXXX-XXXX or ivpnXXXXXXXX).");

	fAccountField = new BTextControl("account", "Account ID:", "",
		new BMessage(kMsgLogin));
	f2faField = new BTextControl("2fa", "2FA code:", "",
		new BMessage(kMsgLogin));
	fLoginButton = new BButton("login", "Log in", new BMessage(kMsgLogin));
	fLoginStatus = new BStringView("loginStatus", "");

	BView* view = new BView("loginCard", 0);
	BLayoutBuilder::Group<>(view, B_VERTICAL)
		.SetInsets(B_USE_WINDOW_SPACING)
		.AddGlue()
		.Add(title)
		.Add(explain)
		.AddGrid()
			.AddTextControl(fAccountField, 0, 0)
			.AddTextControl(f2faField, 0, 1)
		.End()
		.Add(fLoginStatus)
		.AddGroup(B_HORIZONTAL)
			.Add(new BButton("signup", "Create account" B_UTF8_ELLIPSIS,
				new BMessage(kMsgOpenAccountPage)))
			.AddGlue()
			.Add(fLoginButton)
		.End()
		.AddGlue();

	f2faField->Hide();
	return view;
}


BView*
MainWindow::_BuildMainCard()
{
	fStatusView = new StatusView();

	fConnectButton = new BButton("connect", "Connect",
		new BMessage(kMsgConnectToggle));
	fConnectButton->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));
	BFont big(be_bold_font);
	big.SetSize(be_bold_font->Size() * 1.25f);
	fConnectButton->SetFont(&big);

	fLocationButton = new BButton("location", "Location",
		new BMessage(kMsgChooseServer));
	fLocationButton->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));

	fProtocolMenu = new BPopUpMenu("protocol");
	BMessage* wg = new BMessage(kMsgProtocolChanged);
	wg->AddInt32("type", (int32)VpnType::WireGuard);
	fProtocolMenu->AddItem(new BMenuItem("WireGuard", wg));
	BMessage* ovpn = new BMessage(kMsgProtocolChanged);
	ovpn->AddInt32("type", (int32)VpnType::OpenVPN);
	fProtocolMenu->AddItem(new BMenuItem("OpenVPN", ovpn));
	fProtocolField = new BMenuField("protocolField", "Protocol:",
		fProtocolMenu);

	fPortMenu = new BPopUpMenu("port");
	fPortField = new BMenuField("portField", "Port:", fPortMenu);

	fFirewallBox = new BCheckBox("firewall",
		"Firewall (block traffic outside the VPN)",
		new BMessage(kMsgFirewallToggle));
	fFirewallOnConnectBox = new BCheckBox("firewallOnConnect",
		"Turn on the firewall when connecting",
		new BMessage(kMsgFirewallOnConnect));
	fAntiTrackerBox = new BCheckBox("antitracker",
		"AntiTracker (block ads and trackers)",
		new BMessage(kMsgAntiTracker));
	fHardcoreBox = new BCheckBox("hardcore",
		"Hardcore mode (also block Google and Facebook)",
		new BMessage(kMsgAntiTrackerHard));

	fFirewallOnConnectBox->SetValue(fSettings.firewallOnConnect);
	fAntiTrackerBox->SetValue(fSettings.antiTracker);
	fHardcoreBox->SetValue(fSettings.antiTrackerHardcore);
	fHardcoreBox->SetEnabled(fSettings.antiTracker);

	fAccountLabel = new BStringView("accountLabel", "");
	fHintLabel = new BStringView("hint", "");
	BFont small(be_plain_font);
	small.SetSize(be_plain_font->Size() * 0.9f);
	fAccountLabel->SetFont(&small);
	fHintLabel->SetFont(&small);
	fAccountLabel->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED, B_SIZE_UNSET));

	BBox* connectionBox = new BBox("connectionBox");
	connectionBox->SetLabel("Connection");
	BView* connectionInner = new BView("connectionInner", 0);
	BLayoutBuilder::Group<>(connectionInner, B_VERTICAL)
		.SetInsets(B_USE_ITEM_SPACING)
		.Add(fLocationButton)
		.AddGrid()
			.AddMenuField(fProtocolField, 0, 0)
			.AddMenuField(fPortField, 0, 1)
		.End();
	connectionBox->AddChild(connectionInner);

	BBox* privacyBox = new BBox("privacyBox");
	privacyBox->SetLabel("Privacy");
	BView* privacyInner = new BView("privacyInner", 0);
	float indent = be_control_look->DefaultLabelSpacing() * 3;
	BLayoutBuilder::Group<>(privacyInner, B_VERTICAL, 0)
		.SetInsets(B_USE_ITEM_SPACING)
		.Add(fFirewallBox)
		.Add(fFirewallOnConnectBox)
		.Add(fAntiTrackerBox)
		.AddGroup(B_HORIZONTAL, 0)
			.AddStrut(indent)
			.Add(fHardcoreBox)
		.End()
		.Add(fHintLabel);
	privacyBox->AddChild(privacyInner);

	BView* view = new BView("mainCard", 0);
	BLayoutBuilder::Group<>(view, B_VERTICAL)
		.SetInsets(B_USE_WINDOW_SPACING)
		.Add(fStatusView)
		.Add(fConnectButton)
		.Add(connectionBox)
		.Add(privacyBox)
		.AddGlue()
		.Add(new BSeparatorView(B_HORIZONTAL))
		.AddGroup(B_HORIZONTAL)
			.Add(fAccountLabel)
			.Add(new BButton("logout", "Log out", new BMessage(kMsgLogout)))
		.End();
	return view;
}


// #pragma mark - messages


void
MainWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgTryConnectDaemon:
		case kMsgRetryDaemon:
			_TryConnectDaemon();
			break;

		case kMsgDaemonLine:
		{
			const char* line;
			if (message->FindString("line", &line) == B_OK)
				_HandleDaemonLine(line);
			break;
		}

		case kMsgDaemonClosed:
		{
			fDaemon.Disconnect();
			fHelloReceived = false;
			fState = kDisconnected;
			fServiceTitle->SetText("Lost connection to the IVPN service");
			fServiceDetail->SetText(message->GetString("reason", ""));
			_ShowCard(kCardService);
			_ScheduleDaemonRetry();
			break;
		}

		case kMsgTick:
			_UpdateStatus();
			break;

		case kMsgConnectToggle:
			if (fState == kDisconnected)
				_Connect();
			else
				_Disconnect();
			break;

		case kMsgChooseServer:
			_OpenServerWindow();
			break;

		case kMsgServerChosen:
		{
			int32 selection;
			if (message->FindInt32("selection", &selection) != B_OK)
				break;
			fSettings.selection = (ServerSelection)selection;
			fSettings.gatewayId = message->GetString("gateway", "");
			_SaveSettings();
			_UpdateLocationButton();
			// Picking a location connects there (like the official app)
			_Connect();
			break;
		}

		case kMsgServerWindowClosed:
			fServerWindow = BMessenger();
			break;

		case kMsgProtocolChanged:
		{
			int32 type;
			if (message->FindInt32("type", &type) != B_OK
				|| (VpnType)type == fSettings.vpnType)
				break;
			fSettings.vpnType = (VpnType)type;
			_UpdateProtocolControls();
			_UpdateLocationButton();
			_UpdateServerWindow();
			fPings.clear();
			if (fHelloReceived)
				fDaemon.Send(req::PingServers((int)fSettings.vpnType));
			_ApplyChangedSettings();
			break;
		}

		case kMsgPortChanged:
		{
			int32 port;
			bool tcp;
			if (message->FindInt32("port", &port) != B_OK
				|| message->FindBool("tcp", &tcp) != B_OK)
				break;
			Port newPort;
			newPort.port = port;
			newPort.tcp = tcp;
			if (newPort == fSettings.PortFor(fSettings.vpnType))
				break;
			fSettings.PortFor(fSettings.vpnType) = newPort;
			_ApplyChangedSettings();
			break;
		}

		case kMsgFirewallToggle:
			if (fFirewallPersistent) {
				fFirewallBox->SetValue(B_CONTROL_ON);
				break;
			}
			fDaemon.Send(req::SetFirewall(
				fFirewallBox->Value() == B_CONTROL_ON));
			fDaemon.Send(req::GetFirewallStatus());
			break;

		case kMsgFirewallOnConnect:
			fSettings.firewallOnConnect
				= fFirewallOnConnectBox->Value() == B_CONTROL_ON;
			_SaveSettings();
			break;

		case kMsgAntiTracker:
			fSettings.antiTracker = fAntiTrackerBox->Value() == B_CONTROL_ON;
			fHardcoreBox->SetEnabled(fSettings.antiTracker);
			_ApplyChangedSettings();
			break;

		case kMsgAntiTrackerHard:
			fSettings.antiTrackerHardcore
				= fHardcoreBox->Value() == B_CONTROL_ON;
			_ApplyChangedSettings();
			break;

		case kMsgNotifications:
			fSettings.notifications = !fSettings.notifications;
			fNotifyItem->SetMarked(fSettings.notifications);
			_SaveSettings();
			break;

		case kMsgLogin:
			_Login();
			break;

		case kMsgLogout:
		{
			if (fAccountId.IsEmpty() || !fHelloReceived)
				break;
			BAlert* alert = new BAlert("logout",
				"Log out of IVPN on this computer?\n\n"
				"The VPN will be disconnected and the firewall turned off.",
				"Cancel", "Log out", NULL, B_WIDTH_AS_USUAL, B_WARNING_ALERT);
			alert->SetShortcut(0, B_ESCAPE);
			if (alert->Go() == 1)
				fLogoutIdx = fDaemon.Send(req::Logout());
			break;
		}

		case kMsgRefreshServers:
			if (fHelloReceived)
				fDaemon.Send(req::RefreshServers());
			break;

		case kMsgPingServers:
			if (fHelloReceived) {
				fDaemon.Send(req::PingServers((int)fSettings.vpnType));
				fHintLabel->SetText("Testing server latency" B_UTF8_ELLIPSIS);
			}
			break;

		case kMsgOpenAccountPage:
		{
			const char* url = fAccountId.IsEmpty()
				? "https://www.ivpn.net/pricing/"
				: "https://www.ivpn.net/account/";
			const char* args[] = { url, NULL };
			be_roster->Launch("application/x-vnd.Be.URL.https", 1,
				const_cast<char**>(args));
			break;
		}

		default:
			BWindow::MessageReceived(message);
	}
}


// #pragma mark - daemon traffic


void
MainWindow::_TryConnectDaemon()
{
	delete fRetryRunner;
	fRetryRunner = NULL;

	BString error;
	fServiceTitle->SetText("Connecting to the IVPN service" B_UTF8_ELLIPSIS);
	if (!fDaemon.Connect(error)) {
		fServiceTitle->SetText("The IVPN service is not reachable");
		fServiceDetail->SetText(error);
		_ShowCard(kCardService);
		_ScheduleDaemonRetry();
		return;
	}
	fServiceDetail->SetText("Waiting for reply" B_UTF8_ELLIPSIS);
}


void
MainWindow::_ScheduleDaemonRetry()
{
	delete fRetryRunner;
	BMessage retry(kMsgTryConnectDaemon);
	fRetryRunner = new BMessageRunner(BMessenger(this), &retry,
		kDaemonRetryDelay, 1);
}


void
MainWindow::_HandleDaemonLine(const char* line)
{
	json m = json::parse(line, nullptr, false);
	if (m.is_discarded() || !m.is_object())
		return;

	std::string command = JStr(m, "Command");
	uint32 idx = (uint32)JInt(m, "Idx");

	if (command == "HelloResp") {
		_HandleHello(m);
	} else if (command == "ServerListResp") {
		fServers = ParseServerList(m.value("VpnServers", json::object()));
		if (!fPingRequested && !fServers.Empty() && !fAccountId.IsEmpty()) {
			fPingRequested = true;
			fDaemon.Send(req::PingServers((int)fSettings.vpnType));
		}
		if (fState == kConnected && fConnectedServer.IsEmpty()) {
			// resolve name for a connection that existed before we started
			if (const Server* s = fServers.FindByHost(fServerIp.String())) {
				fConnectedServer = s->DisplayName().c_str();
				fConnectedHost = s->HostnameFor(fServerIp.String()).c_str();
			}
		}
		_UpdateProtocolControls();
		_UpdateLocationButton();
		_UpdateServerWindow();
		_UpdateStatus();
	} else if (command == "PingServersResp") {
		UpdatePings(fPings, m.value("PingResults", json::array()));
		fHintLabel->SetText("");
		_UpdateLocationButton();
		_UpdateServerWindow();
	} else if (command == "VpnStateResp") {
		fDaemonStateVal = (int)JInt(m, "StateVal");
		if (fState != kDisconnecting && fDaemonStateVal != kStateConnected
			&& fDaemonStateVal != kStateDisconnected)
			fState = kConnecting;
		_UpdateStatus();
	} else if (command == "ConnectedResp") {
		_HandleConnected(m);
	} else if (command == "DisconnectedResp") {
		_HandleDisconnected(m);
	} else if (command == "KillSwitchStatusResp") {
		fFirewallEnabled = JBool(m, "IsEnabled");
		fFirewallPersistent = JBool(m, "IsPersistent");
		fFirewallBox->SetValue(fFirewallEnabled);
		fFirewallBox->SetEnabled(!fFirewallPersistent);
		fFirewallBox->SetLabel(fFirewallPersistent
			? "Firewall is always on (set with the ivpn command)"
			: "Firewall (block traffic outside the VPN)");
		_UpdateStatus();
	} else if (command == "SessionNewResp") {
		_HandleLoginResponse(m);
	} else if (command == "SessionStatusResp") {
		if (m.contains("Account") && m["Account"].is_object())
			fAccount = m["Account"];
		_UpdateAccountLabel();
	} else if (command == "EmptyResp") {
		if (idx != 0 && idx == fLogoutIdx) {
			fLogoutIdx = 0;
			fAccountId = "";
			fAccount = json();
			fPingRequested = false;
			fLoginStatus->SetText("You have been logged out.");
			_ShowCard(kCardLogin);
		}
	} else if (command == "ErrorResp") {
		_HandleError(m);
	} else if (command == "ServiceExitingResp") {
		fServiceTitle->SetText("The IVPN service is shutting down");
		fServiceDetail->SetText("");
		_ShowCard(kCardService);
	}
}


void
MainWindow::_HandleHello(const json& m)
{
	fHelloReceived = true;

	const json& pm = m.value("ParanoidMode", json::object());
	if (JBool(pm, "IsEnabled")) {
		fServiceTitle->SetText("Enhanced App Authentication is on");
		fServiceDetail->SetText("This app does not support it yet. "
			"Turn it off in Terminal with:  ivpn eaa -off");
		_ShowCard(kCardService);
		return;
	}

	const json& disabled = m.value("DisabledFunctions", json::object());
	fWireGuardDisabled = !JStr(disabled, "WireGuardError").empty();
	if (fWireGuardDisabled && fSettings.vpnType == VpnType::WireGuard)
		fSettings.vpnType = VpnType::OpenVPN;

	const json& session = m.value("Session", json::object());
	fAccountId = JStr(session, "AccountID").c_str();
	if (m.contains("Account") && m["Account"].is_object())
		fAccount = m["Account"];

	_UpdateProtocolControls();
	_UpdateAccountLabel();
	_UpdateLocationButton();

	if (fAccountId.IsEmpty()) {
		_ShowCard(kCardLogin);
		fAccountField->MakeFocus(true);
		return;
	}

	_ShowCard(kCardMain);
	fDaemon.Send(req::GetFirewallStatus());
	fDaemon.Send(req::SessionStatus());
	if (!fServers.Empty() && !fPingRequested) {
		fPingRequested = true;
		fDaemon.Send(req::PingServers((int)fSettings.vpnType));
	}
}


void
MainWindow::_HandleLoginResponse(const json& m)
{
	fLoginButton->SetEnabled(true);
	int status = (int)JInt(m, "APIStatus");

	switch (status) {
		case kApiSuccess:
		{
			fNeed2fa = false;
			fForceLogin = false;
			f2faField->SetText("");
			if (!f2faField->IsHidden())
				f2faField->Hide();
			fLoginStatus->SetText("");
			const json& session = m.value("Session", json::object());
			fAccountId = JStr(session, "AccountID").c_str();
			if (m.contains("Account") && m["Account"].is_object())
				fAccount = m["Account"];
			_UpdateAccountLabel();
			_ShowCard(kCardMain);
			fDaemon.Send(req::GetFirewallStatus());
			if (!fServers.Empty() && !fPingRequested) {
				fPingRequested = true;
				fDaemon.Send(req::PingServers((int)fSettings.vpnType));
			}
			return;
		}

		case kApiSessionLimit:
		{
			BAlert* alert = new BAlert("limit",
				"This account is already logged in on the maximum number of "
				"devices.\n\nLog out of all other devices and continue here?",
				"Cancel", "Log out other devices", NULL, B_WIDTH_AS_USUAL,
				B_WARNING_ALERT);
			alert->SetShortcut(0, B_ESCAPE);
			if (alert->Go() == 1) {
				fForceLogin = true;
				_Login();
			} else
				fLoginStatus->SetText("Login cancelled.");
			return;
		}

		case kApi2faRequired:
			fNeed2fa = true;
			if (f2faField->IsHidden())
				f2faField->Show();
			f2faField->MakeFocus(true);
			fLoginStatus->SetText(
				"Enter the 6-digit code from your authenticator app.");
			return;

		case kApi2faInvalid:
			f2faField->MakeFocus(true);
			fLoginStatus->SetText("That code is not valid. Try again.");
			return;

		case kApiCaptchaRequired:
		case kApiCaptchaInvalid:
			fLoginStatus->SetText("IVPN asks for a captcha. Log in once in "
				"Terminal with:  ivpn login");
			return;

		default:
		{
			BString text = JStr(m, "APIErrorMessage").c_str();
			if (text.IsEmpty())
				text.SetToFormat("Login failed (error %d).", status);
			fLoginStatus->SetText(text);
			return;
		}
	}
}


void
MainWindow::_HandleConnected(const json& m)
{
	// only notify for connections we asked for, not for one that already
	// existed when the app started
	bool wasConnecting = fState == kConnecting;
	fState = kConnected;
	fReconnecting = false;
	fLastError = "";

	BString serverIp = JStr(m, "ServerIP").c_str();
	fServerIp = serverIp;
	fClientIp = JStr(m, "ClientIP").c_str();
	fConnectedType = (VpnType)JInt(m, "VpnType", (int)fSettings.vpnType);
	fConnectedSince = (time_t)JInt(m, "TimeSecFrom1970", time(NULL));

	if (const Server* s = fServers.FindByHost(serverIp.String())) {
		fConnectedServer = s->DisplayName().c_str();
		fConnectedHost = s->HostnameFor(serverIp.String()).c_str();
	} else {
		fConnectedServer = "";
		fConnectedHost = serverIp;
	}

	if (fTickRunner == NULL) {
		BMessage tick(kMsgTick);
		fTickRunner = new BMessageRunner(BMessenger(this), &tick, 1000000);
	}

	_UpdateStatus();
	if (wasConnecting) {
		BString content;
		content.SetToFormat("Your traffic is protected. %s",
			fConnectedServer.String());
		_Notify("Connected", content.String());
	}
}


void
MainWindow::_HandleDisconnected(const json& m)
{
	bool failure = JBool(m, "Failure");
	bool stateInfo = JBool(m, "IsStateInfo");
	bool wasConnected = fState == kConnected;
	bool wasActive = fState != kDisconnected;

	delete fTickRunner;
	fTickRunner = NULL;

	if (fReconnecting && !failure && !stateInfo) {
		// the daemon drops the old tunnel before building the new one
		fState = kConnecting;
		_UpdateStatus();
		return;
	}

	fState = kDisconnected;
	fReconnecting = false;
	fDaemonStateVal = kStateDisconnected;

	if (failure) {
		fLastError = JStr(m, "ReasonDescription").c_str();
		if (fLastError.IsEmpty())
			fLastError = "The connection failed.";
	}

	_UpdateStatus();

	if (stateInfo || !wasActive)
		return;
	if (failure)
		_Notify("Connection failed", fLastError.String());
	else if (wasConnected && !fUserDisconnect)
		_Notify("Disconnected", "Your traffic is no longer protected.");
	fUserDisconnect = false;
}


void
MainWindow::_HandleError(const json& m)
{
	uint32 idx = (uint32)JInt(m, "Idx");
	BString text = JStr(m, "ErrorMessage").c_str();
	if (text.IsEmpty())
		text = "The IVPN service reported an error.";

	if (JInt(m, "ErrorType") == 1) {	// ErrorParanoidModePasswordError
		fServiceTitle->SetText("Enhanced App Authentication is on");
		fServiceDetail->SetText("Turn it off in Terminal with:  ivpn eaa -off");
		_ShowCard(kCardService);
		return;
	}

	if (idx != 0 && idx == fLoginIdx) {
		fLoginButton->SetEnabled(true);
		fLoginStatus->SetText(text);
		return;
	}
	if (idx != 0 && idx == fLogoutIdx) {
		fLogoutIdx = 0;
		(new BAlert("error", text, "OK", NULL, NULL, B_WIDTH_AS_USUAL,
			B_STOP_ALERT))->Go(NULL);
		return;
	}
	if (idx != 0 && idx == fConnectIdx) {
		fState = kDisconnected;
		fReconnecting = false;
	}
	fLastError = text;
	_UpdateStatus();
}


// #pragma mark - actions


void
MainWindow::_Connect()
{
	if (!fHelloReceived || fAccountId.IsEmpty())
		return;

	std::string error;
	const Server* chosen = NULL;
	json params = BuildConnectParams(fSettings, fServers, fPings,
		(unsigned)random(), &chosen, error);
	if (params.is_null()) {
		fLastError = error.c_str();
		_UpdateStatus();
		if (fServers.Empty())
			fDaemon.Send(req::RefreshServers());
		return;
	}

	fReconnecting = fState == kConnected || fState == kConnecting;
	fUserDisconnect = false;
	fLastError = "";
	fConnectedServer = chosen->DisplayName().c_str();
	fConnectedHost = "";
	fDaemonStateVal = kStateConnecting;
	fState = kConnecting;
	fConnectIdx = fDaemon.Send(req::Connect(params));
	_UpdateStatus();
}


void
MainWindow::_Disconnect()
{
	if (!fHelloReceived)
		return;
	fUserDisconnect = true;
	fReconnecting = false;
	fState = kDisconnecting;
	fDaemon.Send(req::Disconnect());
	_UpdateStatus();
}


void
MainWindow::_Login()
{
	if (!fHelloReceived)
		return;

	BString account = fAccountField->Text();
	account.Trim();
	if (account.IsEmpty()) {
		fLoginStatus->SetText("Please enter your account ID.");
		fAccountField->MakeFocus(true);
		return;
	}

	BString code;
	if (fNeed2fa) {
		code = f2faField->Text();
		code.Trim();
		if (code.IsEmpty()) {
			fLoginStatus->SetText("Please enter your 2FA code.");
			f2faField->MakeFocus(true);
			return;
		}
	}

	fLoginButton->SetEnabled(false);
	fLoginStatus->SetText("Logging in" B_UTF8_ELLIPSIS);
	fLoginIdx = fDaemon.Send(req::Login(account.String(), fForceLogin,
		code.String()));
	if (fLoginIdx == 0) {
		fLoginButton->SetEnabled(true);
		fLoginStatus->SetText("Could not reach the IVPN service.");
	}
}


void
MainWindow::_OpenServerWindow()
{
	if (fServerWindow.IsValid()) {
		BMessage activate(B_WINDOW_ACTIVATED);
		fServerWindow.SendMessage(&activate);
		return;
	}
	if (fAccountId.IsEmpty())
		return;

	BRect frame = Frame();
	frame.OffsetBy(frame.Width() + 10, 0);
	BRect screen = BScreen(this).Frame();
	if (frame.right > screen.right)
		frame.OffsetTo(Frame().LeftTop() + BPoint(30, 30));
	frame.right = frame.left + be_plain_font->Size() * 26;

	ServerListWindow* window = new ServerListWindow(frame, BMessenger(this),
		_ServerEntries(), (int32)fSettings.selection,
		fSettings.gatewayId.c_str());
	fServerWindow = BMessenger(window);
	window->Show();

	if (!fPings.empty() || !fHelloReceived)
		return;
	fDaemon.Send(req::PingServers((int)fSettings.vpnType));
}


void
MainWindow::_ApplyChangedSettings()
{
	_SaveSettings();
	// Like the official app: settings that affect the tunnel reconnect it.
	if (fState == kConnected || fState == kConnecting)
		_Connect();
}


// #pragma mark - UI state


void
MainWindow::_ShowCard(int32 index)
{
	if (fCards->VisibleIndex() != index)
		fCards->SetVisibleItem(index);
}


void
MainWindow::_UpdateStatus()
{
	BString headline;
	BString detail;
	StatusView::Level level = StatusView::kUnprotected;

	switch (fState) {
		case kConnected:
		{
			level = StatusView::kProtected;
			headline = "Protected";
			time_t elapsed = time(NULL) - fConnectedSince;
			if (elapsed < 0)
				elapsed = 0;
			BString duration;
			duration.SetToFormat("%02d:%02d:%02d", (int)(elapsed / 3600),
				(int)(elapsed / 60 % 60), (int)(elapsed % 60));
			detail.SetToFormat("%s %s %s %s %s",
				fConnectedServer.IsEmpty()
					? fConnectedHost.String() : fConnectedServer.String(),
				"\xC2\xB7", ProtocolName(fConnectedType), "\xC2\xB7",
				duration.String());
			fConnectButton->SetLabel("Disconnect");
			fConnectButton->SetEnabled(true);
			break;
		}
		case kConnecting:
			level = StatusView::kWorking;
			headline = fReconnecting ? "Reconnecting" B_UTF8_ELLIPSIS
				: "Connecting" B_UTF8_ELLIPSIS;
			if (fConnectedServer.IsEmpty())
				detail = StateDescription(fDaemonStateVal).c_str();
			else {
				detail.SetToFormat("%s %s %s", fConnectedServer.String(),
					"\xC2\xB7", StateDescription(fDaemonStateVal).c_str());
			}
			fConnectButton->SetLabel("Cancel");
			fConnectButton->SetEnabled(true);
			break;
		case kDisconnecting:
			level = StatusView::kWorking;
			headline = "Disconnecting" B_UTF8_ELLIPSIS;
			fConnectButton->SetLabel("Disconnect");
			fConnectButton->SetEnabled(false);
			break;
		case kDisconnected:
			headline = "Not protected";
			if (!fLastError.IsEmpty())
				detail = fLastError;
			else if (fFirewallEnabled)
				detail = "Firewall on: internet access is blocked.";
			else
				detail = "Your traffic is not going through the VPN.";
			fConnectButton->SetLabel("Connect");
			fConnectButton->SetEnabled(fHelloReceived && !fServers.Empty());
			break;
	}

	fStatusView->SetStatus(level, headline.String(), detail.String());
	fProtocolField->SetEnabled(fState != kDisconnecting);
	fPortField->SetEnabled(fState != kDisconnecting);
}


void
MainWindow::_UpdateLocationButton()
{
	BString label;
	switch (fSettings.selection) {
		case ServerSelection::Fastest:
		{
			label = "Location: Fastest server";
			if (const Server* s = FindFastest(fServers.For(fSettings.vpnType),
					fPings)) {
				label << " (" << s->DisplayName().c_str() << ")";
			}
			break;
		}
		case ServerSelection::Random:
			label = "Location: Random server";
			break;
		case ServerSelection::Manual:
		{
			const Server* s = fServers.FindByGatewayId(fSettings.vpnType,
				fSettings.gatewayId);
			if (s == NULL) {
				label.SetToFormat("Location: %s", fServers.Empty()
					? fSettings.gatewayId.c_str()
					: "not available, choose another");
				break;
			}
			label.SetToFormat("Location: %s", s->DisplayName().c_str());
			int ping = ServerPing(*s, fPings);
			if (ping > 0)
				label << " (" << ping << " ms)";
			break;
		}
	}
	label << "  " B_UTF8_ELLIPSIS;
	fLocationButton->SetLabel(label.String());
	fLocationButton->SetEnabled(!fServers.Empty());
}


void
MainWindow::_UpdateProtocolControls()
{
	for (int32 i = 0; BMenuItem* item = fProtocolMenu->ItemAt(i); i++) {
		int32 type = item->Message()->GetInt32("type", -1);
		item->SetMarked(type == (int32)fSettings.vpnType);
		if (type == (int32)VpnType::WireGuard)
			item->SetEnabled(!fWireGuardDisabled);
	}

	while (BMenuItem* item = fPortMenu->RemoveItem((int32)0))
		delete item;

	std::vector<Port> ports = fServers.PortsFor(fSettings.vpnType);
	const Port& current = fSettings.PortFor(fSettings.vpnType);
	if (std::find(ports.begin(), ports.end(), current) == ports.end())
		ports.insert(ports.begin(), current);

	for (const Port& p : ports) {
		BMessage* msg = new BMessage(kMsgPortChanged);
		msg->AddInt32("port", p.port);
		msg->AddBool("tcp", p.tcp);
		BMenuItem* item = new BMenuItem(p.Label().c_str(), msg);
		item->SetMarked(p == current);
		fPortMenu->AddItem(item);
	}
}


void
MainWindow::_UpdateAccountLabel()
{
	BString text;
	if (!fAccountId.IsEmpty()) {
		text.SetToFormat("Account: %s", fAccountId.String());
		std::string plan = JStr(fAccount, "CurrentPlan");
		int64 until = JInt(fAccount, "ActiveUntil");
		if (!plan.empty())
			text << "  " "\xC2\xB7" "  " << plan.c_str();
		if (until > 0) {
			char date[64];
			time_t t = (time_t)until;
			struct tm tm;
			localtime_r(&t, &tm);
			strftime(date, sizeof(date), "%d %b %Y", &tm);
			text << (JBool(fAccount, "Active") ? ", active until "
				: ", expired ") << date;
		}
	}
	fAccountLabel->SetText(text);
}


std::vector<ServerEntry>
MainWindow::_ServerEntries() const
{
	std::vector<ServerEntry> entries;

	ServerEntry fastest;
	fastest.selection = (int32)ServerSelection::Fastest;
	fastest.name = "Fastest server";
	fastest.ping = -1;
	if (const Server* s = FindFastest(fServers.For(fSettings.vpnType), fPings))
		fastest.name << " (" << s->DisplayName().c_str() << ")";
	entries.push_back(fastest);

	ServerEntry random;
	random.selection = (int32)ServerSelection::Random;
	random.name = "Random server";
	random.ping = -1;
	entries.push_back(random);

	for (const Server& s : fServers.For(fSettings.vpnType)) {
		ServerEntry e;
		e.selection = (int32)ServerSelection::Manual;
		e.gatewayId = s.GatewayId().c_str();
		e.name = s.DisplayName().c_str();
		e.countryCode = s.countryCode.c_str();
		e.ping = ServerPing(s, fPings);
		entries.push_back(e);
	}
	return entries;
}


void
MainWindow::_UpdateServerWindow()
{
	if (!fServerWindow.IsValid())
		return;
	BMessage update(kMsgServerEntries);
	ServerListWindow::AddEntries(update, _ServerEntries());
	fServerWindow.SendMessage(&update);
}


void
MainWindow::_Notify(const char* title, const char* content)
{
	if (!fSettings.notifications || IsActive())
		return;
	BNotification notification(B_INFORMATION_NOTIFICATION);
	notification.SetGroup(IVPN_APP_NAME);
	notification.SetTitle(title);
	notification.SetContent(content);
	notification.Send();
}


BString
MainWindow::_SettingsPath() const
{
	BPath path;
	if (find_directory(B_USER_SETTINGS_DIRECTORY, &path, true) != B_OK)
		return BString("/tmp/IVPN_settings.json");
	path.Append("IVPN");
	create_directory(path.Path(), 0755);
	path.Append("settings.json");
	return BString(path.Path());
}


void
MainWindow::_SaveSettings()
{
	fSettings.Save(_SettingsPath().String());
}
