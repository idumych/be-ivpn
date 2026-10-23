/*
 * IVPN for Vitruvian - the Deskbar item.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "DeskbarView.h"

#include <algorithm>

#include <Deskbar.h>
#include <MenuItem.h>
#include <MessageRunner.h>
#include <PopUpMenu.h>
#include <Roster.h>
#include <Window.h>

#include "../core/Requests.h"
#include "../ui/Constants.h"
#include "../ui/DaemonClient.h"

using nlohmann::json;
using namespace ivpn;

enum {
	kMsgRetry		= 'dRty',
	kMsgOpenApp		= 'dOpn',
	kMsgConnect		= 'dCon',
	kMsgDisconnect	= 'dDis',
	kMsgRemove		= 'dRem',
};

static const bigtime_t kRetryDelay = 5000000;	// 5 s

// same colours as the status lamp in the IVPN window
static const rgb_color kGreen = {46, 160, 67, 255};
static const rgb_color kAmber = {222, 152, 20, 255};
static const rgb_color kRed = {200, 55, 55, 255};
static const rgb_color kGrey = {150, 150, 150, 255};


static std::string
JStr(const json& j, const char* key)
{
	if (!j.is_object())
		return std::string();
	auto it = j.find(key);
	return it != j.end() && it->is_string() ? it->get<std::string>()
		: std::string();
}


static int
JInt(const json& j, const char* key, int fallback = 0)
{
	if (!j.is_object())
		return fallback;
	auto it = j.find(key);
	return it != j.end() && it->is_number() ? it->get<int>() : fallback;
}


static bool
JBool(const json& j, const char* key)
{
	if (!j.is_object())
		return false;
	auto it = j.find(key);
	return it != j.end() && it->is_boolean() && it->get<bool>();
}


// #pragma mark -


IVPNDeskbarView::IVPNDeskbarView(BRect frame)
	:
	BView(frame, IVPN_DESKBAR_ITEM_NAME, B_FOLLOW_NONE, B_WILL_DRAW)
{
	_Init();
}


IVPNDeskbarView::IVPNDeskbarView(BMessage* archive)
	:
	BView(archive)
{
	_Init();
}


IVPNDeskbarView::~IVPNDeskbarView()
{
	delete fRetryRunner;
	delete fDaemon;
}


void
IVPNDeskbarView::_Init()
{
	fDaemon = NULL;
	fRetryRunner = NULL;
	fState = kNoService;
	fFirewall = false;
	fType = VpnType::WireGuard;
}


BArchivable*
IVPNDeskbarView::Instantiate(BMessage* archive)
{
	if (!validate_instantiation(archive, "IVPNDeskbarView"))
		return NULL;
	return new IVPNDeskbarView(archive);
}


status_t
IVPNDeskbarView::Archive(BMessage* data, bool deep) const
{
	// "class" (added by BArchivable) lets Deskbar find Instantiate() in
	// this add-on, which stays loaded; no state needs saving.
	return BView::Archive(data, deep);
}


void
IVPNDeskbarView::AttachedToWindow()
{
	BView::AttachedToWindow();
	AdoptParentColors();
	SetLowColor(ViewColor());

	fDaemon = new DaemonClient(BMessenger(this));
	_TryConnect();
}


void
IVPNDeskbarView::DetachedFromWindow()
{
	delete fRetryRunner;
	fRetryRunner = NULL;
	if (fDaemon != NULL)
		fDaemon->Disconnect();
	BView::DetachedFromWindow();
}


void
IVPNDeskbarView::Draw(BRect updateRect)
{
	BRect bounds = Bounds();
	FillRect(bounds, B_SOLID_LOW);

	rgb_color color = kGrey;
	switch (fState) {
		case kConnected:	color = kGreen; break;
		case kConnecting:	color = kAmber; break;
		case kDisconnected:	color = kRed; break;
		default:			break;
	}

	float size = std::min(bounds.Width(), bounds.Height()) - 3;
	BRect lamp(0, 0, size, size);
	lamp.OffsetTo(bounds.left + (bounds.Width() - size) / 2,
		bounds.top + (bounds.Height() - size) / 2);

	SetDrawingMode(B_OP_ALPHA);
	SetHighColor(color);
	FillEllipse(lamp);
	SetHighColor(tint_color(color, B_DARKEN_2_TINT));
	StrokeEllipse(lamp);
	// small highlight, like the lamp in the window
	BRect shine(lamp.left + size * 0.25f, lamp.top + size * 0.2f,
		lamp.left + size * 0.5f, lamp.top + size * 0.45f);
	SetHighColor(255, 255, 255, 110);
	FillEllipse(shine);
	SetDrawingMode(B_OP_COPY);
}


void
IVPNDeskbarView::MouseDown(BPoint where)
{
	int32 buttons = B_PRIMARY_MOUSE_BUTTON;
	if (Window()->CurrentMessage() != NULL)
		Window()->CurrentMessage()->FindInt32("buttons", &buttons);

	if ((buttons & B_SECONDARY_MOUSE_BUTTON) != 0)
		_ShowMenu(where);
	else
		be_roster->Launch(IVPN_APP_SIGNATURE);
}


void
IVPNDeskbarView::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgDaemonLine:
		{
			const char* line;
			if (message->FindString("line", &line) == B_OK)
				_HandleLine(line);
			break;
		}

		case kMsgDaemonClosed:
			fDaemon->Disconnect();
			_SetState(kNoService);
			_ScheduleRetry();
			break;

		case kMsgRetry:
			_TryConnect();
			break;

		case kMsgOpenApp:
			be_roster->Launch(IVPN_APP_SIGNATURE);
			break;

		case kMsgConnect:
		{
			// the window has the settings and server choice; it connects
			// as soon as it is ready (launched first when needed)
			BMessage connect(kMsgConnectWhenReady);
			be_roster->Launch(IVPN_APP_SIGNATURE, &connect);
			break;
		}

		case kMsgDisconnect:
			fDaemon->Send(req::Disconnect());
			break;

		case kMsgRemove:
			BDeskbar().RemoveItem(IVPN_DESKBAR_ITEM_NAME);
			break;

		default:
			BView::MessageReceived(message);
	}
}


// #pragma mark -


void
IVPNDeskbarView::_TryConnect()
{
	delete fRetryRunner;
	fRetryRunner = NULL;

	BString error;
	// ClientType 3 ("other"): the daemon treats only the window as its UI
	if (!fDaemon->Connect(error, IVPN_APP_VERSION ":Vitruvian Deskbar", 3)) {
		_SetState(kNoService);
		_ScheduleRetry();
	}
}


void
IVPNDeskbarView::_ScheduleRetry()
{
	delete fRetryRunner;
	BMessage retry(kMsgRetry);
	fRetryRunner = new BMessageRunner(BMessenger(this), &retry, kRetryDelay, 1);
}


void
IVPNDeskbarView::_HandleLine(const char* line)
{
	json m = json::parse(line, nullptr, false);
	if (m.is_discarded() || !m.is_object())
		return;

	std::string command = JStr(m, "Command");
	if (command == "HelloResp") {
		// also sent to every client when the session changes (log in/out)
		bool loggedIn = !JStr(m.value("Session", json::object()),
			"AccountID").empty();
		if (!loggedIn)
			_SetState(kLoggedOut);
		else if (fState == kLoggedOut || fState == kNoService)
			_SetState(kDisconnected);	// the real state follows
	} else if (command == "ServerListResp") {
		fServers = ParseServerList(m.value("VpnServers", json::object()));
		_SetState(fState);	// may resolve the server name
	} else if (command == "ConnectedResp") {
		fServerIp = JStr(m, "ServerIP");
		fType = (VpnType)JInt(m, "VpnType", (int)VpnType::WireGuard);
		fObfs = ConnectedObfuscation(m);
		_SetState(kConnected);
	} else if (command == "DisconnectedResp") {
		if (fState != kLoggedOut)
			_SetState(kDisconnected);
	} else if (command == "VpnStateResp") {
		int stateVal = JInt(m, "StateVal");
		if (fState != kLoggedOut && stateVal != kStateConnected
			&& stateVal != kStateDisconnected)
			_SetState(kConnecting);
	} else if (command == "KillSwitchStatusResp") {
		fFirewall = JBool(m, "IsEnabled");
		_SetState(fState);
	} else if (command == "ServiceExitingResp") {
		_SetState(kNoService);
	}
}


void
IVPNDeskbarView::_SetState(State state)
{
	fState = state;
	BString tip = _Headline();
	BString detail = _Detail();
	if (!detail.IsEmpty())
		tip << "\n" << detail;
	SetToolTip(tip.String());
	Invalidate();
}


BString
IVPNDeskbarView::_Headline() const
{
	switch (fState) {
		case kConnected:	return "IVPN: Protected";
		case kConnecting:	return "IVPN: Connecting" B_UTF8_ELLIPSIS;
		case kDisconnected:	return "IVPN: Not protected";
		case kLoggedOut:	return "IVPN: Not logged in";
		case kNoService:	break;
	}
	return "IVPN: Service not running";
}


BString
IVPNDeskbarView::_Detail() const
{
	BString detail;
	if (fState == kConnected) {
		const Server* server = fServers.FindByHost(fServerIp);
		detail = server != NULL ? server->DisplayName().c_str()
			: fServerIp.c_str();
		detail << " " "\xC2\xB7" " "
			<< (fType == VpnType::WireGuard ? "WireGuard" : "OpenVPN");
		if (!fObfs.IsOff())
			detail << " + " << fObfs.Label().c_str();
	} else if (fState == kDisconnected && fFirewall)
		detail = "Firewall on: internet access is blocked";
	return detail;
}


void
IVPNDeskbarView::_ShowMenu(BPoint where)
{
	BPopUpMenu* menu = new BPopUpMenu("ivpn", false, false);
	menu->SetFont(be_plain_font);

	BMenuItem* headline = new BMenuItem(_Headline().String(), NULL);
	headline->SetEnabled(false);
	menu->AddItem(headline);
	BString detail = _Detail();
	if (!detail.IsEmpty()) {
		BMenuItem* item = new BMenuItem(detail.String(), NULL);
		item->SetEnabled(false);
		menu->AddItem(item);
	}
	menu->AddSeparatorItem();

	if (fState == kConnected || fState == kConnecting) {
		menu->AddItem(new BMenuItem("Disconnect", new BMessage(kMsgDisconnect)));
	} else {
		BMenuItem* connect = new BMenuItem("Connect", new BMessage(kMsgConnect));
		connect->SetEnabled(fState == kDisconnected);
		menu->AddItem(connect);
	}
	menu->AddItem(new BMenuItem("Open IVPN", new BMessage(kMsgOpenApp)));
	menu->AddSeparatorItem();
	menu->AddItem(new BMenuItem("Remove from Deskbar",
		new BMessage(kMsgRemove)));

	menu->SetTargetForItems(this);
	ConvertToScreen(&where);
	menu->SetAsyncAutoDestruct(true);
	menu->Go(where, true, true, true);
}


// #pragma mark - add-on entry point


extern "C" _EXPORT BView*
instantiate_deskbar_item(float maxWidth, float maxHeight)
{
	float size = std::min(maxWidth, maxHeight);
	return new IVPNDeskbarView(BRect(0, 0, size - 1, size - 1));
}
