/*
 * Be IVPN - location picker.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "ServerListWindow.h"

#include <algorithm>
#include <cmath>

#include <Button.h>
#include <ControlLook.h>
#include <LayoutBuilder.h>
#include <ListItem.h>
#include <ListView.h>
#include <ScrollView.h>
#include <TextControl.h>

#include "../core/Model.h"
#include "Constants.h"


namespace {

class ServerItem : public BListItem {
public:
	ServerItem(const ServerEntry& entry, bool current)
		:
		fEntry(entry),
		fCurrent(current)
	{
	}

	const ServerEntry& Entry() const { return fEntry; }

	virtual void Update(BView* owner, const BFont* font)
	{
		BListItem::Update(owner, font);
		font_height fh;
		font->GetHeight(&fh);
		SetHeight(ceilf((fh.ascent + fh.descent + fh.leading) * 1.9f));
	}

	virtual void DrawItem(BView* owner, BRect frame, bool /*complete*/)
	{
		rgb_color background = IsSelected()
			? ui_color(B_LIST_SELECTED_BACKGROUND_COLOR)
			: ui_color(B_LIST_BACKGROUND_COLOR);
		rgb_color text = IsSelected()
			? ui_color(B_LIST_SELECTED_ITEM_TEXT_COLOR)
			: ui_color(B_LIST_ITEM_TEXT_COLOR);

		owner->SetHighColor(background);
		owner->FillRect(frame);

		float spacing = be_control_look->DefaultLabelSpacing();
		font_height fh;
		owner->GetFontHeight(&fh);
		float baseline = frame.top + (frame.Height() + fh.ascent - fh.descent)
			/ 2;

		// country badge
		BFont font;
		owner->GetFont(&font);
		BFont small(font);
		small.SetSize(font.Size() * 0.8f);
		small.SetFace(B_BOLD_FACE);
		float badgeWidth = small.StringWidth("WWW");
		BRect badge(frame.left + spacing * 2, frame.top + frame.Height() * 0.22f,
			frame.left + spacing * 2 + badgeWidth,
			frame.bottom - frame.Height() * 0.22f);

		BString code = fEntry.countryCode;
		if (fEntry.selection == (int32)ivpn::ServerSelection::Fastest)
			code = "\xC2\xBB";	// "»"
		else if (fEntry.selection == (int32)ivpn::ServerSelection::Random)
			code = "?";

		owner->SetHighColor(tint_color(background, B_DARKEN_2_TINT));
		owner->FillRoundRect(badge, 3, 3);
		owner->SetHighColor(text);
		owner->SetFont(&small);
		font_height sfh;
		small.GetHeight(&sfh);
		owner->DrawString(code.String(),
			BPoint(badge.left + (badge.Width() - small.StringWidth(code)) / 2,
				badge.top + (badge.Height() + sfh.ascent - sfh.descent) / 2));

		// ping, right aligned
		BString ping;
		rgb_color pingColor = text;
		if (fEntry.ping > 0) {
			ping.SetToFormat("%d ms", (int)fEntry.ping);
			if (!IsSelected()) {
				pingColor = fEntry.ping < 100 ? make_color(46, 140, 67)
					: (fEntry.ping < 250 ? make_color(190, 130, 20)
						: make_color(190, 55, 55));
			}
		}
		owner->SetFont(&font);
		float pingWidth = font.StringWidth(ping.String());
		float right = frame.right - spacing * 2;
		if (ping.Length() > 0) {
			owner->SetHighColor(pingColor);
			owner->DrawString(ping.String(),
				BPoint(right - pingWidth, baseline));
		}

		// name (bold if it is the current choice)
		BFont nameFont(font);
		if (fCurrent)
			nameFont.SetFace(B_BOLD_FACE);
		owner->SetFont(&nameFont);
		owner->SetHighColor(text);
		float nameLeft = badge.right + spacing * 2;
		BString name = fEntry.name;
		nameFont.TruncateString(&name, B_TRUNCATE_END,
			right - pingWidth - spacing * 2 - nameLeft);
		owner->DrawString(name.String(), BPoint(nameLeft, baseline));
		owner->SetFont(&font);
	}

private:
	ServerEntry	fEntry;
	bool		fCurrent;
};

}	// namespace


ServerListWindow::ServerListWindow(BRect frame, BMessenger target,
	const std::vector<ServerEntry>& entries, int32 currentSelection,
	const BString& currentGateway)
	:
	BWindow(frame, "Choose location", B_TITLED_WINDOW,
		B_ASYNCHRONOUS_CONTROLS | B_AUTO_UPDATE_SIZE_LIMITS
			| B_CLOSE_ON_ESCAPE),
	fTarget(target),
	fEntries(entries),
	fCurrentSelection(currentSelection),
	fCurrentGateway(currentGateway)
{
	fSearch = new BTextControl("search", "Search:", "", NULL);
	fSearch->SetModificationMessage(new BMessage(kMsgFilterChanged));

	fList = new BListView("servers");
	fList->SetInvocationMessage(new BMessage(kMsgServerInvoked));
	BScrollView* scroll = new BScrollView("scroll", fList, 0, false, true);
	float em = be_plain_font->Size();
	scroll->SetExplicitMinSize(BSize(em * 22, em * 22));

	fChooseButton = new BButton("choose", "Connect here",
		new BMessage(kMsgServerInvoked));
	BButton* cancel = new BButton("cancel", "Cancel",
		new BMessage(B_QUIT_REQUESTED));

	BLayoutBuilder::Group<>(this, B_VERTICAL)
		.SetInsets(B_USE_WINDOW_SPACING)
		.Add(fSearch)
		.Add(scroll)
		.AddGroup(B_HORIZONTAL)
			.AddGlue()
			.Add(cancel)
			.Add(fChooseButton)
		.End();

	SetDefaultButton(fChooseButton);
	_Rebuild();
	fSearch->MakeFocus(true);
}


/*static*/ void
ServerListWindow::AddEntries(BMessage& message,
	const std::vector<ServerEntry>& entries)
{
	for (const ServerEntry& e : entries) {
		message.AddInt32("selection", e.selection);
		message.AddString("gateway", e.gatewayId);
		message.AddString("name", e.name);
		message.AddString("country", e.countryCode);
		message.AddInt32("ping", e.ping);
	}
}


/*static*/ std::vector<ServerEntry>
ServerListWindow::GetEntries(const BMessage& message)
{
	std::vector<ServerEntry> entries;
	ServerEntry e;
	for (int32 i = 0; message.FindInt32("selection", i, &e.selection) == B_OK;
			i++) {
		message.FindString("gateway", i, &e.gatewayId);
		message.FindString("name", i, &e.name);
		message.FindString("country", i, &e.countryCode);
		message.FindInt32("ping", i, &e.ping);
		entries.push_back(e);
	}
	return entries;
}


void
ServerListWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgFilterChanged:
			_Rebuild();
			break;
		case kMsgServerEntries:
			fEntries = GetEntries(*message);
			_Rebuild();
			break;
		case kMsgServerInvoked:
			_Choose();
			break;
		default:
			BWindow::MessageReceived(message);
	}
}


bool
ServerListWindow::QuitRequested()
{
	fTarget.SendMessage(kMsgServerWindowClosed);
	return true;
}


void
ServerListWindow::_Rebuild()
{
	// keep the highlighted row across rebuilds
	BString keepGateway;
	int32 keepSelection = -1;
	if (ServerItem* item = dynamic_cast<ServerItem*>(
			fList->ItemAt(fList->CurrentSelection()))) {
		keepGateway = item->Entry().gatewayId;
		keepSelection = item->Entry().selection;
	} else {
		keepGateway = fCurrentGateway;
		keepSelection = fCurrentSelection;
	}

	while (BListItem* item = fList->RemoveItem((int32)0))
		delete item;

	BString filter = fSearch->Text();
	filter.Trim();

	int32 select = -1;
	for (const ServerEntry& entry : fEntries) {
		bool special = entry.selection
			!= (int32)ivpn::ServerSelection::Manual;
		if (filter.Length() > 0) {
			if (special)
				continue;
			if (entry.name.IFindFirst(filter) < 0
				&& entry.countryCode.ICompare(filter) != 0)
				continue;
		}

		bool current = entry.selection == fCurrentSelection
			&& (special || entry.gatewayId == fCurrentGateway);
		fList->AddItem(new ServerItem(entry, current));

		if (entry.selection == keepSelection
			&& (special || entry.gatewayId == keepGateway))
			select = fList->CountItems() - 1;
	}

	if (select < 0 && fList->CountItems() > 0 && filter.Length() > 0)
		select = 0;
	if (select >= 0) {
		fList->Select(select);
		fList->ScrollToSelection();
	}
	fChooseButton->SetEnabled(fList->CountItems() > 0);
}


void
ServerListWindow::_Choose()
{
	ServerItem* item = dynamic_cast<ServerItem*>(
		fList->ItemAt(fList->CurrentSelection()));
	if (item == NULL)
		return;

	BMessage chosen(kMsgServerChosen);
	chosen.AddInt32("selection", item->Entry().selection);
	chosen.AddString("gateway", item->Entry().gatewayId);
	fTarget.SendMessage(&chosen);
	PostMessage(B_QUIT_REQUESTED);
}
