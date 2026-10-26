/*
 * Be IVPN - location picker: searchable list of servers with
 * their latency, plus "Fastest" and "Random".
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_SERVER_LIST_WINDOW_H
#define IVPN_SERVER_LIST_WINDOW_H

#include <Messenger.h>
#include <String.h>
#include <Window.h>

#include <string>
#include <vector>

class BButton;
class BListView;
class BTextControl;

struct ServerEntry {
	int32		selection;		// ivpn::ServerSelection value
	BString		gatewayId;		// for manual selection
	BString		name;			// "Amsterdam, Netherlands"
	BString		countryCode;	// "NL"
	int32		ping;			// ms, -1 unknown
};

class ServerListWindow : public BWindow {
public:
							ServerListWindow(BRect frame, BMessenger target,
								const std::vector<ServerEntry>& entries,
								int32 currentSelection,
								const BString& currentGateway);

	// Entries travel between windows inside a BMessage (kMsgServerEntries)
	static void				AddEntries(BMessage& message,
								const std::vector<ServerEntry>& entries);
	static std::vector<ServerEntry> GetEntries(const BMessage& message);

	virtual void			MessageReceived(BMessage* message);
	virtual bool			QuitRequested();

private:
	void					_Rebuild();
	void					_Choose();

	BMessenger				fTarget;
	std::vector<ServerEntry> fEntries;
	int32					fCurrentSelection;
	BString					fCurrentGateway;

	BTextControl*			fSearch;
	BListView*				fList;
	BButton*				fChooseButton;
};

#endif	// IVPN_SERVER_LIST_WINDOW_H
