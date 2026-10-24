/*
 * IVPN for Vitruvian - shared constants.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_CONSTANTS_H
#define IVPN_CONSTANTS_H

#include <SupportDefs.h>

#define IVPN_APP_SIGNATURE	"application/x-vnd.IVPN-Client"
#define IVPN_APP_NAME		"IVPN"
#define IVPN_APP_VERSION	"1.0.2"

// The Deskbar item: an add-on library Deskbar loads (see src/deskbar)
#define IVPN_DESKBAR_ITEM_NAME	"IVPN"
#define IVPN_DESKBAR_ADDON_PATH	"/system/add-ons/ivpn-vitruvian/IVPNDeskbar.so"
// Present (in B_USER_SETTINGS_DIRECTORY) when the user removed the Deskbar
// item; otherwise the app puts it back at launch, e.g. after an upgrade.
#define IVPN_DESKBAR_HIDDEN_FILE	"IVPN/deskbar_hidden"

enum {
	// DaemonClient -> MainWindow
	kMsgDaemonLine			= 'dLin',	// "line": one JSON message
	kMsgDaemonClosed		= 'dCls',	// "reason"

	// timers
	kMsgTryConnectDaemon	= 'tCon',
	kMsgTick				= 'tTck',
	kMsgPingTimeout			= 'tPng',	// stop waiting to connect

	// main window controls
	kMsgConnectToggle		= 'mCon',
	kMsgChooseServer		= 'mSrv',
	kMsgProtocolChanged		= 'mPrt',
	kMsgPortChanged			= 'mPor',
	kMsgObfsChanged			= 'mObf',	// "index" int32 into the choices
	kMsgFirewallToggle		= 'mFw ',
	kMsgFirewallOnConnect	= 'mFwC',
	kMsgAntiTracker			= 'mAT ',
	kMsgAntiTrackerHard		= 'mATH',
	kMsgNotifications		= 'mNtf',
	kMsgLogin				= 'mLgi',
	kMsgLogout				= 'mLgo',
	kMsgRetryDaemon			= 'mRtr',
	kMsgRefreshServers		= 'mRfS',
	kMsgPingServers			= 'mPng',
	kMsgOpenAccountPage		= 'mWeb',
	kMsgDeskbarToggle		= 'mDsk',

	// Deskbar item -> application (also as a launch message)
	kMsgConnectWhenReady	= 'aCon',

	// ServerListWindow -> MainWindow
	kMsgServerChosen		= 'sChs',	// "selection" int32, "gateway" str
	kMsgServerWindowClosed	= 'sWCl',
	kMsgServerEntries		= 'sEnt',	// MainWindow -> ServerListWindow

	// ServerListWindow internal
	kMsgFilterChanged		= 'sFlt',
	kMsgServerInvoked		= 'sInv',
};

#endif	// IVPN_CONSTANTS_H
