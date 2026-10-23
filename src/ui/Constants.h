/*
 * IVPN for Vitruvian - shared constants.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPN_CONSTANTS_H
#define IVPN_CONSTANTS_H

#include <SupportDefs.h>

#define IVPN_APP_SIGNATURE	"application/x-vnd.IVPN-Client"
#define IVPN_APP_NAME		"IVPN"
#define IVPN_APP_VERSION	"1.0.0"

enum {
	// DaemonClient -> MainWindow
	kMsgDaemonLine			= 'dLin',	// "line": one JSON message
	kMsgDaemonClosed		= 'dCls',	// "reason"

	// timers
	kMsgTryConnectDaemon	= 'tCon',
	kMsgTick				= 'tTck',

	// main window controls
	kMsgConnectToggle		= 'mCon',
	kMsgChooseServer		= 'mSrv',
	kMsgProtocolChanged		= 'mPrt',
	kMsgPortChanged			= 'mPor',
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

	// ServerListWindow -> MainWindow
	kMsgServerChosen		= 'sChs',	// "selection" int32, "gateway" str
	kMsgServerWindowClosed	= 'sWCl',
	kMsgServerEntries		= 'sEnt',	// MainWindow -> ServerListWindow

	// ServerListWindow internal
	kMsgFilterChanged		= 'sFlt',
	kMsgServerInvoked		= 'sInv',
};

#endif	// IVPN_CONSTANTS_H
