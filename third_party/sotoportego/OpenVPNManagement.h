/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef OPENVPN_MANAGEMENT_H
#define OPENVPN_MANAGEMENT_H


#include <stdint.h>

#include <string>
#include <vector>

#include "VPNState.h"


// Parser and command builder for the OpenVPN "management interface".
//
// When openvpn is started with `--management <addr> <port>` it exposes a
// line-based control protocol on a socket. Asynchronous notifications are
// prefixed with '>' (>STATE:, >BYTECOUNT:, >PASSWORD:, >HOLD:, >LOG:, ...),
// while command replies are plain lines (SUCCESS:, ERROR:, END, ...).
//
// This module is deliberately free of any BeAPI dependency: it speaks only in
// std::string and the platform-neutral VPNState enum, so the protocol logic
// can be unit-tested on any host (see tests/). On Haiku the backend owns a
// BSocket, reads bytes from it, and feeds them to OpenVPNManagement::Feed();
// the parsed events are what drive the VPN state machine.
//
// Reference: OpenVPN management-interface notes, "doc/management-notes.txt".


enum OpenVPNEventType {
	// >STATE: a connection-stage change (CONNECTING, AUTH, CONNECTED, ...).
	OPENVPN_EVENT_STATE,
	// >BYTECOUNT: cumulative tunnel throughput.
	OPENVPN_EVENT_BYTECOUNT,
	// >PASSWORD:Need '<realm>' ... : credentials are required.
	OPENVPN_EVENT_PASSWORD_REQUEST,
	// >PASSWORD:Verification Failed ... : auth was rejected.
	OPENVPN_EVENT_AUTH_FAILED,
	// >HOLD: openvpn is paused waiting for "hold release".
	OPENVPN_EVENT_HOLD,
	// >LOG: a log line.
	OPENVPN_EVENT_LOG,
	// >INFO: an informational line emitted right after connecting.
	OPENVPN_EVENT_INFO,
	// >FATAL: a fatal error; the process is about to exit.
	OPENVPN_EVENT_FATAL,
	// A plain "SUCCESS: ..." command reply.
	OPENVPN_EVENT_SUCCESS,
	// A plain "ERROR: ..." command reply.
	OPENVPN_EVENT_ERROR,
	// Anything not (yet) recognised; raw is always populated.
	OPENVPN_EVENT_UNKNOWN
};


// A single parsed management-interface line. Only the fields relevant to the
// event's type are meaningful; the rest keep their default values.
struct OpenVPNEvent {
								OpenVPNEvent();

			OpenVPNEventType	type;
			std::string			raw;			// the original line, sans EOL

	// OPENVPN_EVENT_STATE:
			std::string			stateName;		// e.g. "CONNECTED"
			std::string			stateDetail;	// description field
			std::string			localIP;		// VPN-assigned local address
			std::string			remoteIP;		// server address
			VPNState			mappedState;	// stateName mapped to VPNState

	// OPENVPN_EVENT_BYTECOUNT:
			uint64_t			bytesIn;
			uint64_t			bytesOut;

	// OPENVPN_EVENT_PASSWORD_REQUEST / AUTH_FAILED:
			std::string			realm;			// e.g. "Auth"

	// OPENVPN_EVENT_LOG / INFO / FATAL / SUCCESS / ERROR:
			std::string			message;
};


class OpenVPNManagement {
public:
	// Parse exactly one complete line (no trailing CR/LF) into an event.
	static	OpenVPNEvent		ParseLine(const std::string& line);

	// Map an OpenVPN state name ("CONNECTED", "AUTH", ...) to a VPNState.
	static	VPNState			StateForName(const std::string& name);

	// Incremental reader: append a chunk of received bytes and return every
	// complete line it now contains as a parsed event. Partial trailing data
	// is buffered until the rest arrives. Handles both "\n" and "\r\n".
			std::vector<OpenVPNEvent>
								Feed(const std::string& chunk);

	// --- Outgoing command builders (each returns a line WITHOUT EOL) -------
	// Callers append "\n" when writing to the socket.
	static	std::string			CommandStateOn();
	static	std::string			CommandByteCount(int intervalSeconds);
	static	std::string			CommandHoldRelease();
	static	std::string			CommandUsername(const std::string& realm,
									const std::string& username);
	static	std::string			CommandPassword(const std::string& realm,
									const std::string& password);
	static	std::string			CommandSignalTerm();

private:
	static	std::string			_Escape(const std::string& value);

			std::string			fBuffer;
};


#endif	// OPENVPN_MANAGEMENT_H
