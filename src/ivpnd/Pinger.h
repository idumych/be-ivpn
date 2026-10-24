/*
 * ivpnd - ICMP echo to many hosts at once, for the location list's
 * latencies and "Fastest". Needs a raw socket (Haiku's user is root).
 *
 * No Be/Haiku API dependency.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPND_PINGER_H
#define IVPND_PINGER_H

#include <map>
#include <string>
#include <vector>

namespace ivpnd {

// Pings every IPv4 address in 'hosts' once and waits up to 'timeoutMs' for
// the replies. Returns host -> round trip in ms (at least 1) for each host
// that answered. 'error' is set when no raw socket could be opened.
std::map<std::string, int> PingHosts(const std::vector<std::string>& hosts,
	int timeoutMs, std::string& error);

}	// namespace ivpnd

#endif	// IVPND_PINGER_H
