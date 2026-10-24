/*
 * ivpnd - points Haiku's resolver at the VPN's DNS while connected.
 *
 * The original resolv.conf is moved aside once, so a crash can't leave name
 * resolution stuck on a dead tunnel: Restore() at startup puts it back.
 * Distributed under the terms of the GNU GPL v3.
 */
#ifndef IVPND_DNS_H
#define IVPND_DNS_H

#include <string>

namespace ivpnd {
namespace dns {

// Writes "nameserver <ip>". Returns false when the file can't be written.
bool	Apply(const std::string& ip);
// True when resolv.conf still says what Apply() wrote (DHCP may rewrite it).
bool	IsApplied(const std::string& ip);
// Puts the original resolv.conf back, if we moved it aside.
void	Restore();

}	// namespace dns
}	// namespace ivpnd

#endif	// IVPND_DNS_H
