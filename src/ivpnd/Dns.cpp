/*
 * ivpnd - points Haiku's resolver at the VPN's DNS while connected.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "Dns.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

namespace ivpnd {
namespace dns {

namespace {

const char* kResolvConf = "/boot/system/settings/network/resolv.conf";
const char* kBackup = "/boot/system/settings/network/resolv.conf.ivpn";


std::string
Content(const std::string& ip)
{
	return "# Set by IVPN while the VPN is connected\nnameserver " + ip + "\n";
}


bool
Exists(const char* path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

}	// namespace


bool
Apply(const std::string& ip)
{
	// Keep the first original: a backup left by an earlier session is the
	// real one, not the file we wrote over it.
	if (!Exists(kBackup) && Exists(kResolvConf)
		&& rename(kResolvConf, kBackup) != 0) {
		fprintf(stderr, "ivpnd: could not move %s aside\n", kResolvConf);
		return false;
	}

	std::string tmp = std::string(kResolvConf) + ".tmp";
	{
		std::ofstream out(tmp, std::ios::trunc);
		out << Content(ip);
		if (!out)
			return false;
	}
	if (rename(tmp.c_str(), kResolvConf) != 0)
		return false;
	printf("ivpnd: DNS -> %s\n", ip.c_str());
	return true;
}


bool
IsApplied(const std::string& ip)
{
	std::ifstream in(kResolvConf);
	std::stringstream ss;
	ss << in.rdbuf();
	return ss.str() == Content(ip);
}


void
Restore()
{
	if (!Exists(kBackup))
		return;
	if (rename(kBackup, kResolvConf) == 0)
		printf("ivpnd: DNS restored\n");
	else
		fprintf(stderr, "ivpnd: could not restore %s\n", kResolvConf);
}

}	// namespace dns
}	// namespace ivpnd
