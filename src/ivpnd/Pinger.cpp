/*
 * ivpnd - ICMP echo to many hosts at once.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "Pinger.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>

namespace ivpnd {

namespace {

typedef std::chrono::steady_clock Clock;

uint16_t
Checksum(const uint8_t* data, size_t length)
{
	uint32_t sum = 0;
	for (size_t i = 0; i + 1 < length; i += 2)
		sum += (uint32_t)(data[i] << 8 | data[i + 1]);
	if (length & 1)
		sum += (uint32_t)(data[length - 1] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons((uint16_t)~sum);
}

}	// namespace


std::map<std::string, int>
PingHosts(const std::vector<std::string>& hosts, int timeoutMs,
	std::string& error)
{
	std::map<std::string, int> results;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		error = std::string("Cannot ping: ") + strerror(errno);
		return results;
	}

	uint16_t id = (uint16_t)(getpid() ^ (uintptr_t)&results);
	std::map<uint16_t, std::string> bySeq;
	std::map<std::string, Clock::time_point> sentAt;

	auto receive = [&](int waitMs) {
		struct pollfd pfd = {sock, POLLIN, 0};
		while (poll(&pfd, 1, waitMs) > 0) {
			uint8_t buf[1500];
			struct sockaddr_in from;
			socklen_t fromLen = sizeof(from);
			ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
				(struct sockaddr*)&from, &fromLen);
			Clock::time_point now = Clock::now();
			waitMs = 0;
			if (n < 8)
				continue;
			// Raw IPv4 sockets deliver the IP header first.
			size_t off = 0;
			if ((buf[0] >> 4) == 4)
				off = (size_t)(buf[0] & 0x0f) * 4;
			if ((size_t)n < off + 8 || buf[off] != 0)	// 0 = echo reply
				continue;
			uint16_t rid = (uint16_t)(buf[off + 4] << 8 | buf[off + 5]);
			uint16_t seq = (uint16_t)(buf[off + 6] << 8 | buf[off + 7]);
			auto host = bySeq.find(seq);
			if (rid != id || host == bySeq.end())
				continue;
			if (results.count(host->second) != 0)
				continue;
			auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				now - sentAt[host->second]).count();
			results[host->second] = ms < 1 ? 1 : (int)ms;
		}
	};

	uint16_t seq = 1;
	for (const std::string& host : hosts) {
		struct sockaddr_in to;
		memset(&to, 0, sizeof(to));
		to.sin_family = AF_INET;
		if (inet_pton(AF_INET, host.c_str(), &to.sin_addr) != 1)
			continue;

		uint8_t packet[16];
		memset(packet, 0, sizeof(packet));
		packet[0] = 8;	// echo request
		packet[4] = (uint8_t)(id >> 8);
		packet[5] = (uint8_t)id;
		packet[6] = (uint8_t)(seq >> 8);
		packet[7] = (uint8_t)seq;
		memcpy(packet + 8, "ivpnd-hk", 8);
		uint16_t sum = Checksum(packet, sizeof(packet));
		memcpy(packet + 2, &sum, 2);

		bySeq[seq] = host;
		sentAt[host] = Clock::now();
		sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&to,
			sizeof(to));
		seq++;
		// Spread the burst a little and pick up early replies, so a few
		// hundred requests don't arrive at the router all at once.
		receive(0);
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}

	Clock::time_point deadline = Clock::now()
		+ std::chrono::milliseconds(timeoutMs);
	while (results.size() < bySeq.size()) {
		auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
			deadline - Clock::now()).count();
		if (left <= 0)
			break;
		receive((int)left);
	}

	close(sock);
	return results;
}

}	// namespace ivpnd
