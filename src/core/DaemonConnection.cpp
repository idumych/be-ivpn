/*
 * IVPN for Vitruvian - connection to the IVPN daemon (ivpn-service).
 * Distributed under the terms of the GNU GPL v3.
 */
#include "DaemonConnection.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

namespace ivpn {

DaemonConnection::DaemonConnection()
	:
	fSocket(-1),
	fSecret(0),
	fNextIdx(1),
	fClosing(false)
{
}


DaemonConnection::~DaemonConnection()
{
	Close();
}


std::vector<std::string>
DaemonConnection::PortFileCandidates()
{
#ifdef IVPN_HAIKU
	// ivpnd, the app's own service (Haiku's user settings directory)
	const char* home = getenv("HOME");
	return {std::string(home != nullptr ? home : "/boot/home")
		+ "/config/settings/IVPN/daemon/port.txt"};
#endif
	// Same lookup order as the official ivpn CLI / UI on Linux.
	return {
		"/etc/opt/ivpn/mutable/port.txt",
		"/opt/ivpn/mutable/port.txt",
		"/var/snap/ivpn/common/opt/ivpn/mutable/port.txt",
	};
}


bool
DaemonConnection::ParsePortFileContent(const std::string& content, int& port,
	uint64_t& secret)
{
	size_t colon = content.find(':');
	if (colon == std::string::npos || content.find(':', colon + 1)
			!= std::string::npos)
		return false;

	std::string portStr = content.substr(0, colon);
	std::string secretStr = content.substr(colon + 1);

	auto trim = [](std::string& s) {
		const char* ws = " \t\r\n";
		size_t b = s.find_first_not_of(ws);
		size_t e = s.find_last_not_of(ws);
		s = (b == std::string::npos) ? std::string() : s.substr(b, e - b + 1);
	};
	trim(portStr);
	trim(secretStr);
	if (portStr.empty() || secretStr.empty() || secretStr.size() > 16)
		return false;

	char* end = nullptr;
	errno = 0;
	long p = strtol(portStr.c_str(), &end, 10);
	if (errno != 0 || *end != '\0' || p <= 0 || p > 65535)
		return false;

	end = nullptr;
	errno = 0;
	unsigned long long s = strtoull(secretStr.c_str(), &end, 16);
	if (errno != 0 || *end != '\0')
		return false;

	port = (int)p;
	secret = (uint64_t)s;
	return true;
}


bool
DaemonConnection::ReadPortFile(PortInfo& info, std::string& error,
	const std::vector<std::string>& candidates)
{
	bool anyExists = false;
	for (const std::string& path : candidates) {
		std::ifstream file(path);
		if (!file.good()) {
			if (access(path.c_str(), F_OK) == 0) {
				anyExists = true;
				error = "Cannot read " + path + " (permission denied?)";
			}
			continue;
		}
		anyExists = true;
		std::stringstream buffer;
		buffer << file.rdbuf();
		int port = 0;
		uint64_t secret = 0;
		if (!ParsePortFileContent(buffer.str(), port, secret)) {
			error = "Unexpected content in " + path;
			continue;
		}
		info.port = port;
		info.secret = secret;
		info.path = path;
		return true;
	}

	if (!anyExists)
		error = "The IVPN service is not running (no connection file found).";
	return false;
}


bool
DaemonConnection::Connect(const PortInfo& info, LineCallback onLine,
	ClosedCallback onClosed, std::string& error, int timeoutMs)
{
	Close();

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		error = std::string("socket(): ") + strerror(errno);
		return false;
	}

	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((uint16_t)info.port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	int rc = connect(fd, (sockaddr*)&addr, sizeof(addr));
	if (rc < 0 && errno != EINPROGRESS) {
		error = std::string("Cannot connect to IVPN service: ")
			+ strerror(errno);
		close(fd);
		return false;
	}
	if (rc < 0) {
		pollfd pfd = { fd, POLLOUT, 0 };
		rc = poll(&pfd, 1, timeoutMs);
		if (rc <= 0) {
			error = "Timed out connecting to the IVPN service.";
			close(fd);
			return false;
		}
		int soError = 0;
		socklen_t len = sizeof(soError);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len);
		if (soError != 0) {
			error = std::string("Cannot connect to IVPN service: ")
				+ strerror(soError);
			close(fd);
			return false;
		}
	}

	// back to blocking mode for simple send/recv
	fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	fSocket = fd;
	fSecret = info.secret;
	fClosing = false;
	fOnLine = std::move(onLine);
	fOnClosed = std::move(onClosed);
	fReader = std::thread(&DaemonConnection::_ReaderLoop, this);
	return true;
}


uint32_t
DaemonConnection::SendHello(const std::string& clientVersion, int clientType)
{
	nlohmann::json hello = {
		{"Command", "Hello"},
		{"ClientType", clientType},
		{"Version", clientVersion},
		{"Secret", fSecret},	// uint64, must be sent as a JSON number
		{"GetServersList", true},
		{"GetStatus", true},
	};
	return Send(std::move(hello));
}


uint32_t
DaemonConnection::Send(nlohmann::json request)
{
	if (fSocket < 0 || !request.contains("Command"))
		return 0;

	uint32_t idx = fNextIdx.fetch_add(1);
	if (idx == 0)
		idx = fNextIdx.fetch_add(1);	// 0 means "no index"

	request["Idx"] = idx;
	if (!request.contains("ProtocolSecret"))
		request["ProtocolSecret"] = "";

	std::string line;
	try {
		// 'replace' keeps us from throwing on odd user input
		line = request.dump(-1, ' ', false,
			nlohmann::json::error_handler_t::replace);
	} catch (...) {
		return 0;
	}
	line.push_back('\n');

	std::lock_guard<std::mutex> lock(fSendLock);
	const char* data = line.data();
	size_t left = line.size();
	while (left > 0) {
		ssize_t sent = ::send(fSocket, data, left, MSG_NOSIGNAL);
		if (sent < 0) {
			if (errno == EINTR)
				continue;
			return 0;
		}
		data += sent;
		left -= (size_t)sent;
	}
	return idx;
}


void
DaemonConnection::Close()
{
	fClosing = true;
	if (fSocket >= 0)
		shutdown(fSocket, SHUT_RDWR);

	if (fReader.joinable()) {
		if (fReader.get_id() == std::this_thread::get_id())
			fReader.detach();	// called from a callback
		else
			fReader.join();
	}

	if (fSocket >= 0) {
		close(fSocket);
		fSocket = -1;
	}
}


void
DaemonConnection::_ReaderLoop()
{
	std::string buffer;
	char chunk[16384];
	std::string reason = "The IVPN service closed the connection.";

	for (;;) {
		ssize_t got = recv(fSocket, chunk, sizeof(chunk), 0);
		if (got == 0)
			break;
		if (got < 0) {
			if (errno == EINTR)
				continue;
			reason = std::string("Connection to IVPN service lost: ")
				+ strerror(errno);
			break;
		}

		buffer.append(chunk, (size_t)got);
		size_t start = 0;
		for (;;) {
			size_t nl = buffer.find('\n', start);
			if (nl == std::string::npos)
				break;
			if (nl > start && fOnLine)
				fOnLine(buffer.substr(start, nl - start));
			start = nl + 1;
		}
		buffer.erase(0, start);
	}

	if (!fClosing && fOnClosed)
		fOnClosed(reason);
}

}	// namespace ivpn
