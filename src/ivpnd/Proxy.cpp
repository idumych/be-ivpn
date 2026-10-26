/*
 * ivpnd - the obfuscation proxies.
 * Distributed under the terms of the GNU GPL v3.
 */
#include "Proxy.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "DaemonLogic.h"

extern "C" char** environ;

namespace ivpnd {

const int kStartTimeoutSeconds = 15;


std::string
HelperPath(const char* name)
{
	const char* dir = getenv("IVPND_HELPERS");
	return std::string(dir != NULL ? dir : "/boot/system/apps/BeIVPN/helpers")
		+ "/" + name;
}


int
FreeUdpPort()
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t len = sizeof(addr);
	int port = 0;
	if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0
		&& getsockname(fd, (struct sockaddr*)&addr, &len) == 0)
		port = ntohs(addr.sin_port);
	close(fd);
	return port;
}


ProxyProcess::ProxyProcess()
	:
	fPid(-1),
	fReady(false),
	fExited(false),
	fStopping(false),
	fObfsVersion(0),
	fSocksPort(0)
{
}


ProxyProcess::~ProxyProcess()
{
	Stop();
}


bool
ProxyProcess::StartV2Ray(const std::string& config,
	std::function<void()> onExit, std::string& error)
{
	std::string binary = HelperPath("v2ray");
	const char* const argv[] = {binary.c_str(), "run", "-config",
		config.c_str(), NULL};
	{
		std::lock_guard<std::mutex> lock(fLock);
		fObfsVersion = 0;
		fOnExit = onExit;
	}
	if (!_Spawn(argv, "v2ray", NULL, error))
		return false;

	std::unique_lock<std::mutex> lock(fLock);
	fChanged.wait_for(lock, std::chrono::seconds(kStartTimeoutSeconds),
		[this]() { return fReady || fExited; });
	if (fReady)
		return true;
	error = fExited ? "V2Ray stopped right away (see the ivpnd log)."
		: "V2Ray did not start in time.";
	lock.unlock();
	Stop();
	return false;
}


int
ProxyProcess::StartObfsproxy(int version, const std::string& stateDir,
	std::function<void()> onExit, std::string& error)
{
	std::string binary = HelperPath("obfs4proxy");
	const char* const argv[] = {binary.c_str(), NULL};
	// Tor's managed transport protocol, as ivpn-service uses it
	std::string transports = "TOR_PT_CLIENT_TRANSPORTS=obfs"
		+ std::to_string(version);
	std::string state = "TOR_PT_STATE_LOCATION=" + stateDir;
	std::vector<std::string> envStrings;
	for (char** e = environ; *e != NULL; e++)
		envStrings.push_back(*e);
	envStrings.push_back("TOR_PT_MANAGED_TRANSPORT_VER=1");
	envStrings.push_back(transports);
	envStrings.push_back(state);
	std::vector<const char*> env;
	for (const std::string& s : envStrings)
		env.push_back(s.c_str());
	env.push_back(NULL);

	{
		std::lock_guard<std::mutex> lock(fLock);
		fObfsVersion = version;
		fSocksPort = 0;
		fOnExit = onExit;
	}
	if (!_Spawn(argv, "obfs4proxy", env.data(), error))
		return 0;

	std::unique_lock<std::mutex> lock(fLock);
	fChanged.wait_for(lock, std::chrono::seconds(kStartTimeoutSeconds),
		[this]() { return fReady || fExited; });
	if (fReady && fSocksPort > 0)
		return fSocksPort;
	error = fExited ? "obfs4proxy stopped right away (see the ivpnd log)."
		: "obfs4proxy did not start in time.";
	lock.unlock();
	Stop();
	return 0;
}


void
ProxyProcess::Stop()
{
	pid_t pid;
	{
		std::lock_guard<std::mutex> lock(fLock);
		pid = fPid;
		if (pid < 0 || fExited)
			return;
		fStopping = true;
	}
	kill(pid, SIGTERM);
	std::unique_lock<std::mutex> lock(fLock);
	if (!fChanged.wait_for(lock, std::chrono::seconds(3),
			[this]() { return fExited; })) {
		kill(pid, SIGKILL);
		fChanged.wait_for(lock, std::chrono::seconds(2),
			[this]() { return fExited; });
	}
}


bool
ProxyProcess::IsRunning() const
{
	std::lock_guard<std::mutex> lock(fLock);
	return fPid >= 0 && !fExited;
}


bool
ProxyProcess::_Spawn(const char* const argv[], const char* name,
	const char* const env[], std::string& error)
{
	if (access(argv[0], X_OK) != 0) {
		error = std::string(name) + " is not installed (" + argv[0] + ").";
		return false;
	}
	int pipeFds[2];
	if (pipe(pipeFds) != 0) {
		error = std::string("Could not start ") + name + ".";
		return false;
	}
	fcntl(pipeFds[0], F_SETFD, FD_CLOEXEC);

	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
		O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&actions, pipeFds[1], STDOUT_FILENO);
	posix_spawn_file_actions_adddup2(&actions, pipeFds[1], STDERR_FILENO);
	posix_spawn_file_actions_addclose(&actions, pipeFds[1]);
	pid_t pid = -1;
	int rc = posix_spawn(&pid, argv[0], &actions, NULL, (char* const*)argv,
		env != NULL ? (char* const*)env : environ);
	posix_spawn_file_actions_destroy(&actions);
	close(pipeFds[1]);
	if (rc != 0) {
		close(pipeFds[0]);
		error = std::string("Could not start ") + name + ": " + strerror(rc);
		return false;
	}
	printf("ivpnd: started %s (pid %d)\n", name, (int)pid);

	{
		std::lock_guard<std::mutex> lock(fLock);
		fPid = pid;
		fReady = false;
		fExited = false;
		fStopping = false;
	}
	std::thread(&ProxyProcess::_ReadOutput, this, pipeFds[0],
		std::string(name)).detach();
	return true;
}


void
ProxyProcess::_ReadOutput(int fd, std::string name)
{
	std::string buffer;
	char chunk[1024];
	while (true) {
		ssize_t n = read(fd, chunk, sizeof(chunk));
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		buffer.append(chunk, (size_t)n);
		size_t nl;
		while ((nl = buffer.find('\n')) != std::string::npos) {
			std::string line = buffer.substr(0, nl);
			buffer.erase(0, nl + 1);
			if (!line.empty() && line.back() == '\r')
				line.pop_back();
			printf("[%s] %s\n", name.c_str(), line.c_str());
			std::lock_guard<std::mutex> lock(fLock);
			if (fObfsVersion == 0) {
				// "V2Ray 5.12.1 started"
				if (line.find("V2Ray") != std::string::npos
					&& line.find(" started") != std::string::npos) {
					fReady = true;
					fChanged.notify_all();
				}
			} else {
				int port = ObfsproxySocksPort(line, fObfsVersion);
				if (port > 0)
					fSocksPort = port;
				if (line == "CMETHODS DONE") {
					fReady = true;
					fChanged.notify_all();
				}
			}
		}
	}
	close(fd);

	pid_t pid;
	{
		std::lock_guard<std::mutex> lock(fLock);
		pid = fPid;
	}
	int status = 0;
	if (pid >= 0)
		waitpid(pid, &status, 0);
	printf("ivpnd: %s exited\n", name.c_str());

	std::function<void()> onExit;
	{
		std::lock_guard<std::mutex> lock(fLock);
		bool unexpected = fReady && !fStopping;
		fExited = true;
		fPid = -1;
		if (unexpected)
			onExit = fOnExit;
		fChanged.notify_all();
	}
	if (onExit)
		onExit();
}

}	// namespace ivpnd
