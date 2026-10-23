#!/bin/sh
# Builds and runs the core tests on any Linux machine (no Vitruvian needed).
# Optional: IVPN_GOCHECK=<path to gocheck binary> to verify our JSON against
# the real IVPN daemon types.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'kill $DAEMON_PID 2>/dev/null; rm -rf "$WORK"' EXIT

g++ -std=c++17 -Wall -Wextra -O1 -g -fsanitize=address,undefined -pthread \
	"$HERE/core_test.cpp" "$HERE/../src/core/DaemonConnection.cpp" \
	"$HERE/../src/core/Model.cpp" -o "$WORK/core_test"

HELLO_DUMP="$WORK/hello.json" python3 "$HERE/fake_daemon.py" "$WORK/port.txt" &
DAEMON_PID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
	[ -f "$WORK/port.txt" ] && break
	sleep 0.2
done

cd "$WORK"
./core_test "$WORK/port.txt"

if [ -n "$IVPN_GOCHECK" ]; then
	"$IVPN_GOCHECK" "$WORK/hello.json" "$WORK"/connect_*.json "$WORK"/req_*.json
fi
