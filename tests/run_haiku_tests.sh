#!/bin/sh
# Builds and runs the platform-independent tests on Haiku (called by
# packaging/haiku/build-hpkg.sh). Usage: run_haiku_tests.sh <build dir>
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-/tmp}"
g++ -std=c++17 -Wall -O1 "$HERE/daemon_logic_test.cpp" \
	"$HERE/../src/ivpnd/DaemonLogic.cpp" "$HERE/../src/core/Model.cpp" \
	-o "$OUT/daemon_logic_test"
"$OUT/daemon_logic_test"
