#!/bin/sh
# Build the obfuscation helpers ivpnd runs, the same programs and versions
# as IVPN's own app: V2Ray (v2fly) and obfs4proxy (Yawning Angel's obfs4).
#
#   sh packaging/haiku/build-helpers.sh [OUT_DIR]     (default: build/helpers)
#
# On Haiku it needs `pkgman install golang git` (HaikuPorts' Go has a haiku
# port); elsewhere set GO to korli's Go fork (github.com/korli/go) and it
# cross-compiles for haiku/amd64. V2Ray needs small patches for Haiku: build
# tags for a dependency that lacks haiku, and no-op socket options and file
# locking (see patch_v2ray).
set -eu
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$(mkdir -p "${1:-$HERE/build/helpers}" && cd "${1:-$HERE/build/helpers}" && pwd)"
GO="${GO:-go}"
V2RAY_VER=v5.12.1
OBFS4_VER=obfs4proxy-0.0.14

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

command -v "$GO" >/dev/null 2>&1 || die "'$GO' not found (pkgman install golang)"
command -v git >/dev/null 2>&1 || die "git not found (pkgman install git)"
[ "$(uname -s)" = Haiku ] || export GOOS=haiku GOARCH=amd64
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
export GOPATH="$WORK/gopath" GOCACHE="$WORK/gocache" CGO_ENABLED=0
# Fewer compilers at once: V2Ray is large, and Go's compiler on Haiku dies
# when memory runs short (seen in a 4 GB CI VM)
export GOFLAGS="-p=2"

# Adds "haiku" next to "linux" in the //go:build lines of the given files
add_haiku_tag() {
	for f in "$@"; do
		grep -q haiku "$f" && continue
		sed -i.orig -e '/^\/\/go:build /s/linux/linux || haiku/' \
			-e '/^\/\/ +build /s/linux/linux haiku/' "$f"
		rm -f "$f.orig"
	done
}

patch_v2ray() {
	# github.com/adrg/xdg lists unix systems one by one
	add_haiku_tag $(grep -rlE '^//go:build .*linux' vendor/github.com/adrg/xdg)
	# Socket options (marks, TFO, tproxy) don't exist on Haiku: the
	# no-op versions other systems use
	sed -i.orig -e '/^\/\/go:build /s/$/ || haiku/' \
		-e '/^\/\/ +build /s/$/ haiku/' transport/internet/sockopt_other.go
	# No flock() in Go's unix package for Haiku; V2Ray only locks a file
	# for its "fileLock" option, which IVPN's config doesn't use
	sed -i.orig -e 's|^//go:build !windows$|//go:build !windows \&\& !haiku|' \
		-e 's|^// +build !windows$|// +build !windows,!haiku|' \
		transport/internet/filelocker_other.go
	cp transport/internet/filelocker_windows.go \
		transport/internet/filelocker_haiku.go
	# Unix domain sockets as a transport also lock with flock(); left out
	# as on Windows (IVPN uses VMess over QUIC or TCP)
	for f in transport/internet/domainsocket/dial.go \
			transport/internet/domainsocket/listener.go; do
		sed -i.orig -e 's|^//go:build !windows && !wasm$|//go:build !windows \&\& !wasm \&\& !haiku|' \
			-e 's|^// +build !windows,!wasm$|// +build !windows,!wasm,!haiku|' "$f"
	done
	rm -f transport/internet/*.orig transport/internet/domainsocket/*.orig
}

say "obfs4proxy $OBFS4_VER"
git clone -q https://gitlab.com/yawning/obfs4.git "$WORK/obfs4"
git -C "$WORK/obfs4" checkout -q "$OBFS4_VER"
( cd "$WORK/obfs4" && "$GO" build -trimpath -ldflags "-s -w" \
	-o "$OUT/obfs4proxy" ./obfs4proxy )
cp "$WORK/obfs4/LICENSE" "$OUT/LICENSE.obfs4proxy"

say "V2Ray $V2RAY_VER"
git -c advice.detachedHead=false clone -q --depth 1 --branch "$V2RAY_VER" \
	https://github.com/v2fly/v2ray-core.git "$WORK/v2ray"
( cd "$WORK/v2ray" && "$GO" mod vendor && patch_v2ray \
	&& "$GO" build -mod=vendor -trimpath -ldflags "-s -w" \
		-o "$OUT/v2ray" ./main )
cp "$WORK/v2ray/LICENSE" "$OUT/LICENSE.v2ray"

ls -l "$OUT"
echo "Built the helpers in $OUT"
