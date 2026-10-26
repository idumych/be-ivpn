#!/bin/sh
# Build Be IVPN for Haiku and Renku OS and package it as an .hpkg.
#
# Run this ON Haiku R1/beta6 (x86_64), from anywhere:
#     sh packaging/haiku/build-hpkg.sh
# Result: be_ivpn-<version>-1-x86_64.hpkg in the project folder.
# Install with: pkgman install ./be_ivpn-*.hpkg
#
# Needs: pkgman install gcc haiku_devel curl_devel openssl3_devel
# (it says what's missing). Built on beta6, the package also installs on
# Renku OS and newer Haiku.
set -eu
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$HERE"

VERSION=$(sed -n 's/^#define IVPN_APP_VERSION[^"]*"\([^"]*\)".*/\1/p' \
	src/ui/Constants.h)
REVISION=1
ARCH=$(getarch)
OBJ="$HERE/build/haiku-$ARCH"
OUT="$HERE/be_ivpn-$VERSION-$REVISION-$ARCH.hpkg"

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

for tool in g++ rc xres mimeset package getarch; do
	command -v "$tool" >/dev/null 2>&1 \
		|| die "'$tool' not found (pkgman install gcc haiku_devel)"
done
[ -f /boot/system/develop/headers/curl/curl.h ] \
	|| die "curl headers missing (pkgman install curl_devel)"
[ -f /boot/system/develop/headers/openssl/evp.h ] \
	|| die "OpenSSL headers missing (pkgman install openssl3_devel)"

CXX="${CXX:-g++}"
# Additive, so packagers can pass their own flags
CXXFLAGS="-std=c++17 -O2 -Wall -Wno-multichar ${CXXFLAGS:-}"
# Strip at link time: xres appends the resources after the ELF data, so
# stripping afterwards would cut them off.
LDFLAGS="-s ${LDFLAGS:-}"

rm -rf "$OBJ"
mkdir -p "$OBJ/app" "$OBJ/pic" "$OBJ/daemon"

compile() {	# <object dir> <extra flags> <sources...>
	dir=$1; extra=$2; shift 2
	for src in "$@"; do
		echo "   $(basename "$src")"
		# shellcheck disable=SC2086
		$CXX $CXXFLAGS $extra -c "$src" -o "$dir/$(basename "$src" .cpp).o"
	done
}

say "Compiling the app ($ARCH)"
compile "$OBJ/app" "" src/core/*.cpp src/ui/*.cpp
# shellcheck disable=SC2086
$CXX -o "$OBJ/BeIVPN" "$OBJ"/app/*.o $LDFLAGS -lbe -lnetwork

say "Building the Deskbar item"
# An add-on Deskbar loads, so position-independent; --no-undefined turns a
# missing symbol into a build error instead of a Deskbar crash.
compile "$OBJ/pic" "-fPIC" src/deskbar/*.cpp src/core/DaemonConnection.cpp \
	src/core/Model.cpp src/ui/DaemonClient.cpp
# shellcheck disable=SC2086
$CXX -shared -o "$OBJ/BeIVPNDeskbar.so" "$OBJ"/pic/*.o $LDFLAGS \
	-Wl,--no-undefined -lbe -lnetwork

say "Building ivpnd (the IVPN service)"
compile "$OBJ/daemon" "-Ithird_party/sotoportego" src/ivpnd/*.cpp \
	third_party/sotoportego/*.cpp
# shellcheck disable=SC2086
$CXX -o "$OBJ/ivpnd" "$OBJ"/daemon/*.o $LDFLAGS -lbe -lnetwork -lcurl \
	-lcrypto

say "Resources"
for pair in "BeIVPN:resources/IVPN.rdef" "ivpnd:resources/ivpnd.rdef"; do
	bin=${pair%%:*}; rdef=${pair#*:}
	rc -o "$OBJ/$bin.rsrc" "$rdef"
	xres -o "$OBJ/$bin" "$OBJ/$bin.rsrc"
	mimeset -f "$OBJ/$bin"
done

say "Tests"
sh tests/run_haiku_tests.sh "$OBJ"

say "Packaging"
PKG="$OBJ/hpkg"
DOC="$PKG/documentation/packages/be_ivpn"
mkdir -p "$PKG/apps/BeIVPN" "$PKG/add-ons/BeIVPN" "$PKG/data/ivpn" \
	"$PKG/data/deskbar/menu/Applications" "$DOC"
cp "$OBJ/BeIVPN" "$OBJ/ivpnd" "$PKG/apps/BeIVPN/"
cp "$OBJ/BeIVPNDeskbar.so" "$PKG/add-ons/BeIVPN/"
cp resources/openvpn/ca.crt resources/openvpn/ta.key "$PKG/data/ivpn/"
ln -s ../../../../apps/BeIVPN/BeIVPN \
	"$PKG/data/deskbar/menu/Applications/Be IVPN"
cp README.md LICENSE "$DOC/"
cp third_party/sotoportego/LICENSE "$DOC/LICENSE.sotoportego"

cat > "$PKG/.PackageInfo" <<EOF
name			be_ivpn
version			$VERSION-$REVISION
architecture	$ARCH
summary			"Native IVPN client"
description		"A native window and Deskbar item for the IVPN VPN service, \
with its own background service (ivpnd) for WireGuard and OpenVPN. \
Not made by IVPN."
packager		"idumych <19998719+idumych@users.noreply.github.com>"
vendor			"idumych"
copyrights		{
	"2026 idumych"
	"2026 atomozero (Sotoportego tunnel code)"
}
licenses		{
	"GNU GPL v3"
	"MIT"
}
urls			{
	"https://github.com/idumych/be-ivpn"
}
provides		{
	be_ivpn = $VERSION
	app:BeIVPN = $VERSION
}
requires		{
	haiku >= r1~beta6
	cmd:openvpn
	lib:libcurl
	lib:libcrypto
}
replaces		{
	ivpn_haiku
}
conflicts		{
	ivpn_haiku
}
EOF

rm -f "$OUT"
package create -C "$PKG" "$OUT"
package list -i "$OUT" >/dev/null
echo "Built $OUT"
