#!/bin/sh
# Build IVPN for Vitruvian and package it as a .deb.
#
# Run this ON a Vitruvian machine:   ./build.sh
# Result:                            ivpn-vitruvian_<version>_<arch>.deb
# Install with:                      sudo apt install ./ivpn-vitruvian_*.deb
#
# Needs only what Vitruvian already ships (g++, curl, tar, dpkg-deb).
# Headers: uses the vos-dev package if installed, otherwise downloads the
# Vitruvian source matching your installed version (or set VOS_SRC to a
# Vitruvian source folder you already have).
#
# Cross-building (e.g. arm64 on an x86_64 PC) - set all of:
#   TARGET_ARCH=arm64  VOS_VERSION=0.6.2  VOS_SRC=<Vitruvian source>
#   CXX="clang++ --target=aarch64-linux-gnu --sysroot=<arm64 Vitruvian root>"
#   STRIP=llvm-strip   (optional)
set -e

APP_VERSION="1.0.0"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/build"
mkdir -p "$OUT"

say() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

CXX="${CXX:-g++}"
STRIP="${STRIP:-strip}"
command -v ${CXX%% *} >/dev/null || die "g++ not found. Install it with: sudo apt install g++"
command -v dpkg-deb >/dev/null || die "dpkg-deb not found."

ARCH="${TARGET_ARCH:-$(dpkg --print-architecture)}"
if [ -z "$VOS_VERSION" ]; then
	VOS_VERSION="$(dpkg-query -W -f='${Version}' vos 2>/dev/null || true)"
fi
[ -n "$VOS_VERSION" ] || die "This does not look like Vitruvian (package 'vos' is not installed)."
case "$ARCH" in
	amd64) HEADER_ARCH=x86_64 ;;
	arm64) HEADER_ARCH=arm64 ;;
	*) die "Unsupported architecture: $ARCH" ;;
esac

# --- compiler flags for the Vitruvian (Haiku API) headers ----------------
if pkg-config --exists vos 2>/dev/null; then
	say "Using installed vos-dev headers"
	VOS_CFLAGS="$(pkg-config --cflags vos)"
else
	if [ -z "$VOS_SRC" ]; then
		VOS_SRC="$OUT/vos-$VOS_VERSION"
		if [ ! -d "$VOS_SRC/headers" ]; then
			say "Downloading Vitruvian $VOS_VERSION headers (one time)"
			command -v curl >/dev/null || die "curl not found."
			TAG="${VOS_VERSION%%[-+~]*}"
			curl -fL --retry 3 -o "$OUT/vos-src.tar.gz" \
				"https://github.com/VitruvianOS/Vitruvian/archive/refs/tags/$TAG.tar.gz" \
				|| die "Could not download Vitruvian $TAG source. Set VOS_SRC to a Vitruvian source folder."
			mkdir -p "$VOS_SRC"
			tar -xzf "$OUT/vos-src.tar.gz" -C "$VOS_SRC" --strip-components=1 \
				--wildcards '*/headers/*' '*/build/headers.cmake'
			rm -f "$OUT/vos-src.tar.gz"
		fi
	fi
	[ -f "$VOS_SRC/build/headers.cmake" ] || die "No Vitruvian headers in $VOS_SRC"
	say "Using Vitruvian headers from $VOS_SRC"
	# Same public include list Vitruvian itself uses (build/headers.cmake)
	VOS_CFLAGS=""
	for d in $(sed -n '/PUBLIC_HEADERS/,/^)/p' "$VOS_SRC/build/headers.cmake" \
			| grep -o '"headers/[^"]*"' | tr -d '"' \
			| sed "s#os/arch/x86_64#os/arch/$HEADER_ARCH#"); do
		VOS_CFLAGS="$VOS_CFLAGS -I$VOS_SRC/${d%/}"
	done
	VOS_CFLAGS="$VOS_CFLAGS -I$VOS_SRC/headers/build \
		-I$VOS_SRC/headers/build/config_headers -I$VOS_SRC/headers/config \
		-include LinuxBuildCompatibility.h"
fi

# --- compile -------------------------------------------------------------
say "Compiling for $ARCH (Vitruvian $VOS_VERSION)"
OBJ="$OUT/obj-$ARCH"
rm -rf "$OBJ"
mkdir -p "$OBJ"
for src in "$HERE"/src/core/*.cpp "$HERE"/src/ui/*.cpp; do
	echo "   $(basename "$src")"
	# shellcheck disable=SC2086
	$CXX -std=c++17 -O2 -g0 -Wall -Wno-multichar -Wno-deprecated-copy \
		$VOS_CFLAGS -c "$src" -o "$OBJ/$(basename "$src" .cpp).o"
done

say "Linking"
# shellcheck disable=SC2086
$CXX -o "$OUT/IVPN" "$OBJ"/*.o $LDFLAGS -Wl,--no-as-needed -lbe -lroot -pthread
$STRIP "$OUT/IVPN" 2>/dev/null || true

# --- package -------------------------------------------------------------
say "Packaging"
PKG="$OUT/pkg"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/system/apps" \
	"$PKG/system/data/deskbar/menu/Applications" \
	"$PKG/system/data/ivpn-vitruvian"
install -m 755 "$OUT/IVPN" "$PKG/system/apps/IVPN"
[ "$(od -A n -t x1 -j 18 -N 1 "$OUT/IVPN" | tr -d ' ')" = "$( [ "$ARCH" = arm64 ] && echo b7 || echo 3e)" ] \
	|| die "Built binary is not $ARCH"
ln -s /system/apps/IVPN "$PKG/system/data/deskbar/menu/Applications/IVPN"
install -m 644 "$HERE/resources/IVPN.rdef" "$PKG/system/data/ivpn-vitruvian/"
install -m 755 "$HERE/packaging/postinst" "$PKG/DEBIAN/postinst"

VOS_MIN="${VOS_VERSION%%[-+~]*}"
cat > "$PKG/DEBIAN/control" <<EOF
Package: ivpn-vitruvian
Version: $APP_VERSION
Architecture: $ARCH
Maintainer: ivpn-vitruvian <noreply@localhost>
Depends: vos (>= $VOS_MIN), ivpn
Section: net
Priority: optional
Description: Native IVPN client for Vitruvian
 A native (Haiku API) window for the IVPN service: connect and disconnect,
 choose a location, protocol and port, firewall and AntiTracker.
 Uses the same ivpn-service as the official app and the ivpn command.
EOF

DEB="$HERE/ivpn-vitruvian_${APP_VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG" "$DEB" >/dev/null
say "Done: $DEB"
echo "   Install with:  sudo apt install $DEB"
