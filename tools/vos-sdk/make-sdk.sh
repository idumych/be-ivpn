#!/bin/sh
# make-sdk.sh - build a link-time SDK for VitruvianOS 0.6.2 (libbe, libroot
# and headers) so CI can compile and link IVPN without a Vitruvian machine.
# Adapted from Folio's tools/vos-sdk/make-sdk.sh (github.com/idumych/folio).
#
#   sh tools/vos-sdk/make-sdk.sh [WORK_DIR]       (default: ./.vos-sdk)
#
# Runs natively on amd64 or arm64 Debian trixie (VitruvianOS's userland),
# with the packages listed in .github/workflows/build.yml installed.
#
# Result in WORK_DIR/sdk: include/vos, lib/{libbe,libroot}.so + vos.pc, env.sh.
# The libraries only prove the link; the package uses the ones installed on
# VitruvianOS at runtime.
set -eu

VOS_TAG=0.6.2
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mkdir -p "${1:-.vos-sdk}" && cd "${1:-.vos-sdk}" && pwd)
SRC=$WORK/src
SDK=$WORK/sdk
JOBS=$(nproc 2>/dev/null || echo 4)

case "$(dpkg --print-architecture)" in
	amd64) ARCH=amd64; LD_SO=/lib64/ld-linux-x86-64.so.2 ;;
	arm64) ARCH=arm64; LD_SO=/lib/ld-linux-aarch64.so.1 ;;
	*) echo "make-sdk: unsupported architecture" >&2; exit 1 ;;
esac

say() { printf '\n== %s\n' "$*"; }

say "VitruvianOS $VOS_TAG source"
mkdir -p "$SRC"
if [ ! -d "$SRC/vos/.git" ]; then
	git clone -q --depth 1 --branch "$VOS_TAG" \
		https://github.com/VitruvianOS/Vitruvian.git "$SRC/vos"
	git -C "$SRC/vos" submodule update --init --depth 1 src/system/kernel/nexus
fi
git -C "$SRC/vos" diff --quiet && git -C "$SRC/vos" apply "$HERE/vos-$VOS_TAG-linkonly.patch"
CMAKE_OPTS="-DVOS_DYNAMIC_LINKER=$LD_SO"

say "Buildtools"
mkdir -p "$SRC/vos/buildtools"
( cd "$SRC/vos/buildtools"
  cmake -DBUILDTOOLS_MODE=1 $CMAKE_OPTS .. -GNinja
  ninja -j"$JOBS" )

say "libroot, libbe ($ARCH)"
G=$SRC/vos/generated
mkdir -p "$G"
( cd "$G"
  cmake -DCMAKE_BUILD_TYPE=Release -DBUILDTOOLS_DIR=../buildtools \
	-DHOST_KERNEL="$(uname -r)" -DKERNEL_RELEASE="$(uname -r)" \
	-DVITRUVIAN_TARGET_ARCH=$ARCH $CMAKE_OPTS .. -GNinja
  ninja -j"$JOBS" root be )

say "SDK in $SDK"
rm -rf "$SDK"; mkdir -p "$SDK/include/vos" "$SDK/lib"
( cd "$SRC/vos/headers" && tar cf - --exclude=./private --exclude=./libs \
	--exclude=./tools . ) | tar xf - -C "$SDK/include/vos"
# libbe/libroot plus any VitruvianOS libraries they link against
find "$G/src" -name 'lib*.so' -exec cp {} "$SDK/lib/" \;
ls "$SDK/lib"

# vos.pc the way newer VitruvianOS (vos-dev) generates it
python3 - "$SRC/vos" "$SDK" "$ARCH" <<'EOF'
import re, sys
vos, sdk, arch = sys.argv[1:]
s = open(vos + '/build/headers.cmake').read()
body = s[s.index('PUBLIC_HEADERS'):]
body = body[:body.index(')')]
flags = []
for d in re.findall(r'"([^"]+)"', body):
    d = d.rstrip('/').replace('os/arch/x86_64', 'os/arch/' + ('arm64' if arch == 'arm64' else 'x86_64'))
    f = '-I${includedir}' if d == 'headers' else '-I${includedir}/' + d[len('headers/'):]
    if f not in flags:
        flags.append(f)
flags += ['-I${includedir}/build', '-I${includedir}/build/config_headers',
          '-I${includedir}/config', '-include LinuxBuildCompatibility.h']
open(sdk + '/lib/vos.pc', 'w').write(f"""prefix={sdk}
includedir=${{prefix}}/include/vos
libdir=${{prefix}}/lib

Name: vos
Description: VitruvianOS 0.6.2 link-time SDK
Version: 0.6.2
Libs: -L${{libdir}} -lbe -lroot
Cflags: {' '.join(flags)}
""")
EOF

cat > "$SDK/env.sh" <<EOF
# source me: . $SDK/env.sh
export PKG_CONFIG_PATH="$SDK/lib"
export LDFLAGS="-L$SDK/lib -Wl,-rpath-link=$SDK/lib"
export VOS_VERSION=$VOS_TAG
EOF
say "done"
