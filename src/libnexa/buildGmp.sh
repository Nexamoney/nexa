#!/bin/bash
# Cross compile a static, position independent libgmp for the light library build (see Makefile).
# Usage: buildGmp.sh <installPrefix>
#   Uses the CC, CFLAGS, AR, RANLIB environment variables of the light build.
#   GMP_HOST (optional): the gmp --host triple.  If empty, gmp builds for the build machine.
# The gmp source must already be in ./gmp (run downloadGmpLib.sh).
# Installs <installPrefix>/include/gmp.h and <installPrefix>/lib/libgmp.a

set -eu

prefix=$1
srcDir="$(cd "$(dirname "$0")" && pwd)/gmp"
buildDir="${prefix}-build"

if [ ! -x "$srcDir/configure" ]; then
    echo "gmp source not found in $srcDir.  Run downloadGmpLib.sh (or prepnexa.sh in lnk/libnexa)"
    exit 1
fi

# The light build makes libnexalight.so and libnexalight.a in separate (parallel) make invocations, and both need
# libgmp, so serialize: the 2nd caller waits for the 1st to finish, then finds libgmp already built.
# (mkdir is atomic, and unlike flock it is available on macOS.  If a build is SIGKILLed, delete ${prefix}.lock)
mkdir -p "$(dirname "$prefix")"
lockDir="${prefix}.lock"
until mkdir "$lockDir" 2>/dev/null; do
    echo "waiting for another libgmp build to finish (or delete stale lock $lockDir)"
    sleep 2
done
trap 'rmdir "$lockDir"' EXIT

if [ -f "$prefix/lib/libgmp.a" ] && [ -f "$prefix/include/gmp.h" ]; then
    echo "libgmp already built in $prefix"
    exit 0
fi

hostArg=""
if [ -n "${GMP_HOST:-}" ]; then
    hostArg="--host=${GMP_HOST}"
fi

rm -rf "$buildDir"
mkdir -p "$buildDir"
cd "$buildDir"
# --disable-assembly: generic C only, as the depends build does for android and darwin.  This avoids
# per-cpu assembly that does not build (or is not position independent) on many mobile targets.
# The CC_FOR_BUILD default is fine: gmp builds some generator programs for the build machine.
"$srcDir/configure" $hostArg --prefix="$prefix" --disable-shared --enable-static --with-pic --disable-assembly \
    CC="${CC}" CFLAGS="${CFLAGS:-} -O2 -fPIC" AR="${AR:-ar}" RANLIB="${RANLIB:-ranlib}"
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
make install
rm -f "$prefix/lib/libgmp.la"
