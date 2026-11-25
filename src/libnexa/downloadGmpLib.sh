#!/bin/bash
# Retrieve and unpack the GNU multiprecision library (libgmp) source into ./gmp
# libgmp is needed by BigNum and therefore by the script machine.
# The light (mobile) builds compile it per target: see buildGmp.sh (Makefile builds) and CMakeLists.txt (android).
# Keep the version and hash in sync with depends/packages/libgmp.mk

version=6.3.0
archiveSha256=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898
echo "Retrieving GMP $version..."

set -eu

# Download $1 to $2, retrying on connection resets, HTTP errors, or other failures.
# Downloads to a temporary file so a partial/failed download never leaves a bogus archive behind.
download() {
    local url="$1" out="$2" tries=6 i
    for ((i=1; i<=tries; i++)); do
        if curl -fL --connect-timeout 30 --retry 3 --retry-delay 5 -o "$out.part" "$url"; then
            mv -f "$out.part" "$out"
            return 0
        fi
        rm -f "$out.part"
        echo "Download of $url failed (attempt $i of $tries)" >&2
        if (( i < tries )); then
            sleep $((i * 10))
        fi
    done
    echo "Giving up downloading $url" >&2
    return 1
}

dir_name=gmp-${version}
archive=gmp-${version}.tar.xz
if [ ! -f "$archive" ]; then
    download "https://gmplib.org/download/gmp/$archive" "$archive" || exit 1
else
  echo "Archive $archive already downloaded"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "$archiveSha256  $archive" | shasum -a 256 --check || { rm -f "$archive"; echo "sha256sum of gmp failed"; exit 1; }
else
    echo "$archiveSha256 $archive" | sha256sum --check || { rm -f "$archive"; echo "sha256sum of gmp failed"; exit 1; }
fi

echo "Extracting..."
if [ -d gmp ]; then
    rm -rf gmp
fi
tar xf $archive
mv $dir_name gmp

echo "Done!"
