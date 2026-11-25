#!/bin/bash
# script modified from: https://gist.github.com/enh/b2dc8e2cbbce7fffffde2135271b10fd

version=1.91.0
echo "Retrieving boost $version..."

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

dir_name=boost_$(sed 's#\.#_#g' <<< $version)
archive=${dir_name}.tar.bz2
if [ ! -f "$archive" ]; then
    download "https://archives.boost.io/release/$version/source/$archive" "$archive" || exit 1
    rm -rf boost  # Clean up any old boost that might exist
else
  echo "Archive $archive already downloaded"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "skipping checksum check on macos"
else
    echo "de5e6b0e4913395c6bdfa90537febd9028ea4c0735d2cdb0cd9b45d5f51264f5 $archive" | sha256sum --check || { rm -f "$archive"; echo "sha256sum of boost failed"; exit 1; }
fi


if [[ -d "$dir_name" || -d boost ]]; then
  echo "Archive $archive already unpacked into $dir_name"
else
  echo "Extracting..."  
  tar xf $archive
fi

if [ ! -d boost ]; then
    echo "renaming $dir_name to boost"  
    mv $dir_name boost
else
    echo "Boost dir already exists"
fi


echo "Done!"
