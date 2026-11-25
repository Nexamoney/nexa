#!/bin/bash

version=3530200
archiveSha256=8a310d0a16c7a90cacd4c884e70faa51c902afed2a89f63aaa0126ab83558a32
echo "Retrieving SQlite $version..."

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

dir_name=sqlite-amalgamation-${version}
archive=sqlite-amalgamation-${version}.zip
if [ ! -f "$archive" ]; then
    download "https://www.sqlite.org/2026/sqlite-amalgamation-$version.zip" "$archive" || exit 1
    # wget -O $archive "https://www.sqlite.org/2023/sqlite-amalgamation-$version.zip"
else
  echo "Archive $archive already downloaded"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "skipping checksum check on macos"
else
  # openssl dgst -sha3-256 sqlite-amalgamation-3500400.zip
    echo "$archiveSha256 $archive" | sha256sum --check || { rm -f "$archive"; echo "sha256sum of sqlite3 failed"; exit 1; }
fi

echo "Extracting..."
if [ ! -d "$dir_name" ]; then
  unzip $archive
else
  echo "Archive $archive already unpacked into $dir_name"
fi

if [ -d sqlite ]; then
    rm -rf sqlite
fi
mv $dir_name sqlite

echo "Done!"
