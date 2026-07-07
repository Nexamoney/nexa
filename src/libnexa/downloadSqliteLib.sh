#!/bin/bash

version=3530200
archiveSha256=8a310d0a16c7a90cacd4c884e70faa51c902afed2a89f63aaa0126ab83558a32
echo "Retrieving SQlite $version..."

set -eu

dir_name=sqlite-amalgamation-${version}
archive=sqlite-amalgamation-${version}.zip
if [ ! -f "$archive" ]; then
    curl -L "https://www.sqlite.org/2026/sqlite-amalgamation-$version.zip" -o $archive
    # wget -O $archive "https://www.sqlite.org/2023/sqlite-amalgamation-$version.zip"
else
  echo "Archive $archive already downloaded"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "skipping checksum check on macos"
else
  # openssl dgst -sha3-256 sqlite-amalgamation-3500400.zip
    echo "$archiveSha256 $archive" | sha256sum --check || { echo "sha256sum of sqlite3 failed"; exit 1; }
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
