#!/bin/bash
# script modified from: https://gist.github.com/enh/b2dc8e2cbbce7fffffde2135271b10fd

version=1.91.0
echo "Retrieving boost $version..."

set -eu

dir_name=boost_$(sed 's#\.#_#g' <<< $version)
archive=${dir_name}.tar.bz2
if [ ! -f "$archive" ]; then
    curl -L "https://archives.boost.io/release/$version/source/$archive" -o $archive
    rm -rf boost  # Clean up any old boost that might exist
else
  echo "Archive $archive already downloaded"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "skipping checksum check on macos"
else
    echo "de5e6b0e4913395c6bdfa90537febd9028ea4c0735d2cdb0cd9b45d5f51264f5 $archive" | sha256sum --check || { echo "sha256sum of boost failed"; exit 1; }
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
