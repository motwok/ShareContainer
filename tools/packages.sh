#!/bin/sh
# Writes the installed Debian packages of the image to packages/sharecontainer.txt.
# Usage: tools/packages.sh [platform ...]   (default: linux/amd64 linux/arm64)
set -eu
cd "$(dirname "$0")/.."
[ "$#" -gt 0 ] || set -- linux/amd64 linux/arm64
mkdir -p packages
out=packages/sharecontainer.txt
tag=sharecontainer-packages
: > "$out"
for platform in "$@"; do
    docker buildx build --quiet --load --platform "$platform" -t "$tag" . > /dev/null
    echo "# $platform" >> "$out"
    docker run --rm --platform "$platform" --entrypoint dpkg-query "$tag" \
        -W -f '${Package} ${Version}\n' | LC_ALL=C sort >> "$out"
done
