#!/bin/sh

DOCKER_IMAGE="$1"
shift
ARCH="$1"

BUILD_DIR=/tmp/static/

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp * .ci/build.sh "$BUILD_DIR"

docker run --rm -v "$BUILD_DIR":/tmp "$DOCKER_IMAGE" /tmp/build.sh || exit 1

mv "$BUILD_DIR"pegh.static.openssl "./pegh-$ARCH-openssl"
mv "$BUILD_DIR"pegh.static.libsodium "./pegh-$ARCH-libsodium"
mv "$BUILD_DIR"pegh.static.libsodium-universal-aes "./pegh-$ARCH-libsodium-universal-aes"
rm -rf "$BUILD_DIR" 2>/dev/null

exit 0
