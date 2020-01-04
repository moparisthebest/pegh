#!/bin/sh

DOCKER_IMAGE="$1"
shift
ARCH="$1"

BUILD_DIR=/tmp/static/

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cp * .ci/build.sh "$BUILD_DIR"

docker run --rm -v "$BUILD_DIR":/tmp "$DOCKER_IMAGE" /tmp/build.sh "$ARCH" || exit 1

mv "$BUILD_DIR"pegh.static.openssl "./pegh-linux-$ARCH-openssl"
mv "$BUILD_DIR"pegh.static.libsodium "./pegh-linux-$ARCH-libsodium"
mv "$BUILD_DIR"pegh.static.libsodium-openssl "./pegh-linux-$ARCH-libsodium-openssl"

mv "$BUILD_DIR"pegh-*.exe ./

git archive HEAD -9 --format zip -o pegh-source.zip
git archive HEAD -9 --format tar.gz -o pegh-source.tar.gz

sha256sum pegh-* > pegh-sha256sum.txt

rm -rf "$BUILD_DIR" 2>/dev/null

exit 0
