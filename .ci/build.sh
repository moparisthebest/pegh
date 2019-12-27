#!/bin/sh

set -exu

# change to the directory this script is in
cd "$(dirname "$0")"

# dependencies to build+test pegh
apk add build-base clang openssl-dev openssl-libs-static bash libsodium-dev libsodium-static
#apk add build-base clang libressl-dev bash

# gcc is apparantly incapable of building a static binary, even gcc -static helloworld.c ends up linked to libc, instead of solving, use clang
make clean all PEGH_LIBSODIUM=1 CC=clang LDFLAGS="-static -lsodium" || clang pegh.c -DPEGH_LIBSODIUM -static -lsodium -O3 -o pegh
mv pegh pegh.static.libsodium
make clean all PEGH_OPENSSL=1 CC=clang LDFLAGS="-static -lcrypto" || clang pegh.c -DPEGH_OPENSSL -static -lcrypto -O3 -o pegh
mv pegh pegh.static.openssl

ls -lah pegh.static.*

strip pegh.static.*

# print out some info about this, size, and to ensure it's actually fully static
ls -lah pegh.static.*
file pegh.static.*
ldd pegh.static.* || true

# libsodium only supports AES-256-GCM on certain CPUs that have hardware instructions for it
# we can build them regardless, but we can't test them without that, pegh prints that right away
set +e
if ./pegh.static.libsodium -h 2>&1 >/dev/null | grep '^Error: libsodium'
then
    echo "CPU does not have AES support so can't run libsodium version"
    # no aes support
    export TEST_BINS="./pegh.static.openssl ./pegh.openssl"
else
    echo "CPU has AES support so can run libsodium version"
    # we can test everything
    export TEST_BINS="./pegh.static.openssl ./pegh.openssl ./pegh.libsodium ./pegh.static.libsodium"
fi
set -e

# compile dynamically linked versions (with gcc) to openssl and libsodium, then test all 4 against each other
./test.sh

echo "successfully built and tested static pegh against libsodium and openssl!"
