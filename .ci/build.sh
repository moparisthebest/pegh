#!/bin/sh

set -exu

# change to the directory this script is in
cd "$(dirname "$0")"

# dependencies to build+test pegh
apk add build-base clang bash libsodium-dev libsodium-static libressl-dev

# first build for libressl, which doesn't have "EVP_PBE_scrypt" so can only be compiled with libsodium
make clean all PEGH_LIBSODIUM=1 PEGH_OPENSSL=1 CC=clang LDFLAGS="-static"
mv pegh pegh.static.libsodium-libressl

# now remove libressl and install openssl
apk del libressl-dev
apk add openssl-dev openssl-libs-static

# gcc is apparantly incapable of building a static binary, even gcc -static helloworld.c ends up linked to libc, instead of solving, use clang
make clean all PEGH_LIBSODIUM=1 CC=clang LDFLAGS="-static"
mv pegh pegh.static.libsodium
make clean all PEGH_OPENSSL=1 CC=clang LDFLAGS="-static"
mv pegh pegh.static.openssl
make clean all PEGH_LIBSODIUM=1 PEGH_OPENSSL=1 CC=clang LDFLAGS="-static"
mv pegh pegh.static.libsodium-openssl

./pegh.static.libsodium-openssl -h

ls -lah pegh.static.*

strip pegh.static.*

# print out some info about this, size, and to ensure it's actually fully static
ls -lah pegh.static.*
file pegh.static.*
ldd pegh.static.* || true

# libsodium only supports AES-256-GCM on certain CPUs that have hardware instructions for it
# we can build them regardless, but we can't test them without that, pegh prints that right away
export TEST_BINS="./pegh.static.openssl ./pegh.openssl ./pegh.static.libsodium-openssl ./pegh.libsodium-openssl ./pegh.static.libsodium-libressl"
set +e
if ./pegh.static.libsodium -h 2>&1 >/dev/null | grep '^Error: libsodium'
then
    echo "CPU does not have AES support so can't run libsodium version"
else
    echo "CPU has AES support so can run libsodium version"
    # we can test everything
    export TEST_BINS="$TEST_BINS ./pegh.libsodium ./pegh.static.libsodium"
fi
set -e

# compile dynamically linked versions (with gcc) to openssl and libsodium, then test all 4 against each other
./test.sh

echo "successfully built and tested static pegh against libsodium and openssl!"
