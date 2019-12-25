#!/bin/bash
set -euo pipefail
# try different size files to encrypt/decrypt
[ -e /dev/shm/randombytes ] || dd if=/dev/urandom bs=1M count=100 of=/dev/shm/randombytes

# compile C and rust code this way
gcc pegh.c -lcrypto -O3 -o pegh
#cargo build --release

export key=$(openssl rand -base64 20)

echo "key: $key"

test () {
    bin=$1
    tee >(md5sum 1>&2) < /dev/shm/randombytes | $bin $key enc | $bin $key | md5sum 1>&2
    #$bin $key enc < /dev/shm/randombytes | $bin $key &>/dev/null
}

time test ./pegh
