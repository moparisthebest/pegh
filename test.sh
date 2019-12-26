#!/bin/bash

set -euo pipefail

# try different size files to encrypt/decrypt
[ -e /dev/shm/randombytes ] || dd if=/dev/urandom bs=1M count=100 of=/dev/shm/randombytes

# try make if it's installed, otherwise fall back to cc
make || cc pegh.c -lcrypto -O3 -o pegh
#cargo build --release

export key="$(openssl rand -base64 20)"

echo "key: $key"

test () {
    bin="$1"

    echo 'encrypting then decrypting with the same key should succeed'
    "$bin" -e "$key" < /dev/shm/randombytes | "$bin" -d "$key" | cmp - /dev/shm/randombytes

    echo 'test with -s 32 requiring 2gb of ram should succeed'
    # can send -s 32 or -m 2048 to decrypt command with identical effect
    "$bin" -e "$key" -s 32 < /dev/shm/randombytes | "$bin" -d "$key" -m 2048 | cmp - /dev/shm/randombytes

    set +e
    # these should fail
    echo 'encrypting with one key and decrypting with another should fail'
    "$bin" -e "$key" -i /dev/shm/randombytes | "$bin" -d "$key-wrongkey" | cmp - /dev/shm/randombytes && echo "ERROR: appending -wrongkey to key somehow still worked" && exit 1

    echo 'large values of N without enough memory should fail'
    "$bin" -e "$key" -N 2000000 -i /dev/shm/randombytes >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1
    "$bin" -d "$key" -N 2000000 -i /dev/shm/randombytes >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1

    # todo: can we also make this the case for stdout? needs some buffering...
    echo 'bad decryption should result in output file being deleted'
    echo 'hopefully this doesnt make it to disk' | "$bin" "$key" | cat - <(echo -n a) | "$bin" -d "$key" -o bla.txt && exit 1
    [ -e bla.txt ] && echo "ERROR: bla.txt should not exist" && exit 1
    set -e
}

time test ./pegh

echo "successful test run!"

