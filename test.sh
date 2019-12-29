#!/bin/bash

export dummy_file="$1"
shift
export dummy_mb="$1"

[ "$dummy_file" = "" ] && export dummy_file='/dev/shm/randombytes'
[ "$dummy_mb" = "" ] && export dummy_mb='100'

set -euo pipefail

# try different size files to encrypt/decrypt
[ -e "$dummy_file" ] || dd if=/dev/urandom bs=1M "count=$dummy_mb" of="$dummy_file"

# try make if it's installed, otherwise fall back to cc
bins="./pegh.openssl ./pegh.libsodium"
#bins="./pegh.libsodium ./pegh.openssl"
rm -f pegh $bins

# compile against openssl
make PEGH_OPENSSL=1 || cc pegh.c -DPEGH_OPENSSL -lcrypto -O3 -o pegh
mv pegh pegh.openssl

# compile against libsodium
make PEGH_LIBSODIUM=1 || cc pegh.c -DPEGH_LIBSODIUM -lsodium -O3 -o pegh
mv pegh pegh.libsodium

export key="$(< /dev/urandom tr -dc 'a-z0-9' | head -c12)"

echo "key: $key"

test () {
    bin="$1"
    bin_decrypt="${2:-$bin}"

    echo "testing bins: $bin bin_decrypt: $bin_decrypt"

    echo 'encrypting then decrypting with the same key should succeed'
    "$bin" -e "$key" < "$dummy_file" | "$bin_decrypt" -d "$key" | cmp - "$dummy_file"

    echo 'test with -s 32 requiring 2gb of ram should succeed'
    # can send -s 32 or -m 2048 to decrypt command with identical effect
    "$bin" -e "$key" -s 32 < "$dummy_file" | "$bin_decrypt" -d "$key" -m 2048 | cmp - "$dummy_file"

    set +e
    # these should fail
    echo 'encrypting with one key and decrypting with another should fail'
    "$bin" -e "$key" -i "$dummy_file" | "$bin_decrypt" -d "$key-wrongkey" | cmp - "$dummy_file" && echo "ERROR: appending -wrongkey to key somehow still worked" && exit 1

    echo 'large values of N without enough memory should fail'
    "$bin" -e "$key" -N 2000000 -i "$dummy_file" >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1
    "$bin_decrypt" -d "$key" -N 2000000 -i "$dummy_file" >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1

    # todo: can we also make this the case for stdout? needs some buffering...
    echo 'bad decryption should result in output file being deleted'
    echo 'hopefully this doesnt make it to disk' | "$bin" "$key" | cat - <(echo -n a) | "$bin_decrypt" -d "$key" -o bla.txt && exit 1
    [ -s bla.txt ] && echo "ERROR: bla.txt should not exist" && exit 1
    set -e
}

for bin in $bins
do
    for bin_decrypt in $bins
    do
        time test $bin $bin_decrypt
    done
done

echo "successful test run!"

