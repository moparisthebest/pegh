#!/bin/bash

export dummy_file="$1"
shift
export dummy_mb="$1"

[ "$dummy_file" = "" ] && export dummy_file='/tmp/randombytes'
[ "$dummy_mb" = "" ] && export dummy_mb='100'

[ "$TEST_BINS" = "" ] && TEST_BINS="./pegh.openssl ./pegh.libsodium ./pegh.libsodium-openssl"

set -euxo pipefail

# try different size files to encrypt/decrypt
[ -e "$dummy_file" ] || dd if=/dev/urandom bs=1M "count=$dummy_mb" of="$dummy_file"

# try make if it's installed, otherwise fall back to cc
rm -f pegh

# compile against openssl
make PEGH_OPENSSL=1 || cc pegh.c -DPEGH_OPENSSL -lcrypto -O3 -o pegh
mv pegh pegh.openssl

# compile against libsodium
make PEGH_LIBSODIUM=1 || cc pegh.c -DPEGH_LIBSODIUM -lsodium -O3 -o pegh
mv pegh pegh.libsodium

# compile against both libsodium and openssl as a fallback for CPUs libsodium doesn't support
make PEGH_LIBSODIUM=1 PEGH_OPENSSL=1 || cc pegh.c -DPEGH_LIBSODIUM -DPEGH_OPENSSL -lsodium -lcrypto -O3 -o pegh
mv pegh pegh.libsodium-openssl

export key="$(< /dev/urandom tr -dc 'a-z0-9' | head -c12)"

echo "key: $key"

test () {
    bin="$1"
    bin_decrypt="${2:-$bin}"

    echo "testing binaries bin: $bin bin_decrypt: $bin_decrypt"

    echo 'encrypting then decrypting with the same key should succeed'
    "$bin" -e "$key" < "$dummy_file" | "$bin_decrypt" -d "$key" | cmp - "$dummy_file"

    echo 'test with -s 32 requiring 2gb of ram should succeed'
    # can send -s 32 or -m 2048 to decrypt command with identical effect
    #"$bin" -e "$key" -s 32 < "$dummy_file" | "$bin_decrypt" -d "$key" -m 2048 | cmp - "$dummy_file"

    set +e
    # these should fail
    echo 'encrypting with one key and decrypting with another should fail'
    "$bin" -e "$key" -i "$dummy_file" | "$bin_decrypt" -d "$key-wrongkey" | cmp - "$dummy_file" && echo "ERROR: appending -wrongkey to key somehow still worked" && exit 1

    echo 'large values of N without enough memory should fail'
    "$bin" -e "$key" -N 2000000 -i "$dummy_file" >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1
    "$bin_decrypt" -d "$key" -N 2000000 -i "$dummy_file" >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1

    echo 'bad decryption bytes are never output, file should be 0 bytes'
    echo 'hopefully this doesnt make it to disk' | "$bin" "$key" | cat - <(echo -n a) | "$bin_decrypt" -d "$key" -o bla.txt && exit 1
    [ -s bla.txt ] && echo "ERROR: bla.txt should be empty" && exit 1
    set -e
}

for bin in $TEST_BINS
do
    for bin_decrypt in $TEST_BINS
    do
        time test $bin $bin_decrypt
    done
done

echo "successful test run!"

