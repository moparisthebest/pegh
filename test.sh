#!/bin/bash

export tmp_folder="$1"
shift
export dummy_mb="$1"

[ "$tmp_folder" = "" ] && export tmp_folder='/tmp'
[ "$dummy_mb" = "" ] && export dummy_mb='100'

[ "$TEST_BINS" = "" ] && TEST_BINS="./pegh.openssl ./pegh.libsodium ./pegh.libsodium-openssl"

dummy_file="${tmp_folder}/randombytes${dummy_mb}"
leading_zero_key="${tmp_folder}/leading_zero_key"
leading_zero_key_a="${tmp_folder}/leading_zero_key_a"
leading_zero_key_b="${tmp_folder}/leading_zero_key_b"

set -euxo pipefail

# try different size files to encrypt/decrypt
[ -e "$dummy_file" ] || dd if=/dev/urandom bs=1M "count=$dummy_mb" of="$dummy_file"

export key="$(< /dev/urandom tr -dc 'a-z0-9' | head -c12)"

echo "key: $key"

[ -e "$leading_zero_key" ] || cat <(dd if=/dev/zero bs=1M count=1) <(echo "$key") > "$leading_zero_key"
[ -e "$leading_zero_key_a" ] || cat "$leading_zero_key" <(echo -n a) > "$leading_zero_key_a"
[ -e "$leading_zero_key_b" ] || cat "$leading_zero_key" <(echo -n b) > "$leading_zero_key_b"

# try make if it's installed, otherwise fall back to cc
rm -f pegh

# compile against openssl
make PEGH_OPENSSL=1 || cc -O3 -DPEGH_OPENSSL pegh.c -lcrypto -o pegh
mv pegh pegh.openssl

# compile against libsodium
make PEGH_LIBSODIUM=1 || cc -O3 -DPEGH_LIBSODIUM pegh.c -lsodium -o pegh
mv pegh pegh.libsodium

# compile against both libsodium and openssl as a fallback for CPUs libsodium doesn't support
make PEGH_LIBSODIUM=1 PEGH_OPENSSL=1 || cc -O3 -DPEGH_LIBSODIUM -DPEGH_OPENSSL pegh.c -lsodium -lcrypto -o pegh
mv pegh pegh.libsodium-openssl

test () {
    bin="$1"
    shift
    bin_decrypt="${1:-$bin}"
    shift

    echo "testing binaries bin: $bin bin_decrypt: $bin_decrypt"

    set +eu
    if [ "$2" != "1" ]
    then
        # check both binaries through full pipe to see if it fails with an AES error
        echo a | "$bin" "$@" "$key" | "$bin_decrypt" -d "$key" >/dev/null
        # 19 is the special return code that means specifically libsodium-only and CPU doesn't support AES
        [ ${PIPESTATUS[1]} -eq 19 -o ${PIPESTATUS[2]} -eq 19 ] && set -eu && echo "skipping this test because libsodium doesn't support AES on this CPU" && return 0
    fi
    set -eu


    echo 'encrypting same data with same key should result in different ciphertext'
    cmp <(echo a | "$bin" "$@" "$key") <(echo a | "$bin" "$@" "$key") && echo "random generation broken? same data and key resulted in same decryption so salt generation is broken and this is insecure" && exit 1 || true

    echo 'encrypting then decrypting with the same key should succeed'
    "$bin" -e "$@" "$key" < "$dummy_file" | "$bin_decrypt" -d "$key" | cmp - "$dummy_file"

    # this test is so (rightly) slow it makes our CI builds take 6+ hours, disable for now
    #echo 'test with -s 32 requiring 2gb of ram should succeed'
    # can send -s 32 or -m 2048 to decrypt command with identical effect
    #"$bin" -e "$@" "$key" -s 32 < "$dummy_file" | "$bin_decrypt" -d "$key" -m 2048 | cmp - "$dummy_file"

    echo 'encrypting/decrypting with key in file should work, even when key has leading 0s and a trailing newline'
    "$bin" -e "$@" -f "$leading_zero_key" < "$dummy_file" | "$bin_decrypt" -d -f "$leading_zero_key" | cmp - "$dummy_file"

    set +e
    # these should fail
    echo 'encrypting with one key and decrypting with another should fail'
    "$bin" -e "$@" "$key" -i "$dummy_file" | "$bin_decrypt" -d "$key-wrongkey" | cmp - "$dummy_file" && echo "ERROR: appending -wrongkey to key somehow still worked" && exit 1

    echo 'encrypting/decrypting with key in file where last byte is different should fail'
    "$bin" -e "$@" -f "$leading_zero_key_a" < "$dummy_file" | "$bin_decrypt" -d -f "$leading_zero_key_b" | cmp - "$dummy_file" && echo "ERROR: differing last byte in password file somehow still worked" && exit 1

    echo 'large values of N without enough memory should fail'
    "$bin" -e "$@" "$key" -N 2000000 -i "$dummy_file" >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1
    "$bin_decrypt" -d "$key" -N 2000000 -i "$dummy_file" >/dev/null && echo "ERROR: N of 2 million without extra memory worked" && exit 1

    echo 'bad decryption bytes are never output, file should be 0 bytes'
    echo 'hopefully this doesnt make it to disk' | "$bin" "$@" "$key" | cat - <(echo -n a) | "$bin_decrypt" -d "$key" -o bla.txt && exit 1
    [ -s bla.txt ] && echo "ERROR: bla.txt should be empty" && exit 1
    set -e
}

for bin in $TEST_BINS
do
    for bin_decrypt in $TEST_BINS
    do
        # test default versions
        time test $bin $bin_decrypt
        # test aes
        time test $bin $bin_decrypt -v 0
        # test chacha
        time test $bin $bin_decrypt -v 1
    done
done

echo "successful test run!"

