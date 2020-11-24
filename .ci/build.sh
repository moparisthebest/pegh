#!/bin/sh

[ "$ARCH" != "aarch64" ] && echo 'skipping all but aarch64 for testing' && exit 0

set -exu

# dependencies to build+test pegh
apk add build-base clang bash libsodium-dev libsodium-static openssl-dev openssl-libs-static

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

export TEST_BINS="./pegh.static.openssl ./pegh.openssl ./pegh.static.libsodium-openssl ./pegh.libsodium-openssl ./pegh.static.libsodium ./pegh.libsodium"

# compile dynamically linked versions (with gcc) to openssl and libsodium, then test all 4 against each other
./test.sh

echo "successfully built and tested static pegh against libsodium and openssl!"

# tests have all passed, move binaries to release directory for later
mkdir -p release
mv pegh.static.openssl "./release/pegh-linux-$ARCH-openssl"
mv pegh.static.libsodium "./release/pegh-linux-$ARCH-libsodium"
mv pegh.static.libsodium-openssl "./release/pegh-linux-$ARCH-libsodium-openssl"

# for our native arch, just once, go ahead and archive the git repo too for later release
if [ "$ARCH" == "amd64" ]
then

    apk add git

    git archive HEAD -9 --format zip -o ./release/pegh-source.zip
    git archive HEAD -9 --format tar.gz -o ./release/pegh-source.tar.gz

fi

if [ "$ARCH" == "amd64" ] || [ "$ARCH" == "i386" ]
then

echo 'going to try to build windows here...'

apk add mingw-w64-gcc curl wine

STATIC_LIB_DIR="$(pwd)"
LIBSODIUM_VERSION='1.0.18'
OPENSSL_VERSION='1.1.1h_3'
OPENSSL_CURL_VERSION='7.73.0_3'

if [ ! -d "${STATIC_LIB_DIR}/libsodium-win32" ]
then

    # only need to grab/unpack these once
    curl -L -O https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}-mingw.tar.gz -O https://curl.se/windows/dl-${OPENSSL_CURL_VERSION}/openssl-${OPENSSL_VERSION}-win64-mingw.zip -O https://curl.se/windows/dl-${OPENSSL_CURL_VERSION}/openssl-${OPENSSL_VERSION}-win32-mingw.zip

    echo "e499c65b1c511cbc6700e436deb3771c3baa737981114c9e9f85f2ec90176861  libsodium-${LIBSODIUM_VERSION}-mingw.tar.gz" > libs.sha256
    echo "fcaa181d848ac56150f00bc46d204d81fde4448a9afe9ef3ca04cc21d3132cb4  openssl-${OPENSSL_VERSION}-win32-mingw.zip" >> libs.sha256
    echo "913ddfa264ed9bae51f9deaa8ebce9d9450fa89fdf4c74ab41a6dfffb5880c67  openssl-${OPENSSL_VERSION}-win64-mingw.zip" >> libs.sha256

    # fail if any of these hashes have changed
    sha256sum -c libs.sha256

    tar xzvf libsodium-${LIBSODIUM_VERSION}-mingw.tar.gz
    unzip openssl-${OPENSSL_VERSION}-win32-mingw.zip
    unzip openssl-${OPENSSL_VERSION}-win64-mingw.zip
fi

if [ "$ARCH" == "i386" ]
then

make CC=i686-w64-mingw32-cc PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win32" clean all
mv pegh.exe pegh-windows-i386-libsodium.exe

make CC=i686-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-${OPENSSL_VERSION}-win32-mingw" clean all
mv pegh.exe pegh-windows-i386-openssl.exe

make CC=i686-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-${OPENSSL_VERSION}-win32-mingw" PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win32" clean all
mv pegh.exe pegh-windows-i386-libsodium-openssl.exe

fi

export wine="wine"

if [ "$ARCH" == "amd64" ]
then

export wine="wine64"

make CC=x86_64-w64-mingw32-cc PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win64" clean all
mv pegh.exe pegh-windows-amd64-libsodium.exe

make CC=x86_64-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-${OPENSSL_VERSION}-win64-mingw" clean all
mv pegh.exe pegh-windows-amd64-openssl.exe

make CC=x86_64-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-${OPENSSL_VERSION}-win64-mingw" PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win64" clean all
mv pegh.exe pegh-windows-amd64-libsodium-openssl.exe

fi

ls -lah *.exe
strip *.exe
ls -lah *.exe
file *.exe

# running the test script sometimes locks up wine, I think due to races on creating ~/.wine, so do that first...
$wine ./pegh-windows-$ARCH-libsodium.exe -h

# now test windows binaries against the static ones with wine
# no binfmt here where executing .exe *just works*, so do it hacky way :'(
export TEST_BINS="./release/pegh-linux-$ARCH-openssl ./release/pegh-linux-$ARCH-libsodium-openssl ./release/pegh-linux-$ARCH-libsodium"
# we've really already tested all of the above against each other, let's just test windows against one
export TEST_BINS="./release/pegh-linux-$ARCH-openssl"

for exe in *.exe
do
script="$exe.sh"
cat > "$script" <<EOF
#!/bin/sh
exec $wine "./$exe" "\$@"
EOF
chmod +x "$script"
export TEST_BINS="./$script $TEST_BINS"
done

./test.sh

echo "windows binaries pass tests through wine!"

killall pegh-windows-amd64-libsodium-openssl.exe pegh-windows-amd64-libsodium.exe pegh-windows-amd64-openssl.exe pegh-windows-i386-libsodium-openssl.exe pegh-windows-i386-libsodium.exe pegh-windows-i386-openssl.exe || true
sleep 5
killall -9 pegh-windows-amd64-libsodium-openssl.exe pegh-windows-amd64-libsodium.exe pegh-windows-amd64-openssl.exe pegh-windows-i386-libsodium-openssl.exe pegh-windows-i386-libsodium.exe pegh-windows-i386-openssl.exe || true
sleep 5
rm -rf ~/.wine /tmp/.wine*

# for later release
mv *.exe ./release/

fi
