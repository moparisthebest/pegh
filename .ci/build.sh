#!/bin/sh

ARCH="$1"

set -exu

# change to the directory this script is in
cd "$(dirname "$0")"

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

if [ "$ARCH" == "amd64" ] || [ "$ARCH" == "i386" ]
then

echo 'going to try to build windows here...'

apk add mingw-w64-gcc curl wine

STATIC_LIB_DIR="$(pwd)"
LIBSODIUM_VERSION=1.0.18

curl -O https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}-stable-mingw.tar.gz -O https://curl.haxx.se/windows/dl-7.67.0_5/openssl-1.1.1d_5-win64-mingw.zip -O https://curl.haxx.se/windows/dl-7.67.0_5/openssl-1.1.1d_5-win32-mingw.zip

echo "241d6c88c2d79e13dae9f4943804a5a855c7d2904b21f74ebd31b15d056e3a4f  libsodium-${LIBSODIUM_VERSION}-stable-mingw.tar.gz" > libs.sha256
echo '4f474918a1597d6d1d35e524cf79827623f8ce511259b0047ee95bc0fddbf29c  openssl-1.1.1d_5-win32-mingw.zip' >> libs.sha256
echo '936260c5a865c8e3f6af35a5394dd1acc43063a40a206c717350f1a341d8d822  openssl-1.1.1d_5-win64-mingw.zip' >> libs.sha256

sha256sum -c libs.sha256

tar xzvf libsodium-${LIBSODIUM_VERSION}-stable-mingw.tar.gz
unzip openssl-1.1.1d_5-win32-mingw.zip
unzip openssl-1.1.1d_5-win64-mingw.zip

if [ "$ARCH" == "i386" ]
then

make CC=i686-w64-mingw32-cc PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win32" clean all
mv pegh.exe pegh-windows-i386-libsodium.exe

make CC=i686-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-1.1.1d-win32-mingw" clean all
mv pegh.exe pegh-windows-i386-openssl.exe

make CC=i686-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-1.1.1d-win32-mingw" PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win32" clean all
mv pegh.exe pegh-windows-i386-libsodium-openssl.exe

fi

export wine="wine"

if [ "$ARCH" == "amd64" ]
then

export wine="wine64"

make CC=x86_64-w64-mingw32-cc PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win64" clean all
mv pegh.exe pegh-windows-amd64-libsodium.exe

make CC=x86_64-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-1.1.1d-win64-mingw" clean all
mv pegh.exe pegh-windows-amd64-openssl.exe

make CC=x86_64-w64-mingw32-cc PEGH_OPENSSL_WIN="${STATIC_LIB_DIR}/openssl-1.1.1d-win64-mingw" PEGH_LIBSODIUM_WIN="${STATIC_LIB_DIR}/libsodium-win64" clean all
mv pegh.exe pegh-windows-amd64-libsodium-openssl.exe

fi

ls -lah *.exe
strip *.exe
ls -lah *.exe
file *.exe

# running the test script sometimes locks up wine, I think due to races on creating ~/.wine, so do that first...
$wine ./pegh-windows-amd64-libsodium.exe -h || true

# now test windows binaries against the static ones with wine
# no binfmt here where executing .exe *just works*, so do it hacky way :'(
export TEST_BINS="./pegh.static.openssl ./pegh.static.libsodium-openssl ./pegh.static.libsodium"

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

fi
