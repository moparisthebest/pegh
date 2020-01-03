# should compile with clang like:
# CC=clang CFLAGS=-Weverything make clean all
# and gcc like:
# CC=gcc make clean all

CFLAGS += -Wall -Wextra -Werror -std=c89 -pedantic \
       -Wstrict-prototypes -Wold-style-definition -Wconversion \
       -Wno-missing-prototypes -Wno-missing-noreturn -Wno-format \
       -O3

# build or grab from https://curl.haxx.se/windows/
ifdef PEGH_OPENSSL_WIN

ifdef PEGH_LIBSODIUM_WIN
# both libsodium and openssl
CFLAGS = -DPEGH_LIBSODIUM -DPEGH_OPENSSL -I "${PEGH_LIBSODIUM_WIN}/include/" -I "${PEGH_OPENSSL_WIN}/include/"
LDLIBS += "${PEGH_LIBSODIUM_WIN}/lib/libsodium.a" "${PEGH_OPENSSL_WIN}/lib/libcrypto.a" -lws2_32
else
# only openssl
CFLAGS = -DPEGH_OPENSSL -I "${PEGH_OPENSSL_WIN}/include/"
LDLIBS += "${PEGH_OPENSSL_WIN}/lib/libcrypto.a" -lws2_32
endif

else
# build or grab from https://download.libsodium.org/libsodium/releases/
ifdef PEGH_LIBSODIUM_WIN
CFLAGS = -DPEGH_LIBSODIUM -I "${PEGH_LIBSODIUM_WIN}/include/"
LDLIBS += "${PEGH_LIBSODIUM_WIN}/lib/libsodium.a"
else

ifdef PEGH_OPENSSL

ifdef PEGH_LIBSODIUM
# both libsodium and openssl
CFLAGS += -DPEGH_LIBSODIUM -DPEGH_OPENSSL
LDLIBS += -lsodium -lcrypto
else
# only openssl
CFLAGS += -DPEGH_OPENSSL
LDLIBS += -lcrypto
endif

else
ifdef PEGH_LIBSODIUM
# only libsodium
CFLAGS += -DPEGH_LIBSODIUM
LDLIBS += -lsodium
else
# default of only openssl
CFLAGS += -DPEGH_OPENSSL
LDLIBS += -lcrypto
endif
endif
endif
endif

all : pegh

clean :
	rm -f pegh
