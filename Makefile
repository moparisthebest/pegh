# should compile with clang like:
# CC=clang CFLAGS=-Weverything make clean all
# and gcc like:
# CC=gcc make clean all

CFLAGS += -Wall -Wextra -Werror -std=c89 -pedantic \
       -Wstrict-prototypes -Wold-style-definition -Wconversion \
       -Wno-missing-prototypes -Wno-missing-noreturn \
       -O3

ifdef PEGH_OPENSSL

ifdef PEGH_LIBSODIUM
# both libsodium and openssl
CFLAGS += -DPEGH_LIBSODIUM -DPEGH_OPENSSL
LDFLAGS += -lsodium -lcrypto
else
# only openssl
CFLAGS += -DPEGH_OPENSSL
LDFLAGS += -lcrypto
endif

else
ifdef PEGH_LIBSODIUM
# only libsodium
CFLAGS += -DPEGH_LIBSODIUM
LDFLAGS += -lsodium
else
# default of only openssl
CFLAGS += -DPEGH_OPENSSL
LDFLAGS += -lcrypto
endif
endif

all : pegh

clean :
	rm -f pegh
