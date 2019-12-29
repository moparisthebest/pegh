# should compile with clang like:
# CC=clang CFLAGS=-Weverything make clean all
# and gcc like:
# CC=gcc make clean all

CFLAGS += -Wall -Wextra -Werror -std=c89 -pedantic \
       -Wstrict-prototypes -Wold-style-definition -Wconversion \
       -Wno-missing-prototypes -Wno-missing-noreturn \
       -O3

ifdef PEGH_OPENSSL
CFLAGS += -DPEGH_OPENSSL
LDFLAGS += -lcrypto
else
ifdef PEGH_LIBSODIUM
CFLAGS += -DPEGH_LIBSODIUM
LDFLAGS += -lsodium
else
CFLAGS += -DPEGH_OPENSSL
LDFLAGS += -lcrypto
endif
endif

all : pegh

clean :
	rm -f pegh
