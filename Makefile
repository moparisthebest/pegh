# should compile with clang like:
# CC=clang CFLAGS=-Weverything make clean all
# and gcc like:
# CC=gcc make clean all

CFLAGS += -Wall -Wextra -Werror -std=c89 -pedantic \
       -Wstrict-prototypes -Wold-style-definition -Wconversion \
        -Wno-missing-prototypes -Wno-missing-noreturn \
       -O3
LDFLAGS += -lcrypto

all : pegh

clean :
	rm -f pegh
