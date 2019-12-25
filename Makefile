pegh : pegh.c
	cc -Wall -Wextra -Werror -std=c89 -pedantic \
	-Wstrict-prototypes -Wold-style-definition \
	pegh.c -lcrypto -O3 -o pegh

clean :
	rm -f pegh
