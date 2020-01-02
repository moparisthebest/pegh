pegh
----

pegh is a file encryption tool using passwords with modern, standardized, and authenticated encryption. It is simple, secure, and returns proper exit codes so you can tell whether encryption or decryption failed or not.

[pegh](http://klingonska.org/dict/?q=tlh%3Apegh) is Klingon for secret

Usage
-----

```sh
# encrypt file.txt to file.txt.pegh with password SUPER_SECRET_1942
pegh -e SUPER_SECRET_1942 <file.txt >file.txt.pegh

# decrypt file.txt.pegh to file.txt with password SUPER_SECRET_1942
pegh -d SUPER_SECRET_1942 <file.txt.pegh >file.txt

# make enrypted backup
tar czv -C /path/to/dir/ . | pegh SUPER_SECRET_1942 -o foo.tar.gz.pegh

# extract encrypted backup
pegh SUPER_SECRET_1942 -d -i foo.tar.gz.pegh | tar xzv
```

The easiest way to scale cost/time it takes for bruteforcing is simply to continue doubling -s, on both encryption and decryption commands.

full help:
```
$ pegh -h
usage: pegh [options...] password
 -e            encrypt input to output, default mode
 -d            decrypt input to output
 -i <filename> file to use for input, default stdin
 -o <filename> file to use for output, default stdout
 -a            append to -o instead of truncate
 -v            pegh file format version to output,
               either 0 (AES-256-GCM) or 1 (Chacha20-Poly1305),
               default: 0 if AES is hardware accelerated, 1 otherwise
 -c <mb>       chunk size for encryption, while decrypting/encrypting twice
               this ram will be used, the same amount will be needed for
               decryption as encryption. This value is saved in the file
               format, so decryption will fail if this isn't set high enough,
               these are only allocated after scrypt is finished so max usage
               will be the highest of these only, not both combined,
               max: 65535 (AES-256-GCM) or 262143 (Chacha20-Poly1305),
               default: 32
 -m <max_mb>   maximum megabytes of ram to use when deriving key from password
               with scrypt, applies for encryption AND decryption, must
               almost linearly scale with -N, if too low operation will fail,
               default: 64
 -N <num>      scrypt parameter N, only applies for encryption, default 32768
               this is rounded up to the next highest power of 2
 -r <num>      scrypt parameter r, only applies for encryption, default 8
 -p <num>      scrypt parameter p, only applies for encryption, default 1
 -s <num>      multiplication factor to apply to both -N and -m for easy
               work scaling, rounded up to the next highest power of 2,
               BEWARE: -s 32 requires 2G ram, -s 64 requires 4G and so on,
               default: 1
 -h            print this usage text
 -q            do not print error output to stderr
 -V            show version number and format version support then quit

For additional info on scrypt params refer to:
    https://blog.filippo.io/the-scrypt-parameters/
    https://tools.ietf.org/html/rfc7914#section-2
```

Security
--------

Each chunk is fully decrypted and authenticated in memory before being written out as plaintext, so an attacker may be able to truncate a file, but NEVER flip any bytes or corrupt it.  Order is enforced by the incrementing the IV, so re-ordered chunks would be decrypted with the wrong IV and would fail authentication.

Of course standard password bruteforcing is possible, but can be mitigated with increased scrypt parameters and longer password lengths.

pegh file format
----------------

pegh implements a simple versioned file format so encryption parameters can change in the future. Numbers here are inclusive 0-based byte array indices, 0th byte is always version number, everything else depends on version number, currently versions 0 and 1 exist.

Version 0, scrypt key derivation, AES-256-GCM encryption, 43 byte header, 16 byte auth tag per chunk. The 12-byte IV for the first chunk is 0, and is incremented by 1 for each successive chunk, if it ever rolls back over to 0 encryption should be aborted (chunk size should be increased).

| indices      | format                                      | value interpretation                    |
|--------------|---------------------------------------------|-----------------------------------------|
| 0            | 8  bit unsigned byte                        | pegh file format version                |
| 1-4          | 32 bit unsigned integer in big endian order | scrypt N parameter                      |
| 5            | 8  bit unsigned byte                        | scrypt r parameter                      |
| 6            | 8  bit unsigned byte                        | scrypt p parameter                      |
| 7-10         | 32 bit unsigned integer in big endian order | aes encrypted chunk size                |
| 11-42        | 32 randomly generated bytes                 | scrypt key derivation seed              |
| 43+end       | any number of chunks, chunk_size + 16 long  | chunks followed by AES-256-GCM auth tag |

Version 1 has the exact same structure as version 0, except Chacha20-Poly1305 encryption instead of AES-256-GCM, key, IV, tag lengths are all the same.

License
-------

pegh.c: AGPLv3 for now, message me if you have a problem with this

documentation/file format: consider this your choice of MIT, Apache 2, or public domain
