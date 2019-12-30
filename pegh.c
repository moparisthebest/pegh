
/*
 * pegh is a file encryption tool using passwords and authenticated encryption
 * Copyright (C) 2019  Travis Burtrum

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* compile with: cc pegh.c -lcrypto -O3 -o pegh */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

/*
 * tweak default scrypt hardness params here
 *
 * https://tools.ietf.org/html/rfc7914#section-2
 * https://blog.filippo.io/the-scrypt-parameters/
 */
#define SCRYPT_N 32768
#define SCRYPT_R 8
#define SCRYPT_P 1
#define SCRYPT_MAX_MEM 1024 * 1024 * 64 /* 64 megabytes */

/* tweak buffer sizes here, memory use will be twice this */
#define BUFFER_SIZE_MB 32

/*
 * pegh file format, numbers are inclusive 0-based byte array indices
 *
 * 0th byte is always version number, everything else depends on version number
 *
 * |------------------------------------------------------------------------------------------------------|
 * | Version 0, scrypt key derivation, aes-256-gcm encryption, 43 byte header, 16 byte auth tag per chunk |
 * | The 12-byte IV for the first chunk is 0, and is incremented by 1 for each successive chunk, if it    |
 * | ever rolls back over to 0 encryption should be aborted (chunk size should be increased).
 * |--------------|---------------------------------------------|-----------------------------------------|
 * | indices      | format                                      | value interpretation                    |
 * |--------------|---------------------------------------------|-----------------------------------------|
 * | 0            | 8  bit unsigned byte                        | pegh file format version                |
 * | 1-4          | 32 bit unsigned integer in big endian order | scrypt N parameter                      |
 * | 5            | 8  bit unsigned byte                        | scrypt r parameter                      |
 * | 6            | 8  bit unsigned byte                        | scrypt p parameter                      |
 * | 7-10         | 32 bit unsigned integer in big endian order | aes encrypted chunk size                |
 * | 11-42        | 32 randomly generated bytes                 | scrypt key derivation seed              |
 * | 43+end       | any number of chunks, chunk_size + 16 long  | chunks followed by AES-256-GCM auth tag |
 * |------------------------------------------------------------------------------------------------------|
 */

/* don't touch below here unless you know what you are doing */

#define PEGH_VERSION "1.0.0"

/* 256 bit key required for AES-256 */
#define KEY_LEN 32

/* 1 for file format version, 4 for N, 1 for r, 1 for p, 4 for block/buffer size */
#define PRE_SALT_LEN 11
/* from libsodium's crypto_pwhash_scryptsalsa208sha256_SALTBYTES */
#define SALT_LEN 32
/* AES-GCM should only ever have an IV_LEN of 12 */
#define IV_LEN 12
#define GCM_TAG_LEN 16

/* libsodium only supports AES on specific platforms, this jazz is to fallback to openssl impls in those cases */
typedef int (*gcm_func)(const unsigned char *, const size_t,
    const unsigned char *, const unsigned char *,
    unsigned char *, unsigned char *
);

/* default of OpenSSL for now... */
#if !defined(PEGH_OPENSSL) && !defined(PEGH_LIBSODIUM)
#define PEGH_OPENSSL 1
#endif

#ifdef PEGH_OPENSSL

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* this is because we read up to buffer_size at once, and then send that value to openssl which uses int instead of size_t, limit of 2gb */
static const size_t CHUNK_SIZE_MAX_OPENSSL = INT_MAX;

/*
 * returns 1 on success, 0 on failure
 *
 * these will be read from:
 * plaintext
 * plaintext_len
 * key must be length KEY_LEN
 * iv must be length IV_LEN
 *
 * these will be written into:
 * ciphertext must have the capacity of at least plaintext_len
 * tag must have the capacity of at least GCM_TAG_LEN
 */
int gcm_encrypt_openssl(const unsigned char *plaintext, const size_t plaintext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag
               )
{
    EVP_CIPHER_CTX *ctx;
    int ciphertext_written, ret = 0;

    do {
        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new()))
            break;

        /* Initialise the encryption operation. */
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            break;

        /* Setting IV length is not necessary because the default of 12 bytes (96 bits) will be used
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
            break;
        */

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
            break;

        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_written, plaintext, (int) plaintext_len))
            break;

        /* if this isn't true, GCM is broken, we probably don't need to check...
        if(ciphertext_written != plaintext_len) {
            if(NULL != err)
                fprintf(err, "ciphertext_written (%d) != plaintext_len (%d)\n", ciphertext_written, plaintext_len);
            break;
        }
        */

        /*
        * Finalise the encryption. Normally ciphertext bytes may be written at
        * this stage, but this does not occur in GCM mode
        */
        if(1 != EVP_EncryptFinal_ex(ctx, NULL, &ciphertext_written))
            break;

        /* Get the tag */
        ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    } while(0);

    /* Clean up */
    if(ctx)
        EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/*
 * returns 1 on success, 0 on failure
 *
 * these will be read from:
 * ciphertext
 * ciphertext_len
 * key must be length KEY_LEN
 * iv must be length IV_LEN
 * tag must be length GCM_TAG_LEN
 *
 * these will be written into:
 * plaintext must have the capacity of at least ciphertext_len
 */
int gcm_decrypt_openssl(const unsigned char *ciphertext, const size_t ciphertext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *tag,
                unsigned char *plaintext
               )
{
    EVP_CIPHER_CTX *ctx;
    int plaintext_written, ret = 0;

    do {
        /* Create and initialise the context */
        if(!(ctx = EVP_CIPHER_CTX_new()))
            break;

        /* Initialise the decryption operation. */
        if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            break;

        /* Setting IV length is not necessary because the default of 12 bytes (96 bits) will be used
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL))
            break;
        */

        /* Initialise key and IV */
        if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
            break;

        /*
        * Provide the message to be decrypted, and obtain the plaintext output.
        * EVP_DecryptUpdate can be called multiple times if necessary
        */
        if(!EVP_DecryptUpdate(ctx, plaintext, &plaintext_written, ciphertext, (int) ciphertext_len))
            break;

        /* if this isn't true, GCM is broken, we probably don't need to check...
        if(plaintext_written != ciphertext_len) {
            if(NULL != err)
                fprintf(err, "plaintext_written (%d) != ciphertext_len (%d)\n", plaintext_written, ciphertext_len);
            break;
        }
        */

        /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag))
            break;

        /*
        * Finalise the decryption. A return value of 1 indicates success,
        * return value of 0 is a failure - the plaintext is not trustworthy.
        */
        ret = EVP_DecryptFinal_ex(ctx, NULL, &plaintext_written);
    } while(0);

    /* Clean up */
    if(ctx)
        EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/* if both PEGH_OPENSSL and PEGH_LIBSODIUM are defined, we only want the AES funcs from OpenSSL */

#ifndef PEGH_LIBSODIUM

/* returns 1 on success, 0 on error */
int scrypt_derive_key(char *password, size_t password_len,
         uint32_t scrypt_max_mem, uint32_t N,
         uint8_t r, uint8_t p, unsigned char *salt, unsigned char *key, FILE *err) {
    /* derive key using salt, password, and scrypt parameters */
    if (EVP_PBE_scrypt(
        password, password_len,
        salt, SALT_LEN,
        (uint64_t) N, (uint64_t) r, (uint64_t) p,
        (uint64_t) scrypt_max_mem,
        key, KEY_LEN
    ) <= 0) {
        if(NULL != err) {
            fprintf(err, "scrypt key derivation error\n");
            ERR_print_errors_fp(err);
        }
        return 0;
    }
    return 1;
}

/* returns 1 on success, 0 on error */
int random_salt(unsigned char *salt) {
    return RAND_bytes(salt, SALT_LEN) <= 0 ? 0 : 1;
}

void wipe_memory(void * const ptr, const size_t len) {
    OPENSSL_cleanse(ptr, len);
}

#endif /* PEGH_LIBSODIUM */

#endif /* PEGH_OPENSSL */

#ifdef PEGH_LIBSODIUM

#include <sodium.h>

/*
 * unlike openssl, libsodium uses proper types, so we can go all the way up to the "aes-gcm-256 is still secure" limit of around 32gb
 * but 32-bit systems have SIZE_MAX smaller than that, so special case that here
 */
#if (1024UL * 1024 * 1024 * 32) > SIZE_MAX
static const size_t CHUNK_SIZE_MAX_LIBSODIUM = SIZE_MAX;
#else
static const size_t CHUNK_SIZE_MAX_LIBSODIUM = 1024UL * 1024 * 1024 * 32;
#endif

/*
 * returns 1 on success, 0 on failure
 *
 * these will be read from:
 * plaintext
 * plaintext_len
 * key must be length KEY_LEN
 * iv must be length IV_LEN
 *
 * these will be written into:
 * ciphertext must have the capacity of at least plaintext_len
 * tag must have the capacity of at least GCM_TAG_LEN
 */
int gcm_encrypt_libsodium(const unsigned char *plaintext, const size_t plaintext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag
               )
{
    crypto_aead_aes256gcm_encrypt_detached(ciphertext,
                                           tag, NULL,
                              plaintext, plaintext_len,
                              NULL, 0,
                              NULL, iv, key);
    return 1;
}

/*
 * returns 1 on success, 0 on failure
 *
 * these will be read from:
 * ciphertext
 * ciphertext_len
 * key must be length KEY_LEN
 * iv must be length IV_LEN
 * tag must be length GCM_TAG_LEN
 *
 * these will be written into:
 * plaintext must have the capacity of at least ciphertext_len
 */
int gcm_decrypt_libsodium(const unsigned char *ciphertext, const size_t ciphertext_len,
                const unsigned char *key,
                const unsigned char *iv,
                unsigned char *tag,
                unsigned char *plaintext
               )
{
    return crypto_aead_aes256gcm_decrypt_detached(plaintext,
                                  NULL,
                                  ciphertext, (size_t) ciphertext_len,
                                  tag,
                                  NULL, 0,
                                  iv, key) != 0 ? 0 : 1;
}

/* returns 1 on success, 0 on error */
int scrypt_derive_key(char *password, size_t password_len,
         uint32_t scrypt_max_mem, uint32_t N,
         uint8_t r, uint8_t p, unsigned char *salt, unsigned char *key, FILE *err) {
    size_t needed_memory;
    /* derive key using salt, password, and scrypt parameters */

    /* this is how crypto_pwhash_scryptsalsa208sha256_ll calculates the memory needed, so do it here first and check */
    needed_memory = (size_t) 128 * r * p;
    needed_memory += (size_t) 128 * r * (size_t) N;
    needed_memory += (size_t) 256 * r + 64;

    if (needed_memory > scrypt_max_mem) {
        if(NULL != err) {
            /* +1 is to round up here and avoid math.h and ceil()... */
            fprintf(err, "scrypt key derivation error, needed memory %lu mb, allowed memory %d mb, increase -m\n", (needed_memory / 1024 / 1024) + 1, scrypt_max_mem / 1024 / 1024);
        }
        return 0;
    }

    if (crypto_pwhash_scryptsalsa208sha256_ll(
        (const uint8_t *) password, password_len,
        salt, SALT_LEN,
        (uint64_t) N, (uint32_t) r, (uint32_t) p,
        key, KEY_LEN
    ) < 0) {
        if(NULL != err) {
            fprintf(err, "scrypt key derivation error\n");
        }
        return 0;
    }
    return 1;
}

/* returns 1 on success, 0 on error */
int random_salt(unsigned char *salt) {
    randombytes_buf(salt, SALT_LEN);
    return 1;
}

void wipe_memory(void * const ptr, const size_t len) {
    sodium_memzero(ptr, len);
}

#endif /* PEGH_LIBSODIUM */

/* always prefer libsodium AES if possible because it's faster */
#ifdef PEGH_LIBSODIUM

/* if PEGH_OPENSSL is defined, these can be redefined at runtime depending on CPU, otherwise const */
#ifndef PEGH_OPENSSL
#define PEGH_CONST const
#else
#define PEGH_CONST
#endif

static PEGH_CONST gcm_func gcm_encrypt = gcm_encrypt_libsodium;
static PEGH_CONST gcm_func gcm_decrypt = gcm_decrypt_libsodium;
static PEGH_CONST size_t CHUNK_SIZE_MAX = CHUNK_SIZE_MAX_LIBSODIUM;

#elif PEGH_OPENSSL
static const gcm_func gcm_encrypt = gcm_encrypt_openssl;
static const gcm_func gcm_decrypt = gcm_decrypt_openssl;
static const size_t CHUNK_SIZE_MAX = CHUNK_SIZE_MAX_OPENSSL;
#endif

/* returns 1 on success, 0 on failure */
int iv_increment_forbid_zero(unsigned char *n, const size_t nlen, FILE *err)
{
    int all_zero = 0;
    size_t i = 0U;
    uint_fast16_t c = 1U;

    for (; i < nlen; ++i) {
        c += (uint_fast16_t) n[i];
        if(c != 0)
            all_zero = 1;
        n[i] = (unsigned char) c;
        c >>= 8;
    }
    if(all_zero == 0 && NULL != err)
        fprintf(err, "aborting before IV reuse could happen, increase block_size ?\n");
    return all_zero;
}

/* returns 1 on success, 0 on failure */
int gcm_encrypt_stream(const unsigned char *key, unsigned char *iv, size_t buffer_size,
        unsigned char *plaintext, unsigned char *ciphertext,
        FILE *in, FILE *out, FILE *err
       ) {
    size_t plaintext_read;

    while ((plaintext_read = fread(plaintext, 1, buffer_size, in)) > 0) {

        if(1 != gcm_encrypt(plaintext, plaintext_read, key, iv, ciphertext, ciphertext + plaintext_read))
            return 0;

        if(1 != iv_increment_forbid_zero(iv, IV_LEN, err))
            return 0;

        fwrite(ciphertext, 1, plaintext_read + GCM_TAG_LEN, out);
    }
    return 1;
}

/* returns 1 on success, 0 on failure */
int gcm_decrypt_stream(const unsigned char *key, unsigned char *iv, size_t buffer_size,
        unsigned char *plaintext, unsigned char *ciphertext,
        FILE *in, FILE *out, FILE *err
       ) {
    size_t ciphertext_read;

    buffer_size += GCM_TAG_LEN;

    while ((ciphertext_read = fread(ciphertext, 1, buffer_size, in)) > 0) {

        if(ciphertext_read < GCM_TAG_LEN) {
            if(NULL != err)
                fprintf(err, "File too small for decryption, truncated?\n");
            return 0;
        }

        ciphertext_read -= GCM_TAG_LEN;

        if(1 != gcm_decrypt(ciphertext, ciphertext_read, key, iv, ciphertext + ciphertext_read, plaintext))
                return 0;

        if(1 != iv_increment_forbid_zero(iv, IV_LEN, err))
            return 0;

        fwrite(plaintext, 1, ciphertext_read, out);
    }
    return 1;
}

/*
 * reads buffer_size at a time from in, encrypts with AES-256-GCM, and writes them to out
 *
 * returns 1 on success, 0 on failure
 *
 * key must be length KEY_LEN
 * iv must be length IV_LEN
 *
 * buffer_size must be non-zero, this function will allocate this twice
 * in/out must be set
 * err can be NULL in which case no messages are printed
 */
int gcm_stream(const unsigned char *key, size_t buffer_size,
                int decrypt,
                FILE *in, FILE *out, FILE *err
)
{
    /* this is ok because the random salt makes the key random, and we increment this for encryption operation */
    unsigned char iv[IV_LEN] = {0};
    /* these are actually mallocd and freed */
    unsigned char *plaintext = NULL, *ciphertext = NULL;

    int exit_code = 0;

    if(buffer_size > CHUNK_SIZE_MAX) {
        if(NULL != err) {
#ifdef PEGH_OPENSSL
            fprintf(err, "due to openssl API limitation, buffer_size can at most be %ld\n", CHUNK_SIZE_MAX);
#endif
#ifdef PEGH_LIBSODIUM
            fprintf(err, "due to AES-256-GCM security constraints, buffer_size can at most be %ld\n", CHUNK_SIZE_MAX);
#endif
        }
        return 0;
    }

    plaintext = malloc(buffer_size);
    if(!plaintext) {
        if(NULL != err)
            fprintf(err, "plaintext memory allocation failed\n");
        return 0;
    }
    ciphertext = malloc(buffer_size + GCM_TAG_LEN);
    if(!ciphertext) {
        if(NULL != err)
            fprintf(err, "ciphertext memory allocation failed\n");
        free(plaintext);
        return 0;
    }

    exit_code = decrypt ? gcm_decrypt_stream(key, iv, buffer_size, plaintext, ciphertext, in, out, err) :
                          gcm_encrypt_stream(key, iv, buffer_size, plaintext, ciphertext, in, out, err);

    free(plaintext);
    free(ciphertext);

    if(NULL != err && exit_code != 1) {
#ifdef PEGH_OPENSSL
        /* print openssl errors */
        ERR_print_errors_fp(err);
#endif
        fprintf(err, "%scryption failed\n", decrypt ? "de" : "en");
    }

    return exit_code;
}

/* buf must be at least 4 bytes */
uint32_t read_uint32_big_endian(const unsigned char *buf) {
    return (uint32_t) ((buf[0] & 0xFF) << 24)
        | (uint32_t) ((buf[1] & 0xFF) << 16)
        | (uint32_t) ((buf[2] & 0xFF) << 8)
        | (uint32_t) (buf[3] & 0xFF);
}

/* buf must be at least 4 bytes */
void write_uint32_big_endian(uint32_t val, unsigned char *buf) {
    buf[0] = (unsigned char) ((val >> 24) & 0xFF);
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

/* returns 1 on success, 0 on failure */
int scrypt_derive_key_gcm_stream(char *password,
         uint32_t scrypt_max_mem, size_t buffer_size,
         FILE *in, FILE *out, FILE *err,
         uint32_t N, uint8_t r, uint8_t p, unsigned char *salt, int decrypt) {
    unsigned char key[KEY_LEN] = {0};
    int ret;
    size_t password_len;

    password_len = strlen(password);

    ret = scrypt_derive_key(password, password_len, scrypt_max_mem, N, r, p, salt, key, err);
    wipe_memory(password, password_len);

    if(ret == 1)
        ret = gcm_stream(key, buffer_size, decrypt, in, out, err);

    wipe_memory(key, KEY_LEN);
    return ret;
}

/* returns 1 on success, 0 on failure */
int pegh_encrypt(char *password,
         uint32_t scrypt_max_mem, size_t buffer_size,
         FILE *in, FILE *out, FILE *err,
         uint32_t N, uint8_t r, uint8_t p)
{
    unsigned char salt[SALT_LEN] = {0};

    /* first write the version and parameters */
    salt[0] = 0;
    write_uint32_big_endian(N, salt+1);
    salt[5] = r;
    salt[6] = p;
    write_uint32_big_endian((uint32_t) buffer_size, salt+7);
    fwrite(salt, 1, PRE_SALT_LEN, out);

    /* generate random salt, then write it out */
    if (random_salt(salt) != 1) {
        if(NULL != err) {
            fprintf(err, "random salt generation error\n");
#ifdef PEGH_OPENSSL
            ERR_print_errors_fp(err);
#endif
        }
        return 0;
    }
    fwrite(salt, 1, SALT_LEN, out);

    return scrypt_derive_key_gcm_stream(password, scrypt_max_mem, buffer_size, in, out, err, N, r, p, salt, 0);
}

/* returns 1 on success, 0 on failure */
int pegh_decrypt(char *password,
         uint32_t scrypt_max_mem, size_t max_buffer_size,
         FILE *in, FILE *out, FILE *err)
{
    unsigned char salt[SALT_LEN] = {0};

    size_t header_read, buffer_size;

    uint32_t N;
    uint8_t r, p;

    /* first read the version and parameters */
    header_read = fread(salt, 1, PRE_SALT_LEN, in);
    if(header_read != PRE_SALT_LEN) {
        if(NULL != err)
            fprintf(err, "File too small for decryption, invalid header?\n");
        return 0;
    }
    if(salt[0] != 0) {
        if(NULL != err)
            fprintf(err, "unsupported file format version %d, we only support version 0\n", salt[0]);
        return 0;
    }
    N = read_uint32_big_endian(salt+1);
    r = salt[5];
    p = salt[6];
    buffer_size = read_uint32_big_endian(salt+7);
    if(buffer_size > max_buffer_size) {
        if(NULL != err)
            fprintf(err, "memory required to decrypt file is %lu MB but only %lu MB allowed, increase -c\n", buffer_size / 1024 / 1024, max_buffer_size / 1024 / 1024);
        return 0;
    }

    /* next read salt */
    header_read = fread(salt, 1, SALT_LEN, in);
    if(header_read != SALT_LEN) {
        if(NULL != err)
            fprintf(err, "File too small for decryption, invalid header?\n");
        return 0;
    }

    return scrypt_derive_key_gcm_stream(password, scrypt_max_mem, buffer_size, in, out, err, N, r, p, salt, 1);
}

int help(int exit_code) {
    /* this ridiculous split is because C89 only supports strings of 509 characters */
    fprintf(stderr, "\
usage: pegh [options...] password\n\
 -e            encrypt input to output, default mode\n\
 -d            decrypt input to output\n\
 -i <filename> file to use for input, default stdin\n\
 -o <filename> file to use for output, default stdout\n");
    fprintf(stderr, "\
 -a            append to -o instead of truncate\n\
 -c <max_mb>   maximum megabytes of ram to use per encrypted chunk, so while\n\
               decrypting/encrypting twice this will be used, the same\n\
               amount will be needed for decryption as encryption and is\n\
               saved in the file format, so decryption will fail if this\n\
               isn't set high enough, these are\n");
    fprintf(stderr, "\
               only allocated after scrypt is finished so max usage will be\n\
               the highest of these only, not both combined,\n\
               max: %ld, default: %d\n\
 -m <max_mb>   maximum megabytes of ram to use when deriving key from password\n\
               with scrypt, applies for encryption AND decryption, must\n\
               almost linearly scale with -N, if too low operation will fail,\n\
               default: %d\n", CHUNK_SIZE_MAX / 1024 / 1024, BUFFER_SIZE_MB, SCRYPT_MAX_MEM / 1024 / 1024);
    fprintf(stderr, "\
 -N <num>      scrypt parameter N, only applies for encryption, default %d\n\
               this is rounded up to the next highest power of 2\n\
 -r <num>      scrypt parameter r, only applies for encryption, default %d\n\
 -p <num>      scrypt parameter p, only applies for encryption, default %d\n\
 -s <num>      multiplication factor to apply to both -N and -m for easy\n\
               work scaling, rounded up to the next highest power of 2,\n", SCRYPT_N, SCRYPT_R, SCRYPT_P);
    fprintf(stderr, "\
               BEWARE: -s 32 requires 2G ram, -s 64 requires 4G and so on,\n\
               default: 1\n\
 -h            print this usage text\n\
 -q            do not print error output to stderr\n\
 -V            show version number and format version support then quit\n\
\nFor additional info on scrypt params refer to:\n\
    https://blog.filippo.io/the-scrypt-parameters/\n\
    https://tools.ietf.org/html/rfc7914#section-2\n\n");

    return exit_code;
}

void help_exit(int exit_code) {
    help(exit_code);
    exit(exit_code);
}

uint32_t parse_int_arg(int optind, int argc, char **argv) {
    uint64_t tmp = 0;

    if(optind >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", argv[optind - 1]);
        help_exit(2);
        return 0;
    }
    errno = 0;
    tmp = strtoul(argv[optind], NULL, 10);
    if(errno != 0 || tmp < 1 || tmp > UINT_MAX) {
        fprintf(stderr, "Error: %s %s failed to parse as a number\n", argv[optind - 1], argv[optind]);
        help_exit(2);
        return 0;
    }
    return (uint32_t) tmp;
}

uint8_t parse_byte_arg(int optind, int argc, char **argv) {
    uint32_t tmp;

    tmp = parse_int_arg(optind, argc, argv);
    if(tmp > 255) {
        fprintf(stderr, "Error: %s %s failed to parse as a number 1-255\n", argv[optind - 1], argv[optind]);
        help_exit(2);
        return 0;
    }
    return (uint8_t) tmp;
}

uint32_t next_highest_power_of_2(uint32_t v) {
    --v;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return ++v;
}

/* returns 0 on success, 1 on openssl failure, 2 on other failure */
int main(int argc, char **argv)
{
    int optind, decrypt = 0, append = 0, exit_code = 2;
    char *password = NULL;
    uint32_t N = SCRYPT_N, scrypt_max_mem = SCRYPT_MAX_MEM, buffer_size = BUFFER_SIZE_MB * 1024 * 1024, scale = 1;
    uint8_t r = SCRYPT_R, p = SCRYPT_P;

    FILE *in = stdin, *out = stdout, *err = stderr;
    char *in_filename = NULL, *out_filename = NULL;

#ifdef PEGH_LIBSODIUM
    if (sodium_init() == -1) {
        fprintf(stderr, "Error: libsodium could not be initialized, compile/use openssl version?\n");
        return 2;
    }
    if (crypto_aead_aes256gcm_is_available() == 0) {
#ifdef PEGH_OPENSSL
        /* swap to OpenSSL AES which is always supported */
        fprintf(stderr, "Warning: libsodium does not support AES-256-GCM on this CPU, falling back to openssl version instead...\n");
        gcm_encrypt = gcm_encrypt_openssl;
        gcm_decrypt = gcm_decrypt_openssl;
        CHUNK_SIZE_MAX = CHUNK_SIZE_MAX_OPENSSL;
#else
        /* nothing we can do */
        fprintf(stderr, "Error: libsodium does not support AES-256-GCM on this CPU, compile/use openssl version?\n");
        return 2;
#endif /* PEGH_OPENSSL */
    }
#endif /* PEGH_LIBSODIUM */

    for (optind = 1; optind < argc; ++optind) {
        if(strlen(argv[optind]) == 2 && argv[optind][0] == '-') {

            /* -- means stop parsing options */
            if(argv[optind][1] == '-') {
                ++optind;
                break;
            }

            switch (argv[optind][1]) {
            case 'e':
                decrypt = 0;
                break;
            case 'd':
                decrypt = 1;
                break;
            case 'a':
                append = 1;
                break;
            case 'i':
                if(++optind >= argc) {
                    fprintf(stderr, "Error: %s requires an argument\n", argv[optind - 1]);
                    return help(2);
                }
                in_filename = argv[optind];
                break;
            case 'o':
                if(++optind >= argc) {
                    fprintf(stderr, "Error: %s requires an argument\n", argv[optind - 1]);
                    return help(2);
                }
                out_filename = argv[optind];
                break;
            case 'c':
                buffer_size = parse_int_arg(++optind, argc, argv) * 1024 * 1024;
                if(buffer_size > CHUNK_SIZE_MAX) {
                    fprintf(stderr, "Error: %s chunk size cannot exceed %ld megabytes\n", argv[optind - 1], CHUNK_SIZE_MAX / 1024 / 1024);
                    return help(2);
                }
                break;
            case 'm':
                scrypt_max_mem = parse_int_arg(++optind, argc, argv) * 1024 * 1024;
                break;
            case 'N':
                N = next_highest_power_of_2(parse_int_arg(++optind, argc, argv));
                break;
            case 's':
                scale = next_highest_power_of_2(parse_int_arg(++optind, argc, argv));
                break;
            case 'r':
                r = parse_byte_arg(++optind, argc, argv);
                break;
            case 'p':
                p = parse_byte_arg(++optind, argc, argv);
                break;
            case 'q':
                err = NULL;
                break;
            case 'V':
                fprintf(stderr, "pegh %s\nformat versions supported: 0\n", PEGH_VERSION);
                return 0;
            case 'h':
                return help(0);
            default:
                fprintf(stderr, "Error: invalid option %s\n", argv[optind]);
                return help(exit_code);
            }
        } else if (password == NULL) {
            password = argv[optind];
        } else {
            fprintf (stderr, "Error: more than one password provided\n");
            return help(exit_code);
        }
    }

    if(password == NULL) {
        if(argc == optind) {
            fprintf (stderr, "Error: no password provided\n");
            return help(exit_code);
        }

        if((argc - optind) != 1) {
            fprintf (stderr, "Error: more than one password provided\n");
            return help(exit_code);
        }
        password = argv[optind];
    }

    /* apply scale */
    N *= scale;
    scrypt_max_mem *= scale;

    /*
    fprintf (stderr, "decrypt = %d, key = %s, scrypt_max_mem = %d, N = %d, r = %d, p = %d, scale = %d\n",
            decrypt, password, scrypt_max_mem, N, r, p, scale);
    return 0;
    */

    if(NULL != in_filename) {
        in = fopen(in_filename, "rb");
        if(!in) {
            fprintf (stderr, "Error: file '%s' cannot be opened for reading\n", in_filename);
            return exit_code;
        }
    }
    if(NULL != out_filename) {
        out = fopen(out_filename, append ? "ab" : "wb");
        if(!out) {
            fprintf (stderr, "Error: file '%s' cannot be opened for writing\n", out_filename);
            if(NULL != in_filename)
                fclose(in);
            return exit_code;
        }
    }

    if(decrypt)
        exit_code = pegh_decrypt(password, scrypt_max_mem, buffer_size, in, out, err);
    else
        exit_code = pegh_encrypt(password, scrypt_max_mem, buffer_size, in, out, err, N, r, p);

    if(NULL != in_filename)
        fclose(in);
    if(NULL != out_filename) {
        fclose(out);
    }

    /* to the OS, 0 means success, the above functions 1 means success */
    return exit_code == 1 ? 0 : 1;
}
