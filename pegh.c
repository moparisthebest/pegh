
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

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * tweak scrypt hardness params here
 *
 * https://tools.ietf.org/html/rfc7914#section-2
 * https://blog.filippo.io/the-scrypt-parameters/
 */
#define SCRYPT_N 32768
#define SCRYPT_R 8
#define SCRYPT_P 1
#define SCRYPT_MAX_MEM_MB 64

/* tweak initial read buffer size/reads here */
#define BYTES_PER_READ (1024 * 32) /* 32kb */
#define INITIAL_BUFFER_SIZE (1024 * 256) /* 256kb, must be at least 2*BYTES_PER_READ */

/* don't touch below here unless you know what you are doing */

#define PEGH_VERSION "1.0.0"

#define KEY_LEN 32 /* 256 bit key required for AES-256 */

/* 1 for file format version, 4 for N, 1 for r, 1 for p */
#define PRE_SALT_LEN 7
/* from libsodium's crypto_pwhash_scryptsalsa208sha256_SALTBYTES */
#define SALT_LEN 32
/* AES-GCM should only ever have an IV_LEN of 12 */
#define IV_LEN 12
#define GCM_TAG_LEN 16

#define SALT_IV_LEN (SALT_LEN+IV_LEN)

#define OVERHEAD_LEN (PRE_SALT_LEN+SALT_IV_LEN+GCM_TAG_LEN)

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
int gcm_encrypt(unsigned char *plaintext, size_t plaintext_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len, ret = 0;

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
        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            break;

        /*
        * Finalise the encryption. Normally ciphertext bytes may be written at
        * this stage, but this does not occur in GCM mode
        */
        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
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
int gcm_decrypt(unsigned char *ciphertext, size_t ciphertext_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *tag,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, ret = 0;

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
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            break;

        /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag))
            break;

        /*
        * Finalise the decryption. A return value of 1 indicates success,
        * return value of 0 is a failure - the plaintext is not trustworthy.
        */
        ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    } while(0);

    /* Clean up */
    if(ctx)
        EVP_CIPHER_CTX_free(ctx);

    return ret;
}

/* returns 0 on success, 1 on openssl failure, 2 on other failure */
int pegh(char *password, int decrypt,
         uint32_t scrypt_max_mem_mb, uint32_t N,
         uint8_t r, uint8_t p)
{
    unsigned char key[KEY_LEN] = {0};
    /* these are actually mallocd and freed */
    unsigned char *in_buffer, *out_buffer = NULL;
    /* these are simply pointers into the above */
    unsigned char *salt, *iv, *ciphertext, *plaintext, *tag;
    int exit_code = 2;
    size_t read, in_buffer_len = 0, out_buffer_len, in_buffer_allocd_size = INITIAL_BUFFER_SIZE;

    in_buffer = malloc(in_buffer_allocd_size);
    if(!in_buffer) {
        fprintf(stderr, "in_buffer memory allocation failed\n");
        return exit_code;
    }

    while ((read = fread(in_buffer + in_buffer_len, 1, BYTES_PER_READ, stdin)) > 0) {
        in_buffer_len += read;
        if ((in_buffer_len + BYTES_PER_READ) > in_buffer_allocd_size) {
            in_buffer_allocd_size = in_buffer_allocd_size * 1.5;
            in_buffer = realloc(in_buffer, in_buffer_allocd_size);
            if(!in_buffer) {
                fprintf(stderr, "in_buffer memory reallocation failed\n");
                return exit_code;
            }
        }
    }

    do {
        if (in_buffer_len <= (decrypt ? OVERHEAD_LEN : 0)) {
            fprintf(stderr, "File too small for %scryption\n", decrypt ? "de" : "en");
            break;
        }

        out_buffer_len = decrypt ? (in_buffer_len - OVERHEAD_LEN) : (in_buffer_len + OVERHEAD_LEN);
        out_buffer = malloc(out_buffer_len);
        if(!out_buffer) {
            fprintf(stderr, "out_buffer memory allocation failed\n");
            break;
        }

        if(decrypt) {
            if(in_buffer[0] != 0) {
                fprintf(stderr, "unsupported file format version %d, we only support version 0\n", in_buffer[0]);
                break;
            }
            N = ((in_buffer[1] & 0xFF) << 24)
                | ((in_buffer[2] & 0xFF) << 16)
                | ((in_buffer[3] & 0xFF) << 8)
                | (in_buffer[4] & 0xFF);
            r = in_buffer[5];
            p = in_buffer[6];
            salt = in_buffer + PRE_SALT_LEN;
            iv = salt + SALT_LEN;
            ciphertext = iv + IV_LEN;
            tag = ciphertext + out_buffer_len;
            plaintext = out_buffer;
        } else {
            out_buffer[0] = 0;
            out_buffer[1] = (N >> 24) & 0xFF;
            out_buffer[2] = (N >> 16) & 0xFF;
            out_buffer[3] = (N >> 8) & 0xFF;
            out_buffer[4] = N & 0xFF;
            out_buffer[5] = r;
            out_buffer[6] = p;
            salt = out_buffer + PRE_SALT_LEN;
            /* generate random salt+iv */
            if (RAND_bytes(salt, SALT_IV_LEN) <= 0) {
                fprintf(stderr, "random salt+iv generation error\n");
                exit_code = 1;
                break;
            }
            iv = salt + SALT_LEN;
            ciphertext = iv + IV_LEN;
            tag = ciphertext + in_buffer_len;
            plaintext = in_buffer;
        }

        /* https://commondatastorage.googleapis.com/chromium-boringssl-docs/evp.h.html#EVP_PBE_scrypt */
        if (EVP_PBE_scrypt(
            password, strlen(password),
            salt, SALT_LEN,
            (uint64_t) N, (uint64_t) r, (uint64_t) p,
            (uint64_t) scrypt_max_mem_mb * 1024 * 1024,
            key, KEY_LEN
        ) <= 0) {
            fprintf(stderr, "scrypt key derivation error\n");
            exit_code = 1;
            break;
        }

        if(decrypt) {
            if (1 != gcm_decrypt(ciphertext, out_buffer_len,
                                            key, iv,
                                            tag,
                                            plaintext)) {
                fprintf(stderr, "integrity check failed\n");
                exit_code = 1;
                break;
            }
        } else {
            if (1 != gcm_encrypt(plaintext, in_buffer_len,
                                        key, iv,
                                        ciphertext, tag)) {
                fprintf(stderr, "encryption failed\n");
                exit_code = 1;
                break;
            }
        }
        /* success! */
        fwrite(out_buffer, 1, out_buffer_len, stdout);
        exit_code = 0;
    } while(0);

    if(in_buffer)
        free(in_buffer);
    if(out_buffer)
        free(out_buffer);

    /* print openssl errors */
    if(exit_code == 1)
        ERR_print_errors_fp(stderr);

    return exit_code;
}

int help(int exit_code) {
    /* this ridiculous split is because C89 only supports strings of 509 characters */
    fprintf(stderr, "\
usage: pegh [-demNrphV] password\n\
 -d            decrypt stdin to stdout, default mode\n\
 -e            encrypt stdin to stdout\n\
 -m <max_mb>   maximum megabytes of ram to use when deriving key from password\n\
               with scrypt, applies for encryption AND decryption, must\n\
               almost linearly scale with -N, if too low operation will fail,\n\
               default: %d\n", SCRYPT_MAX_MEM_MB);
    fprintf(stderr, "\
 -N <num>      scrypt parameter N, only applies for encryption, default %d\n\
               this is rounded up to the next highest power of 2\n\
 -r <num>      scrypt parameter r, only applies for encryption, default %d\n\
 -p <num>      scrypt parameter p, only applies for encryption, default %d\n\
 -s <num>      multiplication factor to apply to both -N and -m for easy\n\
               work scaling, rounded up to the next highest power of 2,\n\
               default: 1\n", SCRYPT_N, SCRYPT_R, SCRYPT_P);
    fprintf(stderr, "\
 -h            print this usage text\n\
 -V            show version number and format version support then quit\n\
\nFor additional info on scrypt params refer to:\n\
    https://blog.filippo.io/the-scrypt-parameters/\n\
    https://tools.ietf.org/html/rfc7914#section-2\n\n");
    exit(exit_code);
    return exit_code;
}

uint32_t parse_int_arg(int optind, int argc, char **argv) {
    uint32_t tmp = 0;

    if(optind >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", argv[optind - 1]);
        return help(2);
    }
    errno = 0;
    tmp = strtoul(argv[optind], NULL, 10);
    if(errno != 0 || tmp < 1) {
        fprintf(stderr, "Error: %s %s failed to parse as a number\n", argv[optind - 1], argv[optind]);
        return help(2);
    }
    return tmp;
}

uint8_t parse_byte_arg(int optind, int argc, char **argv) {
    uint32_t tmp;

    tmp = parse_int_arg(optind, argc, argv);
    if(tmp > 255) {
        fprintf(stderr, "Error: %s %s failed to parse as a number 1-255\n", argv[optind - 1], argv[optind]);
        return help(2);
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
    int optind, decrypt = 1;
    char *password = NULL;
    uint32_t N = SCRYPT_N, scrypt_max_mem_mb = SCRYPT_MAX_MEM_MB, scale = 1;
    uint8_t r = SCRYPT_R, p = SCRYPT_P;

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
            case 'm':
                scrypt_max_mem_mb = parse_int_arg(++optind, argc, argv);
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
            case 'V':
                fprintf(stderr, "pegh %s\nformat versions supported: 0\n", PEGH_VERSION);
                return 0;
            case 'h':
                return help(0);
            default:
                fprintf(stderr, "Error: invalid option %s\n", argv[optind]);
                return help(2);
            }
        } else if (password == NULL) {
            password = argv[optind];
        } else {
            fprintf (stderr, "Error: more than one password provided\n");
            return help(2);
        }
    }

    if(password == NULL) {
        if(argc == optind) {
            fprintf (stderr, "Error: no password provided\n");
            return help(2);
        }

        if((argc - optind) != 1) {
            fprintf (stderr, "Error: more than one password provided\n");
            return help(2);
        }
        password = argv[optind];
    }

    /* apply scale */
    N *= scale;
    scrypt_max_mem_mb *= scale;

    /*
    fprintf (stderr, "decrypt = %d, key = %s, scrypt_max_mem_mb = %d, N = %d, r = %d, p = %d, scale = %d\n",
            decrypt, password, scrypt_max_mem_mb, N, r, p, scale);
    return 0;
    */

    return pegh(password, decrypt, scrypt_max_mem_mb, N, r, p);
}
