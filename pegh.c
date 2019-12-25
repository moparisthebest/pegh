
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

// compile with: gcc pegh.c -lcrypto -O3 -o pegh

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
#define SCRYPT_MAX_MEM (1024 * 1024 * 64) // 64mb, must be sufficient for N

// tweak initial read buffer size/reads here
#define BYTES_PER_READ (1024 * 32) // 32kb
#define INITIAL_BUFFER_SIZE (1024 * 256) // 256kb, must be at least 2*BYTES_PER_READ

// don't touch below here unless you know what you are doing

#define KEY_LEN 32 // 256 bit key required for AES-256

// 1 for file format version, 4 for N, 1 for r, 1 for p
#define PRE_SALT_LEN 7
// from libsodium's crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#define SALT_LEN 32
// AES-GCM should only ever have an IV_LEN of 12
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
int main(int argc, char **argv)
{
    unsigned char key[KEY_LEN] = {0};
    /* these are actually mallocd and freed */
    unsigned char *in_buffer, *out_buffer;
    /* these are simply pointers into the above */
    unsigned char *salt, *iv, *ciphertext, *plaintext, *tag;
    int exit_code = 2, decrypt = 1;
    size_t read, in_buffer_len = 0, out_buffer_len, in_buffer_allocd_size = INITIAL_BUFFER_SIZE;

    uint32_t N = SCRYPT_N;
    uint8_t r = SCRYPT_R, p = SCRYPT_P;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <key> [enc]\n", argv[0]);
        return exit_code;
    }

    // this means we want to encrypt, not decrypt
    if (argc > 2 && strcmp("enc", argv[2]) == 0)
        decrypt = 0;

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
            // generate random salt
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
            argv[1], strlen(argv[1]),
            salt, SALT_LEN,
            (uint64_t) N, (uint64_t) r, (uint64_t) p,
            SCRYPT_MAX_MEM,
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
        // success!
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
