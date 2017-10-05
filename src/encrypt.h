/*
 * encrypt.h - Define the enryptor's interface
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef __MINGW32__
#include <sys/socket.h>
#else

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
typedef EVP_CIPHER cipher_core_t;
typedef EVP_CIPHER_CTX cipher_core_ctx_t;
typedef EVP_MD digest_type_t;
#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

#elif defined(USE_CRYPTO_POLARSSL)

#include <polarssl/cipher.h>
#include <polarssl/md.h>
typedef cipher_info_t cipher_core_t;
typedef cipher_context_t cipher_core_ctx_t;
typedef md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH POLARSSL_MAX_IV_LENGTH
#define MAX_MD_SIZE POLARSSL_MD_MAX_SIZE

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
typedef mbedtls_cipher_info_t cipher_core_t;
typedef mbedtls_cipher_context_t cipher_core_ctx_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH MBEDTLS_MAX_IV_LENGTH
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE

/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#if !defined(MBEDTLS_CIPHER_MODE_CFB)
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif

#endif

#ifdef USE_CRYPTO_APPLECC

#include <CommonCrypto/CommonCrypto.h>

#define kCCAlgorithmInvalid UINT32_MAX
#define kCCContextValid 0
#define kCCContextInvalid -1

typedef struct {
    CCCryptorRef cryptor;
    int valid;
    CCOperation encrypt;
    CCAlgorithm cipher;
    CCMode mode;
    CCPadding padding;
    uint8_t iv[MAX_IV_LENGTH];
    uint8_t key[MAX_KEY_LENGTH];
    size_t iv_len;
    size_t key_len;
} cipher_cc_t;

#endif


enum cipher_index {
    NONE,
    TABLE,
    RC4,
    RC4_MD5_6,
    RC4_MD5,
    AES_128_CFB,
    AES_192_CFB,
    AES_256_CFB,
    AES_128_CTR,
    AES_192_CTR,
    AES_256_CTR,
    BF_CFB,
    CAMELLIA_128_CFB,
    CAMELLIA_192_CFB,
    CAMELLIA_256_CFB,
    CAST5_CFB,
    DES_CFB,
    IDEA_CFB,
    RC2_CFB,
    SEED_CFB,
    SALSA20,
    CHACHA20,
    CHACHA20IETF,
    CIPHER_NUM,
};

struct cipher_env_t {
    uint8_t *enc_table;
    uint8_t *dec_table;
    uint8_t enc_key[MAX_KEY_LENGTH];
    int enc_key_len;
    int enc_iv_len;
    enum cipher_index enc_method;

    struct cache *iv_cache;
};

struct cipher_ctx_t {
    cipher_core_ctx_t *core_ctx;
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t cc;
#endif
    uint8_t iv[MAX_IV_LENGTH];
};

struct cipher_wrapper {
    cipher_core_t *core;
    size_t iv_len;
    size_t key_len;
};

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define SODIUM_BLOCK_SIZE   64

#define ADDRTYPE_MASK 0xEF

#define MD5_BYTES 16U
#define SHA1_BYTES 20U

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

struct buffer_t {
    size_t len;
    size_t capacity;
    char   *buffer;
};

struct chunk_t {
    uint32_t idx;
    uint32_t len;
    uint32_t counter;
    struct buffer_t *buf;
};

struct enc_ctx {
    uint8_t init;
    uint64_t counter;
    struct cipher_ctx_t cipher_ctx;
};

void bytes_to_key_with_size(const char *pass, size_t len, uint8_t *md, size_t md_size);

int rand_bytes(uint8_t *output, int len);

int ss_encrypt_all(struct cipher_env_t* env, struct buffer_t *plaintext, size_t capacity);
int ss_decrypt_all(struct cipher_env_t* env, struct buffer_t *ciphertext, size_t capacity);
int ss_encrypt(struct cipher_env_t* env, struct buffer_t *plaintext, struct enc_ctx *ctx, size_t capacity);
int ss_decrypt(struct cipher_env_t* env, struct buffer_t *ciphertext, struct enc_ctx *ctx, size_t capacity);

enum cipher_index enc_init(struct cipher_env_t *env, const char *pass, const char *method);
void enc_release(struct cipher_env_t *env);
void enc_ctx_init(struct cipher_env_t *env, struct enc_ctx *ctx, int enc);
void enc_ctx_release(struct cipher_env_t* env, struct enc_ctx *ctx);
int enc_get_iv_len(struct cipher_env_t* env);
uint8_t* enc_get_key(struct cipher_env_t* env);
int enc_get_key_len(struct cipher_env_t* env);
void cipher_context_release(struct cipher_env_t *env, struct cipher_ctx_t *ctx);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);

int ss_md5_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len);
int ss_md5_hash_func(char *auth, char *msg, int msg_len);
int ss_sha1_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len);
int ss_sha1_hash_func(char *auth, char *msg, int msg_len);
int ss_aes_128_cbc(char *encrypt, char *out_data, char *key);
int ss_encrypt_buffer(struct cipher_env_t *env, struct enc_ctx *ctx, char *in, size_t in_size, char *out, size_t *out_size);
int ss_decrypt_buffer(struct cipher_env_t *env, struct enc_ctx *ctx, char *in, size_t in_size, char *out, size_t *out_size);

struct buffer_t * buffer_alloc(size_t capacity);
int buffer_realloc(struct buffer_t *ptr, size_t capacity);
void buffer_free(struct buffer_t *ptr);

//extern struct cipher_env_t cipher_env;

#endif // _ENCRYPT_H
