/*
 * encrypt.c - Manage the global encryptor
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

#include <stdint.h>
#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#include <sodium.h>

#ifndef __MINGW32__
#include <arpa/inet.h>
#endif

#include "cache.h"
#include "encrypt.h"
#include "ssrutils.h"
#include "ssrbuffer.h"

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

#ifdef DEBUG
static void
dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
        printf("0x%02x ", (uint8_t)text[i]);
    printf("\n");
}

#endif

static const char *supported_ciphers[CIPHER_NUM] = {
    "none",
    "table",
    "rc4",
    "rc4-md5-6",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf"
};

static int supported_ciphers_iv_size[CIPHER_NUM] = {
    0 ,  0,  0,  6, 16, 16, 16, 16, 16, 16, 16,  8, 16, 16, 16,  8,  8,  8,  8, 16,  8,  8, 12
};

static int supported_ciphers_key_size[CIPHER_NUM] = {
    16, 16, 16, 16, 16, 16, 24, 32, 16, 24, 32, 16, 16, 24, 32, 16,  8, 16, 16, 16, 32, 32, 32
};

const char *
cipher_name_from_index(enum cipher_index index)
{
    if (index < NONE || index >= CIPHER_NUM) {
        LOGE("cipher_name_from_index(): Illegal method");
        return NULL;
    }
    return supported_ciphers[index];
}

static int strcicmp(char const *a, char const *b) {
    for (;; a++, b++) {
        int d = tolower(*a) - tolower(*b);
        if (d != 0 || !*a) {
            return d;
        }
    }
}

enum cipher_index
cipher_index_from_name(const char *name)
{
    enum cipher_index m = NONE;
    if (name != NULL) {
        for (m = NONE; m < CIPHER_NUM; ++m) {
            if (strcicmp(name, supported_ciphers[m]) == 0) {
                break;
            }
        }
        if (m >= CIPHER_NUM) {
            LOGE("Invalid cipher name: %s, use rc4-md5 instead", name);
            // m = RC4_MD5;
        }
    }
    return m;
}

static int
crypto_stream_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen,
                     const uint8_t *n, uint64_t ic, const uint8_t *k,
                     enum cipher_index method)
{
    switch (method) {
    case SALSA20:
        return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
    case CHACHA20:
        return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
    case CHACHA20IETF:
        return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, (uint32_t)ic, k);
    default:
        break;
    }
    // always return 0
    return 0;
}

static int
random_compare(const void *_x, const void *_y, uint32_t i, uint64_t a)
{
    uint8_t x = *((uint8_t *)_x);
    uint8_t y = *((uint8_t *)_y);
    return (int) (a % (x + i) - a % (y + i));
}

static void
merge(uint8_t *left, int llength, uint8_t *right,
      int rlength, uint32_t salt, uint64_t key)
{
    uint8_t *ltmp = (uint8_t *)malloc((size_t)llength * sizeof(uint8_t));
    uint8_t *rtmp = (uint8_t *)malloc((size_t)rlength * sizeof(uint8_t));

    uint8_t *ll = ltmp;
    uint8_t *rr = rtmp;

    uint8_t *result = left;

    memcpy(ltmp, left, (size_t)llength * sizeof(uint8_t));
    memcpy(rtmp, right, (size_t)rlength * sizeof(uint8_t));

    while (llength > 0 && rlength > 0) {
        if (random_compare(ll, rr, salt, key) <= 0) {
            *result = *ll;
            ++ll;
            --llength;
        } else {
            *result = *rr;
            ++rr;
            --rlength;
        }
        ++result;
    }

    if (llength > 0) {
        while (llength > 0) {
            *result = *ll;
            ++result;
            ++ll;
            --llength;
        }
    } else {
        while (rlength > 0) {
            *result = *rr;
            ++result;
            ++rr;
            --rlength;
        }
    }

    ss_free(ltmp);
    ss_free(rtmp);
}

static void
merge_sort(uint8_t array[], int length, uint32_t salt, uint64_t key)
{
    uint8_t middle;
    uint8_t *left, *right;
    int llength;

    if (length <= 1) {
        return;
    }

    middle = (uint8_t)length / 2;

    llength = length - middle;

    left  = array;
    right = array + llength;

    merge_sort(left, llength, salt, key);
    merge_sort(right, middle, salt, key);
    merge(left, llength, right, middle, salt, key);
}

int
enc_get_iv_len(struct cipher_env_t *env)
{
    return env->enc_iv_len;
}

uint8_t *
enc_get_key(struct cipher_env_t *env)
{
    return env->enc_key;
}

int
enc_get_key_len(struct cipher_env_t *env)
{
    return env->enc_key_len;
}

unsigned char *
enc_md5(const unsigned char *d, size_t n, unsigned char *md)
{
    return MD5(d, n, md);
}

int
cipher_iv_size(const struct cipher_wrapper *cipher)
{
    if (cipher->core == NULL) {
        return (int) cipher->iv_len;
    } else {
        return EVP_CIPHER_iv_length(cipher->core);
    }
}

int
cipher_key_size(const struct cipher_wrapper *cipher)
{
    if (cipher->core == NULL) {
        return (int) cipher->key_len;
    } else {
        return EVP_CIPHER_key_length(cipher->core);
    }
}

void
bytes_to_key_with_size(const char *pass, size_t len, uint8_t *md, size_t md_size)
{
    uint8_t result[128];
    enc_md5((const unsigned char *)pass, len, result);
    memcpy(md, result, 16);
    int i = 16;
    for (; i < (int)md_size; i += 16) {
        memcpy(result + 16, pass, len);
        enc_md5(result, 16 + len, result);
        memcpy(md + i, result, 16);
    }
}

int
bytes_to_key(const struct cipher_wrapper *cipher, const digest_type_t *md,
             const uint8_t *pass, uint8_t *key)
{
    size_t datal;
    datal = strlen((const char *)pass);

    MD5_CTX c;
    unsigned char md_buf[MAX_MD_SIZE];
    int nkey;
    unsigned int i, mds;

    mds  = 16;
    nkey = 16;
    if (cipher != NULL) {
        nkey = cipher_key_size(cipher);
    }
    if (pass == NULL) {
        return nkey;
    }
    memset(&c, 0, sizeof(MD5_CTX));

    for (int j = 0, addmd = 0; j < nkey; addmd++) {
        MD5_Init(&c);
        if (addmd) {
            MD5_Update(&c, md_buf, mds);
        }
        MD5_Update(&c, pass, datal);
        MD5_Final(md_buf, &c);

        for (i = 0; i < mds; i++, j++) {
            if (j >= nkey) {
                break;
            }
            key[j] = md_buf[i];
        }
    }

    return nkey;
}

int
rand_bytes(uint8_t *output, int len)
{
    randombytes_buf(output, (size_t)len);
    // always return success
    return 0;
}

const cipher_core_t *
get_cipher_of_type(enum cipher_index method)
{
    if (method >= SALSA20) {
        return NULL;
    }

    if (method == RC4_MD5 || method == RC4_MD5_6) {
        method = RC4;
    }

    const char *cipherName = cipher_name_from_index(method);
    if (cipherName == NULL) {
        return NULL;
    }
    return EVP_get_cipherbyname(cipherName);
}

const digest_type_t *
get_digest_type(const char *digest)
{
    if (digest == NULL) {
        LOGE("get_digest_type(): Digest name is null");
        return NULL;
    }

    return EVP_get_digestbyname(digest);
}

void
cipher_context_init(struct cipher_env_t *env, struct cipher_ctx_t *ctx, int enc)
{
    enum cipher_index method = env->enc_method;

    if (method >= SALSA20) {
//        enc_iv_len = supported_ciphers_iv_size[method];
        return;
    }

    const char *cipherName = cipher_name_from_index(method);
    if (cipherName == NULL) {
        return;
    }

    const cipher_core_t *cipher = get_cipher_of_type(method);

    ctx->core_ctx = EVP_CIPHER_CTX_new();
    cipher_core_ctx_t *core_ctx = ctx->core_ctx;

    if (cipher == NULL) {
        LOGE("Cipher %s not found in OpenSSL library", cipherName);
        FATAL("Cannot initialize cipher");
    }
    if (!EVP_CipherInit_ex(core_ctx, cipher, NULL, NULL, NULL, enc)) {
        LOGE("Cannot initialize cipher %s", cipherName);
        exit(EXIT_FAILURE);
    }
    if (!EVP_CIPHER_CTX_set_key_length(core_ctx, env->enc_key_len)) {
        EVP_CIPHER_CTX_cleanup(core_ctx);
        LOGE("Invalid key length: %d", env->enc_key_len);
        exit(EXIT_FAILURE);
    }
    if (method > RC4_MD5) {
        EVP_CIPHER_CTX_set_padding(core_ctx, 1);
    }
}

void
cipher_context_set_iv(struct cipher_env_t *env, struct cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len,
                      int enc)
{
    const unsigned char *true_key;

    if (iv == NULL) {
        LOGE("cipher_context_set_iv(): IV is null");
        return;
    }

    if (!enc) {
        memcpy(ctx->iv, iv, iv_len);
    }

    if (env->enc_method >= SALSA20) {
        return;
    }

    if (env->enc_method == RC4_MD5 || env->enc_method == RC4_MD5_6) {
        unsigned char key_iv[32];
        memcpy(key_iv, env->enc_key, 16);
        memcpy(key_iv + 16, iv, iv_len);
        true_key = enc_md5(key_iv, 16 + iv_len, NULL);
        iv_len   = 0;
    } else {
        true_key = env->enc_key;
    }
    cipher_core_ctx_t *core_ctx = ctx->core_ctx;
    if (core_ctx == NULL) {
        LOGE("cipher_context_set_iv(): Cipher context is null");
        return;
    }
    if (!EVP_CipherInit_ex(core_ctx, NULL, NULL, true_key, iv, enc)) {
        EVP_CIPHER_CTX_cleanup(core_ctx);
        FATAL("Cannot set key and IV");
    }
#ifdef DEBUG
    dump("IV", (char *)iv, (int)iv_len);
#endif
}

void
cipher_context_release(struct cipher_env_t *env, struct cipher_ctx_t *ctx)
{
    if (env->enc_method >= SALSA20) {
        return;
    }
    EVP_CIPHER_CTX_free(ctx->core_ctx);
}

static int
cipher_context_update(struct cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
                      const uint8_t *input, size_t ilen)
{
    cipher_core_ctx_t *core_ctx = ctx->core_ctx;
    int err = 0, tlen = (int)*olen;
    err = EVP_CipherUpdate(core_ctx, (unsigned char *)output, &tlen,
                           (const unsigned char *)input, (int)ilen);
    *olen = (size_t)tlen;
    return err;
}

int
ss_md5_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len)
{
    uint8_t hash[MD5_BYTES];
    HMAC(EVP_md5(), auth_key, key_len, (unsigned char *)msg, (size_t)msg_len, (unsigned char *)hash, NULL);
    memcpy(auth, hash, MD5_BYTES);

    return 0;
}

int
ss_md5_hash_func(char *auth, char *msg, int msg_len)
{
    uint8_t hash[MD5_BYTES];
    MD5((unsigned char *)msg, (size_t)msg_len, (unsigned char *)hash);
    memcpy(auth, hash, MD5_BYTES);

    return 0;
}

int
ss_sha1_hmac_with_key(char *auth, char *msg, int msg_len, uint8_t *auth_key, int key_len)
{
    uint8_t hash[SHA1_BYTES];
    HMAC(EVP_sha1(), auth_key, key_len, (unsigned char *)msg, (size_t)msg_len, (unsigned char *)hash, NULL);
    memcpy(auth, hash, SHA1_BYTES);

    return 0;
}

int
ss_sha1_hash_func(char *auth, char *msg, int msg_len)
{
    uint8_t hash[SHA1_BYTES];
    SHA1((unsigned char *)msg, (size_t)msg_len, (unsigned char *)hash);
    memcpy(auth, hash, SHA1_BYTES);

    return 0;
}

int
ss_aes_128_cbc(char *encrypt, char *out_data, char *key)
{
    unsigned char iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    AES_KEY aes;
    AES_set_encrypt_key((unsigned char*)key, 128, &aes);
    AES_cbc_encrypt((const unsigned char *)encrypt, (unsigned char *)out_data, 16, &aes, iv, AES_ENCRYPT);
    return 0;
}

int
ss_encrypt_all(struct cipher_env_t *env, struct buffer_t *plain, size_t capacity)
{
    enum cipher_index method = env->enc_method;
    if (method > TABLE) {
        struct cipher_ctx_t cipher_ctx;
        cipher_context_init(env, &cipher_ctx, 1);

        size_t iv_len = (size_t) env->enc_iv_len;
        int err       = 1;

        struct buffer_t *cipher = buffer_alloc(max(iv_len + plain->len, capacity));
        cipher->len = plain->len;

        uint8_t iv[MAX_IV_LENGTH];

        rand_bytes(iv, (int)iv_len);
        cipher_context_set_iv(env, &cipher_ctx, iv, iv_len, 1);
        memcpy(cipher->buffer, iv, iv_len);

        if (method >= SALSA20) {
            crypto_stream_xor_ic((uint8_t *)(cipher->buffer + iv_len),
                                 (const uint8_t *)plain->buffer, (uint64_t)(plain->len),
                                 (const uint8_t *)iv,
                                 0, env->enc_key, method);
        } else {
            err = cipher_context_update(&cipher_ctx, (uint8_t *)(cipher->buffer + iv_len),
                                        &cipher->len, (const uint8_t *)plain->buffer,
                                        plain->len);
        }

        if (!err) {
            cipher_context_release(env, &cipher_ctx);
            buffer_free(cipher);
            return -1;
        }

#ifdef DEBUG
        dump("PLAIN", plain->buffer, (int)plain->len);
        dump("CIPHER", cipher->buffer + iv_len, (int)cipher->len);
#endif

        cipher_context_release(env, &cipher_ctx);

        buffer_realloc(plain, max(iv_len + cipher->len, capacity));
        memcpy(plain->buffer, cipher->buffer, iv_len + cipher->len);
        plain->len = iv_len + cipher->len;

        buffer_free(cipher);
        return 0;
    } else {
        if (env->enc_method == TABLE) {
            char *begin = plain->buffer;
            char *ptr   = plain->buffer;
            while (ptr < begin + plain->len) {
                *ptr = (char)env->enc_table[(uint8_t)*ptr];
                ptr++;
            }
        }

        return 0;
    }
}

int
ss_encrypt(struct cipher_env_t *env, struct buffer_t *plain, struct enc_ctx *ctx, size_t capacity)
{
    if (ctx != NULL) {
        int err       = 1;
        size_t iv_len = 0;
        if (!ctx->init) {
            iv_len = (size_t)env->enc_iv_len;
        }

        struct buffer_t *cipher = buffer_alloc(max(iv_len + plain->len, capacity));
        cipher->len = plain->len;

        if (!ctx->init) {
            cipher_context_set_iv(env, &ctx->cipher_ctx, ctx->cipher_ctx.iv, iv_len, 1);
            memcpy(cipher->buffer, ctx->cipher_ctx.iv, iv_len);
            ctx->counter = 0;
            ctx->init    = 1;
        }

        if (env->enc_method >= SALSA20) {
            size_t padding = (size_t)(ctx->counter % SODIUM_BLOCK_SIZE);
            buffer_realloc(cipher, max(iv_len + (padding + cipher->len) * 2, capacity));
            if (padding) {
                buffer_realloc(plain, max(plain->len + padding, capacity));
                memmove(plain->buffer + padding, plain->buffer, plain->len);
                sodium_memzero(plain->buffer, padding);
            }
            crypto_stream_xor_ic((uint8_t *)(cipher->buffer + iv_len),
                                 (const uint8_t *)plain->buffer,
                                 (uint64_t)(plain->len + padding),
                                 (const uint8_t *)ctx->cipher_ctx.iv,
                                 ctx->counter / SODIUM_BLOCK_SIZE, env->enc_key,
                                 env->enc_method);
            ctx->counter += plain->len;
            if (padding) {
                memmove(cipher->buffer + iv_len,
                        cipher->buffer + iv_len + padding, cipher->len);
            }
        } else {
            err =
                cipher_context_update(&ctx->cipher_ctx,
                                      (uint8_t *)(cipher->buffer + iv_len),
                                      &cipher->len, (const uint8_t *)plain->buffer,
                                      plain->len);
            if (!err) {
                buffer_free(cipher);
                return -1;
            }
        }

#ifdef DEBUG
        dump("PLAIN", plain->buffer, (int)plain->len);
        dump("CIPHER", cipher->buffer + iv_len, (int)cipher->len);
#endif

        buffer_realloc(plain, max(iv_len + cipher->len, capacity));
        memcpy(plain->buffer, cipher->buffer, iv_len + cipher->len);
        plain->len = iv_len + cipher->len;

        buffer_free(cipher);
        return 0;
    } else {
        if (env->enc_method == TABLE) {
            char *begin = plain->buffer;
            char *ptr   = plain->buffer;
            while (ptr < begin + plain->len) {
                *ptr = (char)env->enc_table[(uint8_t)*ptr];
                ptr++;
            }
        }
        return 0;
    }
}

int
ss_decrypt_all(struct cipher_env_t *env, struct buffer_t *cipher, size_t capacity)
{
    enum cipher_index method = env->enc_method;
    if (method > TABLE) {
        size_t iv_len = (size_t)env->enc_iv_len;
        int ret       = 1;

        if (cipher->len <= iv_len) {
            return -1;
        }

        struct cipher_ctx_t cipher_ctx;
        cipher_context_init(env, &cipher_ctx, 0);

        struct buffer_t *plain = buffer_alloc(max(cipher->len, capacity));
        plain->len = cipher->len - iv_len;

        uint8_t iv[MAX_IV_LENGTH];
        memcpy(iv, cipher->buffer, iv_len);
        cipher_context_set_iv(env, &cipher_ctx, iv, iv_len, 0);

        if (method >= SALSA20) {
            crypto_stream_xor_ic((uint8_t *)plain->buffer,
                                 (const uint8_t *)(cipher->buffer + iv_len),
                                 (uint64_t)(cipher->len - iv_len),
                                 (const uint8_t *)iv, 0, env->enc_key, method);
        } else {
            ret = cipher_context_update(&cipher_ctx, (uint8_t *)plain->buffer, &plain->len,
                                        (const uint8_t *)(cipher->buffer + iv_len),
                                        cipher->len - iv_len);
        }

        if (!ret) {
            cipher_context_release(env, &cipher_ctx);
            buffer_free(plain);
            return -1;
        }

#ifdef DEBUG
        dump("PLAIN", plain->buffer, (int)plain->len);
        dump("CIPHER", cipher->buffer + iv_len, (int)(cipher->len - iv_len));
#endif

        cipher_context_release(env, &cipher_ctx);

        buffer_realloc(cipher, max(plain->len, capacity));
        memcpy(cipher->buffer, plain->buffer, plain->len);
        cipher->len = plain->len;

        buffer_free(plain);
        return 0;
    } else {
        if (method == TABLE) {
            char *begin = cipher->buffer;
            char *ptr   = cipher->buffer;
            while (ptr < begin + cipher->len) {
                *ptr = (char)env->dec_table[(uint8_t)*ptr];
                ptr++;
            }
        }

        return 0;
    }
}

int
ss_decrypt(struct cipher_env_t *env, struct buffer_t *cipher, struct enc_ctx *ctx, size_t capacity)
{
    if (ctx != NULL) {
        size_t iv_len = 0;
        int err       = 1;

        struct buffer_t *plain = buffer_alloc(max(cipher->len, capacity));
        plain->len = cipher->len;

        if (!ctx->init) {
            uint8_t iv[MAX_IV_LENGTH];
            iv_len      = (size_t)env->enc_iv_len;
            plain->len -= iv_len;

            memcpy(iv, cipher->buffer, iv_len);
            cipher_context_set_iv(env, &ctx->cipher_ctx, iv, iv_len, 0);
            ctx->counter = 0;
            ctx->init    = 1;

            if (env->enc_method > RC4) {
                if (cache_key_exist(env->iv_cache, (char *)iv, iv_len)) {
                    return -1;
                } else {
                    cache_insert(env->iv_cache, (char *)iv, iv_len, NULL);
                }
            }
        }

        if (env->enc_method >= SALSA20) {
            size_t padding = (size_t)(ctx->counter % SODIUM_BLOCK_SIZE);
            buffer_realloc(plain, max((plain->len + padding) * 2, capacity));

            if (padding) {
                buffer_realloc(cipher, max(cipher->len + padding, capacity));
                memmove(cipher->buffer + iv_len + padding, cipher->buffer + iv_len,
                        cipher->len - iv_len);
                sodium_memzero(cipher->buffer + iv_len, padding);
            }
            crypto_stream_xor_ic((uint8_t *)plain->buffer,
                                 (const uint8_t *)(cipher->buffer + iv_len),
                                 (uint64_t)(cipher->len - iv_len + padding),
                                 (const uint8_t *)ctx->cipher_ctx.iv,
                                 ctx->counter / SODIUM_BLOCK_SIZE, env->enc_key,
                                 env->enc_method);
            ctx->counter += cipher->len - iv_len;
            if (padding) {
                memmove(plain->buffer, plain->buffer + padding, plain->len);
            }
        } else {
            err = cipher_context_update(&ctx->cipher_ctx, (uint8_t *)plain->buffer, &plain->len,
                                        (const uint8_t *)(cipher->buffer + iv_len),
                                        cipher->len - iv_len);
        }

        if (!err) {
            buffer_free(plain);
            return -1;
        }

#ifdef DEBUG
        dump("PLAIN", plain->buffer, (int)plain->len);
        dump("CIPHER", cipher->buffer + iv_len, (int)(cipher->len - iv_len));
#endif

        buffer_realloc(cipher, max(plain->len, capacity));
        memcpy(cipher->buffer, plain->buffer, plain->len);
        cipher->len = plain->len;

        buffer_free(plain);
        return 0;
    } else {
        if(env->enc_method == TABLE) {
            char *begin = cipher->buffer;
            char *ptr   = cipher->buffer;
            while (ptr < begin + cipher->len) {
                *ptr = (char)env->dec_table[(uint8_t)*ptr];
                ptr++;
            }
        }
        return 0;
    }
}

int
ss_encrypt_buffer(struct cipher_env_t *env, struct enc_ctx *ctx, char *in, size_t in_size, char *out, size_t *out_size)
{
    struct buffer_t *cipher = buffer_alloc(in_size + 32);
    cipher->len = in_size;
    memcpy(cipher->buffer, in, in_size);
    int s = ss_encrypt(env, cipher, ctx, in_size + 32);
    if (s == 0) {
        *out_size = cipher->len;
        memcpy(out, cipher->buffer, cipher->len);
    }
    buffer_free(cipher);
    return s;
}

int
ss_decrypt_buffer(struct cipher_env_t *env, struct enc_ctx *ctx, char *in, size_t in_size, char *out, size_t *out_size)
{
    struct buffer_t *cipher = buffer_alloc(in_size + 32);
    cipher->len = in_size;
    memcpy(cipher->buffer, in, in_size);
    int s = ss_decrypt(env, cipher, ctx, in_size + 32);
    if (s == 0) {
        *out_size = cipher->len;
        memcpy(out, cipher->buffer, cipher->len);
    }
    buffer_free(cipher);
    return s;
}

void
enc_ctx_init(struct cipher_env_t *env, struct enc_ctx *ctx, int enc)
{
    sodium_memzero(ctx, sizeof(struct enc_ctx));
    cipher_context_init(env, &ctx->cipher_ctx, enc);

    if (enc) {
        rand_bytes(ctx->cipher_ctx.iv, env->enc_iv_len);
    }
}

void
enc_ctx_release(struct cipher_env_t *env, struct enc_ctx *ctx)
{
    cipher_context_release(env, &ctx->cipher_ctx);
}

void
enc_table_init(struct cipher_env_t * env, enum cipher_index method, const char *pass)
{
    uint32_t i;
    uint64_t key = 0;
    uint8_t *digest;

    env->enc_table = ss_malloc(256);
    env->dec_table = ss_malloc(256);

    digest = enc_md5((const uint8_t *)pass, strlen(pass), NULL);

    for (i = 0; i < 8; i++) {
        key += OFFSET_ROL(digest, i);
    }
    for (i = 0; i < 256; ++i) {
        env->enc_table[i] = (uint8_t)i;
    }
    for (i = 1; i < 1024; ++i) {
        merge_sort(env->enc_table, 256, i, key);
    }
    for (i = 0; i < 256; ++i) {
        // gen decrypt table from encrypt table
        env->dec_table[env->enc_table[i]] = (uint8_t)i;
    }

    if (method == TABLE) {
        env->enc_key_len = (int) strlen(pass);
        memcpy(&env->enc_key, pass, env->enc_key_len);
    } else {
        const digest_type_t *md = get_digest_type("MD5");

        env->enc_key_len = bytes_to_key(NULL, md, (const uint8_t *)pass, env->enc_key);

        if (env->enc_key_len == 0) {
            FATAL("Cannot generate key and IV");
        }
    }

    env->enc_iv_len = 0;

    env->enc_method = method;
}

void
enc_key_init(struct cipher_env_t *env, enum cipher_index method, const char *pass)
{
    if (method < NONE || method >= CIPHER_NUM) {
        LOGE("enc_key_init(): Illegal method");
        return;
    }

    // Initialize cache
    cache_create(&env->iv_cache, 256, NULL);

    OpenSSL_add_all_algorithms();

    struct cipher_wrapper cipher = { NULL, 0, 0 };

    // Initialize sodium for random generator
    if (sodium_init() == -1) {
        FATAL("Failed to initialize sodium");
    }

    if (method == SALSA20 || method == CHACHA20 || method == CHACHA20IETF) {
        cipher.core    = NULL;
        cipher.key_len = (size_t) supported_ciphers_key_size[method];
        cipher.iv_len  = (size_t) supported_ciphers_iv_size[method];
    } else {
        cipher.core = (cipher_core_t *)get_cipher_of_type(method);
    }

    if (cipher.core == NULL && cipher.key_len == 0) {
        do {
            LOGE("Cipher %s not found in crypto library", cipher_name_from_index(method));
            FATAL("Cannot initialize cipher");
        } while (0);
    }

    const digest_type_t *md = get_digest_type("MD5");
    if (md == NULL) {
        FATAL("MD5 Digest not found in crypto library");
    }

    env->enc_key_len = bytes_to_key(&cipher, md, (const uint8_t *)pass, env->enc_key);

    if (env->enc_key_len == 0) {
        FATAL("Cannot generate key and IV");
    }
    if (method == RC4_MD5 || method == RC4_MD5_6) {
        env->enc_iv_len = supported_ciphers_iv_size[method];
    } else {
        env->enc_iv_len = cipher_iv_size(&cipher);
    }
    env->enc_method = method;
}

enum cipher_index
enc_init(struct cipher_env_t *env, const char *pass, const char *method)
{
    enum cipher_index m = cipher_index_from_name(method);
    if (m <= TABLE) {
        enc_table_init(env, m, pass);
    } else {
        enc_key_init(env, m, pass);
    }
    env->enc_method = m;
    return m;
}

void
enc_release(struct cipher_env_t *env)
{
    if (env->enc_method == TABLE) {
        ss_free(env->enc_table);
        ss_free(env->dec_table);
    } else {
        cache_delete(env->iv_cache, 0);
    }
}
