/*
 * aead.c - Manage AEAD ciphers
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 * Copyright (C) 2021 - 2021, ssrlive
 *
 * This file is part of the shadowsocksr-native.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocksr-native is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Definitions for libsodium */
#include <sodium.h>
typedef crypto_aead_aes256gcm_state aes256gcm_ctx;
/* Definitions for mbedTLS */
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_NONCE_LENGTH 32
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE
/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#if !defined(MBEDTLS_CIPHER_MODE_CFB)
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif
#ifndef MBEDTLS_GCM_C
#error No GCM support detected
#endif
#ifdef crypto_aead_xchacha20poly1305_ietf_ABYTES
#define FS_HAVE_XCHACHA20IETF
#endif

//#define ADDRTYPE_MASK 0xF

/*
#define CRYPTO_ERROR     -2
#define CRYPTO_NEED_MORE -1
#define CRYPTO_OK         0
*/

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define SUBKEY_INFO "ss-subkey"
#define IV_INFO "ss-iv"

#ifndef BF_NUM_ENTRIES_FOR_SERVER
#define BF_NUM_ENTRIES_FOR_SERVER 1e6
#endif

#ifndef BF_NUM_ENTRIES_FOR_CLIENT
#define BF_NUM_ENTRIES_FOR_CLIENT 1e4
#endif

#ifndef BF_ERROR_RATE_FOR_SERVER
#define BF_ERROR_RATE_FOR_SERVER 1e-10
#endif

#ifndef BF_ERROR_RATE_FOR_CLIENT
#define BF_ERROR_RATE_FOR_CLIENT 1e-15
#endif

struct aead_buffer_t {
    size_t idx;
    size_t len;
    size_t capacity;
    char   *data;
};

struct aead_cipher_t {
    int method;
    int skey;
    cipher_kt_t *info;
    size_t nonce_len;
    size_t key_len;
    size_t tag_len;
    uint8_t key[MAX_KEY_LENGTH];

    struct aead_buffer_t *encrypt_all_cache;
    struct aead_buffer_t *decrypt_all_cache;
    struct aead_buffer_t *encrypt_cache;
    struct aead_buffer_t *decrypt_cache;
};

struct aead_cipher_ctx_t {
    uint32_t init;
    uint64_t counter;
    cipher_evp_t *evp;
    aes256gcm_ctx *aes256gcm_ctx;
    struct aead_cipher_t *cipher;
    struct aead_buffer_t *chunk;
    uint8_t salt[MAX_KEY_LENGTH];
    uint8_t skey[MAX_KEY_LENGTH];
    uint8_t nonce[MAX_NONCE_LENGTH];
};

#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"
#include <time.h>
#include <stdio.h>
#include <assert.h>

#include <sodium.h>
#if !defined(__MINGW32__) && !defined(_MSC_VER)
#include <arpa/inet.h>
#endif

#include "ppbloom.h"
#include "aead.h"
#include "ssrutils.h"
#if defined(_MSC_VER)
#include <winsock.h>
#endif
#include "encrypt.h"

#define NONE                    (-1)
#define AES128GCM               0
#define AES192GCM               1
#define AES256GCM               2
/*
 * methods above requires gcm context
 * methods below doesn't require it,
 * then we need to fake one
 */
#define CHACHA20POLY1305IETF    3

#ifdef FS_HAVE_XCHACHA20IETF
#define XCHACHA20POLY1305IETF   4
#endif

#define CHUNK_SIZE_LEN          2
#define CHUNK_SIZE_MASK         0x3FFF

/*
 * Spec: http://shadowsocks.org/en/wiki/AEAD-Ciphers.html
 *
 * The way Shadowsocks using AEAD ciphers is specified in SIP004 and amended in SIP007. SIP004 was proposed by @Mygod
 * with design inspirations from @wongsyrone, @Noisyfox and @breakwa11. SIP007 was proposed by @riobard with input from
 * @madeye, @Mygod, @wongsyrone, and many others.
 *
 * Key Derivation
 *
 * HKDF_SHA1 is a function that takes a secret key, a non-secret salt, an info string, and produces a subkey that is
 * cryptographically strong even if the input secret key is weak.
 *
 *      HKDF_SHA1(key, salt, info) => subkey
 *
 * The info string binds the generated subkey to a specific application context. In our case, it must be the string
 * "ss-subkey" without quotes.
 *
 * We derive a per-session subkey from a pre-shared master key using HKDF_SHA1. Salt must be unique through the entire
 * life of the pre-shared master key.
 *
 * TCP
 *
 * An AEAD encrypted TCP stream starts with a randomly generated salt to derive the per-session subkey, followed by any
 * number of encrypted chunks. Each chunk has the following structure:
 *
 *      [encrypted payload length][length tag][encrypted payload][payload tag]
 *
 * Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF. The higher two bits are reserved and must be
 * set to zero. Payload is therefore limited to 16*1024 - 1 bytes.
 *
 * The first AEAD encrypt/decrypt operation uses a counting nonce starting from 0. After each encrypt/decrypt operation,
 * the nonce is incremented by one as if it were an unsigned little-endian integer. Note that each TCP chunk involves
 * two AEAD encrypt/decrypt operation: one for the payload length, and one for the payload. Therefore each chunk
 * increases the nonce twice.
 *
 * UDP
 *
 * An AEAD encrypted UDP packet has the following structure:
 *
 *      [salt][encrypted payload][tag]
 *
 * The salt is used to derive the per-session subkey and must be generated randomly to ensure uniqueness. Each UDP
 * packet is encrypted/decrypted independently, using the derived subkey and a nonce with all zero bytes.
 *
 */

const char *supported_aead_ciphers[AEAD_CIPHER_NUM] = {
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
#ifdef FS_HAVE_XCHACHA20IETF
    "xchacha20-ietf-poly1305"
#endif
};

/*
 * use mbed TLS cipher wrapper to unify handling
 */
static const char *supported_aead_ciphers_mbedtls[AEAD_CIPHER_NUM] = {
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    CIPHER_UNSUPPORTED,
#ifdef FS_HAVE_XCHACHA20IETF
    CIPHER_UNSUPPORTED
#endif
};

static const int supported_aead_ciphers_nonce_size[AEAD_CIPHER_NUM] = {
    12, 12, 12, 12,
#ifdef FS_HAVE_XCHACHA20IETF
    24
#endif
};

static const int supported_aead_ciphers_key_size[AEAD_CIPHER_NUM] = {
    16, 24, 32, 32,
#ifdef FS_HAVE_XCHACHA20IETF
    32
#endif
};

static const int supported_aead_ciphers_tag_size[AEAD_CIPHER_NUM] = {
    16, 16, 16, 16,
#ifdef FS_HAVE_XCHACHA20IETF
    16
#endif
};

static int
aead_cipher_encrypt(struct aead_cipher_ctx_t *cipher_ctx,
                    uint8_t *c,
                    size_t *clen,
                    uint8_t *m,
                    size_t mlen,
                    uint8_t *ad,
                    size_t adlen,
                    uint8_t *n,
                    uint8_t *k)
{
    int err                      = CRYPTO_OK;
    unsigned long long long_clen = 0;

    size_t nlen = cipher_ctx->cipher->nonce_len;
    size_t tlen = cipher_ctx->cipher->tag_len;

    switch (cipher_ctx->cipher->method) {
    case AES256GCM: // Only AES-256-GCM is supported by libsodium.
        if (cipher_ctx->aes256gcm_ctx != NULL) { // Use it if availble
            err = crypto_aead_aes256gcm_encrypt_afternm(c, &long_clen, m, mlen,
                                                        ad, adlen, NULL, n,
                                                        (const aes256gcm_ctx *)cipher_ctx->aes256gcm_ctx);
            *clen = (size_t)long_clen; // it's safe to cast 64bit to 32bit length here
            break;
        }
    //fall through
    // Otherwise, just use the mbedTLS one with crappy AES-NI.
    case AES192GCM:
    case AES128GCM:

        err = mbedtls_cipher_auth_encrypt(cipher_ctx->evp, n, nlen, ad, adlen,
                                          m, mlen, c, clen, c + mlen, tlen);
        *clen += tlen;
        break;
    case CHACHA20POLY1305IETF:
        err = crypto_aead_chacha20poly1305_ietf_encrypt(c, &long_clen, m, mlen,
                                                        ad, adlen, NULL, n, k);
        *clen = (size_t)long_clen;
        break;
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        err = crypto_aead_xchacha20poly1305_ietf_encrypt(c, &long_clen, m, mlen,
                                                         ad, adlen, NULL, n, k);
        *clen = (size_t)long_clen;
        break;
#endif
    default:
        return CRYPTO_ERROR;
    }

    return err;
}

static int
aead_cipher_decrypt(struct aead_cipher_ctx_t *cipher_ctx,
                    uint8_t *p, size_t *plen,
                    uint8_t *m, size_t mlen,
                    uint8_t *ad, size_t adlen,
                    uint8_t *n, uint8_t *k)
{
    int err                      = CRYPTO_ERROR;
    unsigned long long long_plen = 0;

    size_t nlen = cipher_ctx->cipher->nonce_len;
    size_t tlen = cipher_ctx->cipher->tag_len;

    switch (cipher_ctx->cipher->method) {
    case AES256GCM: // Only AES-256-GCM is supported by libsodium.
        if (cipher_ctx->aes256gcm_ctx != NULL) { // Use it if availble
            err = crypto_aead_aes256gcm_decrypt_afternm(p, &long_plen, NULL, m, mlen,
                                                        ad, adlen, n,
                                                        (const aes256gcm_ctx *)cipher_ctx->aes256gcm_ctx);
            *plen = (size_t)long_plen; // it's safe to cast 64bit to 32bit length here
            break;
        }
    //fall through
    // Otherwise, just use the mbedTLS one with crappy AES-NI.
    case AES192GCM:
    case AES128GCM:
        err = mbedtls_cipher_auth_decrypt(cipher_ctx->evp, n, nlen, ad, adlen,
                                          m, mlen - tlen, p, plen, m + mlen - tlen, tlen);
        break;
    case CHACHA20POLY1305IETF:
        err = crypto_aead_chacha20poly1305_ietf_decrypt(p, &long_plen, NULL, m, mlen,
                                                        ad, adlen, n, k);
        *plen = (size_t)long_plen; // it's safe to cast 64bit to 32bit length here
        break;
#ifdef FS_HAVE_XCHACHA20IETF
    case XCHACHA20POLY1305IETF:
        err = crypto_aead_xchacha20poly1305_ietf_decrypt(p, &long_plen, NULL, m, mlen,
                                                         ad, adlen, n, k);
        *plen = (size_t)long_plen; // it's safe to cast 64bit to 32bit length here
        break;
#endif
    default:
        return CRYPTO_ERROR;
    }

    // The success return value ln libsodium and mbedTLS are both 0
    if (err != 0)
        // Although we never return any library specific value in the caller,
        // here we still set the error code to CRYPTO_ERROR to avoid confusion.
        err = CRYPTO_ERROR;

    return err;
}

/*
 * get basic cipher info structure
 * it's a wrapper offered by crypto library
 */
const cipher_kt_t *
aead_get_cipher_type(int method)
{
    const char *ciphername;
    const char *mbedtlsname;
    if (method < AES128GCM || method >= AEAD_CIPHER_NUM) {
        LOGE("%s", "aead_get_cipher_type(): Illegal method");
        return NULL;
    }

    /* cipher that don't use mbed TLS, just return */
    if (method >= CHACHA20POLY1305IETF) {
        return NULL;
    }

    ciphername  = supported_aead_ciphers[method];
    mbedtlsname = supported_aead_ciphers_mbedtls[method];
    if (strcmp(mbedtlsname, CIPHER_UNSUPPORTED) == 0) {
        LOGE("Cipher %s currently is not supported by mbed TLS library",
             ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedtlsname);
}

static void
aead_cipher_ctx_set_key(struct aead_cipher_ctx_t *cipher_ctx, int enc)
{
    int err;
    const digest_type_t *md = mbedtls_md_info_from_string("SHA1");
    if (md == NULL) {
        FATAL("SHA1 Digest not found in crypto library");
    }

    err = crypto_hkdf(md,
                          cipher_ctx->salt, cipher_ctx->cipher->key_len,
                          cipher_ctx->cipher->key, cipher_ctx->cipher->key_len,
                          (uint8_t *)SUBKEY_INFO, strlen(SUBKEY_INFO),
                          cipher_ctx->skey, cipher_ctx->cipher->key_len);
    if (err) {
        FATAL("Unable to generate subkey");
    }

    memset(cipher_ctx->nonce, 0, cipher_ctx->cipher->nonce_len);

    /* cipher that don't use mbed TLS, just return */
    if (cipher_ctx->cipher->method >= CHACHA20POLY1305IETF) {
        return;
    }
    if (cipher_ctx->aes256gcm_ctx != NULL) {
        if (crypto_aead_aes256gcm_beforenm(cipher_ctx->aes256gcm_ctx,
                                           cipher_ctx->skey) != 0) {
            FATAL("Cannot set libsodium cipher key");
        }
        return;
    }
    if (mbedtls_cipher_setkey(cipher_ctx->evp, cipher_ctx->skey,
                              (int)cipher_ctx->cipher->key_len * 8, (mbedtls_operation_t)enc) != 0) {
        FATAL("Cannot set mbed TLS cipher key");
    }
    if (mbedtls_cipher_reset(cipher_ctx->evp) != 0) {
        FATAL("Cannot finish preparation of mbed TLS cipher context");
    }
}

static void
aead_cipher_ctx_init(struct aead_cipher_ctx_t *cipher_ctx, int method, int enc)
{
    const char *ciphername;
    const cipher_kt_t *cipher;
    if (method < AES128GCM || method >= AEAD_CIPHER_NUM) {
        LOGE("%s", "aead_cipher_ctx_init(): Illegal method");
        return;
    }

    if (method >= CHACHA20POLY1305IETF) {
        return;
    }

    ciphername = supported_aead_ciphers[method];

    cipher = aead_get_cipher_type(method);

    if (method == AES256GCM && crypto_aead_aes256gcm_is_available()) {
        cipher_ctx->aes256gcm_ctx = ss_aligned_malloc(sizeof(aes256gcm_ctx));
        memset(cipher_ctx->aes256gcm_ctx, 0, sizeof(aes256gcm_ctx));
    } else {
        cipher_evp_t *evp;
        cipher_ctx->aes256gcm_ctx = NULL;
        cipher_ctx->evp           = ss_malloc(sizeof(cipher_evp_t));
        memset(cipher_ctx->evp, 0, sizeof(cipher_evp_t));
        evp = cipher_ctx->evp;
        mbedtls_cipher_init(evp);
        if (mbedtls_cipher_setup(evp, cipher) != 0) {
            FATAL("Cannot initialize mbed TLS cipher context");
        }
    }

    if (cipher == NULL) {
        LOGE("Cipher %s not found in mbed TLS library", ciphername);
        FATAL("Cannot initialize mbed TLS cipher");
    }

#ifdef SS_DEBUG
    dump("KEY", (char *)cipher_ctx->cipher->key, cipher_ctx->cipher->key_len);
#endif
    (void)enc;
}

void
aead_ctx_init(struct aead_cipher_t *cipher, struct aead_cipher_ctx_t *cipher_ctx, int enc)
{
    sodium_memzero(cipher_ctx, sizeof(struct aead_cipher_ctx_t));
    cipher_ctx->cipher = cipher;

    aead_cipher_ctx_init(cipher_ctx, cipher->method, enc);

    if (enc) {
        rand_bytes(cipher_ctx->salt, cipher->key_len);
    }
}

void aead_ctx_release(struct aead_cipher_ctx_t *cipher_ctx, int free_this) {
    do {
        if (cipher_ctx == NULL) {
            break;
        }
        if (cipher_ctx->chunk != NULL) {
            bfree(cipher_ctx->chunk, 1);
            cipher_ctx->chunk = NULL;
        }

        if (cipher_ctx->cipher->method >= CHACHA20POLY1305IETF) {
            break;
        }

        if (cipher_ctx->aes256gcm_ctx != NULL) {
            ss_aligned_free(cipher_ctx->aes256gcm_ctx);
        } else {
            mbedtls_cipher_free(cipher_ctx->evp);
            ss_free(cipher_ctx->evp);
        }
    } while (0);

    if (free_this) {
        free(cipher_ctx);
    }
}

int
aead_encrypt_all(struct aead_buffer_t *plaintext, struct aead_cipher_t *cipher, size_t capacity)
{
    size_t salt_len, tag_len, clen;
    int err;
    struct aead_buffer_t *ciphertext;

    struct aead_cipher_ctx_t cipher_ctx;
    aead_ctx_init(cipher, &cipher_ctx, 1);

    salt_len = cipher->key_len;
    tag_len  = cipher->tag_len;
    err         = CRYPTO_OK;

    brealloc(cipher->encrypt_all_cache, salt_len + tag_len + plaintext->len, capacity);
    ciphertext = cipher->encrypt_all_cache;
    ciphertext->len = tag_len + plaintext->len;

    /* copy salt to first pos */
    memcpy(ciphertext->data, cipher_ctx.salt, salt_len);

    ppbloom_add((void *)cipher_ctx.salt, salt_len);

    aead_cipher_ctx_set_key(&cipher_ctx, 1);

    clen = ciphertext->len;
    err = aead_cipher_encrypt(&cipher_ctx,
                              (uint8_t *)ciphertext->data + salt_len, &clen,
                              (uint8_t *)plaintext->data, plaintext->len,
                              NULL, 0, cipher_ctx.nonce, cipher_ctx.skey);

    aead_ctx_release(&cipher_ctx, 0);

    if (err)
        return CRYPTO_ERROR;

    assert(ciphertext->len == clen);

    brealloc(plaintext, salt_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, salt_len + ciphertext->len);
    plaintext->len = salt_len + ciphertext->len;

    return CRYPTO_OK;
}

int
aead_decrypt_all(struct aead_buffer_t *ciphertext, struct aead_cipher_t *cipher, size_t capacity)
{
    size_t plen;
    size_t salt_len = cipher->key_len;
    size_t tag_len  = cipher->tag_len;
    int err         = CRYPTO_OK;
    struct aead_buffer_t *plaintext;
    uint8_t *salt;
    struct aead_cipher_ctx_t cipher_ctx;

    if (ciphertext->len <= salt_len + tag_len) {
        return CRYPTO_ERROR;
    }

    aead_ctx_init(cipher, &cipher_ctx, 0);

    brealloc(cipher->decrypt_all_cache, ciphertext->len, capacity);
    plaintext = cipher->decrypt_all_cache;
    plaintext->len = ciphertext->len - salt_len - tag_len;

    /* get salt */
    salt = cipher_ctx.salt;
    memcpy(salt, ciphertext->data, salt_len);

    if (ppbloom_check((void *)salt, salt_len) == 1) {
        LOGE("%s", "crypto: AEAD: repeat salt detected");
        return CRYPTO_ERROR;
    }

    aead_cipher_ctx_set_key(&cipher_ctx, 0);

    plen = plaintext->len;
    err = aead_cipher_decrypt(&cipher_ctx,
                              (uint8_t *)plaintext->data, &plen,
                              (uint8_t *)ciphertext->data + salt_len,
                              ciphertext->len - salt_len, NULL, 0,
                              cipher_ctx.nonce, cipher_ctx.skey);

    aead_ctx_release(&cipher_ctx, 0);

    if (err)
        return CRYPTO_ERROR;

    ppbloom_add((void *)salt, salt_len);

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return CRYPTO_OK;
}

static int
aead_chunk_encrypt(struct aead_cipher_ctx_t *ctx, uint8_t *p, uint8_t *c,
                   uint8_t *n, size_t plen)
{
    int err;
    size_t clen;
    uint8_t len_buf[CHUNK_SIZE_LEN];
    uint16_t t;

    size_t nlen = ctx->cipher->nonce_len;
    size_t tlen = ctx->cipher->tag_len;

    assert(plen <= CHUNK_SIZE_MASK);

    t = htons(((uint16_t)plen) & CHUNK_SIZE_MASK);
    memcpy(len_buf, &t, CHUNK_SIZE_LEN);

    clen = CHUNK_SIZE_LEN + tlen;
    err  = aead_cipher_encrypt(ctx, c, &clen, len_buf, CHUNK_SIZE_LEN,
                               NULL, 0, n, ctx->skey);
    if (err) {
        return CRYPTO_ERROR;
    }
    assert(clen == CHUNK_SIZE_LEN + tlen);

    sodium_increment(n, nlen);

    clen = plen + tlen;
    err  = aead_cipher_encrypt(ctx, c + CHUNK_SIZE_LEN + tlen, &clen, p, plen,
                               NULL, 0, n, ctx->skey);
    if (err) {
        return CRYPTO_ERROR;
    }
    assert(clen == plen + tlen);

    sodium_increment(n, nlen);

    return CRYPTO_OK;
}

/* TCP */
int
aead_encrypt(struct aead_buffer_t *plaintext, struct aead_cipher_ctx_t *cipher_ctx, size_t capacity)
{
    struct aead_buffer_t *ciphertext;
    struct aead_cipher_t *cipher;
    int err;
    size_t salt_ofst, salt_len, tag_len, out_len;

    if (cipher_ctx == NULL)
        return CRYPTO_ERROR;

    if (plaintext->len == 0) {
        return CRYPTO_OK;
    }

    cipher = cipher_ctx->cipher;
    err          = CRYPTO_ERROR;
    salt_ofst = 0;
    salt_len  = cipher->key_len;
    tag_len   = cipher->tag_len;

    if (!cipher_ctx->init) {
        salt_ofst = salt_len;
    }

    out_len = salt_ofst + 2 * tag_len + plaintext->len + CHUNK_SIZE_LEN;
    brealloc(cipher_ctx->cipher->encrypt_cache, out_len, capacity);
    ciphertext      = cipher_ctx->cipher->encrypt_cache;
    ciphertext->len = out_len;

    if (!cipher_ctx->init) {
        memcpy(ciphertext->data, cipher_ctx->salt, salt_len);
        aead_cipher_ctx_set_key(cipher_ctx, 1);
        cipher_ctx->init = 1;

        ppbloom_add((void *)cipher_ctx->salt, salt_len);
    }

    err = aead_chunk_encrypt(cipher_ctx,
                             (uint8_t *)plaintext->data,
                             (uint8_t *)ciphertext->data + salt_ofst,
                             cipher_ctx->nonce, plaintext->len);
    if (err)
        return err;

    brealloc(plaintext, ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, ciphertext->len);
    plaintext->len = ciphertext->len;

    return 0;
}

static int
aead_chunk_decrypt(struct aead_cipher_ctx_t *ctx, uint8_t *p, uint8_t *c, uint8_t *n,
                   size_t *plen, size_t *clen)
{
    int err;
    size_t mlen;
    size_t nlen = ctx->cipher->nonce_len;
    size_t tlen = ctx->cipher->tag_len;
    uint8_t len_buf[2];
    size_t chunk_len;

    if (*clen <= 2 * tlen + CHUNK_SIZE_LEN) {
        return CRYPTO_NEED_MORE;
    }
    err = aead_cipher_decrypt(ctx, len_buf, plen, c, CHUNK_SIZE_LEN + tlen,
                              NULL, 0, n, ctx->skey);
    if (err) {
        return CRYPTO_ERROR;
    }
    assert(*plen == CHUNK_SIZE_LEN);

    mlen = load16_be(len_buf);
    mlen = mlen & CHUNK_SIZE_MASK;

    if (mlen == 0) {
        return CRYPTO_ERROR;
    }
    chunk_len = 2 * tlen + CHUNK_SIZE_LEN + mlen;

    if (*clen < chunk_len) {
        return CRYPTO_NEED_MORE;
    }
    sodium_increment(n, nlen);

    err = aead_cipher_decrypt(ctx, p, plen, c + CHUNK_SIZE_LEN + tlen, mlen + tlen,
                              NULL, 0, n, ctx->skey);
    if (err) {
        return CRYPTO_ERROR;
    }
    assert(*plen == mlen);

    sodium_increment(n, nlen);

    *clen = *clen - chunk_len;

    return CRYPTO_OK;
}

int
aead_decrypt(struct aead_buffer_t *ciphertext, struct aead_cipher_ctx_t *cipher_ctx, size_t capacity)
{
    size_t plen, cidx;
    struct aead_buffer_t *plaintext;

    int err             = CRYPTO_OK;

    struct aead_cipher_t *cipher = cipher_ctx->cipher;

    size_t salt_len = cipher->key_len;

    if (cipher_ctx->chunk == NULL) {
        cipher_ctx->chunk = (struct aead_buffer_t *)ss_malloc(sizeof(struct aead_buffer_t));
        memset(cipher_ctx->chunk, 0, sizeof(struct aead_buffer_t));
        balloc(cipher_ctx->chunk, capacity);
    }

    brealloc(cipher_ctx->chunk,
             cipher_ctx->chunk->len + ciphertext->len, capacity);
    memcpy(cipher_ctx->chunk->data + cipher_ctx->chunk->len,
           ciphertext->data, ciphertext->len);
    cipher_ctx->chunk->len += ciphertext->len;

    brealloc(cipher_ctx->cipher->decrypt_cache, cipher_ctx->chunk->len, capacity);
    plaintext = cipher_ctx->cipher->decrypt_cache;

    if (!cipher_ctx->init) {
        if (cipher_ctx->chunk->len <= salt_len)
            return CRYPTO_NEED_MORE;

        memcpy(cipher_ctx->salt, cipher_ctx->chunk->data, salt_len);

        if (ppbloom_check((void *)cipher_ctx->salt, salt_len) == 1) {
            LOGE("%s", "crypto: AEAD: repeat salt detected");
            return CRYPTO_ERROR;
        }

        aead_cipher_ctx_set_key(cipher_ctx, 0);

        memmove(cipher_ctx->chunk->data, cipher_ctx->chunk->data + salt_len,
                cipher_ctx->chunk->len - salt_len);
        cipher_ctx->chunk->len -= salt_len;

        cipher_ctx->init = 1;
    }

    plen = 0;
    cidx = 0;
    while (cipher_ctx->chunk->len > 0) {
        size_t chunk_clen = cipher_ctx->chunk->len;
        size_t chunk_plen = 0;
        err = aead_chunk_decrypt(cipher_ctx,
                                 (uint8_t *)plaintext->data + plen,
                                 (uint8_t *)cipher_ctx->chunk->data + cidx,
                                 cipher_ctx->nonce, &chunk_plen, &chunk_clen);
        if (err == CRYPTO_ERROR) {
            return err;
        } else if (err == CRYPTO_NEED_MORE) {
            if (plen == 0) {
                return err;
            } else{
                memmove((uint8_t *)cipher_ctx->chunk->data, 
                        (uint8_t *)cipher_ctx->chunk->data + cidx, chunk_clen);
                break;
            }
        }
        assert(cipher_ctx->chunk->len >= chunk_clen);
        cipher_ctx->chunk->len = chunk_clen;
        cidx += cipher_ctx->cipher->tag_len * 2 + CHUNK_SIZE_LEN + chunk_plen;
        plen                  += chunk_plen;
    }
    plaintext->len = plen;

    // Add the salt to bloom filter
    if (cipher_ctx->init == 1) {
        if (ppbloom_check((void *)cipher_ctx->salt, salt_len) == 1) {
            LOGE("%s", "crypto: AEAD: repeat salt detected");
            return CRYPTO_ERROR;
        }
        ppbloom_add((void *)cipher_ctx->salt, salt_len);
        cipher_ctx->init = 2;
    }

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return CRYPTO_OK;
}

static int bloom_ref_count = 0;

struct aead_cipher_t *
aead_key_init(int method, const char *pass, const char *key)
{
    struct aead_cipher_t *cipher;
    if (method < AES128GCM || method >= AEAD_CIPHER_NUM) {
        LOGE("%s", "aead_key_init(): Illegal method");
        return NULL;
    }

    // Initialize sodium for random generator
    if (sodium_init() == -1) {
        FATAL("Failed to initialize sodium");
    }

    if (bloom_ref_count++ == 0) {
        // Initialize NONCE bloom filter
#ifdef MODULE_LOCAL
        ppbloom_init((int)BF_NUM_ENTRIES_FOR_CLIENT, BF_ERROR_RATE_FOR_CLIENT);
#else
        ppbloom_init((int)BF_NUM_ENTRIES_FOR_SERVER, BF_ERROR_RATE_FOR_SERVER);
#endif
    }

    cipher = (struct aead_cipher_t *)ss_malloc(sizeof(struct aead_cipher_t));
    memset(cipher, 0, sizeof(struct aead_cipher_t));

    if (method >= CHACHA20POLY1305IETF) {
        cipher_kt_t *cipher_info = (cipher_kt_t *)ss_malloc(sizeof(cipher_kt_t));
        cipher->info             = cipher_info;
        cipher->info->base       = NULL;
        cipher->info->key_bitlen = supported_aead_ciphers_key_size[method] * 8;
        cipher->info->iv_size    = supported_aead_ciphers_nonce_size[method];
    } else {
        cipher->info = (cipher_kt_t *)aead_get_cipher_type(method);
    }

    if (cipher->info == NULL && cipher->key_len == 0) {
        LOGE("Cipher %s not found in crypto library", supported_aead_ciphers[method]);
        FATAL("Cannot initialize cipher");
    }

    if (key != NULL)
        cipher->key_len = crypto_parse_key(key, cipher->key,
                                           supported_aead_ciphers_key_size[method]);
    else
        cipher->key_len = crypto_derive_key(pass, cipher->key,
                                            supported_aead_ciphers_key_size[method]);

    if (cipher->key_len == 0) {
        FATAL("Cannot generate key and nonce");
    }

    cipher->nonce_len = supported_aead_ciphers_nonce_size[method];
    cipher->tag_len   = supported_aead_ciphers_tag_size[method];
    cipher->method    = method;

    cipher->encrypt_all_cache = aead_buffer_create(4096);
    cipher->decrypt_all_cache = aead_buffer_create(4096);
    cipher->encrypt_cache = aead_buffer_create(4096);
    cipher->decrypt_cache = aead_buffer_create(4096);

    return cipher;
}

struct aead_cipher_t *
aead_init(const char *pass, const char *key, const char *method)
{
    int m = AES128GCM;
    if (method != NULL) {
        /* check method validity */
        for (m = AES128GCM; m < AEAD_CIPHER_NUM; m++)
            if (strcmp(method, supported_aead_ciphers[m]) == 0) {
                break;
            }
        if (m >= AEAD_CIPHER_NUM) {
            LOGE("Invalid cipher name: %s, use chacha20-ietf-poly1305 instead", method);
            m = CHACHA20POLY1305IETF;
        }
    }
    return aead_key_init(m, pass, key);
}

///////////////////////////////////////////////////////////////////////////////

size_t
crypto_derive_key(const char *pass, uint8_t *key, size_t key_len)
{
    const digest_type_t *md;
    size_t datal;
    mbedtls_md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int addmd;
    unsigned int i, j, mds;

    datal = strlen((const char *)pass);

    md = mbedtls_md_info_from_string("MD5");
    if (md == NULL) {
        FATAL("MD5 Digest not found in crypto library");
    }

    mds = mbedtls_md_get_size(md);
    memset(&c, 0, sizeof(mbedtls_md_context_t));

    if (pass == NULL)
        return key_len;
    if (mbedtls_md_setup(&c, md, 0))
        return 0;

    for (j = 0, addmd = 0; j < key_len; addmd++) {
        mbedtls_md_starts(&c);
        if (addmd) {
            mbedtls_md_update(&c, md_buf, mds);
        }
        mbedtls_md_update(&c, (uint8_t *)pass, datal);
        mbedtls_md_finish(&c, &(md_buf[0]));

        for (i = 0; i < mds; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    mbedtls_md_free(&c);
    return key_len;
}

/* HKDF-Extract + HKDF-Expand */
int
crypto_hkdf(const struct mbedtls_md_info_t *md, const unsigned char *salt,
            size_t salt_len, const unsigned char *ikm, size_t ikm_len,
            const unsigned char *info, size_t info_len, unsigned char *okm,
            size_t okm_len)
{
    unsigned char prk[MBEDTLS_MD_MAX_SIZE];

    return crypto_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk) ||
           crypto_hkdf_expand(md, prk, mbedtls_md_get_size(md), info, info_len,
                              okm, okm_len);
}

/* HKDF-Extract(salt, IKM) -> PRK */
int
crypto_hkdf_extract(const struct mbedtls_md_info_t *md, const unsigned char *salt,
                    size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                    unsigned char *prk)
{
    size_t hash_len;
    unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = { '\0' };

    if ((int)salt_len < 0) {
        return CRYPTO_ERROR;
    }

    hash_len = mbedtls_md_get_size(md);

    if (salt == NULL) {
        salt     = null_salt;
        salt_len = hash_len;
    }

    return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

/* HKDF-Expand(PRK, info, L) -> OKM */
int
crypto_hkdf_expand(const struct mbedtls_md_info_t *md, const unsigned char *prk,
                   size_t prk_len, const unsigned char *info, size_t info_len,
                   unsigned char *okm, size_t okm_len)
{
    int ret;
    size_t hash_len, N, T_len = 0, where = 0, i;
    mbedtls_md_context_t ctx;
    unsigned char T[MBEDTLS_MD_MAX_SIZE];

    if ((int)info_len < 0 || (int)okm_len < 0 || okm == NULL) {
        return CRYPTO_ERROR;
    }

    hash_len = (size_t) mbedtls_md_get_size(md);

    if (prk_len < hash_len) {
        return CRYPTO_ERROR;
    }

    if (info == NULL) {
        info = (const unsigned char *)"";
    }

    N = okm_len / hash_len;

    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
        return CRYPTO_ERROR;
    }

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md, 1)) != 0) {
        mbedtls_md_free(&ctx);
        return ret;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        uint8_t c = (uint8_t)i;

        ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len) ||
              mbedtls_md_hmac_update(&ctx, T, T_len) ||
              mbedtls_md_hmac_update(&ctx, info, info_len) ||
              /* The constant concatenated to the end of each T(n) is a single
               * octet. */
              mbedtls_md_hmac_update(&ctx, &c, 1) ||
              mbedtls_md_hmac_finish(&ctx, T);

        if (ret != 0) {
            mbedtls_md_free(&ctx);
            return ret;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len  = hash_len;
    }

    mbedtls_md_free(&ctx);

    return 0;
}

#include <mbedtls/base64.h>
#define BASE64_SIZE(x)  (((x)+2) / 3 * 4 + 1)

// Workaround for "%z" in Windows printf
#ifdef __MINGW32__
#define SSIZE_FMT "%Id"
#define SIZE_FMT "%Iu"
#else
#define SSIZE_FMT "%zd"
#define SIZE_FMT "%zu"
#endif

size_t
crypto_parse_key(const char *base64, uint8_t *key, size_t key_len)
{
    size_t base64_len = strlen(base64);
    size_t out_len       = BASE64_SIZE(base64_len);
    uint8_t *out = (uint8_t*)calloc(out_len, sizeof(uint8_t));
    uint8_t *out_key;

    //out_len = base64_decode(out, base64, out_len);
    mbedtls_base64_decode(out, out_len, &out_len, (const unsigned char *)base64, base64_len);

    if (out_len > 0 && out_len >= key_len) {
        memcpy(key, out, key_len);
#ifdef SS_DEBUG
        dump("KEY", (char *)key, key_len);
#endif
        free(out);
        return key_len;
    }

    out_len = BASE64_SIZE(key_len);
    rand_bytes(key, key_len);
    out_key = (uint8_t *) calloc(out_len, sizeof(uint8_t));
    //base64_encode(out_key, out_len, key, key_len);
    mbedtls_base64_encode(out_key, out_len, &out_len, key, key_len);
    LOGE("%s", "Invalid key for your chosen cipher!");
    LOGE("It requires a " SIZE_FMT "-byte key encoded with URL-safe Base64", key_len);
    LOGE("Generating a new random key: %s", out_key);
    FATAL("Please use the key above or input a valid key");
    free(out);
    return key_len;
}

struct aead_buffer_t* aead_buffer_create(size_t capacity) {
    struct aead_buffer_t* obj = (struct aead_buffer_t*) calloc(1, sizeof(*obj));
    assert(capacity);
    balloc(obj, capacity);
    return obj;
}

int
balloc(struct aead_buffer_t *ptr, size_t capacity)
{
    sodium_memzero(ptr, sizeof(struct aead_buffer_t));
    ptr->data     = (char*) ss_malloc(capacity);
    ptr->capacity = capacity;
    return (int)capacity;
}

int
brealloc(struct aead_buffer_t *ptr, size_t len, size_t capacity)
{
    size_t real_capacity;
    if (ptr == NULL)
        return -1;
    real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity) {
        ptr->data     = (char*) ss_realloc(ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return (int)real_capacity;
}

void bfree(struct aead_buffer_t *ptr, int free_this) {
    if (ptr == NULL) {
        return;
    }
    ptr->idx      = 0;
    ptr->len      = 0;
    ptr->capacity = 0;
    if (ptr->data != NULL) {
        ss_free(ptr->data);
    }
    if (free_this) {
        ss_free(ptr);
    }
}

int
bprepend(struct aead_buffer_t *dst, struct aead_buffer_t *src, size_t capacity)
{
    brealloc(dst, dst->len + src->len, capacity);
    memmove(dst->data + src->len, dst->data, dst->len);
    memcpy(dst->data, src->data, src->len);
    dst->len = dst->len + src->len;
    return (int)dst->len;
}

void *
ss_malloc(size_t size)
{
    void *tmp = malloc(size);
    if (tmp == NULL)
        exit(EXIT_FAILURE);
    return tmp;
}

void *
ss_aligned_malloc(size_t size)
{
    int err;
    void *tmp = NULL;
#ifdef HAVE_POSIX_MEMALIGN
    /* ensure 16 byte alignment */
    err = posix_memalign(&tmp, 16, size);
#elif __MINGW32__
    tmp = _aligned_malloc(size, 16);
    err = tmp == NULL;
#else
    err = -1;
#endif
    if (err) {
        return ss_malloc(size);
    } else {
        return tmp;
    }
}

void *
ss_realloc(void *ptr, size_t new_size)
{
    void *_new = realloc(ptr, new_size);
    if (_new == NULL) {
        free(ptr);
        ptr = NULL;
        exit(EXIT_FAILURE);
    }
    return _new;
}

uint16_t
load16_be(const void *s)
{
    const uint8_t *in = (const uint8_t *)s;
    return ((uint16_t)in[0] << 8)
           | ((uint16_t)in[1]);
}

size_t ss_buffer_get_length(struct aead_buffer_t *buf) {
    return buf ? buf->len : 0;
}

const uint8_t* ss_buffer_get_data(struct aead_buffer_t *buf) {
    return buf ? (uint8_t*) buf->data : NULL;
}

#include "ssrbuffer.h"
struct aead_buffer_t* convert_buffer_t_to_aead_buffer_t(struct buffer_t *origin) {
    struct aead_buffer_t* res = (struct aead_buffer_t*) calloc(1, sizeof(*res));
    balloc(res, buffer_get_capacity(origin));
    res->len = buffer_get_length(origin);
    memcpy(res->data, buffer_get_data(origin), res->len);
    return res;
}

void aead_cipher_destroy(struct aead_cipher_t *cipher) {
    if (cipher) {
        if (cipher->method >= CHACHA20POLY1305IETF) {
            free(cipher->info);
        }

        if(--bloom_ref_count <= 0) {
            ppbloom_free();
        }

        bfree(cipher->encrypt_all_cache, 1);
        bfree(cipher->decrypt_all_cache, 1);
        bfree(cipher->encrypt_cache, 1);
        bfree(cipher->decrypt_cache, 1);

        free(cipher);
    }
}

struct aead_cipher_ctx_t * create_aead_cipher_ctx(struct aead_cipher_t *cipher, int enc) {
    struct aead_cipher_ctx_t *obj = (struct aead_cipher_ctx_t *)calloc(1, sizeof(*obj));
    if (obj) {
        aead_ctx_init(cipher, obj, enc);
    }
    return obj;
}
