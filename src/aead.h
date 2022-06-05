/*
 * aead.h - Define the AEAD interface
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

#ifndef __SS_AEAD_H__
#define __SS_AEAD_H__

#define CRYPTO_ERROR     -2
#define CRYPTO_NEED_MORE -1
#define CRYPTO_OK         0

// currently, XCHACHA20POLY1305IETF is not released yet
// XCHACHA20POLY1305 is removed in upstream
#ifdef FS_HAVE_XCHACHA20IETF
#define AEAD_CIPHER_NUM              5
#else
#define AEAD_CIPHER_NUM              4
#endif

struct aead_buffer_t;
struct aead_cipher_t;
struct aead_cipher_ctx_t;

int aead_encrypt_all(struct aead_buffer_t *, struct aead_cipher_t *, size_t);
int aead_decrypt_all(struct aead_buffer_t *, struct aead_cipher_t *, size_t);

int aead_encrypt(struct aead_buffer_t *, struct aead_cipher_ctx_t *, size_t);
int aead_decrypt(struct aead_buffer_t *, struct aead_cipher_ctx_t *, size_t);

struct aead_cipher_ctx_t * create_aead_cipher_ctx(struct aead_cipher_t *, int enc);
void aead_ctx_init(struct aead_cipher_t *, struct aead_cipher_ctx_t *, int);
void aead_ctx_release(struct aead_cipher_ctx_t *cipher_ctx, int free_this);

struct aead_cipher_t *aead_init(const char *pass, const char *key, const char *method);
void aead_cipher_destroy(struct aead_cipher_t *);

size_t crypto_derive_key(const char *, uint8_t *, size_t);
size_t crypto_parse_key(const char *, uint8_t *, size_t);
struct mbedtls_md_info_t;
int crypto_hkdf(const struct mbedtls_md_info_t *md, const unsigned char *salt,
                size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                const unsigned char *info, size_t info_len, unsigned char *okm,
                size_t okm_len);
int crypto_hkdf_extract(const struct mbedtls_md_info_t *md, const unsigned char *salt,
                        size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                        unsigned char *prk);
int crypto_hkdf_expand(const struct mbedtls_md_info_t *md, const unsigned char *prk,
                       size_t prk_len, const unsigned char *info, size_t info_len,
                       unsigned char *okm, size_t okm_len);

struct aead_buffer_t* aead_buffer_create(size_t capacity);
int balloc(struct aead_buffer_t *, size_t);
int brealloc(struct aead_buffer_t *, size_t, size_t);
int bprepend(struct aead_buffer_t *, struct aead_buffer_t *, size_t);
void bfree(struct aead_buffer_t *, int free_this);

void *ss_malloc(size_t size);
void *ss_aligned_malloc(size_t size);
void *ss_realloc(void *ptr, size_t new_size);

#define ss_free(ptr) \
    { \
        free(ptr); \
        ptr = NULL; \
    }

#ifdef __MINGW32__
#define ss_aligned_free(ptr) \
    { \
        _aligned_free(ptr); \
        ptr = NULL; \
    }
#else
#define ss_aligned_free(ptr) ss_free(ptr)
#endif

uint16_t load16_be(const void *s);

struct buffer_t;

size_t ss_buffer_get_length(struct aead_buffer_t *buf);
const uint8_t* ss_buffer_get_data(struct aead_buffer_t *buf);
struct aead_buffer_t* convert_buffer_t_to_aead_buffer_t(struct buffer_t *origin);

#endif // __SS_AEAD_H__
