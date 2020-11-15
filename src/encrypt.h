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

#if !defined(__MINGW32__) && !defined(_WIN32)
#include <sys/socket.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "ssr_cipher_names.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define SODIUM_BLOCK_SIZE   64

#define ADDRTYPE_MASK 0xEF

#define MD5_BYTES 16U
#define SHA1_BYTES 20U

#undef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#undef max
#define max(a, b) (((a) > (b)) ? (a) : (b))

struct buffer_t;

struct cipher_env_t;
struct enc_ctx;

void dump(const char *tag, const uint8_t *text, size_t len);

size_t ss_max_iv_length(void);
size_t ss_max_key_length(void);

void bytes_to_key_with_size(const uint8_t *pass, size_t len, uint8_t *md, size_t md_size);

void rand_bytes(uint8_t *output, size_t len);
int rand_integer(void);

int ss_encrypt_all(struct cipher_env_t* env, struct buffer_t *plaintext, size_t capacity);
int ss_decrypt_all(struct cipher_env_t* env, struct buffer_t *ciphertext, size_t capacity);
int ss_encrypt(struct cipher_env_t* env, struct buffer_t *plaintext, struct enc_ctx *ctx, size_t capacity);
int ss_decrypt(struct cipher_env_t* env, struct buffer_t *ciphertext, struct enc_ctx *ctx, size_t capacity);

struct cipher_env_t * cipher_env_new_instance(const char *pass, const char *method);
enum ss_cipher_type cipher_env_enc_method(const struct cipher_env_t *env);
void cipher_env_release(struct cipher_env_t *env);

const uint8_t * enc_ctx_get_iv(const struct enc_ctx *ctx);

struct enc_ctx * enc_ctx_new_instance(struct cipher_env_t *env, bool encrypt);
void enc_ctx_release_instance(struct cipher_env_t* env, struct enc_ctx *ctx);
size_t enc_get_iv_len(struct cipher_env_t* env);
uint8_t* enc_get_key(struct cipher_env_t* env);
int enc_get_key_len(struct cipher_env_t* env);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);

size_t ss_md5_hmac_with_key(uint8_t auth[MD5_BYTES], const struct buffer_t *msg, const struct buffer_t *key);
size_t ss_md5_hash_func(uint8_t *auth, const uint8_t *msg, size_t msg_len);
size_t ss_sha1_hmac_with_key(uint8_t auth[SHA1_BYTES], const struct buffer_t *msg, const struct buffer_t *key);
size_t ss_sha1_hash_func(uint8_t *auth, const uint8_t *msg, size_t msg_len);
size_t ss_aes_128_cbc_encrypt(size_t length, const uint8_t *plain_text, uint8_t *out_data, const uint8_t key[16]);
size_t ss_aes_128_cbc_decrypt(size_t length, const uint8_t *cipher_text, uint8_t *out_data, const uint8_t key[16]);
int ss_encrypt_buffer(struct cipher_env_t *env, struct enc_ctx *ctx, const uint8_t *in, size_t in_size, uint8_t *out, size_t *out_size);
int ss_decrypt_buffer(struct cipher_env_t *env, struct enc_ctx *ctx, const uint8_t *in, size_t in_size, uint8_t *out, size_t *out_size);

struct buffer_t * cipher_simple_update_data(const char *key, const char *method, bool encrypt, const struct buffer_t *data);

#endif // _ENCRYPT_H
