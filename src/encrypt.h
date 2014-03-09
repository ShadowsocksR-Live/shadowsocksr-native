#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include "config.h"

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

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/evp.h>
typedef EVP_CIPHER cipher_kt_t;
typedef EVP_CIPHER_CTX cipher_evp_t;
typedef EVP_MD digest_type_t;
#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

#elif defined(USE_CRYPTO_POLARSSL)

#include <polarssl/cipher.h>
#include <polarssl/md.h>
typedef cipher_info_t cipher_kt_t;
typedef cipher_context_t cipher_evp_t;
typedef md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH POLARSSL_MAX_IV_LENGTH
#define MAX_MD_SIZE POLARSSL_MD_MAX_SIZE

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

typedef struct {
    cipher_evp_t evp;
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t cc;
#endif
} cipher_ctx_t;

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define BLOCK_SIZE 32

#define CIPHER_NUM          14
#define NONE                -1
#define TABLE               0
#define RC4                 1
#define AES_128_CFB         2
#define AES_192_CFB         3
#define AES_256_CFB         4
#define BF_CFB              5
#define CAMELLIA_128_CFB    6
#define CAMELLIA_192_CFB    7
#define CAMELLIA_256_CFB    8
#define CAST5_CFB           9
#define DES_CFB             10
#define IDEA_CFB            11
#define RC2_CFB             12
#define SEED_CFB            13

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

struct enc_ctx
{
    uint8_t init;
    cipher_ctx_t evp;
};

char* ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method);
char* ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method);
char* ss_encrypt(int buf_size, char *plaintext, ssize_t *len, struct enc_ctx *ctx);
char* ss_decrypt(int buf_size, char *ciphertext, ssize_t *len, struct enc_ctx *ctx);
void enc_ctx_init(int method, struct enc_ctx *ctx, int enc);
int enc_init(const char *pass, const char *method);
int enc_get_iv_len(void);
void cipher_context_release(cipher_ctx_t *evp);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);

#endif // _ENCRYPT_H
