#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include "config.h"

#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/evp.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define BUF_SIZE 4096
#define BLOCK_SIZE 32

#define NONE            -1 
#define TABLE           0
#define RC4             1
#define AES_128_CFB     2
#define AES_192_CFB     3
#define AES_256_CFB     4
#define BF_CFB          5
#define CAST5_CFB       6
#define DES_CFB         7

struct enc_ctx {
    int method;
    uint8_t iv[EVP_MAX_IV_LENGTH];
    EVP_CIPHER_CTX *evp;
};

char* encrypt(char *plaintext, int *len, struct enc_ctx *ctx);
char* decrypt(char *ciphertext, int *len, struct enc_ctx *ctx);
void enc_ctx_init(int method, struct enc_ctx *ctx, int enc);
int enc_init(const char *pass, const char *method);

#endif // _ENCRYPT_H
