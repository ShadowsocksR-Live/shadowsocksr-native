#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <openssl/md5.h>

#include "encrypt.h"
#include "utils.h"

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

static char *enc_table;
static char *dec_table;
static char *pass;

static char* supported_ciphers[8] = {
    "table",
    "rc4",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "bf-cfb",
    "cast5-cfb",
    "des-cfb"
};

static int random_compare(const void *_x, const void *_y, uint32_t i, uint64_t a) {
    uint8_t x = *((uint8_t *) _x);
    uint8_t y = *((uint8_t*) _y);
    return (a % (x + i) - a % (y + i));
}

static void merge(uint8_t *left, int llength, uint8_t *right,
        int rlength, uint32_t salt, uint64_t key) {
	uint8_t *ltmp = (uint8_t *) malloc(llength * sizeof(uint8_t));
	uint8_t *rtmp = (uint8_t *) malloc(rlength * sizeof(uint8_t));

	uint8_t *ll = ltmp;
	uint8_t *rr = rtmp;

	uint8_t *result = left;

	memcpy(ltmp, left, llength * sizeof(uint8_t));
	memcpy(rtmp, right, rlength * sizeof(uint8_t));

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

	if (llength > 0)
		while (llength > 0) {
			*result = *ll;
			++result;
			++ll;
			--llength;
		}
	else
		while (rlength > 0) {
			*result = *rr;
			++result;
			++rr;
			--rlength;
		}

	free(ltmp);
	free(rtmp);
}

static void merge_sort(uint8_t array[], int length,
        uint32_t salt, uint64_t key) {
	uint8_t middle;
	uint8_t *left, *right;
	int llength;

	if (length <= 1)
		return;

	middle = length / 2;

	llength = length - middle;

	left = array;
	right = array + llength;

	merge_sort(left, llength, salt, key);
	merge_sort(right, middle, salt, key);
	merge(left, llength, right, middle, salt, key);
}

void enc_table_init(const char *pass) {
    uint32_t i;
    uint32_t salt;
    uint64_t key = 0;
    uint8_t *digest;

    enc_table = malloc(256);
    dec_table = malloc(256);

    digest = MD5((const uint8_t *)key, strlen((const uint8_t *)key), NULL);

    for (i = 0; i < 8; i++) {
        key += OFFSET_ROL(digest, i);
    }

    for(i = 0; i < 256; ++i) {
        enc_table[i] = i;
    }
    for(i = 1; i < 1024; ++i) {
        salt = i;
        merge_sort(enc_table, 256, salt, key);
    }
    for(i = 0; i < 256; ++i) {
        // gen decrypt table from encrypt table
        dec_table[enc_table[i]] = i;
    }
}

char* encrypt(char *plaintext, int *len, struct enc_ctx *ctx) {
    if (ctx != NULL) {
        int c_len = *len + BLOCK_SIZE;
        uint8_t *ciphertext;
        int iv_len = 0;

        if (ctx->method > RC4) {
            iv_len += strlen(ctx->iv);
            ciphertext = malloc(iv_len + c_len);
            strcpy(ciphertext, ctx->iv);
            ctx->method = NONE;
        } else {
            ciphertext = malloc(c_len);
        }

        EVP_EncryptUpdate(ctx->evp, ciphertext + iv_len, &c_len, plaintext, *len);
        *len = iv_len + c_len;
        free(plaintext);
        return ciphertext;
    } else {
        char *begin = plaintext;
        while (plaintext < begin + *len) {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return begin;
    }
}

char* decrypt(char *ciphertext, int *len, struct enc_ctx *ctx) {
    if (ctx != NULL) {
        int p_len = *len + BLOCK_SIZE;
        uint8_t *plaintext = malloc(p_len);
        int iv_len = 0;

        if (ctx->method > RC4) {
            iv_len = strlen(ctx->iv);
            memcpy(ctx->iv, ciphertext, iv_len);
            ctx->method = NONE;
        }

        EVP_DecryptUpdate(ctx->evp, plaintext, &p_len,
                (uint8_t*)(ciphertext + iv_len), *len - iv_len);
        *len = p_len;
        free(ciphertext);
        return plaintext;
    } else {
        char *begin = ciphertext;
        while (ciphertext < begin + *len) {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return begin;
    }
}

void enc_ctx_init(int method, struct enc_ctx *ctx, int enc) {
    uint8_t key[EVP_MAX_KEY_LENGTH] = {0};
    uint8_t iv[EVP_MAX_IV_LENGTH] = {0};
    int key_len, i;

    EVP_CIPHER *cipher = EVP_get_cipherbyname(supported_ciphers[method]);
    key_len = EVP_BytesToKey(cipher, EVP_md5(), NULL, (uint8_t *)pass, 
            strlen(pass), 1, key, iv);

    EVP_CIPHER_CTX_init(ctx->evp);
    EVP_CipherInit_ex(ctx->evp, cipher, NULL, NULL, NULL, enc);
    if (!EVP_CIPHER_CTX_set_key_length(ctx->evp, key_len)) {
        EVP_CIPHER_CTX_cleanup(ctx->evp);
        LOGE("Invalid key length: %d", key_len);
        exit(EXIT_FAILURE);
    }
    EVP_CIPHER_CTX_set_padding(ctx->evp, 1);

    if (enc) {
        EVP_CipherInit_ex(ctx->evp, NULL, NULL, key, iv, enc);
    }

    memset(ctx->iv, 0, strlen(iv));
    for (i = 0; i < strlen(iv); i++) {
        ctx->iv[i] = rand() % 256;
    }
    ctx->method = method;
}

int enc_init(const char *pass, const char *method) {
    pass = pass;
    if (method == NULL || strcmp(method, "table") == 0) {
        enc_table_init(pass);
        return TABLE;
    } else if (strcmp(method, "aes-128-cfb") == 0) {
        return AES_128_CFB;
    } else if (strcmp(method, "aes-192-cfb") == 0) {
        return AES_192_CFB;
    } else if (strcmp(method, "aes-256-cfb") == 0) {
        return AES_256_CFB;
    } else if (strcmp(method, "bf-cfb") == 0) {
        return BF_CFB;
    } else if (strcmp(method, "cast5-cfb") == 0) {
        return CAST5_CFB;
    } else if (strcmp(method, "des-cfb") == 0) {
        return DES_CFB;
    } else if (strcmp(method, "rc4") == 0) {
        return RC4;
    }
    return TABLE;
}

