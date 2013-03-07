#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "encrypt.h"

#define OFFSET_ROL(p, o) ((u_int64_t)(*(p + o)) << (8 * o))

static void md5(const uint8_t *text, uint8_t *digest) {
    md5_state_t state;
    md5_init(&state);
    md5_append(&state, text, strlen((char*)text));
    md5_finish(&state, digest);
}

static int random_compare(const void *_x, const void *_y) {
    uint32_t i = enc_conf.ctx.table.salt;
    uint64_t a = enc_conf.ctx.table.key;
    uint8_t x = *((uint8_t *) _x);
    uint8_t y = *((uint8_t*) _y);
    return (a % (x + i) - a % (y + i));
}

static void merge(uint8_t *left, int llength, uint8_t *right, int rlength)
{
	uint8_t *ltmp = (uint8_t *) malloc(llength * sizeof(uint8_t));
	uint8_t *rtmp = (uint8_t *) malloc(rlength * sizeof(uint8_t));

	uint8_t *ll = ltmp;
	uint8_t *rr = rtmp;

	uint8_t *result = left;

	memcpy(ltmp, left, llength * sizeof(uint8_t));
	memcpy(rtmp, right, rlength * sizeof(uint8_t));

	while (llength > 0 && rlength > 0) {
		if (random_compare(ll, rr) <= 0) {
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

static void merge_sort(uint8_t array[], int length)
{
	uint8_t middle;
	uint8_t *left, *right;
	int llength;

	if (length <= 1)
		return;

	middle = length / 2;

	llength = length - middle;

	left = array;
	right = array + llength;

	merge_sort(left, llength);
	merge_sort(right, middle);
	merge(left, llength, right, middle);
}

void encrypt_ctx(char *buf, int len, struct rc4_state *ctx) {
    if (ctx != NULL) {
        rc4_crypt(ctx, (uint8_t*) buf, (uint8_t*) buf, len);
    } else {
        char *end = buf + len;
        while (buf < end) {
            *buf = (char)enc_conf.ctx.table.encrypt_table[(uint8_t)*buf];
            buf++;
        }
    }
}

void decrypt_ctx(char *buf, int len, struct rc4_state *ctx) {
    if (ctx != NULL) {
        rc4_crypt(ctx, (uint8_t*) buf, (uint8_t*) buf, len);
    } else {
        char *end = buf + len;
        while (buf < end) {
            *buf = (char)enc_conf.ctx.table.decrypt_table[(uint8_t)*buf];
            buf++;
        }
    }
}

void enc_ctx_init(struct rc4_state *ctx, int enc) {
    uint8_t *key = enc_conf.ctx.rc4.key;
    int key_len = enc_conf.ctx.rc4.key_len;
    rc4_init(ctx, key, key_len);
}

static void enc_rc4_init(const char *pass) {
    enc_conf.ctx.rc4.key_len = 16;
    enc_conf.ctx.rc4.key = malloc(16);
    md5((const uint8_t*)pass, enc_conf.ctx.rc4.key);
}

static void enc_table_init(const char *pass) {
    uint8_t *enc_table = malloc(256);
    uint8_t *dec_table = malloc(256);
    uint8_t digest[16];
    uint32_t *salt = &enc_conf.ctx.table.salt;
    uint64_t *key = &enc_conf.ctx.table.key;
    uint32_t i;

    md5((const uint8_t*)pass, digest);

    *key = 0;
    for (i = 0; i < 8; i++) {
        *key += OFFSET_ROL(digest, i);
    }

    for(i = 0; i < 256; ++i) {
        enc_table[i] = i;
    }
    for(i = 1; i < 1024; ++i) {
        *salt = i;
        merge_sort(enc_table, 256);
    }
    for(i = 0; i < 256; ++i) {
        // gen decrypt table from encrypt table
        dec_table[enc_table[i]] = i;
    }

    enc_conf.ctx.table.encrypt_table = enc_table;
    enc_conf.ctx.table.decrypt_table = dec_table;
}

void enc_conf_init(const char *pass, const char *method) {
    enc_conf.method = TABLE;
    if (method != NULL && strcmp(method, "rc4") == 0) {
        enc_conf.method = RC4;
    }
    if (enc_conf.method == TABLE) {
        enc_table_init(pass);
    } else if (enc_conf.method == RC4) {
        enc_rc4_init(pass);
    }
}

