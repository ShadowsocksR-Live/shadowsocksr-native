#ifndef _OBFS_OBFSUTIL_H
#define _OBFS_OBFSUTIL_H

#include <stdint.h>

size_t get_s5_head_size(const uint8_t *plaindata, size_t size, size_t def_size);

void init_shift128plus(void);

uint64_t xorshift128plus(void);

size_t ss_md5_hmac(uint8_t *auth, const uint8_t *msg, size_t msg_len, const uint8_t *iv, size_t enc_iv_len, const uint8_t *enc_key, size_t enc_key_len);

size_t ss_sha1_hmac(uint8_t auth[20], const uint8_t *msg, size_t msg_len, const uint8_t *iv, size_t iv_len, const uint8_t *key, size_t key_len);

void memintcopy_lt(void *mem, uint32_t val);

#endif // _OBFS_OBFSUTIL_H
