#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "md5.h"
#include "rc4.h"

#define BUF_SIZE 4096

#define TABLE 0
#define RC4   1

struct {
    int method;
    union {
        struct {
            uint8_t *encrypt_table;
            uint8_t *decrypt_table;
            uint32_t salt;
            uint64_t key;
        } table;

        struct {
            uint8_t *key;
            int key_len;
        } rc4;
    } ctx;
} enc_conf;

void encrypt_ctx(char *buf, int len, struct rc4_state *ctx);
void decrypt_ctx(char *buf, int len, struct rc4_state *ctx);
void enc_ctx_init(struct rc4_state *ctx, int enc);
void enc_conf_init(const char *pass, const char *method);

#define LOGD(...) ((void)fprintf(stdout, __VA_ARGS__))
#define LOGE(...) ((void)fprintf(stderr, __VA_ARGS__))

#endif // _ENCRYPT_H
