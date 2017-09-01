/*
 * obfs.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_OBFS_H
#define _OBFS_OBFS_H

#include <stdint.h>
#include <unistd.h>

#define OBFS_HMAC_SHA1_LEN 10

struct server_info_t {
    char host[256];
    uint16_t port;
    char *param;
    void *g_data;
    uint8_t *iv;
    uint16_t iv_len;
    uint8_t *recv_iv;
    uint16_t recv_iv_len;
    uint8_t *key;
    uint16_t key_len;
    int head_len;
    uint16_t tcp_mss;
    uint16_t overhead;
    uint32_t buffer_size;
    struct cipher_env_t *cipher_env;
};

struct obfs_t {
    struct server_info_t server;
    void *l_data;
};

typedef struct _obfs_class {
    void * (*init_data)();
    struct obfs_t * (*new_obfs)();
    int  (*get_overhead)(struct obfs_t *self);
    void (*get_server_info)(struct obfs_t *self, struct server_info_t *server);
    void (*set_server_info)(struct obfs_t *self, struct server_info_t *server);
    void (*dispose)(struct obfs_t *self);

    int (*client_pre_encrypt)(struct obfs_t *self,
            char **pplaindata,
            int datalength,
            size_t* capacity);
    int (*client_encode)(struct obfs_t *self,
            char **pencryptdata,
            int datalength,
            size_t* capacity);
    int (*client_decode)(struct obfs_t *self,
            char **pencryptdata,
            int datalength,
            size_t* capacity,
            int *needsendback);
    int (*client_post_decrypt)(struct obfs_t *self,
            char **pplaindata,
            int datalength,
            size_t* capacity);
    int (*client_udp_pre_encrypt)(struct obfs_t *self,
            char **pplaindata,
            int datalength,
            size_t* capacity);
    int (*client_udp_post_decrypt)(struct obfs_t *self,
            char **pplaindata,
            int datalength,
            size_t* capacity);
} obfs_class;

obfs_class * new_obfs_class(const char *plugin_name);
void free_obfs_class(obfs_class *plugin);

void set_server_info(struct obfs_t *self, struct server_info_t *server);
void get_server_info(struct obfs_t *self, struct server_info_t *server);
struct obfs_t * new_obfs();
void dispose_obfs(struct obfs_t *self);

#endif // _OBFS_OBFS_H
