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

#ifndef SSR_BUFF_SIZE
#define SSR_BUFF_SIZE 2048
#endif // !SSR_BUFF_SIZE

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

struct obfs_manager {
    void * (*init_data)(void);
    struct obfs_t * (*new_obfs)(void);
    int  (*get_overhead)(struct obfs_t *obfs);
    void (*get_server_info)(struct obfs_t *obfs, struct server_info_t *server);
    void (*set_server_info)(struct obfs_t *obfs, struct server_info_t *server);
    void (*dispose)(struct obfs_t *obfs);

    int (*client_pre_encrypt)(struct obfs_t *obfs,
            char **pplaindata,
            int datalength,
            size_t* capacity);
    size_t (*client_encode)(struct obfs_t *obfs,
            char **pencryptdata,
            size_t datalength,
            size_t* capacity);
    ssize_t (*client_decode)(struct obfs_t *obfs,
            char **pencryptdata,
            size_t datalength,
            size_t* capacity,
            int *needsendback);
    ssize_t (*client_post_decrypt)(struct obfs_t *obfs,
            char **pplaindata,
            int datalength,
            size_t* capacity);
    int (*client_udp_pre_encrypt)(struct obfs_t *obfs,
            char **pplaindata,
            int datalength,
            size_t* capacity);
    int (*client_udp_post_decrypt)(struct obfs_t *obfs,
            char **pplaindata,
            int datalength,
            size_t* capacity);
};

struct obfs_manager * new_obfs_manager(const char *plugin_name);
void free_obfs_manager(struct obfs_manager *plugin);

void set_server_info(struct obfs_t *obfs, struct server_info_t *server);
void get_server_info(struct obfs_t *obfs, struct server_info_t *server);
struct obfs_t * new_obfs(void);
void dispose_obfs(struct obfs_t *obfs);

#endif // _OBFS_OBFS_H
