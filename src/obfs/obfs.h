/*
 * obfs.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_OBFS_H
#define _OBFS_OBFS_H

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

#if !defined(ARRAY_SIZE)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))
#endif

#define OBFS_HMAC_SHA1_LEN 10

#ifndef SSR_BUFF_SIZE
#define SSR_BUFF_SIZE 2048
#endif // !SSR_BUFF_SIZE

struct buffer_t;
struct cipher_env_t;
struct server_config;

struct server_info_t {
    char host[256];
    uint16_t port;
    char *param;
    void *g_data;
    uint8_t iv[64]; //const uint8_t *iv;
    size_t iv_len;
    uint8_t recv_iv[256];
    size_t recv_iv_len;
    uint8_t *key;
    uint16_t key_len;
    size_t head_len;
    uint16_t tcp_mss;
    uint16_t overhead;
    uint32_t buffer_size;
    struct cipher_env_t *cipher_env;
    struct server_config *config;
};

struct obfs_t {
    struct server_info_t server_info;
    void *l_data;

    void * (*generate_global_init_data)(void);
    size_t (*get_overhead)(struct obfs_t *obfs);
    bool (*need_feedback)(struct obfs_t *obfs);
    struct server_info_t * (*get_server_info)(struct obfs_t *obfs);
    void (*set_server_info)(struct obfs_t *obfs, struct server_info_t *server);
    void (*dispose)(struct obfs_t *obfs);

    bool (*audit_incoming_user)(struct obfs_t *obfs, const char *user_id, const char **auth_key, bool *is_multi_user);

    size_t (*client_pre_encrypt)(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity);
    ssize_t (*client_post_decrypt)(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

    struct buffer_t * (*client_encode)(struct obfs_t *obfs, const struct buffer_t *buf);
    struct buffer_t * (*client_decode)(struct obfs_t *obfs, const struct buffer_t *buf, bool *needsendback);

    struct buffer_t * (*server_pre_encrypt)(struct obfs_t *obfs, const struct buffer_t *buf);
    struct buffer_t * (*server_post_decrypt)(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback);

    struct buffer_t * (*server_encode)(struct obfs_t *obfs, const struct buffer_t *buf);
    struct buffer_t * (*server_decode)(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback);
};

void * generate_global_init_data(void);
size_t get_overhead(struct obfs_t *obfs);
bool need_feedback_false(struct obfs_t *obfs);
bool need_feedback_true(struct obfs_t *obfs);

struct obfs_t * protocol_instance_create(const char *plugin_name);
struct obfs_t * obfs_instance_create(const char *plugin_name);
void obfs_instance_destroy(struct obfs_t *plugin);

void set_server_info(struct obfs_t *obfs, struct server_info_t *server);
struct server_info_t * get_server_info(struct obfs_t *obfs);
void dispose_obfs(struct obfs_t *obfs);

struct buffer_t * generic_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * generic_server_encode(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * generic_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback);
struct buffer_t * generic_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback);

#if (defined(_MSC_VER) && (_MSC_VER < 1800))
#include <stdio.h>
#if !defined(snprintf)
#define snprintf(dst, size, fmt, ...) _snprintf_s((dst), (size), _TRUNCATE, (fmt), __VA_ARGS__)
#endif // !defined(snprintf)
#endif // (defined(_MSC_VER) && (_MSC_VER < 1800))

#endif // _OBFS_OBFS_H
