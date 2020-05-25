/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_AUTH_H
#define _OBFS_AUTH_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

struct obfs_t;
struct buffer_t;

struct obfs_t * auth_simple_new_obfs(void);
struct obfs_t * auth_sha1_new_obfs(void);
struct obfs_t * auth_sha1_v2_new_obfs(void);
struct obfs_t * auth_sha1_v4_new_obfs(void);

struct obfs_t * auth_aes128_md5_new_obfs(void);
struct obfs_t * auth_aes128_sha1_new_obfs(void);
void auth_simple_dispose(struct obfs_t *obfs);

size_t auth_simple_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity);
ssize_t auth_simple_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

size_t auth_sha1_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity);
ssize_t auth_sha1_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

size_t auth_sha1_v2_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity);
ssize_t auth_sha1_v2_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

size_t auth_sha1_v4_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity);
ssize_t auth_sha1_v4_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

size_t auth_aes128_sha1_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity);
ssize_t auth_aes128_sha1_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

size_t auth_aes128_sha1_get_overhead(struct obfs_t *obfs);

struct buffer_t * auth_aes128_sha1_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * auth_aes128_sha1_server_encode(struct obfs_t *obfs, const struct buffer_t *buf);
struct buffer_t * auth_aes128_sha1_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback);
struct buffer_t * auth_aes128_sha1_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback);

#endif // _OBFS_AUTH_H
