/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_AUTH_H
#define _OBFS_AUTH_H

void * auth_simple_init_data(void);
struct obfs_t * auth_simple_new_obfs(void);
struct obfs_t * auth_aes128_md5_new_obfs(void);
struct obfs_t * auth_aes128_sha1_new_obfs(void);
void auth_simple_dispose(struct obfs_t *obfs);

//int auth_simple_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
//int auth_simple_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_sha1_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_sha1_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_sha1_v2_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_sha1_v2_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_sha1_v4_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_sha1_v4_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_aes128_sha1_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_aes128_sha1_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_aes128_sha1_client_udp_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_aes128_sha1_client_udp_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_aes128_sha1_get_overhead(struct obfs_t *obfs);

#endif // _OBFS_AUTH_H
