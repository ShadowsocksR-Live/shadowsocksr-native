/*
 * auth.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_AUTH_CHAIN_H
#define _OBFS_AUTH_CHAIN_H

void * auth_chain_a_init_data();
struct obfs_t * auth_chain_a_new_obfs();
void auth_chain_a_dispose(struct obfs_t *obfs);


int auth_chain_a_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_chain_a_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_chain_a_client_udp_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int auth_chain_a_client_udp_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

int auth_chain_a_get_overhead(struct obfs_t *obfs);

#endif // _OBFS_AUTH_CHAIN_H
