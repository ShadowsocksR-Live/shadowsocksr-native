/*
 * verify.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_VERIFY_H
#define _OBFS_VERIFY_H

#include <unistd.h>

struct obfs_t;

struct obfs_t * verify_simple_new_obfs(void);
void verify_simple_dispose(struct obfs_t *obfs);

size_t verify_simple_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, size_t datalength, size_t* capacity);
ssize_t verify_simple_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

#endif // _OBFS_VERIFY_H
