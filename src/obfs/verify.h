/*
 * verify.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_VERIFY_H
#define _OBFS_VERIFY_H

#include "obfs.h"

struct obfs_t * verify_simple_new_obfs();
void verify_simple_dispose(struct obfs_t *obfs);

int verify_simple_client_pre_encrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);
int verify_simple_client_post_decrypt(struct obfs_t *obfs, char **pplaindata, int datalength, size_t* capacity);

#endif // _OBFS_VERIFY_H
