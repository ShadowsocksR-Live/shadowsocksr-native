/*
 * http_simple.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_HTTP_SIMPLE_H
#define _OBFS_HTTP_SIMPLE_H

struct obfs_t * http_simple_new_obfs();
void http_simple_dispose(struct obfs_t *obfs);

size_t http_simple_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity);
size_t http_simple_client_decode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity, int *needsendback);

size_t http_post_client_encode(struct obfs_t *obfs, char **pencryptdata, size_t datalength, size_t* capacity);

#endif // _OBFS_HTTP_SIMPLE_H
