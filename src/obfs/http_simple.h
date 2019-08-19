/*
 * http_simple.h - Define shadowsocksR server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2016, Break Wa11 <mmgac001@gmail.com>
 */

#ifndef _OBFS_HTTP_SIMPLE_H
#define _OBFS_HTTP_SIMPLE_H

#include <stdint.h>
#include <unistd.h>

struct obfs_t;

struct obfs_t * http_simple_new_obfs(void);
void http_simple_dispose(struct obfs_t *obfs);

struct obfs_t * http_post_new_obfs(void);

struct obfs_t * http_mix_new_obfs(void);

#endif // _OBFS_HTTP_SIMPLE_H
