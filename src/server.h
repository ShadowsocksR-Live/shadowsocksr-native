/*
 * server.h - Define shadowsocks server's buffers and callbacks
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _SERVER_H
#define _SERVER_H

#include <ev.h>
#include <time.h>
#include <libcork/ds.h>

#include "encrypt.h"
#include "jconf.h"
#include "resolv.h"

#include "common.h"

struct listen_ctx_t {
    ev_io io;
    int fd;
    int timeout;
    int method;
    char *iface;
    struct ev_loop *loop;
};

struct server_ctx_t {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct server_t *server;
};

struct server_t {
    int fd;
    enum net_stage stage;
    struct buffer_t *buf;
    ssize_t buf_capacity;
    struct buffer_t *header_buf;

    struct chunk *chunk;

    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx_t *recv_ctx;
    struct server_ctx_t *send_ctx;
    struct listen_ctx_t *listen_ctx;
    struct remote_t *remote;

    struct ResolvQuery *query;

    struct cork_dllist_item entries;
};

typedef struct query {
    struct server_t *server;
    char hostname[257];
} query_t;

struct remote_ctx_t {
    ev_io io;
    int connected;
    struct remote_t *remote;
};

struct remote_t {
    int fd;
    struct buffer_t *buf;
    ssize_t buf_capacity;
    struct remote_ctx_t *recv_ctx;
    struct remote_ctx_t *send_ctx;
    struct server_t *server;
};

#endif // _SERVER_H
