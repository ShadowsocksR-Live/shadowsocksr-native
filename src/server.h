/*
 * server.h - Define shadowsocks server's buffers and callbacks
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
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

struct listen_ctx {
    ev_io io;
    int fd;
    int timeout;
    int method;
    char *iface;
    struct ev_loop *loop;
};

struct server_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct server *server;
};

struct server {
    int fd;
    int stage;
    ssize_t buf_len;
    ssize_t buf_idx;
    char *buf; // server send from, remote recv into
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct listen_ctx *listen_ctx;
    struct remote *remote;

    struct ResolvQuery *query;

    struct cork_dllist_item entries;
};

struct remote_ctx {
    ev_io io;
    int connected;
    struct remote *remote;
};

struct remote {
    int fd;
    ssize_t buf_len;
    ssize_t buf_idx;
    char *buf; // remote send from, server recv into
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
};

#endif // _SERVER_H
