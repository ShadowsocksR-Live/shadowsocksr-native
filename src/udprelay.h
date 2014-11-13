/*
 * udprelay.h - Define UDP relay's buffers and callbacks
 *
 * Copyright (C) 2013 - 2014, Max Lv <max.c.lv@gmail.com>
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
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <ev.h>
#include <time.h>

#include "encrypt.h"
#include "jconf.h"

#ifdef UDPRELAY_REMOTE
#include "asyncns.h"
#endif

#include "cache.h"

#include "common.h"

#define MAX_UDP_PACKET_SIZE (64 * 1024)

struct server_ctx {
    ev_io io;
    int fd;
    int method;
    int timeout;
    const char *iface;
    struct cache *conn_cache;
#ifdef UDPRELAY_REMOTE
    asyncns_t *asyncns;
#endif
#ifdef UDPRELAY_LOCAL
    const char *remote_host;
    const char *remote_port;
#ifdef UDPRELAY_TUNNEL
    ss_addr_t tunnel_addr;
#endif
#endif
};

#ifdef UDPRELAY_REMOTE
struct resolve_ctx {
    ev_io io;
    asyncns_t *asyncns;
    int asyncnsfd;
};

struct query_ctx {
    asyncns_query_t *query;
    struct sockaddr_storage src_addr;
    int buf_len;
    char *buf; // server send from, remote recv into
    int addr_header_len;
    char addr_header[384];
    struct server_ctx *server_ctx;
};
#endif

struct remote_ctx {
    ev_io io;
    ev_timer watcher;
    int fd;
    int addr_header_len;
    char addr_header[384];
    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    struct server_ctx *server_ctx;
};

static void server_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents);
static char *hash_key(const char *header, const int header_len,
                      const struct sockaddr_storage *addr);
#ifdef UDPRELAY_REMOTE
static void query_resolve_cb(EV_P_ ev_io *w, int revents);
#endif
static void close_and_free_remote(EV_P_ struct remote_ctx *ctx);

static struct remote_ctx * new_remote(int fd, struct server_ctx * server_ctx);

#endif // _UDPRELAY_H
