/*
 * tunnel.h - Define tunnel's buffers and callbacks
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

#ifndef _TUNNEL_H
#define _TUNNEL_H

#include <ev.h>
#include "encrypt.h"
#include "jconf.h"

#include "include.h"

struct listen_ctx
{
    ev_io io;
    ss_addr_t tunnel_addr;
    ss_addr_t *remote_addr;
    char *iface;
    int remote_num;
    int method;
    int timeout;
    int fd;
    struct sockaddr sock;
};

struct server_ctx
{
    ev_io io;
    int connected;
    struct server *server;
};

struct server
{
    int fd;
    ssize_t buf_len;
    ssize_t buf_idx;
    char *buf; // server send from, remote recv into
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct remote *remote;
    ss_addr_t destaddr;
};

struct remote_ctx
{
    ev_io io;
    ev_timer watcher;
    int connected;
    struct remote *remote;
};

struct remote
{
    int fd;
    ssize_t buf_len;
    ssize_t buf_idx;
    char *buf; // remote send from, server recv into
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
};

static void accept_cb (EV_P_ ev_io *w, int revents);
static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void server_send_cb (EV_P_ ev_io *w, int revents);
static void remote_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_send_cb (EV_P_ ev_io *w, int revents);
static void free_remote(struct remote *remote);
static void close_and_free_remote(EV_P_ struct remote *remote);
static void free_server(struct server *server);
static void close_and_free_server(EV_P_ struct server *server);

struct remote* new_remote(int fd, int timeout);
struct server* new_server(int fd, int method);

#endif // _TUNNEL_H
