/*
 * redir.h - Define the redirector's buffers and callbacks
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

#ifndef _LOCAL_H
#define _LOCAL_H

#include <ev.h>
#include "encrypt.h"
#include "jconf.h"

struct listen_ctx
{
    ev_io io;
    ss_addr_t *remote_addr;
    int remote_num;
    int timeout;
    int fd;
    int method;
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
    struct sockaddr_in destaddr;
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct remote *remote;
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
struct remote* new_remote(int fd, int timeout);
void free_remote(struct remote *remote);
void close_and_free_remote(EV_P_ struct remote *remote);
struct server* new_server(int fd, int method);
void free_server(struct server *server);
void close_and_free_server(EV_P_ struct server *server);

#endif // _LOCAL_H
