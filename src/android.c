/*
 * android.c - Setup IPC for shadowsocks-android
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/un.h>
#include <ancillary.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "netutils.h"
#include "utils.h"
#include "android.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

static void remote_recv_cb(EV_P_ ev_io *w, int revents);
static void remote_send_cb(EV_P_ ev_io *w, int revents);

static struct remote * new_remote(int fd, int timeout);

static void free_remote(struct remote *remote);
static void close_and_free_remote(EV_P_ struct remote *remote);

extern int verbose;

static int setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *)(((void *)watcher) - sizeof(ev_io));
    struct remote *remote = remote_ctx->remote;

    if (verbose) {
        LOGI("[android] IPC connection timeout");
    }

    remote->protect_cb(-1, remote->data);
    close_and_free_remote(EV_A_ remote);
}

static void remote_recv_cb(EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_recv_ctx->remote;

    int fd, ret = 0;

    if (ancil_recv_fd(remote->fd, &fd)) {
        ERROR("[android] ancil_recv_fd");
        ret = -1;
    }

    if (fd != remote->protect_fd) {
        ret = -1;
    }

    remote->protect_cb(ret, remote->data);
    close_and_free_remote(EV_A_ remote);
}

static void remote_send_cb(EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_send_ctx->remote;

    struct sockaddr_storage addr;
    socklen_t len = sizeof addr;

    int r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);

    if (r == 0) {
        ev_io_stop(EV_A_ & remote_send_ctx->io);
        ev_timer_stop(EV_A_ & remote_send_ctx->watcher);

        if (ancil_send_fd(remote->fd, remote->protect_fd)) {
            ERROR("[android] ancil_send_fd");
            remote->protect_cb(-1, remote->data);
            close_and_free_remote(EV_A_ remote);
            return;
        }

        ev_io_start(EV_A_ & remote->recv_ctx->io);
        ev_timer_start(EV_A_ & remote->recv_ctx->watcher);
    } else {
        ERROR("[android] getpeername");
        remote->protect_cb(-1, remote->data);
        close_and_free_remote(EV_A_ remote);
        return;
    }
}


static struct remote * new_remote(int fd, int timeout)
{
    struct remote *remote;
    remote = malloc(sizeof(struct remote));
    remote->recv_ctx = malloc(sizeof(struct remote_ctx));
    remote->send_ctx = malloc(sizeof(struct remote_ctx));
    remote->fd = fd;
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb, timeout, 0);
    ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb, timeout, 0);
    remote->recv_ctx->remote = remote;
    remote->send_ctx->remote = remote;
    return remote;
}

static void free_remote(struct remote *remote)
{
    if (remote != NULL) {
        free(remote->recv_ctx);
        free(remote->send_ctx);
        free(remote);
    }
}

static void close_and_free_remote(EV_P_ struct remote *remote)
{
    if (remote != NULL) {
        ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
        ev_io_stop(EV_A_ & remote->send_ctx->io);
        ev_io_stop(EV_A_ & remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

int protect_socket(void (*protect_cb)(int ret, void *data), void *data, int fd) {
    // Inilitialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    int remotefd;
    struct sockaddr_un addr;

    if ( (remotefd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        LOGE("[android] socket() failed: %s (socket fd = %d)\n", strerror(errno), remotefd);
        return -1;
    }

    // Setup
    setnonblocking(remotefd);

    const char path[] = "/data/data/com.github.shadowsocks/protect_path";

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

    struct remote *remote = new_remote(remotefd, 1);

    remote->protect_fd = fd;
    remote->protect_cb = protect_cb;
    remote->data = data;

    connect(remotefd, (struct sockaddr*)&addr, sizeof(addr));

    // listen to remote connected event
    ev_io_start(EV_A_ & remote->send_ctx->io);
    ev_timer_start(EV_A_ & remote->send_ctx->watcher);

    return 0;
}

