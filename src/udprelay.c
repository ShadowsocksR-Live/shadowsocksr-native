/*
 * udprelay.c - Setup UDP relay for both client and server
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#if !defined(__MINGW32__) && !defined(_WIN32)
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#ifdef __MINGW32__
#include "win32.h"
#endif

#include "ssrutils.h"
#include "cache.h"
#include "udprelay.h"
#include "encrypt.h"
#include "sockaddr_universal.h"
#include "ssrbuffer.h"
#include "jconf.h"

#include "obfs/obfs.h"

#include "common.h"
#include "sockaddr_universal.h"
#include "ssr_executive.h"
#include "dump_info.h"
#include "s5.h"
#include "ref_count_def.h"

#ifdef MODULE_REMOTE
#define MAX_UDP_CONN_NUM 512
#else
#define MAX_UDP_CONN_NUM 256
#endif

#if defined(MODULE_REMOTE) && defined(MODULE_LOCAL)
#error "MODULE_REMOTE and MODULE_LOCAL should not be both defined"
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define MAX_UDP_PACKET_SIZE (65507)

#define DEFAULT_PACKET_SIZE MAX_UDP_PACKET_SIZE // 1492 - 1 - 28 - 2 - 64 = 1397, the default MTU for UDP relay

struct udp_listener_ctx_t {
    uv_udp_t udp;
    union sockaddr_universal remote_addr;
    struct cipher_env_t *cipher_env;

    udp_on_recv_data_callback udp_on_recv_data;
    void* recv_p;
};

struct udp_remote_ctx_t {
    uv_udp_t rmt_udp;
    uv_timer_t rmt_expire;
    struct socks5_address dst_addr;
    uint64_t timeout;
    udp_remote_data_arrived_callback data_cb;
    void *data_cb_p;
    udp_remote_dying_callback dying_cb;
    void *dying_p;
    bool shutting_down;
    REF_COUNT_MEMBER;
};

static REF_COUNT_ADD_REF_DECL(udp_remote_ctx_t); // udp_remote_ctx_t_add_ref
static REF_COUNT_RELEASE_DECL(udp_remote_ctx_t); // udp_remote_ctx_t_release

static void udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void udp_remote_timeout_cb(uv_timer_t* handle);
static void udp_remote_reset_timer(struct udp_remote_ctx_t *remote_ctx);

static size_t packet_size                            = DEFAULT_PACKET_SIZE;

static void udp_uv_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *tmp = (char *) calloc(suggested_size, sizeof(char));
    (void)handle;
    *buf = uv_buf_init(tmp, (unsigned int)suggested_size);
}

static void udp_uv_release_buffer(uv_buf_t *buf) {
    if (buf->base) {
        free(buf->base);
        buf->base = NULL;
    }
    buf->len = 0;
}

int udp_create_remote_socket(bool ipv6, uv_loop_t *loop, uv_udp_t *udp) {
    int err = 0;
    union sockaddr_universal addr = { {0} };

    uv_udp_init(loop, udp);

    if (ipv6) {
        // Try to bind IPv6 first
        addr.addr6.sin6_family = AF_INET6;
        addr.addr6.sin6_addr   = in6addr_any;
        addr.addr6.sin6_port   = 0;
    } else {
        // Or else bind to IPv4
        addr.addr4.sin_family      = AF_INET;
        addr.addr4.sin_addr.s_addr = INADDR_ANY;
        addr.addr4.sin_port        = 0;
    }
    err = uv_udp_bind(udp, &addr.addr, 0);
    if (err != 0) {
        LOGE("[UDP] udp_create_remote_socket: %s\n", uv_strerror(err));
    }
    return err;
}

static int
udp_create_local_listener(const char *host, uint16_t port, uv_loop_t *loop, uv_udp_t *udp)
{
    struct addrinfo *result = NULL, *rp, *ipv4v6bindall;
    int s, server_sock = 0;
    char str_port[32] = { 0 };

    sprintf(str_port, "%d", port);

    s = getaddrinfo(host, str_port, NULL, &result);
    if (s != 0) {
        LOGE("[UDP] getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    uv_udp_init(loop, udp);

    rp = result;

    /*
     * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
     * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
     * return a list of addresses to listen on, but it is impossible to listen on
     * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
     */
    if (!host) {
        ipv4v6bindall = result;

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        int r = uv_udp_bind(udp, rp->ai_addr, UV_UDP_REUSEADDR);
        if (r == 0) {
            break;
        }
        LOGE("[UDP] udp_create_local_listener: %s\n", uv_strerror(r));
    }

    if (rp == NULL) {
        LOGE("%s", "[UDP] cannot bind");
        return -1;
    }

    freeaddrinfo(result);

    return server_sock;
}


static void udp_remote_ctx_free_internal(struct udp_remote_ctx_t *ctx) {
    free(ctx);
}

static REF_COUNT_ADD_REF_IMPL(udp_remote_ctx_t)

static REF_COUNT_RELEASE_IMPL(udp_remote_ctx_t, udp_remote_ctx_free_internal)

static void udp_remote_close_done_cb(uv_handle_t* handle) {
    struct udp_remote_ctx_t *ctx = (struct udp_remote_ctx_t *)handle->data;
    udp_remote_ctx_t_release(ctx);
}

static void udp_remote_shutdown(struct udp_remote_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->shutting_down) {
        return;
    }
    ctx->shutting_down = true;

    {
        uv_timer_t *timer = &ctx->rmt_expire;
        uv_timer_stop(timer);
        uv_close((uv_handle_t *)timer, udp_remote_close_done_cb);
        udp_remote_ctx_t_add_ref(ctx);
    }
    {
        uv_udp_t *udp = &ctx->rmt_udp;
        uv_udp_recv_stop(udp);
        uv_close((uv_handle_t *)udp, udp_remote_close_done_cb);
        udp_remote_ctx_t_add_ref(ctx);
    }

    if (ctx->dying_cb) {
        ctx->dying_cb(ctx, ctx->dying_p);
        ctx->dying_cb = NULL;
    }
}

bool udp_remote_is_alive(struct udp_remote_ctx_t *ctx) {
    return (ctx && (ctx->shutting_down == false));
}

void udp_remote_set_dying_callback(struct udp_remote_ctx_t *ctx, udp_remote_dying_callback callback, void*p) {
    if (ctx) {
        ctx->dying_cb = callback;
        ctx->dying_p = p;
    }
}

void udp_remote_destroy(struct udp_remote_ctx_t *ctx) {
    udp_remote_shutdown(ctx);
    udp_remote_ctx_t_release(ctx);
}

static void udp_remote_timeout_cb(uv_timer_t* handle) {
    struct udp_remote_ctx_t *remote_ctx = CONTAINER_OF(handle, struct udp_remote_ctx_t, rmt_expire);

    pr_info("%s", "[UDP] connection timeout, shutting down");

    udp_remote_shutdown(remote_ctx);
}

void upd_remote_sent_cb(uv_udp_send_t* req, int status) {
    struct udp_remote_ctx_t *remote_ctx;
    uint8_t *dup_data = (uint8_t *) req->data;
    remote_ctx = CONTAINER_OF(req->handle, struct udp_remote_ctx_t, rmt_udp);
    udp_remote_reset_timer(remote_ctx);
    free(dup_data);
    free(req);
    (void)status;
}

void udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags) {
    struct udp_remote_ctx_t *rmt_ctx;

    do {
        rmt_ctx = CONTAINER_OF(handle, struct udp_remote_ctx_t, rmt_udp);
        if (rmt_ctx == NULL) {
            ASSERT(false);
            break;
        }
        ASSERT(rmt_ctx == handle->data);

        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            udp_remote_shutdown(rmt_ctx);
            break;
        }

        if (rmt_ctx->data_cb) {
            rmt_ctx->data_cb(rmt_ctx, (const uint8_t *) buf0->base, (size_t)nread, rmt_ctx->data_cb_p);
        }

        udp_remote_reset_timer(rmt_ctx);
    } while (0);
    udp_uv_release_buffer((uv_buf_t *)buf0);
    (void)addr; (void)flags;
}

struct udp_remote_ctx_t * udp_remote_launch_begin(uv_loop_t* loop, uint64_t timeout, const struct socks5_address *dst_addr) {
    union sockaddr_universal u_dst_addr = { {0} };
    uv_udp_t *udp = NULL;
    uv_timer_t *timer;

    struct udp_remote_ctx_t *remote_ctx;
    remote_ctx = (struct udp_remote_ctx_t *) calloc(1, sizeof(*remote_ctx));
    remote_ctx->timeout = timeout;
    remote_ctx->dst_addr = *dst_addr;
    udp_remote_ctx_t_add_ref(remote_ctx);

    udp = &remote_ctx->rmt_udp;

    uv_udp_init(loop, udp);
    udp->data = remote_ctx;

    socks5_address_to_universal(dst_addr, true, &u_dst_addr);
    uv_udp_bind(udp, &u_dst_addr.addr, 0);
    uv_udp_recv_start(udp, udp_uv_alloc_buffer, udp_remote_recv_cb);

    timer = &remote_ctx->rmt_expire;
    uv_timer_init(loop, timer);
    timer->data = remote_ctx;

    udp_remote_reset_timer(remote_ctx);

    return remote_ctx;
}

void udp_remote_set_data_arrived_callback(struct udp_remote_ctx_t *ctx, udp_remote_data_arrived_callback callback, void*p) {
    if (ctx) {
        ctx->data_cb = callback;
        ctx->data_cb_p = p;
    }
}

void udp_remote_send_data(struct udp_remote_ctx_t *remote_ctx, const uint8_t*data, size_t len) {
    uv_udp_t *udp = NULL;
    uv_buf_t sndbuf;
    uint8_t *dup_data;
    uv_udp_send_t *send_req;
    union sockaddr_universal u_dst_addr = { {0} };

    if (remote_ctx==NULL || data==NULL || len==0) {
        return;
    }

    udp = &remote_ctx->rmt_udp;

    socks5_address_to_universal(&remote_ctx->dst_addr, true, &u_dst_addr);

    dup_data = (uint8_t *) calloc(len+1, sizeof(*dup_data));
    memcpy(dup_data, data, len);

    sndbuf = uv_buf_init((char*)dup_data, (unsigned int)len);

    send_req = (uv_udp_send_t *) calloc(1, sizeof(*send_req));
    send_req->data = dup_data;
    uv_udp_send(send_req, udp, &sndbuf, 1, &u_dst_addr.addr, upd_remote_sent_cb);
}

static void udp_remote_reset_timer(struct udp_remote_ctx_t *remote_ctx) {
    uv_timer_t *timer = &remote_ctx->rmt_expire;
    uv_timer_stop(timer);
    uv_timer_start(timer, udp_remote_timeout_cb, remote_ctx->timeout, 0);
}

static void udp_tls_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    uv_loop_t* loop = handle->loop;
    struct server_env_t* env = (struct server_env_t*) loop->data;
    struct server_config* config = env->config;

    union sockaddr_universal addr_u = { {0} };
    struct udp_listener_ctx_t *server_ctx;
    struct buffer_t *data = NULL;
    do {
        if (config->over_tls_enable == false) {
            ASSERT(false);
            break;
        }

        server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, udp);
        if (server_ctx == NULL) {
            ASSERT(false);
            break;
        }
        (void)flags;
        if (nread < 0) {
            pr_err("%s", "[UDP] udp_tls_listener_recv_cb something wrong.");
            break;
        } else if (nread > (ssize_t) packet_size) {
            pr_err("%s", "[UDP] udp_tls_listener_recv_cb fragmentation");
            break;
        } else if (nread == 0) {
            if (addr == NULL) {
                // there is nothing to read
                pr_err("%s", "[UDP] udp_tls_listener_recv_cb there is nothing to read");
                break;
            } else {
                //  an empty UDP packet is received.
                data = buffer_create_from((const uint8_t*)"", 0);
            }
        } else {
            data = buffer_create_from((uint8_t*)buf->base, nread);
        }

        if (addr) {
            addr_u.addr = *addr;
        }

        if (server_ctx->udp_on_recv_data) {
            server_ctx->udp_on_recv_data(server_ctx, (addr ? &addr_u : NULL), data, server_ctx->recv_p);
        }
    } while (false);
    udp_uv_release_buffer((uv_buf_t*)buf);
    buffer_release(data);
}

struct udp_listener_ctx_t *
udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
    const union sockaddr_universal *remote_addr, struct cipher_env_t *cipher_env)
{
    struct udp_listener_ctx_t *server_ctx;
    int serverfd;

    // ////////////////////////////////////////////////
    // Setup server context

    server_ctx = (struct udp_listener_ctx_t *)calloc(1, sizeof(struct udp_listener_ctx_t));

    // Bind to port
    serverfd = udp_create_local_listener(server_host, server_port, loop, &server_ctx->udp);
    if (serverfd < 0) {
        FATAL("[UDP] bind() error");
    }

    server_ctx->cipher_env = cipher_env;
    server_ctx->remote_addr     = *remote_addr;

    uv_udp_recv_start(&server_ctx->udp, udp_uv_alloc_buffer, udp_tls_listener_recv_cb);
    
    return server_ctx;
}

static void udp_local_listener_close_done_cb(uv_handle_t* handle) {
    struct udp_listener_ctx_t *server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, udp);
    free(server_ctx);
}

void udprelay_shutdown(struct udp_listener_ctx_t *server_ctx) {
    if (server_ctx == NULL) {
        return;
    }
    uv_close((uv_handle_t *)&server_ctx->udp, udp_local_listener_close_done_cb);
}

void udp_relay_set_udp_on_recv_data_callback(struct udp_listener_ctx_t *udp_ctx, udp_on_recv_data_callback callback, void*p) {
    if (udp_ctx) {
        udp_ctx->udp_on_recv_data = callback;
        udp_ctx->recv_p = p;
    }
}

uv_loop_t * udp_relay_context_get_loop(struct udp_listener_ctx_t *udp_ctx) {
    return udp_ctx->udp.loop;
}

void udp_relay_sent_cb(uv_udp_send_t* req, int status) {
    struct udp_listener_ctx_t* udp_ctx = CONTAINER_OF(req->handle, struct udp_listener_ctx_t, udp);
    uint8_t *dup_data = (uint8_t*)req->data;
    free(dup_data);
    free(req);
    (void)status; (void)udp_ctx;
}

void udp_relay_send_data(struct udp_listener_ctx_t *udp_ctx, union sockaddr_universal *addr, const uint8_t *data, size_t len) {
    uv_udp_send_t* send_req;
    uint8_t* dup_data;
    uv_buf_t sndbuf;
    struct socks5_address s5addr = { {{0}}, 0, SOCKS5_ADDRTYPE_INVALID };

    universal_address_to_socks5(addr, &s5addr);
    dup_data = s5_build_udp_datagram(&s5addr, data, len, &malloc, &len);
    sndbuf = uv_buf_init((char*)dup_data, (unsigned int)len);

    send_req = (uv_udp_send_t*)calloc(1, sizeof(*send_req));
    send_req->data = dup_data;
    uv_udp_send(send_req, &udp_ctx->udp, &sndbuf, 1, &addr->addr, udp_relay_sent_cb);
}

