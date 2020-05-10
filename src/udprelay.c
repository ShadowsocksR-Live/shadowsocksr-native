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

#ifndef __MINGW32__
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

//#include <libcork/core.h>
//#include <udns.h>

#include "ssrutils.h"
#include "netutils.h"
#include "cache.h"
#include "udprelay.h"
#include "encrypt.h"
#include "sockaddr_universal.h"
#include "ssrbuffer.h"
#include "jconf.h"

#include "obfs/obfs.h"

#ifdef MODULE_REMOTE
#include "resolv.h"
#endif

#include "common.h"
#include "sockaddr_universal.h"
#include "ssr_executive.h"
#include "dump_info.h"
#include "s5.h"

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
/*
size_t
get_sockaddr_len(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}
*/
struct udp_listener_ctx_t {
    uv_udp_t udp;
    int timeout;
    struct cstl_set *connections;
#ifdef MODULE_LOCAL
    union sockaddr_universal remote_addr;
    struct ss_host_port tunnel_addr;
#endif
    struct cipher_env_t *cipher_env;
    // SSR
    struct obfs_t *protocol_plugin;
    void *protocol_global;

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
    int ref_count;
};

static void udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void udp_remote_timeout_cb(uv_timer_t* handle);
static void udp_remote_reset_timer(struct udp_remote_ctx_t *remote_ctx);

static size_t packet_size                            = DEFAULT_PACKET_SIZE;
static size_t buf_size                               = DEFAULT_PACKET_SIZE * 2;

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

int
udprelay_parse_header(const char *buf, size_t buf_len,
                      char *host, char *port, struct sockaddr_storage *storage)
{
    const uint8_t addr_type = *(uint8_t *)buf;
    int offset         = 1;

    // get remote addr and port
    if ((addr_type & ADDRTYPE_MASK) == SOCKS5_ADDRTYPE_IPV4) {
        // IP V4
        size_t in_addr_len = sizeof(struct in_addr);
        if (buf_len >= in_addr_len + 3) {
            if (storage != NULL) {
                struct sockaddr_in *addr = (struct sockaddr_in *)storage;
                addr->sin_family = AF_INET;
                addr->sin_addr   = *(struct in_addr *)(buf + offset);
                addr->sin_port   = *(uint16_t *)(buf + offset + in_addr_len);
            }
            if (host != NULL) {
                uv_inet_ntop(AF_INET, (const void *)(buf + offset),
                         host, INET_ADDRSTRLEN);
            }
            offset += (int) in_addr_len;
        }
    } else if ((addr_type & ADDRTYPE_MASK) == SOCKS5_ADDRTYPE_DOMAINNAME) {
        // Domain name
        uint8_t name_len = *(uint8_t *)(buf + offset);
        if ((size_t)(name_len + 4) <= buf_len) {
            if (storage != NULL) {
                char tmp[257] = { 0 };
                union sockaddr_universal addr_u = { {0} };
                memcpy(tmp, buf + offset + 1, name_len);

                if (universal_address_from_string(tmp, 80, true, &addr_u) == 0) {
                    if (addr_u.addr4.sin_family == AF_INET) {
                        struct sockaddr_in *addr = (struct sockaddr_in *)storage;
                        addr->sin_addr = addr_u.addr4.sin_addr;
                        addr->sin_port   = *(uint16_t *)(buf + offset + 1 + name_len);
                        addr->sin_family = AF_INET;
                    } else if (addr_u.addr6.sin6_family == AF_INET6) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
                        addr->sin6_addr = addr_u.addr6.sin6_addr;
                        addr->sin6_port   = *(uint16_t *)(buf + offset + 1 + name_len);
                        addr->sin6_family = AF_INET6;
                    }
                }
            }
            if (host != NULL) {
                memcpy(host, buf + offset + 1, name_len);
            }
            offset += 1 + name_len;
        }
    } else if ((addr_type & ADDRTYPE_MASK) == SOCKS5_ADDRTYPE_IPV6) {
        // IP V6
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (buf_len >= in6_addr_len + 3) {
            if (storage != NULL) {
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *)storage;
                addr->sin6_family = AF_INET6;
                addr->sin6_addr   = *(struct in6_addr *)(buf + offset);
                addr->sin6_port   = *(uint16_t *)(buf + offset + in6_addr_len);
            }
            if (host != NULL) {
                uv_inet_ntop(AF_INET6, (const void *)(buf + offset),
                         host, INET6_ADDRSTRLEN);
            }
            offset += (int)in6_addr_len;
        }
    }

    if (offset == 1) {
        LOGE("[udp] invalid header with addr type %d", addr_type);
        return 0;
    }

    if (port != NULL) {
        sprintf(port, "%d", ntohs(*(uint16_t *)(buf + offset)));
    }
    offset += 2;

    return offset;
}

char *
get_addr_str(const struct sockaddr *sa)
{
    static char s[SS_ADDRSTRLEN];
    char addr[INET6_ADDRSTRLEN] = { 0 };
    char port[PORTSTRLEN]       = { 0 };
    uint16_t p;
    size_t addr_len;
    size_t port_len;

    memset(s, 0, SS_ADDRSTRLEN);
    switch (sa->sa_family) {
    case AF_INET:
        uv_inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                 addr, INET_ADDRSTRLEN);
        p = ntohs(((struct sockaddr_in *)sa)->sin_port);
        sprintf(port, "%d", p);
        break;

    case AF_INET6:
        uv_inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                 addr, INET6_ADDRSTRLEN);
        p = ntohs(((struct sockaddr_in *)sa)->sin_port);
        sprintf(port, "%d", p);
        break;

    default:
        strncpy(s, "Unknown AF", SS_ADDRSTRLEN);
    }

    addr_len = strlen(addr);
    port_len = strlen(port);
    memcpy(s, addr, addr_len);
    memcpy(s + addr_len + 1, port, port_len);
    s[addr_len] = ':';

    return s;
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
        LOGE("[udp] udp_create_remote_socket: %s\n", uv_strerror(err));
    }
    return err;
}

int
udp_create_local_listener(const char *host, uint16_t port, uv_loop_t *loop, uv_udp_t *udp)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result = NULL, *rp, *ipv4v6bindall;
    int s, server_sock = 0;
    char str_port[32] = { 0 };

    hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM;              /* We want a UDP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_UDP;

    sprintf(str_port, "%d", port);

    s = getaddrinfo(host, str_port, &hints, &result);
    if (s != 0) {
        LOGE("[udp] getaddrinfo: %s", gai_strerror(s));
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
        LOGE("[udp] udp_create_local_listener: %s\n", uv_strerror(r));
    }

    if (rp == NULL) {
        LOGE("%s", "[udp] cannot bind");
        return -1;
    }

    freeaddrinfo(result);

    return server_sock;
}

static void udp_remote_ctx_add_ref(struct udp_remote_ctx_t *ctx) {
    if (ctx) {
        ++ctx->ref_count;
    }
}

static void udp_remote_ctx_release(struct udp_remote_ctx_t *ctx) {
    if (ctx) {
        --ctx->ref_count;
        if (ctx->ref_count <= 0) {
            free(ctx);
        }
    }
}

static void udp_remote_close_done_cb(uv_handle_t* handle) {
    struct udp_remote_ctx_t *ctx = (struct udp_remote_ctx_t *)handle->data;
    udp_remote_ctx_release(ctx);
}

static void udp_remote_shutdown(struct udp_remote_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    if (ctx->shutting_down) {
        return;
    }
    ctx->shutting_down = true;

    //cstl_set_container_remove(ctx->server_ctx->connections, ctx);
    {
        uv_timer_t *timer = &ctx->rmt_expire;
        uv_timer_stop(timer);
        uv_close((uv_handle_t *)timer, udp_remote_close_done_cb);
        udp_remote_ctx_add_ref(ctx);
    }
    {
        uv_udp_t *udp = &ctx->rmt_udp;
        uv_udp_recv_stop(udp);
        uv_close((uv_handle_t *)udp, udp_remote_close_done_cb);
        udp_remote_ctx_add_ref(ctx);
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
    udp_remote_ctx_release(ctx);
}

static void udp_remote_timeout_cb(uv_timer_t* handle) {
    struct udp_remote_ctx_t *remote_ctx = CONTAINER_OF(handle, struct udp_remote_ctx_t, rmt_expire);

    LOGI("%s", "[udp] connection timeout, shutting down");

    udp_remote_shutdown(remote_ctx);
}

/*
#ifdef MODULE_REMOTE
static void udp_remote_send_done_cb(uv_udp_send_t* req, int status) {
    struct udp_remote_ctx_t *remote_ctx = (struct udp_remote_ctx_t *)req->data;
    free(req);
    if (status < 0) {
        SS_ERROR("[udp] sendto_remote");
        udp_remote_shutdown(remote_ctx);
    } else {
        // *
        // Add to conn cache
        char *key = hash_key(AF_UNSPEC, &remote_ctx->src_addr);
        cache_insert(remote_ctx->server_ctx->conn_cache, key, HASH_KEY_LEN, (void *)remote_ctx);
        // ev_io_start(EV_A_ & remote_ctx->io);
        //ev_timer_start(EV_A_ & remote_ctx->watcher);
        // * /
    }
}

static void query_resolve_cb(struct sockaddr *addr, void *data) {
    struct query_ctx *query_ctx = (struct query_ctx *)data;
    struct uv_loop_s *loop = query_ctx->server_ctx->io.loop;
    // *
    if (verbose) {
        LOGI("[udp] udns resolved");
    }
    // * /
    query_ctx->query = NULL;

    if (addr == NULL) {
        LOGE("[udp] udns returned an error");
    } else {
        struct udp_remote_ctx_t *remote_ctx = query_ctx->remote_ctx;
        int cache_hit            = 0;

        // *
        // Lookup in the conn cache
        if (remote_ctx == NULL) {
            char *key = hash_key(AF_UNSPEC, &query_ctx->src_addr);
            cache_lookup(query_ctx->server_ctx->conn_cache, key, HASH_KEY_LEN, (void *)&remote_ctx);
        }
        // * /

        if (remote_ctx == NULL) {
            remote_ctx = calloc(1, sizeof(struct udp_remote_ctx_t));
            bool ipv6 = (addr->sa_family == AF_INET6);
            int remotefd = udp_create_remote_socket(ipv6, loop, &remote_ctx->io);
            if (remotefd != -1) {
                // setnonblocking(remotefd);
#ifdef SO_BROADCAST
                set_broadcast(remotefd);
#endif
#ifdef SO_NOSIGPIPE
                set_nosigpipe(remotefd);
#endif
#ifdef IP_TOS
                // Set QoS flag
                int tos = 46;
                setsockopt(remotefd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
#ifdef SET_INTERFACE
                if (query_ctx->server_ctx->iface) {
                    if (setinterface(remotefd, query_ctx->server_ctx->iface) == -1)
                        SS_ERROR("setinterface");
                }
#endif
                // remote_ctx                  = new_udp_remote(remotefd, query_ctx->server_ctx);
                remote_ctx->src_addr        = query_ctx->src_addr;
                remote_ctx->server_ctx      = query_ctx->server_ctx;
                remote_ctx->addr_header_len = query_ctx->addr_header_len;
                memcpy(remote_ctx->addr_header, query_ctx->addr_header,
                       query_ctx->addr_header_len);
            } else {
                SS_ERROR("[udp] bind() error");
            }
        } else {
            cache_hit = 1;
        }

        if (remote_ctx != NULL) {
            memcpy(&remote_ctx->dst_addr, addr, sizeof(struct sockaddr_storage));
#if 0
            size_t addr_len = get_sockaddr_len(addr);
            int s           = sendto(remote_ctx->fd, query_ctx->buf->buffer, query_ctx->buf->len,
                                     0, addr, addr_len);

            if (s == -1) {
                SS_ERROR("[udp] sendto_remote");
                if (!cache_hit) {
                    udp_remote_shutdown(remote_ctx);
                }
            } else {
                if (!cache_hit) {
                    // Add to conn cache
                    char *key = hash_key(AF_UNSPEC, &remote_ctx->src_addr);
                    cache_insert(query_ctx->server_ctx->conn_cache, key, HASH_KEY_LEN, (void *)remote_ctx);
                    ev_io_start(EV_A_ & remote_ctx->io);
                    ev_timer_start(EV_A_ & remote_ctx->watcher);
                }
            }
#else
            uv_udp_send_t *req = (uv_udp_send_t *)calloc(1, sizeof(uv_udp_send_t));
            req->data = remote_ctx;
            uv_buf_t tmp = uv_buf_init(query_ctx->buf->buffer, (unsigned int)query_ctx->buf->len);
            uv_udp_send(req, &remote_ctx->io, &tmp, 1, (const struct sockaddr *)&remote_ctx->dst_addr, udp_remote_send_done_cb);
#endif
        }
    }

    // clean up
    close_and_free_query(query_ctx);
}
#endif

static void udp_send_done_cb(uv_udp_send_t* req, int status) {
    //struct udp_listener_ctx_t *server_ctx = (struct udp_listener_ctx_t *)req->data;
    struct buffer_t *buf = (struct buffer_t *)req->data;
    (void)status;
    buffer_release(buf);
    free(req);
}
*/

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
        ASSERT(rmt_ctx);
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
    union sockaddr_universal u_dst_addr = { 0 };
    uv_udp_t *udp = NULL;
    uv_timer_t *timer;

    struct udp_remote_ctx_t *remote_ctx;
    remote_ctx = (struct udp_remote_ctx_t *) calloc(1, sizeof(*remote_ctx));
    remote_ctx->timeout = timeout;
    remote_ctx->dst_addr = *dst_addr;
    udp_remote_ctx_add_ref(remote_ctx);

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
    union sockaddr_universal u_dst_addr = { 0 };

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

void udp_tls_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    union sockaddr_universal addr_u = { {0} };
    struct udp_listener_ctx_t *server_ctx;
    struct buffer_t *data = NULL;

    server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, udp);
    ASSERT(server_ctx);
    (void)flags;
    if (nread < 0) {
        LOGE("%s", "[udp] udp_tls_listener_recv_cb something wrong.");
        goto __EXIT__;
    } else if (nread > (ssize_t) packet_size) {
        LOGE("%s", "[udp] udp_tls_listener_recv_cb fragmentation");
        goto __EXIT__;
    } else if (nread == 0) {
        if (addr == NULL) {
            // there is nothing to read
            LOGE("%s", "[udp] udp_tls_listener_recv_cb there is nothing to read");
            goto __EXIT__;
        } else {
            //  an empty UDP packet is received.
            data = buffer_create_from((const uint8_t *)"", 0);
        }
    } else {
        data = buffer_create_from((uint8_t *)buf->base, nread);
    }

    if (addr) {
        addr_u.addr = *addr;
    }

__EXIT__:
    udp_uv_release_buffer((uv_buf_t *)buf);

    if (server_ctx->udp_on_recv_data) {
        server_ctx->udp_on_recv_data(server_ctx, (addr ? &addr_u : NULL), data, server_ctx->recv_p);
    }
    buffer_release(data);
}

static void 
udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags)
{
    struct udp_listener_ctx_t *server_ctx;
    struct sockaddr_storage src_addr;
    struct buffer_t *buf;
    socklen_t src_addr_len;
    unsigned int offset;
    char addr_header[512] = { 0 };
    int addr_header_len   = 0;
    uint8_t frag = 0;

    char host[257] = { 0 };
    char port[65]  = { 0 };

    const struct sockaddr *remote_addr;
    int err;

    uv_loop_t *loop;
    struct server_env_t *env;
    struct server_config *config;

    loop = handle->loop;
    env = (struct server_env_t *) loop->data;
    config = env->config;

    (void)port; (void)host; (void)frag; (void)addr_header_len; (void)addr_header; (void)offset;
    if (config->over_tls_enable) {
        udp_tls_listener_recv_cb(handle, nread, buf0, addr, flags);
        return;
    }

    if (NULL == addr) {
        return;
    }

    server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, udp);
    ASSERT(server_ctx);

    src_addr = *(struct sockaddr_storage *)addr;

    buf = buffer_create(max((size_t)buf_size, (size_t)nread));

    src_addr_len = sizeof(src_addr);
    offset    = 0;
    (void)src_addr_len; (void)remote_addr;

#ifdef MODULE_REDIR
    char control_buffer[64] = { 0 };
    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    struct iovec iov[1];
    struct sockaddr_storage dst_addr;
    memset(&dst_addr, 0, sizeof(struct sockaddr_storage));

    msg.msg_name       = &src_addr;
    msg.msg_namelen    = src_addr_len;
    msg.msg_control    = control_buffer;
    msg.msg_controllen = sizeof(control_buffer);

    iov[0].iov_base = buf->buffer;
    iov[0].iov_len  = buf_size;
    msg.msg_iov     = iov;
    msg.msg_iovlen  = 1;

    buf->len = recvmsg(server_ctx->fd, &msg, 0);
    if (buf->len == -1) {
        SS_ERROR("[udp] server_recvmsg");
        goto CLEAN_UP;
    } else if (buf->len > packet_size) {
        SS_ERROR("[udp] UDP server_recv_recvmsg fragmentation");
        goto CLEAN_UP;
    }

    if (get_dstaddr(&msg, &dst_addr)) {
        LOGE("[udp] unable to get dest addr");
        goto CLEAN_UP;
    }

    src_addr_len = msg.msg_namelen;
#else
    // http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_recv_cb

    if (nread <= 0) {
        // error on recv
        // simply drop that packet
        LOGE("%s", "[udp] server_recv_recvfrom");
        goto CLEAN_UP;
    } else if (nread > (ssize_t) packet_size) {
        LOGE("%s", "[udp] server_recv_recvfrom fragmentation");
        goto CLEAN_UP;
    }

    buffer_store(buf, (uint8_t *)buf0->base, nread);

    udp_uv_release_buffer((uv_buf_t *)buf0);
#endif

#ifdef MODULE_REMOTE
    (void)remote_addr; (void)err;
    /*
    tx += buf->len;

    int err = ss_decrypt_all(server_ctx->cipher_env, buf, buf_size);
    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }
    */
#endif

    /*
     *
     * SOCKS5 UDP Request
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     *
     * SOCKS5 UDP Response
     * +----+------+------+----------+----------+----------+
     * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +----+------+------+----------+----------+----------+
     * | 2  |  1   |  1   | Variable |    2     | Variable |
     * +----+------+------+----------+----------+----------+
     *
     * shadowsocks UDP Request (before encrypted)
     * +------+----------+----------+----------+
     * | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+----------+----------+----------+
     * |  1   | Variable |    2     | Variable |
     * +------+----------+----------+----------+
     *
     * shadowsocks UDP Response (before encrypted)
     * +------+----------+----------+----------+
     * | ATYP | DST.ADDR | DST.PORT |   DATA   |
     * +------+----------+----------+----------+
     * |  1   | Variable |    2     | Variable |
     * +------+----------+----------+----------+
     *
     * shadowsocks UDP Request and Response (after encrypted)
     * +-------+--------------+
     * |   IV  |    PAYLOAD   |
     * +-------+--------------+
     * | Fixed |   Variable   |
     * +-------+--------------+
     *
     */

#ifdef MODULE_REDIR
    if (verbose) {
        char src[SS_ADDRSTRLEN];
        char dst[SS_ADDRSTRLEN];
        strcpy(src, get_addr_str((struct sockaddr *)&src_addr));
        strcpy(dst, get_addr_str((struct sockaddr *)&dst_addr));
        LOGI("[udp] redir to %s from %s", dst, src);
    }

    char addr_header[512] = { 0 };
    size_t addr_header_len   = construct_udprealy_header(&dst_addr, addr_header);

    if (addr_header_len == 0) {
        LOGE("[udp] failed to parse tproxy addr");
        goto CLEAN_UP;
    }

    // reconstruct the buffer
    buffer_realloc(buf, max(buf->len + addr_header_len, buf_size));
    memmove(buf->buffer + addr_header_len, buf->buffer, buf->len);
    memcpy(buf->buffer, addr_header, addr_header_len);
    buf->len += addr_header_len;

#elif MODULE_LOCAL

    if (server_ctx->tunnel_addr.host && server_ctx->tunnel_addr.port) {
        uint16_t port_num;
        uint16_t port_net_num;
        union sockaddr_universal addr = { {0} };

        strncpy(host, server_ctx->tunnel_addr.host, 256);
        strncpy(port, server_ctx->tunnel_addr.port, 64);
        port_num     = (uint16_t)atoi(port);
        port_net_num = htons(port_num);
        
        if (universal_address_from_string(host, port_num, true, &addr) == 0) {
            if (addr.addr4.sin_family == AF_INET) {
                // send as IPv4
                struct in_addr host_addr = addr.addr4.sin_addr;
                int host_len = sizeof(struct in_addr);

                addr_header[addr_header_len++] = 1;
                memcpy(addr_header + addr_header_len, &host_addr, host_len);
                addr_header_len += host_len;
            } else if (addr.addr4.sin_family == AF_INET6) {
                // send as IPv6
                struct in6_addr host_addr = addr.addr6.sin6_addr;
                int host_len = sizeof(struct in6_addr);

                addr_header[addr_header_len++] = 4;
                memcpy(addr_header + addr_header_len, &host_addr, host_len);
                addr_header_len += host_len;
            } else {
                FATAL("IP parser error");
            }
        } else {
            // send as domain
            int host_len = (int) strlen(host);

            addr_header[addr_header_len++] = 3;
            addr_header[addr_header_len++] = host_len;
            memcpy(addr_header + addr_header_len, host, host_len);
            addr_header_len += host_len;
        }
        memcpy(addr_header + addr_header_len, &port_net_num, 2);
        addr_header_len += 2;

        // reconstruct the buffer
        {
            struct buffer_t *tmp = buffer_clone(buf);
            buffer_store(buf, (const uint8_t *)addr_header, addr_header_len);
            buffer_concatenate2(buf, tmp);
            buffer_release(tmp);
        }
    } else {
        struct sockaddr_storage dst_addr;
        size_t len = 0;
        const uint8_t *buffer = buffer_get_data(buf, &len);

        frag = *(uint8_t *)(buffer + 2);
        offset += 3;
        memset(&dst_addr, 0, sizeof(struct sockaddr_storage));

        addr_header_len = udprelay_parse_header((const char *)(buffer + offset), len - offset,
                                                    host, port, &dst_addr);
        if (addr_header_len == 0) {
            // error in parse header
            goto CLEAN_UP;
        }

        memcpy(addr_header, buffer + offset, (size_t) addr_header_len);
    }
#else
/*
    // MODULE_REMOTE
    char host[257] = { 0 };
    char port[64] = { 0 };
    struct sockaddr_storage dst_addr = { 0 };

    int addr_header_len = udprelay_parse_header(buf->buffer + offset, buf->len - offset, host, port, &dst_addr);
    if (addr_header_len == 0) {
        // error in parse header
        goto CLEAN_UP;
    }

    char *addr_header = buf->buffer + offset;
    */
#endif

#ifdef MODULE_LOCAL

#if !defined(MODULE_TUNNEL) && !defined(MODULE_REDIR)
    if (frag) {
        LOGE("[udp] drop a message since frag is not 0, but %d", frag);
        goto CLEAN_UP;
    }
#endif

    remote_addr = &server_ctx->remote_addr.addr;

    {
        /*
        bool ipv6;
        int remotefd;
        remote_ctx = (struct udp_remote_ctx_t *) calloc(1, sizeof(struct udp_remote_ctx_t));

        // Bind to any port
        ipv6 = (remote_addr->sa_family == AF_INET6);
        remotefd = udp_create_remote_socket(ipv6, server_ctx->io.loop, &remote_ctx->io);
        if (remotefd < 0) {
            LOGE("%s", "[udp] udprelay bind() error");
            goto CLEAN_UP;
        }

        // Init remote_ctx
        remote_ctx->server_ctx = server_ctx;
        remote_ctx->src_addr        = src_addr;
        remote_ctx->addr_header_len = addr_header_len;
        memcpy(remote_ctx->addr_header, addr_header, (size_t) addr_header_len);

        uv_timer_init(server_ctx->io.loop, &remote_ctx->watcher);

        cstl_set_container_add(server_ctx->connections, (void *)remote_ctx);

        uv_udp_recv_start(&remote_ctx->io, udp_uv_alloc_buffer, udp_remote_recv_cb);
        uv_timer_start(&remote_ctx->watcher, udp_remote_timeout_cb, (uint64_t)server_ctx->timeout, 0);
        */
    }

    buffer_shortened_to(buf, offset, buffer_get_length(buf) - offset);

    // SSR beg
    if (server_ctx->protocol_plugin) {
        struct obfs_t *protocol_plugin = server_ctx->protocol_plugin;
        if (protocol_plugin->client_udp_pre_encrypt) {
            size_t len = 0, capacity = 0;
            uint8_t *buffer = (uint8_t *) buffer_raw_clone(buf, &malloc, &len, &capacity);
            len = (size_t) protocol_plugin->client_udp_pre_encrypt(protocol_plugin, (char **)&buffer, len, &capacity);
            buffer_store(buf, buffer, len);
            free(buffer);
        }
    }
    //SSR end

    err = ss_encrypt_all(server_ctx->cipher_env, buf, buffer_get_capacity(buf));

    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }

    if (buffer_get_length(buf) > packet_size) {
        LOGE("%s", "[udp] server_recv_sendto fragmentation");
        goto CLEAN_UP;
    }
    {
        /*
    uv_buf_t tmp;
    uv_udp_send_t *req = (uv_udp_send_t *)calloc(1, sizeof(uv_udp_send_t));
    size_t len = 0;
    const uint8_t *buffer = buffer_get_data(buf, &len);
    req->data = buf;
    tmp = uv_buf_init((char *)buffer, (unsigned int) len);
    uv_udp_send(req, &remote_ctx->io, &tmp, 1, remote_addr, udp_send_done_cb);
    */
    }
    return;
#if !defined(MODULE_TUNNEL) && !defined(MODULE_REDIR)
#ifdef ANDROID
    if (log_tx_rx)
        tx += buf->len;
#endif
#endif

#else
    /*
    int cache_hit  = 0;
    int need_query = 0;

    if (buf->len - addr_header_len > packet_size) {
        LOGE("[udp] server_recv_sendto fragmentation");
        goto CLEAN_UP;
    }

    if (remote_ctx != NULL) {
        cache_hit = 1;
        // detect destination mismatch
        if (remote_ctx->addr_header_len != addr_header_len
            || memcmp(addr_header, remote_ctx->addr_header, addr_header_len) != 0) {
            if (dst_addr.ss_family != AF_INET && dst_addr.ss_family != AF_INET6) {
                need_query = 1;
            }
        } else {
            memcpy(&dst_addr, &remote_ctx->dst_addr, sizeof(struct sockaddr_storage));
        }
    } else {
        if (dst_addr.ss_family == AF_INET || dst_addr.ss_family == AF_INET6) {
            remote_ctx = calloc(1, sizeof(struct udp_remote_ctx_t));

            bool ipv6 = (dst_addr.ss_family == AF_INET6);
            int remotefd = udp_create_remote_socket(ipv6, server_ctx->io.loop, &remote_ctx->io);
            if (remotefd != -1) {
                // setnonblocking(remotefd);
#ifdef SO_BROADCAST
                set_broadcast(remotefd);
#endif
#ifdef SO_NOSIGPIPE
                set_nosigpipe(remotefd);
#endif
#ifdef IP_TOS
                // Set QoS flag
                int tos = 46;
                setsockopt(remotefd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
#ifdef SET_INTERFACE
                if (server_ctx->iface) {
                    if (setinterface(remotefd, server_ctx->iface) == -1)
                        SS_ERROR("setinterface");
                }
#endif
                remote_ctx->src_addr        = src_addr;
                remote_ctx->server_ctx      = server_ctx;
                remote_ctx->addr_header_len = addr_header_len;
                memcpy(remote_ctx->addr_header, addr_header, addr_header_len);
                memcpy(&remote_ctx->dst_addr, &dst_addr, sizeof(struct sockaddr_storage));
            } else {
                SS_ERROR("[udp] bind() error");
                goto CLEAN_UP;
            }
        }
    }

    if (remote_ctx != NULL && !need_query) {
        // *
        size_t addr_len = get_sockaddr_len((struct sockaddr *)&dst_addr);
        int s           = sendto(remote_ctx->fd, buf->buffer + addr_header_len,
                                 buf->len - addr_header_len, 0,
                                 (struct sockaddr *)&dst_addr, addr_len);

        if (s == -1) {
            SS_ERROR("[udp] sendto_remote");
            if (!cache_hit) {
                udp_remote_shutdown(remote_ctx);
            }
        } else {
            if (!cache_hit) {
                // Add to conn cache
                remote_ctx->af = dst_addr.ss_family;
                char *key = hash_key(remote_ctx->af, &remote_ctx->src_addr);
                cache_insert(server_ctx->conn_cache, key, HASH_KEY_LEN, (void *)remote_ctx);

                ev_io_start(EV_A_ & remote_ctx->io);
                ev_timer_start(EV_A_ & remote_ctx->watcher);
            }
        }
        // * /
        remote_ctx->dst_addr;
        uv_udp_send_t *req = (uv_udp_send_t *)calloc(1, sizeof(uv_udp_send_t));
        req->data = remote_ctx;
        uv_buf_t tmp = uv_buf_init(buf->buffer + addr_header_len, (unsigned int)buf->len - addr_header_len);
        uv_udp_send(req, &remote_ctx->io, &tmp, 1, (const struct sockaddr *)&remote_ctx->dst_addr, udp_remote_send_done_cb);
    } else {
        struct addrinfo hints;
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        struct query_ctx *query_ctx = new_query_ctx(buf->buffer + addr_header_len,
                                                    buf->len - addr_header_len);
        query_ctx->server_ctx      = server_ctx;
        query_ctx->addr_header_len = addr_header_len;
        query_ctx->src_addr        = src_addr;
        memcpy(query_ctx->addr_header, addr_header, addr_header_len);

        if (need_query) {
            query_ctx->remote_ctx = remote_ctx;
        }

        struct resolv_query *query = 
            resolv_query(host, query_resolve_cb, NULL, query_ctx, htons(atoi(port)));
        if (query == NULL) {
            SS_ERROR("[udp] unable to create DNS query");
            close_and_free_query(query_ctx);
            goto CLEAN_UP;
        }
        query_ctx->query = query;
    }
    */
#endif

CLEAN_UP:
    buffer_release(buf);
}

struct udp_listener_ctx_t *
udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
#ifdef MODULE_LOCAL
    const union sockaddr_universal *remote_addr,
    const struct ss_host_port *tunnel_addr,
#endif
    int mtu, int timeout, struct cipher_env_t *cipher_env,
    const char *protocol, const char *protocol_param)
{
    struct udp_listener_ctx_t *server_ctx;
    int serverfd;
    struct server_info_t server_info = { {0}, 0, 0, 0, {0}, 0, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

    // Initialize MTU
    if (mtu > 0) {
        packet_size = mtu - 1 - 28 - 2 - 64;
        buf_size    = packet_size * 2;
    }

    (void)server_info; (void)protocol; (void)protocol_param;

    // ////////////////////////////////////////////////
    // Setup server context

    server_ctx = (struct udp_listener_ctx_t *)calloc(1, sizeof(struct udp_listener_ctx_t));

    // Bind to port
    serverfd = udp_create_local_listener(server_host, server_port, loop, &server_ctx->udp);
    if (serverfd < 0) {
        FATAL("[udp] bind() error");
    }

    server_ctx->cipher_env = cipher_env;
#ifdef MODULE_REMOTE
    //server_ctx->loop = loop;
#endif
    server_ctx->timeout    = max(timeout, MIN_UDP_TIMEOUT);
    server_ctx->connections = cstl_set_container_create(tunnel_ctx_compare_for_c_set, NULL);
#ifdef MODULE_LOCAL
    server_ctx->remote_addr     = *remote_addr;
    //SSR beg
    server_ctx->protocol_plugin = protocol_instance_create(protocol);
    if (server_ctx->protocol_plugin) {
        server_ctx->protocol_global = server_ctx->protocol_plugin->generate_global_init_data();
    }

    strcpy(server_info.host, server_host);
    server_info.port = server_port;
    server_info.g_data = server_ctx->protocol_global;
    server_info.param = (char *)protocol_param;
    server_info.key = enc_get_key(cipher_env);
    server_info.key_len = (uint16_t) enc_get_key_len(cipher_env);

    if (server_ctx->protocol_plugin) {
        server_ctx->protocol_plugin->set_server_info(server_ctx->protocol_plugin, &server_info);
    }
    //SSR end
    if (tunnel_addr) {
        server_ctx->tunnel_addr = *tunnel_addr;
    }
#endif

    uv_udp_recv_start(&server_ctx->udp, udp_uv_alloc_buffer, udp_listener_recv_cb);
    
    return server_ctx;
}

static void udp_local_listener_close_done_cb(uv_handle_t* handle) {
    struct udp_listener_ctx_t *server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, udp);
    cstl_set_container_destroy(server_ctx->connections);

#ifdef MODULE_LOCAL
    // SSR beg
    if (server_ctx->protocol_plugin) {
        object_safe_free(&server_ctx->protocol_global);
        obfs_instance_destroy(server_ctx->protocol_plugin);
        server_ctx->protocol_plugin = NULL;
    }
    // SSR end
#endif

    free(server_ctx);
}

void connection_release(struct cstl_set *set, const void *obj, bool *stop, void *p) {
    (void)set; (void)obj; (void)stop; (void)p;
    //udp_remote_shutdown((struct udp_remote_ctx_t *)obj);
}

void udprelay_shutdown(struct udp_listener_ctx_t *server_ctx) {
    if (server_ctx == NULL) {
        return;
    }
    cstl_set_container_traverse(server_ctx->connections, &connection_release, NULL);
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

