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

struct udp_listener_ctx_t {
    uv_udp_t io;
    int timeout;
    struct cstl_set *connections;
#ifdef MODULE_LOCAL
    union sockaddr_universal remote_addr;
    struct ss_host_port tunnel_addr;
#endif
//#ifdef MODULE_REMOTE
//    struct uv_loop_s *loop;
//#endif
    struct cipher_env_t *cipher_env;
    // SSR
    struct obfs_t *protocol_plugin;
    void *protocol_global;

    udp_on_recv_data_callback udp_on_recv_data;
};

#ifdef MODULE_REMOTE
struct query_ctx {
    struct resolv_query *query;
    struct sockaddr_storage src_addr;
    struct buffer_t *buf;
    int addr_header_len;
    char addr_header[384];
    struct udp_listener_ctx_t *server_ctx;
    struct udp_remote_ctx_t *remote_ctx;
};
#endif

struct udp_remote_ctx_t {
    uv_udp_t io;
    uv_timer_t watcher;
    int addr_header_len;
    char addr_header[384];
    struct sockaddr_storage src_addr;
#ifdef MODULE_REMOTE
    struct sockaddr_storage dst_addr;
#endif
    struct udp_listener_ctx_t *server_ctx;
    int ref_count;
};

static void udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void udp_remote_timeout_cb(uv_timer_t* handle);

#ifdef MODULE_REMOTE
static void query_resolve_cb(struct sockaddr *addr, void *data);
#endif
static void udp_remote_shutdown(struct udp_remote_ctx_t *ctx);

#ifdef ANDROID
extern int log_tx_rx;
extern uint64_t tx;
extern uint64_t rx;
extern int vpn;
#endif

//extern int verbose;
#ifdef MODULE_REMOTE
extern uint64_t tx;
extern uint64_t rx;
#endif

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

#if defined(MODULE_REMOTE) && defined(SO_BROADCAST)
static int
set_broadcast(int socket_fd)
{
    int opt = 1;
    return setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
}

#endif

#ifdef SO_NOSIGPIPE
static int
set_nosigpipe(int socket_fd)
{
    int opt = 1;
    return setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
}

#endif

#ifdef MODULE_REDIR

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT       19
#endif

#ifndef IP_RECVORIGDSTADDR
#ifdef  IP_ORIGDSTADDR
#   define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR
#else
#   define IP_RECVORIGDSTADDR   20
#   endif
#endif

#ifndef IPV6_RECVORIGDSTADDR
#ifdef  IPV6_ORIGDSTADDR
#define IPV6_RECVORIGDSTADDR   IPV6_ORIGDSTADDR
#else
#define IPV6_RECVORIGDSTADDR   74
#endif
#endif

static int
get_dstaddr(struct msghdr *msg, struct sockaddr_storage *dstaddr)
{
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            dstaddr->ss_family = AF_INET;
            return 0;
        } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
            memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            dstaddr->ss_family = AF_INET6;
            return 0;
        }
    }

    return 1;
}

#endif

#if defined(MODULE_REDIR) || defined(MODULE_REMOTE)
static size_t
construct_udprealy_header(const struct sockaddr_storage *in_addr, char *addr_header)
{
    size_t addr_header_len = 0;
    if (in_addr->ss_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)in_addr;
        size_t addr_len          = sizeof(struct in_addr);
        addr_header[addr_header_len++] = 1;
        memcpy(addr_header + addr_header_len, &addr->sin_addr, addr_len);
        addr_header_len += addr_len;
        memcpy(addr_header + addr_header_len, &addr->sin_port, 2);
        addr_header_len += 2;
    } else if (in_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)in_addr;
        size_t addr_len           = sizeof(struct in6_addr);
        addr_header[addr_header_len++] = 4;
        memcpy(addr_header + addr_header_len, &addr->sin6_addr, addr_len);
        addr_header_len += addr_len;
        memcpy(addr_header + addr_header_len, &addr->sin6_port, 2);
        addr_header_len += 2;
    } else {
        return 0;
    }
    return addr_header_len;
}

#endif

static int
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

                if (universal_address_from_string(tmp, 80, &addr_u) == 0) {
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

#ifdef MODULE_REMOTE
struct query_ctx * new_query_ctx(char *buf, size_t len) {
    struct query_ctx *ctx = calloc(1, sizeof(struct query_ctx));
    ctx->buf = buffer_create_from((uint8_t *)buf, len);
    return ctx;
}

static void close_and_free_query(struct query_ctx *ctx) {
    if (ctx != NULL) {
        if (ctx->query != NULL) {
            resolv_cancel(ctx->query);
            ctx->query = NULL;
        }
        buffer_release(ctx->buf);
        free(ctx);
    }
}

#endif

static void udp_remote_close_done_cb(uv_handle_t* handle) {
    struct udp_remote_ctx_t *ctx = (struct udp_remote_ctx_t *)handle->data;
    --ctx->ref_count;
    if (ctx->ref_count <= 0) {
        free(ctx);
    }
}

static void udp_remote_shutdown(struct udp_remote_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }
    cstl_set_container_remove(ctx->server_ctx->connections, ctx);

    ctx->watcher.data = ctx;
    uv_timer_stop(&ctx->watcher);
    uv_close((uv_handle_t *)&ctx->watcher, udp_remote_close_done_cb);
    ++ctx->ref_count;

    uv_udp_recv_stop(&ctx->io);
    ctx->io.data = ctx;
    uv_close((uv_handle_t *)&ctx->io, udp_remote_close_done_cb);
    ++ctx->ref_count;
}

static void udp_remote_timeout_cb(uv_timer_t* handle) {
    struct udp_remote_ctx_t *remote_ctx
        = CONTAINER_OF(handle, struct udp_remote_ctx_t, watcher);

    LOGI("%s", "[udp] connection timeout");

    udp_remote_shutdown(remote_ctx);
}

#ifdef MODULE_REMOTE

static void udp_remote_send_done_cb(uv_udp_send_t* req, int status) {
    struct udp_remote_ctx_t *remote_ctx = (struct udp_remote_ctx_t *)req->data;
    free(req);
    if (status < 0) {
        SS_ERROR("[udp] sendto_remote");
        udp_remote_shutdown(remote_ctx);
    } else {
        /*
        // Add to conn cache
        char *key = hash_key(AF_UNSPEC, &remote_ctx->src_addr);
        cache_insert(remote_ctx->server_ctx->conn_cache, key, HASH_KEY_LEN, (void *)remote_ctx);
        // ev_io_start(EV_A_ & remote_ctx->io);
        //ev_timer_start(EV_A_ & remote_ctx->watcher);
        */
    }
}

static void query_resolve_cb(struct sockaddr *addr, void *data) {
    struct query_ctx *query_ctx = (struct query_ctx *)data;
    struct uv_loop_s *loop = query_ctx->server_ctx->io.loop;
    /*
    if (verbose) {
        LOGI("[udp] udns resolved");
    }
    */
    query_ctx->query = NULL;

    if (addr == NULL) {
        LOGE("[udp] udns returned an error");
    } else {
        struct udp_remote_ctx_t *remote_ctx = query_ctx->remote_ctx;
        int cache_hit            = 0;

        /*
        // Lookup in the conn cache
        if (remote_ctx == NULL) {
            char *key = hash_key(AF_UNSPEC, &query_ctx->src_addr);
            cache_lookup(query_ctx->server_ctx->conn_cache, key, HASH_KEY_LEN, (void *)&remote_ctx);
        }
        */

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

static void
udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags)
{
    struct udp_remote_ctx_t *remote_ctx = CONTAINER_OF(handle, struct udp_remote_ctx_t, io);
    struct udp_listener_ctx_t *server_ctx = remote_ctx->server_ctx;
    struct buffer_t *buf = NULL;
    int err;
    int len;
    size_t remote_src_addr_len;

    (void)addr;
    (void)flags;
    uv_timer_stop(&remote_ctx->watcher);

    // server has been closed
    if (server_ctx == NULL) {
        LOGE("%s", "[udp] invalid server");
        udp_remote_shutdown(remote_ctx);
        return;
    }

    if (nread == -1) {
        // error on recv, simply drop that packet
        LOGE("%s", "[udp] remote_recv_recvfrom");
        goto CLEAN_UP;
    } else if (nread > (ssize_t) packet_size) {
        LOGE("%s", "[udp] remote_recv_recvfrom fragmentation");
        goto CLEAN_UP;
    }

    buf = buffer_create(max((size_t)buf_size, (size_t)nread));
    buffer_store(buf, (uint8_t *)buf0->base, (size_t)nread);

    udp_uv_release_buffer((uv_buf_t *)buf0);

#ifdef MODULE_LOCAL
    err = ss_decrypt_all(server_ctx->cipher_env, buf, buf_size);
    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }

    //SSR beg
    if (server_ctx->protocol_plugin) {
        struct obfs_t *protocol_plugin = server_ctx->protocol_plugin;
        if (protocol_plugin->client_udp_post_decrypt) {
            ssize_t sslen;
            size_t len0 = 0;
            const uint8_t *pOld = buffer_get_data(buf, &len0);
            size_t capacity = buffer_get_capacity(buf);
            uint8_t *p = (uint8_t *) calloc(capacity, sizeof(*p));
            memcpy(p, pOld, len0);
            sslen = protocol_plugin->client_udp_post_decrypt(protocol_plugin, (char **)&p, len0, &capacity);
            if (sslen >= 0) {
                buffer_store(buf, p, (size_t)sslen);
            }
            free(p);
            if (sslen < 0) {
                LOGE("%s", "client_udp_post_decrypt");
                udp_remote_shutdown(remote_ctx);
                return;
            }
            if (sslen == 0) {
                return;
            }
        }
    }
    // SSR end

#ifdef MODULE_REDIR
    struct sockaddr_storage dst_addr;
    memset(&dst_addr, 0, sizeof(struct sockaddr_storage));
    len = udprelay_parse_header(buf->buffer, buf->len, NULL, NULL, &dst_addr);

    if (dst_addr.ss_family != AF_INET && dst_addr.ss_family != AF_INET6) {
        LOGI("[udp] ss-redir does not support domain name");
        goto CLEAN_UP;
    }

    if (verbose) {
        char src[SS_ADDRSTRLEN];
        char dst[SS_ADDRSTRLEN];
        strcpy(src, get_addr_str((struct sockaddr *)&src_addr));
        strcpy(dst, get_addr_str((struct sockaddr *)&dst_addr));
        LOGI("[udp] recv %s via %s", dst, src);
    }
#else
    len = udprelay_parse_header((const char *) buffer_get_data(buf, NULL), buffer_get_length(buf), NULL, NULL, NULL);
#endif

    if (len == 0) {
        LOGI("%s", "[udp] error in parse header");
        // error in parse header
        goto CLEAN_UP;
    }

    // server may return using a different address type other than the type we
    // have used during sending
#if defined(MODULE_TUNNEL) || defined(MODULE_REDIR)
    // Construct packet
    buf->len -= len;
    memmove(buf->buffer, buf->buffer + len, buf->len);
#else
#ifdef ANDROID
    if (r > 0 && log_tx_rx)
        rx += r;
#endif
    // Construct packet
    if (server_ctx->tunnel_addr.host && server_ctx->tunnel_addr.port) {
        buffer_shortened_to(buf, len, buffer_get_length(buf)-len);
    } else {
        struct buffer_t *temp = buffer_clone(buf);
        buffer_store(buf, (const uint8_t *)"\0\0\0", 3);
        buffer_concatenate2(buf, temp);
        buffer_release(temp);
    }
#endif

#endif

#ifdef MODULE_REMOTE

    rx += buf->len;

    char addr_header_buf[512] = { 0 };
    char *addr_header   = remote_ctx->addr_header;
    size_t addr_header_len = remote_ctx->addr_header_len;

    if (remote_ctx->dst_addr.ss_family == AF_INET || remote_ctx->dst_addr.ss_family == AF_INET6) {
        addr_header_len = construct_udprealy_header((const struct sockaddr_storage *)addr, addr_header_buf);
        addr_header     = addr_header_buf;
    }

    // Construct packet
    buffer_realloc(buf, max(buf->len + addr_header_len, buf_size));
    memmove(buf->buffer + addr_header_len, buf->buffer, buf->len);
    memcpy(buf->buffer, addr_header, addr_header_len);
    buf->len += addr_header_len;

    int err = ss_decrypt_all(server_ctx->cipher_env, buf, buf_size);
    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }

#endif

    if (buffer_get_length(buf) > packet_size) {
        LOGE("%s", "[udp] remote_recv_sendto fragmentation");
        goto CLEAN_UP;
    }

    remote_src_addr_len = get_sockaddr_len((struct sockaddr *)&remote_ctx->src_addr);
    (void)remote_src_addr_len;

#ifdef MODULE_REDIR

    size_t remote_dst_addr_len = get_sockaddr_len((struct sockaddr *)&dst_addr);

    int src_fd = socket(remote_ctx->src_addr.ss_family, SOCK_DGRAM, 0);
    if (src_fd < 0) {
        SS_ERROR("[udp] remote_recv_socket");
        goto CLEAN_UP;
    }
    int opt = 1;
    if (setsockopt(src_fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt))) {
        SS_ERROR("[udp] remote_recv_setsockopt");
        close(src_fd);
        goto CLEAN_UP;
    }
    if (setsockopt(src_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        SS_ERROR("[udp] remote_recv_setsockopt");
        close(src_fd);
        goto CLEAN_UP;
    }
#ifdef IP_TOS
    // Set QoS flag
    int tos = 46;
    setsockopt(src_fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
#endif
    if (bind(src_fd, (struct sockaddr *)&dst_addr, remote_dst_addr_len) != 0) {
        SS_ERROR("[udp] remote_recv_bind");
        close(src_fd);
        goto CLEAN_UP;
    }

    int s = sendto(src_fd, buf->buffer, buf->len, 0,
                   (struct sockaddr *)&remote_ctx->src_addr, remote_src_addr_len);
    if (s == -1) {
        SS_ERROR("[udp] remote_recv_sendto");
        close(src_fd);
        goto CLEAN_UP;
    }
    close(src_fd);

#else
    {
    uv_buf_t tmp;
    uv_udp_send_t *req = (uv_udp_send_t *)calloc(1, sizeof(uv_udp_send_t));
    size_t len = 0;
    const uint8_t *buffer = buffer_get_data(buf, &len);
    req->data = buf;
    tmp = uv_buf_init((char *)buffer, (unsigned int)len);
    uv_udp_send(req, &server_ctx->io, &tmp, 1, (const struct sockaddr *)&remote_ctx->src_addr, udp_send_done_cb);
    }
    udp_remote_shutdown(remote_ctx);
    return;
#endif

CLEAN_UP:

    udp_remote_shutdown(remote_ctx);

    buffer_release(buf);
}

void udp_tls_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags)
{
    union sockaddr_universal addr_u = { {0} };
    struct udp_listener_ctx_t *server_ctx;
    struct buffer_t *data = NULL;

    server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, io);
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
        server_ctx->udp_on_recv_data(server_ctx, (addr ? &addr_u : NULL), data);
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

    struct udp_remote_ctx_t *remote_ctx = NULL;
    const struct sockaddr *remote_addr;
    int err;

    uv_loop_t *loop;
    struct server_env_t *env;
    struct server_config *config;

    loop = handle->loop;
    env = (struct server_env_t *) loop->data;
    config = env->config;

    if (config->over_tls_enable) {
        udp_tls_listener_recv_cb(handle, nread, buf0, addr, flags);
        return;
    }

    if (NULL == addr) {
        return;
    }

    server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, io);
    ASSERT(server_ctx);

    src_addr = *(struct sockaddr_storage *)addr;

    buf = buffer_create(max((size_t)buf_size, (size_t)nread));

    src_addr_len = sizeof(src_addr);
    offset    = 0;
    (void)src_addr_len;

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
    tx += buf->len;

    int err = ss_decrypt_all(server_ctx->cipher_env, buf, buf_size);
    if (err) {
        // drop the packet silently
        goto CLEAN_UP;
    }
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
        
        if (universal_address_from_string(host, port_num, &addr) == 0) {
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
    }

    buffer_shortened_to(buf, offset, buffer_get_length(buf) - offset);

    // SSR beg
    if (server_ctx->protocol_plugin) {
        struct obfs_t *protocol_plugin = server_ctx->protocol_plugin;
        if (protocol_plugin->client_udp_pre_encrypt) {
            size_t len = 0;
            const uint8_t *pOld = buffer_get_data(buf, &len);
            size_t capacity = buffer_get_capacity(buf);
            uint8_t *buffer = (uint8_t *) calloc(capacity, sizeof(*buffer));
            memcpy(buffer, pOld, len);
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
    uv_buf_t tmp;
    uv_udp_send_t *req = (uv_udp_send_t *)calloc(1, sizeof(uv_udp_send_t));
    size_t len = 0;
    const uint8_t *buffer = buffer_get_data(buf, &len);
    req->data = buf;
    tmp = uv_buf_init((char *)buffer, (unsigned int) len);
    uv_udp_send(req, &remote_ctx->io, &tmp, 1, remote_addr, udp_send_done_cb);
    }
    return;
#if !defined(MODULE_TUNNEL) && !defined(MODULE_REDIR)
#ifdef ANDROID
    if (log_tx_rx)
        tx += buf->len;
#endif
#endif

#else

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
        /*
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
        */
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

    // ////////////////////////////////////////////////
    // Setup server context

    server_ctx = (struct udp_listener_ctx_t *)calloc(1, sizeof(struct udp_listener_ctx_t));

    // Bind to port
    serverfd = udp_create_local_listener(server_host, server_port, loop, &server_ctx->io);
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

    uv_udp_recv_start(&server_ctx->io, udp_uv_alloc_buffer, udp_listener_recv_cb);
    
    return server_ctx;
}

static void udp_local_listener_close_done_cb(uv_handle_t* handle) {
    struct udp_listener_ctx_t *server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, io);
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

void connection_release(const void *obj, void *p) {
    (void)p;
    udp_remote_shutdown((struct udp_remote_ctx_t *)obj);
}

void udprelay_shutdown(struct udp_listener_ctx_t *server_ctx) {
    if (server_ctx == NULL) {
        return;
    }
    cstl_set_container_traverse(server_ctx->connections, &connection_release, NULL);
    uv_close((uv_handle_t *)&server_ctx->io, udp_local_listener_close_done_cb);
}

void udp_relay_set_udp_on_recv_data_callback(struct udp_listener_ctx_t *udp_ctx, udp_on_recv_data_callback callback) {
    if (udp_ctx) {
        udp_ctx->udp_on_recv_data = callback;
    }
}

uv_loop_t * udp_relay_context_get_loop(struct udp_listener_ctx_t *udp_ctx) {
    return udp_ctx->io.loop;
}
