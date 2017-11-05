/*
 * local.c - Setup a socks5 proxy through remote shadowsocks server
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <stddef.h>

#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#endif

#ifdef LIB_ONLY
#include <pthread.h>
#include "shadowsocks.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include <libcork/core.h>
#include <udns.h>
#include <uv.h>

#ifdef __MINGW32__
#include "win32.h"
#endif

#include "netutils.h"
#include "ssrutils.h"
#include "socks5.h"
#include "acl.h"
#include "http.h"
#include "tls.h"
#include "local.h"
#include "udprelay.h"

#ifndef LIB_ONLY
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 2048
#endif

int verbose = 0;
int keep_resolving = 1;

#ifdef ANDROID
int log_tx_rx  = 0;
int vpn        = 0;
uint64_t tx    = 0;
uint64_t rx    = 0;
ev_tstamp last = 0;
char *prefix;
#endif

#include "includeobfs.h" // I don't want to modify makefile
#include "jconf.h"

static int acl       = 0;
static int mode = TCP_ONLY;
static int ipv6first = 0;

static int fast_open = 0;
#ifdef HAVE_SETRLIMIT
#ifndef LIB_ONLY
static int nofile = 0;
#endif
#endif

static void local_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0);
static void local_send_cb(uv_write_t* req, int status);
static void local_send_data(struct local_t *local, char *data, unsigned int size);
static void remote_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0);
static void remote_send_data(struct remote_t *remote);
static void remote_connected_cb(uv_connect_t* req, int status);
static void remote_timeout_cb(uv_timer_t *handle);

static struct remote_t *remote_object_with_addr(struct listener_t *listener, struct sockaddr *addr);
static void remote_destroy(struct remote_t *remote);
static void remote_close_and_free(struct remote_t *remote);
static void local_destroy(struct local_t *local);
static void local_close_and_free(struct local_t *local);

static void tunnel_close_and_free(struct remote_t *remote, struct local_t *local);

static struct remote_t * remote_new_object(uv_loop_t *loop, int timeout);
static struct local_t * local_new_object(struct listener_t *listener);

static struct cork_dllist inactive_listeners;
static struct listener_t *current_listener;
static struct cork_dllist all_connections;


void do_alloc_uv_buffer(size_t suggested_size, uv_buf_t *buf) {
    suggested_size = BUF_SIZE;
    buf->base = malloc(suggested_size * sizeof(char));
    buf->len = (uv_buf_len_t) suggested_size;
}

void do_dealloc_uv_buffer(uv_buf_t *buf) {
    free(buf->base);
    buf->base = NULL;
    buf->len = 0;
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    do_alloc_uv_buffer(suggested_size, buf);
}

#ifndef __MINGW32__
int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

int uv_stream_fd(const uv_tcp_t *handle) {
#if defined(_WIN32)
    return (int) handle->socket;
#elif defined(__APPLE__)
    int uv___stream_fd(const uv_stream_t* handle);
    return uv___stream_fd((const uv_stream_t *)handle);
#else
    return (handle)->io_watcher.fd;
#endif
}

void
local_read_start(struct local_t *local)
{
    if (local) {
        uv_read_start((uv_stream_t *) &local->socket, on_alloc, local_recv_cb);
    }
}

void
local_read_stop(struct local_t *local)
{
    if (local) {
        uv_read_stop((uv_stream_t *) &local->socket);
    }
}

int
create_and_bind(const char *addr, const char *port, uv_loop_t *loop, uv_tcp_t *tcp)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result = NULL, *rp;
    int s, listen_sock = 0;

    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    uv_tcp_init(loop, tcp);

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        int r = uv_tcp_bind(tcp, rp->ai_addr, 0);
        if (r == 0) {
            break;
        }
        LOGE("uv_tcp_bind: %s\n", uv_strerror(r));
    }

    if (rp == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, const char *port, uv_loop_t *loop, uv_tcp_t *tcp)
{
    int *fds;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &fds, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            return fds[0];
        } else {
            FATAL("please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /* ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *          in the caller's launchd.plist(5).
         */
        if (port == NULL) {
            usage();
            exit(EXIT_FAILURE);
        }
        return create_and_bind(addr, port, loop, tcp);
    } else {
        FATAL("launch_activate_socket() error");
    }
    return -1;
}
#endif

static void
free_connections(void)
{
    struct cork_dllist_item *curr, *next;
    cork_dllist_foreach_void(&all_connections, curr, next) {
        struct local_t *local = cork_container_of(curr, struct local_t, entries_all);
        struct remote_t *remote = local->remote;
        tunnel_close_and_free(remote, local);
    }
}

static void
local_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0)
{
    struct local_t *local = cork_container_of(stream, struct local_t, socket);
    struct remote_t *remote = local->remote;
    struct buffer_t *buf;

    if (local->dying || (remote && remote->dying) ) {
        do_dealloc_uv_buffer((uv_buf_t *)buf0);
        return;
    }

    if (remote == NULL) {
        buf = local->buf;
    } else {
        buf = remote->buf;
    }

    if (nread > 0) {
        buffer_realloc(buf, (size_t)nread * 2);
        memcpy(buf->buffer, buf0->base, (size_t)nread);
        buf->len = (size_t)nread;
    }

    do_dealloc_uv_buffer((uv_buf_t *)buf0);

    if (nread == UV_EOF) {
        // connection closed
        tunnel_close_and_free(remote, local);
        return;
    } else if (nread == 0) {
        // http://docs.libuv.org/en/v1.x/stream.html
        // (errno == EAGAIN || errno == EWOULDBLOCK): no data, continue to wait for recv
        return;
    } else if (nread < 0) {
        if (verbose) {
            ERROR("local recieve callback for recv");
        }
        tunnel_close_and_free(remote, local);
        return;
    }

    if (local->stage == STAGE_INIT) {
        char *host = local->listener->tunnel_addr.host;
        char *port = local->listener->tunnel_addr.port;
        if (host && port) {
            struct buffer_t *buffer = buffer_alloc(BUF_SIZE);
            size_t header_len = 0;
            struct socks5_request *hdr =
                    build_socks5_request(host, (uint16_t)atoi(port), buffer->buffer, buffer->capacity, &header_len);

            memmove(buf->buffer + header_len, buf->buffer, buf->len);
            memmove(buf->buffer, hdr, header_len);
            buf->len += header_len;

            buffer_free(buffer);

            local->stage = STAGE_PARSE;
        }
    }
    while (1) {
        // local socks5 server
        if (local->stage == STAGE_STREAM) {
            if (remote == NULL) {
                LOGE("invalid remote");
                tunnel_close_and_free(remote, local);
                return;
            }

            // insert shadowsocks header
            {
                struct server_env_t *server_env = local->server_env;
                // SSR beg
                struct obfs_manager *protocol_plugin = server_env->protocol_plugin;

                if (protocol_plugin && protocol_plugin->client_pre_encrypt) {
                    remote->buf->len = (size_t) protocol_plugin->client_pre_encrypt(local->protocol, &remote->buf->buffer, (int)remote->buf->len, &remote->buf->capacity);
                }
                int err = ss_encrypt(&server_env->cipher, remote->buf, local->e_ctx, BUF_SIZE);

                if (err) {
                    LOGE("local invalid password or cipher");
                    tunnel_close_and_free(remote, local);
                    return;
                }

                struct obfs_manager *obfs_plugin = server_env->obfs_plugin;
                if (obfs_plugin && obfs_plugin->client_encode) {
                    remote->buf->len = obfs_plugin->client_encode(local->obfs, &remote->buf->buffer, remote->buf->len, &remote->buf->capacity);
                }
                // SSR end
#ifdef ANDROID
                if (log_tx_rx) {
                    tx += buf->len;
                }
#endif
            }

            if (!remote->connected) {
#ifdef ANDROID
                if (vpn) {
                    int not_protect = 0;
                    if (remote->direct_addr.addr.ss_family == AF_INET) {
                        struct sockaddr_in *s = (struct sockaddr_in *)&remote->direct_addr.addr;
                        if (s->sin_addr.s_addr == inet_addr("127.0.0.1")) {
                            not_protect = 1;
                        }
                    }
                    if (!not_protect) {
                        if (protect_socket(remote->fd) == -1) {
                            ERROR("protect_socket");
                            tunnel_close_and_free(remote, local);
                            return;
                        }
                    }
                }
#endif
                local_read_stop(local);

                uv_connect_t *connect = (uv_connect_t *)ss_malloc(sizeof(uv_connect_t));
                connect->data = remote;

                struct sockaddr *addr = (struct sockaddr*)&(remote->addr);
                uv_tcp_connect(connect, &remote->socket, addr, remote_connected_cb);
                return;
            } else {
                if (nread > 0 && remote->buf->len == 0) {
                    local_read_stop(local);
                    return;
                }
                remote_send_data(remote);
            }

            // all processed
            return;
        } else if (local->stage == STAGE_INIT) {
            struct method_select_request *request = (struct method_select_request *)buf->buffer;

            struct buffer_t *buffer = buffer_alloc(BUF_SIZE);
            struct method_select_response *response =
                    build_socks5_method_select_response(SOCKS5_METHOD_NOAUTH, buffer->buffer, buffer->capacity);

            local_send_data(local, (char *)response, sizeof(*response));

            buffer_free(buffer);

            local->stage = STAGE_HANDSHAKE;

            int off = (request->nmethods & 0xff) + sizeof(*request);
            if ((request->ver == SOCKS5_VERSION) && (off < (int)(buf->len))) {
                memmove(buf->buffer, buf->buffer + off, buf->len - off);
                buf->len -= off;
                continue;
            }

            buf->len = 0;

            return;
        } else if (local->stage == STAGE_HANDSHAKE || local->stage == STAGE_PARSE) {
            struct socks5_request *request = (struct socks5_request *)buf->buffer;

            struct sockaddr_in sock_addr = { 0 };

            int udp_assc = 0;

            if (request->cmd == SOCKS5_COMMAND_UDPASSOC) {
                udp_assc = 1;
                socklen_t addr_len = sizeof(sock_addr);
                getsockname(uv_stream_fd(&local->socket), (struct sockaddr *)&sock_addr, &addr_len);
                if (verbose) {
                    LOGI("udp assc request accepted");
                }
            } else if (request->cmd != SOCKS5_COMMAND_CONNECT) {
                LOGE("unsupported cmd: %d", request->cmd);
                struct buffer_t *buffer = buffer_alloc(BUF_SIZE);
                size_t size = 0;
                struct socks5_response *response =
                        build_socks5_response(SOCKS5_REPLY_CMDUNSUPP, SOCKS5_ADDRTYPE_IPV4,
                                              &sock_addr, buffer->buffer, buffer->capacity, &size);

                local_send_data(local, (char *)response, (unsigned int)size);

                buffer_free(buffer);

                tunnel_close_and_free(remote, local);
                return;
            }

            // Fake reply
            if (local->stage == STAGE_HANDSHAKE) {
                struct buffer_t *buffer = buffer_alloc(BUF_SIZE);
                size_t size = 0;
                struct socks5_response *response =
                        build_socks5_response(SOCKS5_REPLY_SUCCESS, SOCKS5_ADDRTYPE_IPV4,
                                              &sock_addr, buffer->buffer, buffer->capacity, &size);

                local_send_data(local, (char *)response, (unsigned int)size);

                buffer_free(buffer);

                if (udp_assc) {
                    // Wait until client closes the connection
                    return;
                }
            }

            char host[257], ip[INET6_ADDRSTRLEN], port[16];

            struct buffer_t *abuf = buffer_alloc(BUF_SIZE);

            char addr_type = request->addr_type;

            abuf->buffer[abuf->len++] = addr_type;

            char *addr_n_port = request->addr_n_port;

            // get remote addr and port
            if (addr_type == SOCKS5_ADDRTYPE_IPV4) {
                // IP V4
                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(abuf->buffer + abuf->len, addr_n_port, in_addr_len + 2);
                abuf->len += in_addr_len + 2;

                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(addr_n_port + in_addr_len));
                    dns_ntop(AF_INET, (const void *)(addr_n_port), ip, INET_ADDRSTRLEN);
                    sprintf(port, "%d", p);
                }
            } else if (addr_type == SOCKS5_ADDRTYPE_NAME) {
                // Domain name
                uint8_t name_len = *(uint8_t *)addr_n_port;
                abuf->buffer[abuf->len++] = name_len;
                memcpy(abuf->buffer + abuf->len, addr_n_port + 1, name_len + 2);
                abuf->len += name_len + 2;

                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(addr_n_port + 1 + name_len));
                    memcpy(host, addr_n_port + 1, name_len);
                    host[name_len] = '\0';
                    sprintf(port, "%d", p);
                }
            } else if (addr_type == SOCKS5_ADDRTYPE_IPV6) {
                // IP V6
                size_t in6_addr_len = sizeof(struct in6_addr);
                memcpy(abuf->buffer + abuf->len, addr_n_port, in6_addr_len + 2);
                abuf->len += in6_addr_len + 2;

                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(addr_n_port + in6_addr_len));
                    dns_ntop(AF_INET6, (const void *)addr_n_port, ip, INET6_ADDRSTRLEN);
                    sprintf(port, "%d", p);
                }
            } else {
                buffer_free(abuf);
                LOGE("unsupported addrtype: %d", addr_type);
                tunnel_close_and_free(remote, local);
                return;
            }

            size_t abuf_len  = abuf->len;
            int sni_detected = 0;

            if (addr_type == SOCKS5_ADDRTYPE_IPV4 || addr_type == SOCKS5_ADDRTYPE_IPV6) {
                char *hostname;
                uint16_t p = ntohs(*(uint16_t *)(abuf->buffer + abuf->len - 2));
                int ret    = 0;
                if (p == http_protocol->default_port) {
                    const char *data = buf->buffer + 3 + abuf->len;
                    size_t data_len  = buf->len    - 3 - abuf->len;
                    ret = http_protocol->parse_packet(data, data_len, &hostname);
                } else if (p == tls_protocol->default_port) {
                    const char *data = buf->buffer + 3 + abuf->len;
                    size_t data_len  = buf->len    - 3 - abuf->len;
                    ret = tls_protocol->parse_packet(data, data_len, &hostname);
                }
                if (ret == -1 && buf->len < BUF_SIZE) {
                    local->stage = STAGE_PARSE;
                    buffer_free(abuf);
                    return;
                } else if (ret > 0) {
                    sni_detected = 1;

                    // Reconstruct address buffer
                    abuf->len                = 0;
                    abuf->buffer[abuf->len++] = 3;
                    abuf->buffer[abuf->len++] = ret;
                    memcpy(abuf->buffer + abuf->len, hostname, ret);
                    abuf->len += ret;
                    p          = htons(p);
                    memcpy(abuf->buffer + abuf->len, &p, 2);
                    abuf->len += 2;

                    if (acl || verbose) {
                        memcpy(host, hostname, ret);
                        host[ret] = '\0';
                    }

                    ss_free(hostname);
                } else {
                    strncpy(host, ip, sizeof(ip));
                }
            }

            local->stage = STAGE_STREAM;

            buf->len -= (3 + abuf_len);
            if (buf->len > 0) {
                memmove(buf->buffer, buf->buffer + 3 + abuf_len, buf->len);
            }

            if (acl) {
                if (outbound_block_match_host(host) == 1) {
                    if (verbose) {
                        LOGI("outbound blocked %s", host);
                    }
                    tunnel_close_and_free(remote, local);
                    return;
                }

                int host_match = acl_match_host(host);
                int bypass = 0;
                int resolved = 0;
                struct sockaddr_storage storage;
                memset(&storage, 0, sizeof(struct sockaddr_storage));
                int err;

                if (verbose) {
                    LOGI("acl_match_host %s result %d", host, host_match);
                }
                if (host_match > 0) {
                    bypass = 0;                 // bypass hostnames in black list
                } else if (host_match < 0) {
                    bypass = 1;                 // proxy hostnames in white list
                } else {
#ifndef ANDROID
                    if (addr_type == SOCKS5_ADDRTYPE_NAME) {            // resolve domain so we can bypass domain with geoip
                        err = (int) get_sockaddr(host, port, &storage, 0, ipv6first);
                        if ( err != -1) {
                            resolved = 1;
                            switch(((struct sockaddr*)&storage)->sa_family) {
                                case AF_INET: {
                                    struct sockaddr_in *addr_in = (struct sockaddr_in *)&storage;
                                    dns_ntop(AF_INET, &(addr_in->sin_addr), ip, INET_ADDRSTRLEN);
                                    break;
                                }
                                case AF_INET6: {
                                    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&storage;
                                    dns_ntop(AF_INET6, &(addr_in6->sin6_addr), ip, INET6_ADDRSTRLEN);
                                    break;
                                }
                                default:
                                    break;
                            }
                        }
                    }
#endif
                    if (outbound_block_match_host(ip) == 1) {
                        if (verbose) {
                            LOGI("outbound blocked %s", ip);
                        }
                        tunnel_close_and_free(remote, local);
                        return;
                    }

                    int ip_match = acl_match_host(ip);// -1 if IP in white list or 1 if IP in black list
                    if (verbose) {
                        LOGI("acl_match_host ip %s result %d mode %d",
                             ip, ip_match, get_acl_mode());
                    }
                    if (ip_match < 0) {
                        bypass = 1;
                    } else if (ip_match > 0) {
                        bypass = 0;
                    } else {
                        bypass = (get_acl_mode() == BLACK_LIST);
                    }
                }

                if (bypass) {
                    if (verbose) {
                        if (sni_detected || addr_type == SOCKS5_ADDRTYPE_NAME) {
                            LOGI("bypass %s:%s", host, port);
                        } else if (addr_type == SOCKS5_ADDRTYPE_IPV4) {
                            LOGI("bypass %s:%s", ip, port);
                        } else if (addr_type == SOCKS5_ADDRTYPE_IPV6) {
                            LOGI("bypass [%s]:%s", ip, port);
                        }
                    }
                    struct sockaddr_storage storage;
                    memset(&storage, 0, sizeof(struct sockaddr_storage));
                    ssize_t err;
#ifndef ANDROID
                    if (addr_type == SOCKS5_ADDRTYPE_NAME && resolved != 1) {
                        err = get_sockaddr(host, port, &storage, 0, ipv6first);
                    } else
#endif
                    {
                        err = get_sockaddr(ip, port, &storage, 0, ipv6first);
                    }
                    if (err != -1) {
                        remote = remote_object_with_addr(local->listener, (struct sockaddr *)&storage);
                    }
                }
            }

            // Not match ACL
            if (remote == NULL) {
                // pick a server
                struct listener_t *listener = local->listener;
                int index = rand() % listener->server_num;
                struct server_env_t *server_env = &listener->servers[index];

                if (verbose) {
                    if (sni_detected || addr_type == SOCKS5_ADDRTYPE_NAME) {
                        LOGI("connect to %s:%s via %s:%d",
                             host, port, server_env->host, server_env->port);
                    } else if (addr_type == SOCKS5_ADDRTYPE_IPV4) {
                        LOGI("connect to %s:%s via %s:%d",
                             ip, port, server_env->host, server_env->port);
                    } else if (addr_type == SOCKS5_ADDRTYPE_IPV6) {
                        LOGI("connect to [%s]:%s via %s:%d",
                             ip, port, server_env->host, server_env->port);
                    }
                }

                local->server_env = server_env;

                remote = remote_object_with_addr(listener, (struct sockaddr *) server_env->addr);
            }

            if (remote == NULL) {
                buffer_free(abuf);
                LOGE("invalid remote addr");
                tunnel_close_and_free(remote, local);
                return;
            }

            {
                struct server_env_t *server_env = local->server_env;

                // expelled from eden
                cork_dllist_remove(&local->entries);
                cork_dllist_add(&server_env->connections, &local->entries);

                // init server cipher
                if (server_env->cipher.enc_method > TABLE) {
                    local->e_ctx = ss_malloc(sizeof(struct enc_ctx));
                    local->d_ctx = ss_malloc(sizeof(struct enc_ctx));
                    enc_ctx_init(&server_env->cipher, local->e_ctx, 1);
                    enc_ctx_init(&server_env->cipher, local->d_ctx, 0);
                } else {
                    local->e_ctx = NULL;
                    local->d_ctx = NULL;
                }
                // SSR beg
                struct server_info_t server_info;
                memset(&server_info, 0, sizeof(struct server_info_t));
                if (server_env->hostname) {
                    strcpy(server_info.host, server_env->hostname);
                } else {
                    strcpy(server_info.host, server_env->host);
                }
                if (verbose) {
                    LOGI("struct server_info_t host %s", server_info.host);
                }
                server_info.port = server_env->port;
                server_info.param = server_env->obfs_param;
                server_info.g_data = server_env->obfs_global;
                server_info.head_len = get_head_size(abuf->buffer, 320, 30);
                server_info.iv = local->e_ctx->cipher_ctx.iv;
                server_info.iv_len = enc_get_iv_len(&server_env->cipher);
                server_info.key = enc_get_key(&server_env->cipher);
                server_info.key_len = enc_get_key_len(&server_env->cipher);
                server_info.tcp_mss = 1452;
                server_info.buffer_size = BUF_SIZE;
                server_info.cipher_env = &server_env->cipher;

                if (server_env->obfs_plugin) {
                    local->obfs = server_env->obfs_plugin->new_obfs();
                    server_env->obfs_plugin->set_server_info(local->obfs, &server_info);
                }

                server_info.param = server_env->protocol_param;
                server_info.g_data = server_env->protocol_global;

                if (server_env->protocol_plugin) {
                    local->protocol = server_env->protocol_plugin->new_obfs();
                    server_info.overhead = server_env->protocol_plugin->get_overhead(local->protocol)
                        + (server_env->obfs_plugin ? server_env->obfs_plugin->get_overhead(local->obfs) : 0);
                    server_env->protocol_plugin->set_server_info(local->protocol, &server_info);
                }
                // SSR end

                size_t total_len = abuf->len + buf->len;
                buffer_realloc(remote->buf, total_len * 2);
                remote->buf->len = total_len;

                memcpy(remote->buf->buffer, abuf->buffer, abuf->len);
                if (buf->len > 0) {
                    memcpy(remote->buf->buffer + abuf->len, buf->buffer, buf->len);
                }
            }

            local->remote = remote;
            remote->local = local;

            buffer_free(abuf);
            continue; // return;
        }
    } // while (1)
}

static void
local_send_cb(uv_write_t* req, int status)
{
    struct local_t *local = (struct local_t *) req->data;
    assert(local);
    struct remote_t *remote = local->remote;

    free(req);

    if (local->dying || (remote && remote->dying) ) {
        return;
    }

    if (status < 0) {
        LOGE("local_send_cb: %s", uv_strerror(status));
        tunnel_close_and_free(remote, local);
    } else if (status == 0) {
        local->buf->len = 0;
    }
}

#ifdef ANDROID
static void
stat_update_cb()
{
    if (log_tx_rx) {
        ev_tstamp now = ev_time();
        if (now - last > 1.0) {
            send_traffic_stat(tx, rx);
            last = now;
        }
    }
}
#endif

static void
remote_connected_cb(uv_connect_t* req, int status)
{
    struct remote_t *remote = (struct remote_t *)req->data;
    assert(remote);
    struct local_t *local = remote->local;

    free(req);

    if (local==NULL || local->dying || remote->dying) {
        return;
    }

    if (status == 0) {
        remote->connected = true;

        uv_timer_start(&remote->recv_ctx->watcher, remote_timeout_cb, remote->recv_ctx->watcher_interval, 0);
        uv_read_start((uv_stream_t *)&remote->socket, on_alloc, remote_recv_cb);

        remote_send_data(remote);
        local_read_start(local);
    } else {
        tunnel_close_and_free(remote, local);
    }
}

static void
remote_timeout_cb(uv_timer_t *handle)
{
    struct remote_ctx_t *remote_ctx
        = cork_container_of(handle, struct remote_ctx_t, watcher);

    struct remote_t *remote = remote_ctx->remote;
    struct local_t *local = remote->local;

    if (local==NULL || local->dying || remote->dying) {
        return;
    }

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    tunnel_close_and_free(remote, local);
}

static void
remote_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0)
{
    struct remote_t *remote = cork_container_of(stream, struct remote_t, socket);
    assert(remote);
    struct local_t *local = remote->local;
    struct server_env_t *server_env = local->server_env;

    if (local==NULL || local->dying || remote->dying) {
        do_dealloc_uv_buffer((uv_buf_t *)buf0);
        return;
    }

    uv_timer_start(&remote->recv_ctx->watcher, remote_timeout_cb, remote->recv_ctx->watcher_interval, 0);

#ifdef ANDROID
    stat_update_cb();
#endif

    if (nread <= 0) {
        do_dealloc_uv_buffer((uv_buf_t *)buf0);
        if (nread == UV_EOF) {
            // connection closed
            tunnel_close_and_free(remote, local);
        } else if (nread == 0) {
            // (errno == EAGAIN || errno == EWOULDBLOCK):
            ; // LOGI("remote_recv_cb: no data. continue to wait for recv");
        } else if (nread < 0) {
            if (verbose) {
                ERROR("remote_recv_cb_recv");
            }
            tunnel_close_and_free(remote, local);
        }
        return;
    }

    static const size_t FIXED_BUFF_SIZE = BUF_SIZE;

    buffer_realloc(local->buf, FIXED_BUFF_SIZE);

    char *guard = buf0->base + nread;

    for (char *iter = buf0->base; iter < guard; iter += FIXED_BUFF_SIZE) {
        size_t remain = guard - iter;
        size_t len = remain > FIXED_BUFF_SIZE ? FIXED_BUFF_SIZE : remain;

        memcpy(local->buf->buffer, iter, (size_t)len);
        local->buf->len = len;

#ifdef ANDROID
        if (log_tx_rx) {
            rx += local->buf->len;
        }
#endif
        // SSR beg
        struct obfs_manager *obfs_plugin = server_env->obfs_plugin;
        if (obfs_plugin && obfs_plugin->client_decode) {
            int needsendback;
            local->buf->len = obfs_plugin->client_decode(local->obfs, &local->buf->buffer, local->buf->len, &local->buf->capacity, &needsendback);
            if ((ssize_t)local->buf->len < 0) {
                LOGE("client_decode nread = %d", (int)nread);
                tunnel_close_and_free(remote, local);
                break; // return;
            }
            if (needsendback && obfs_plugin->client_encode) {
                remote->buf->len = obfs_plugin->client_encode(local->obfs, &remote->buf->buffer, 0, &remote->buf->capacity);
                remote_send_data(remote);
                local_read_start(local);
            }
        }
        if (local->buf->len > 0) {
            int err = ss_decrypt(&server_env->cipher, local->buf, local->d_ctx, FIXED_BUFF_SIZE);
            if (err) {
                LOGE("remote invalid password or cipher");
                tunnel_close_and_free(remote, local);
                break; // return;
            }
        }
        struct obfs_manager *protocol_plugin = server_env->protocol_plugin;
        if (protocol_plugin && protocol_plugin->client_post_decrypt) {
            local->buf->len = (size_t)protocol_plugin->client_post_decrypt(local->protocol, &local->buf->buffer, (int)local->buf->len, &local->buf->capacity);
            if ((int)local->buf->len < 0) {
                LOGE("client_post_decrypt and nread=%d", (int)nread);
                tunnel_close_and_free(remote, local);
                break; // return;
            }
            if (local->buf->len == 0) {
                continue;
            }
        }
        // SSR end

        local_send_data(local, local->buf->buffer, (unsigned int)local->buf->len);
    } // for loop

    do_dealloc_uv_buffer((uv_buf_t *)buf0);
}

static void
remote_send_cb(uv_write_t* req, int status)
{
    struct remote_t *remote = (struct remote_t *)req->data;
    assert(remote);
    struct local_t *local = remote->local;
    struct buffer_t *buf = remote->buf;

    free(req);

    if (local==NULL || local->dying || remote->dying) {
        return;
    }

    uv_timer_stop(&remote->send_ctx->watcher);

    if (status != 0) {
        tunnel_close_and_free(remote, local);
        return;
    }

    buf->len = 0;
}

static void
remote_send_data(struct remote_t *remote)
{
    uv_buf_t tmp = uv_buf_init(remote->buf->buffer, (unsigned int)remote->buf->len);

    uv_write_t *write_req = (uv_write_t *)ss_malloc(sizeof(uv_write_t));
    write_req->data = remote;

    uv_write(write_req, (uv_stream_t *)&remote->socket, &tmp, 1, remote_send_cb);
    uv_timer_start(&remote->send_ctx->watcher, remote_timeout_cb, remote->send_ctx->watcher_interval, 0);
}

static void 
local_send_data(struct local_t *local, char *data, unsigned int size)
{
    uv_buf_t buf = uv_buf_init(data, size);

    uv_write_t *write_req = (uv_write_t *)ss_malloc(sizeof(uv_write_t));
    write_req->data = local;

    uv_write(write_req, (uv_stream_t*)&local->socket, &buf, 1, local_send_cb);
}


static struct remote_t *
remote_new_object(uv_loop_t *loop, int timeout)
{
    struct remote_t *remote = ss_malloc(sizeof(struct remote_t));

    uv_tcp_init(loop, &remote->socket);

    remote->buf                 = buffer_alloc(BUF_SIZE);
    remote->recv_ctx            = ss_malloc(sizeof(struct remote_ctx_t));
    remote->send_ctx            = ss_malloc(sizeof(struct remote_ctx_t));
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    int timeMax = min(MAX_CONNECT_TIMEOUT * SECONDS_PER_MINUTE, timeout);
    uv_timer_init(loop, &remote->send_ctx->watcher);
    remote->send_ctx->watcher_interval = (uint64_t) timeMax;

    uv_timer_init(loop, &remote->recv_ctx->watcher);
    remote->recv_ctx->watcher_interval = (uint64_t) timeout;

    return remote;
}

static void
remote_destroy(struct remote_t *remote)
{
    LOGI("remote object destroyed");

    if (remote->local != NULL) {
        remote->local->remote = NULL;
    }
    if (remote->buf != NULL) {
        buffer_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
remote_after_close_cb(uv_handle_t* handle)
{
    struct remote_t *remote = handle->data;
    --remote->release_count;
    if (remote->release_count == 0) {
        // remote_destroy(remote);
    }
}

static void
remote_close_and_free(struct remote_t *remote)
{
    if (remote != NULL) {
        remote->dying = true;

        remote->send_ctx->watcher.data = remote;
        uv_close((uv_handle_t *)&remote->send_ctx->watcher, remote_after_close_cb);
        ++remote->release_count;

        remote->recv_ctx->watcher.data = remote;
        uv_close((uv_handle_t *)&remote->recv_ctx->watcher, remote_after_close_cb);
        ++remote->release_count;

        uv_read_stop((uv_stream_t *)&remote->socket);
        remote->socket.data = remote;
        uv_close((uv_handle_t *)&remote->socket, remote_after_close_cb);
        ++remote->release_count;
    }
}

static struct local_t *
local_new_object(struct listener_t *listener)
{
    assert(listener);

    struct local_t *local = ss_malloc(sizeof(struct local_t));

    local->listener = listener;
    local->buf = buffer_alloc(BUF_SIZE);
    local->stage = STAGE_INIT;

    cork_dllist_add(&listener->connections_eden, &local->entries);
    cork_dllist_add(&all_connections, &local->entries_all);

    return local;
}

static void
listener_release(struct listener_t *listener)
{
    ss_free(listener->iface);

    for(int i = 0; i < listener->server_num; i++) {
        struct server_env_t *server_env = &listener->servers[i];

        ss_free(server_env->host);

        if(server_env->addr != server_env->addr_udp) {
            ss_free(server_env->addr_udp);
        }
        ss_free(server_env->addr);

        ss_free(server_env->psw);

        ss_free(server_env->protocol_name);
        ss_free(server_env->obfs_name);
        ss_free(server_env->protocol_param);
        ss_free(server_env->obfs_param);
        ss_free(server_env->protocol_global);
        ss_free(server_env->obfs_global);
        if(server_env->protocol_plugin){
            free_obfs_manager(server_env->protocol_plugin);
        }
        if(server_env->obfs_plugin){
            free_obfs_manager(server_env->obfs_plugin);
        }
        ss_free(server_env->id);
        ss_free(server_env->group);

        enc_release(&server_env->cipher);
    }
    ss_free(listener);
}

static void
listener_check_and_free(struct listener_t *listener)
{
    int i;

    if(listener == current_listener) {
        return;
    }
    // if this connection is created from an inactive listener, then we need to free the listener
    // when the last connection of that listener is colsed
    if(!cork_dllist_is_empty(&listener->connections_eden)) {
        return;
    }

    for(i = 0; i < listener->server_num; i++) {
        if(!cork_dllist_is_empty(&listener->servers[i].connections)) {
            return;
        }
    }

    // No connections anymore
    cork_dllist_remove(&listener->entries);
    listener_release(listener);
}

static void
local_destroy(struct local_t *local)
{
    struct listener_t *listener = local->listener;
    struct server_env_t *server_env = local->server_env;

    cork_dllist_remove(&local->entries);
    cork_dllist_remove(&local->entries_all);

    if (local->remote != NULL) {
        local->remote->local = NULL;
    }
    if (local->buf != NULL) {
        buffer_free(local->buf);
    }

    if(server_env) {
        if (local->e_ctx != NULL) {
            enc_ctx_release(&server_env->cipher, local->e_ctx);
            ss_free(local->e_ctx);
        }
        if (local->d_ctx != NULL) {
            enc_ctx_release(&server_env->cipher, local->d_ctx);
            ss_free(local->d_ctx);
        }
        // SSR beg
        if (server_env->obfs_plugin) {
            server_env->obfs_plugin->dispose(local->obfs);
            local->obfs = NULL;
        }
        if (server_env->protocol_plugin) {
            server_env->protocol_plugin->dispose(local->protocol);
            local->protocol = NULL;
        }
        // SSR end
    }

    ss_free(local);

    // after free server, we need to check the listener
    listener_check_and_free(listener);
}

static void
local_after_close_cb(uv_handle_t* handle)
{
    struct local_t *local = cork_container_of(handle, struct local_t, socket);

    --local->release_count;
    LOGI("local->release_count %d", local->release_count);
    if (local->release_count <= 0) {
        local_destroy(local);
    }
}

static void
local_close_and_free(struct local_t *local)
{
    if (local != NULL) {
        local->dying = true;

        uv_read_stop((uv_stream_t *)&local->socket);
        uv_close((uv_handle_t *)&local->socket, local_after_close_cb);

        ++local->release_count;
    }
}

static void
tunnel_close_and_free(struct remote_t *remote, struct local_t *local)
{
    remote_close_and_free(remote);
    local_close_and_free(local);
}

static struct remote_t *
remote_object_with_addr(struct listener_t *listener, struct sockaddr *addr)
{
    uv_loop_t *loop = listener->socket.loop;
    struct remote_t *remote = remote_new_object(loop, listener->timeout);

#ifdef SET_INTERFACE
    if (listener->iface) {
        if (setinterface(uv_stream_fd(&remote->socket), listener->iface) == -1) {
            ERROR("setinterface");
        }
    }
#endif

    size_t addr_len = get_sockaddr_len(addr);
    remote->addr_len = addr_len;
    memcpy(&(remote->addr), addr, addr_len);

    return remote;
}

static void
signal_cb(uv_signal_t* handle, int signum)
{
    switch (signum) {
        case SIGINT:
        case SIGTERM:
#ifndef __MINGW32__
        case SIGUSR1:
#endif
            keep_resolving = 0;
            uv_stop(handle->loop);
            break;
        default:
            assert(0);
            break;
    }
}

void
accept_cb(uv_stream_t* server, int status)
{
    struct listener_t *listener = cork_container_of(server, struct listener_t, socket);

    assert(status == 0);

    struct local_t *local = local_new_object(listener);

    int r = uv_tcp_init(server->loop, &local->socket);
    if (r != 0) {
        LOGE("uv_tcp_init error: %s\n", uv_strerror(r));
        return;
    }

    r = uv_accept(server, (uv_stream_t*)&local->socket);
    if (r != 0) {
        LOGE("uv_accept: %s\n", uv_strerror(r));
        return;
    }

    uv_read_start((uv_stream_t*)&local->socket, on_alloc, local_recv_cb);
}

static void
init_obfs(struct server_env_t *env, const char *protocol, const char *protocol_param, const char *obfs, const char *obfs_param)
{
    env->protocol_name = ss_strdup(protocol);
    env->protocol_param = ss_strdup(protocol_param);
    env->protocol_plugin = new_obfs_manager(protocol);
    env->obfs_name = ss_strdup(obfs);
    env->obfs_param = ss_strdup(obfs_param);
    env->obfs_plugin = new_obfs_manager(obfs);

    if (env->obfs_plugin) {
        env->obfs_global = env->obfs_plugin->init_data();
    }
    if (env->protocol_plugin) {
        env->protocol_global = env->protocol_plugin->init_data();
    }
}

#ifndef LIB_ONLY
int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags    = 0;
    int mtu          = 0;
    int mptcp        = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *protocol = NULL; // SSR
    char *protocol_param = NULL; // SSR
    char *method = NULL;
    char *obfs = NULL; // SSR
    char *obfs_param = NULL; // SSR
    char *pid_path = NULL;
    char *conf_path = NULL;
    char *iface = NULL;
    int remote_num = 0;
    char *hostnames[MAX_REMOTE_NUM] = {NULL};
    struct ss_host_port remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;
    int use_new_listener = 0;
    jconf_t *conf = NULL;

    struct ss_host_port tunnel_addr = { .host = NULL, .port = NULL };
    char *tunnel_addr_str = NULL;

    int option_index                    = 0;
    static struct option long_options[] = {
            { "fast-open", no_argument,       0, 0 },
            { "acl",       required_argument, 0, 0 },
            { "mtu",       required_argument, 0, 0 },
            { "mptcp",     no_argument,       0, 0 },
            { "help",      no_argument,       0, 0 },
            { "host",      required_argument, 0, 0 },
            { 0,           0,                 0, 0 },
    };

    opterr = 0;

    USE_TTY();

#ifdef ANDROID
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:L:a:n:P:xhuUvVA6"
                            "O:o:G:g:",
                            long_options, &option_index)) != -1)
#else
    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:i:c:b:L:a:n:huUvA6"
                            "O:o:G:g:",
                            long_options, &option_index)) != -1)
#endif
    {
        switch (c) {
            case 0:
                if (option_index == 0) {
                    fast_open = 1;
                } else if (option_index == 1) {
                    LOGI("initializing acl...");
                    acl = !init_acl(optarg);
                } else if (option_index == 2) {
                    mtu = atoi(optarg);
                    LOGI("set MTU to %d", mtu);
                } else if (option_index == 3) {
                    mptcp = 1;
                    LOGI("enable multipath TCP");
                } else if (option_index == 4) {
                    usage();
                    exit(EXIT_SUCCESS);
                } else if (option_index == 5) {
                    hostnames[remote_num] = optarg;
                }
                break;
            case 's':
                if (remote_num < MAX_REMOTE_NUM) {
                    remote_addr[remote_num].host   = optarg;
                    remote_addr[remote_num++].port = NULL;
                }
                break;
            case 'p':
                remote_port = optarg;
                break;
            case 'l':
                local_port = optarg;
                break;
            case 'k':
                password = optarg;
                break;
            case 'f':
                pid_flags = 1;
                pid_path  = optarg;
                break;
            case 't':
                timeout = optarg;
                break;
                // SSR beg
            case 'O':
                protocol = optarg;
                break;
            case 'm':
                method = optarg;
                break;
            case 'o':
                obfs = optarg;
                break;
            case 'G':
                protocol_param = optarg;
                break;
            case 'g':
                obfs_param = optarg;
                break;
                // SSR end
            case 'c':
                conf_path = optarg;
                break;
            case 'i':
                iface = optarg;
                break;
            case 'b':
                local_addr = optarg;
                break;
            case 'L':
                tunnel_addr_str = optarg;
                break;
            case 'a':
                user = optarg;
                break;
#ifdef HAVE_SETRLIMIT
            case 'n':
            nofile = atoi(optarg);
            break;
#endif
            case 'u':
                mode = TCP_AND_UDP;
                break;
            case 'U':
                mode = UDP_ONLY;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
            case 'A':
                LOGI("The 'A' argument is deprecate! Ignored.");
                break;
            case '6':
                ipv6first = 1;
                break;
#ifdef ANDROID
            case 'V':
                vpn = 1;
                break;
            case 'P':
                prefix = optarg;
                break;
            case 'x':
                log_tx_rx = 1;
                break;
#endif
            case '?':
                // The option character is not recognized.
                LOGE("Unrecognized option: %s", optarg);
                opterr = 1;
                break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = DEFAULT_CONF_PATH;
        }
    }

    if (conf_path != NULL) {
        conf = read_jconf(conf_path);
        if(conf->conf_ver != CONF_VER_LEGACY){
            use_new_listener = 1;
        } else {
            if (remote_num == 0) {
                remote_num = conf->server_legacy.remote_num;
                for (i = 0; i < remote_num; i++) {
                    remote_addr[i] = conf->server_legacy.remote_addr[i];
                }
            }
            if (remote_port == NULL) {
                remote_port = conf->server_legacy.remote_port;
            }
            if (local_addr == NULL) {
                local_addr = conf->server_legacy.local_addr;
            }
            if (local_port == NULL) {
                local_port = conf->server_legacy.local_port;
            }
            if (password == NULL) {
                password = conf->server_legacy.password;
            }
            // SSR beg
            if (protocol == NULL) {
                protocol = conf->server_legacy.protocol;
                LOGI("protocol %s", protocol);
            }
            if (protocol_param == NULL) {
                protocol_param = conf->server_legacy.protocol_param;
                LOGI("protocol_param %s", protocol_param);
            }
            if (method == NULL) {
                method = conf->server_legacy.method;
                LOGI("method %s", method);
            }
            if (obfs == NULL) {
                obfs = conf->server_legacy.obfs;
                LOGI("obfs %s", obfs);
            }
            if (obfs_param == NULL) {
                obfs_param = conf->server_legacy.obfs_param;
                LOGI("obfs_param %s", obfs_param);
            }
            // SSR end
        }

        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (tunnel_addr_str == NULL) {
            tunnel_addr_str = conf->tunnel_address;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
    }
    if (protocol && strcmp(protocol, "verify_sha1") == 0) {
        LOGI("The verify_sha1 protocol is deprecate! Fallback to origin protocol.");
        protocol = NULL;
    }

    if (remote_num == 0 || remote_port == NULL ||
        #ifndef HAVE_LAUNCHD
        local_port == NULL ||
        #endif
        password == NULL) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (method == NULL) {
        method = "rc4-md5";
    }

    if (timeout == NULL) {
        timeout = "60";
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

    if (pid_flags) {
        USE_SYSLOG(argv[0]);
        daemonize(pid_path);
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }
    srand((unsigned int)time(NULL));

    // parse tunnel addr
    if (tunnel_addr_str) {
        parse_addr(tunnel_addr_str, &tunnel_addr);
    }

#ifdef __MINGW32__
    winsock_init();
#endif

    // Setup listeners
    struct listener_t *listener = (struct listener_t *)ss_malloc(sizeof(struct listener_t));

    cork_dllist_init(&listener->connections_eden);

    listener->timeout = atoi(timeout) * SECONDS_PER_MINUTE;
    listener->iface = ss_strdup(iface);
    listener->mptcp = mptcp;
    listener->tunnel_addr = tunnel_addr;

    if(use_new_listener) {
        char port[6];

        ss_server_new_1_t *servers = &conf->server_new_1;
        listener->server_num = servers->server_num;
        for(i = 0; i < servers->server_num; i++) {
            struct server_env_t *serv = &listener->servers[i];
            ss_server_t *serv_cfg = &servers->servers[i];

            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));

            char *host = serv_cfg->server;
            snprintf(port, sizeof(port), "%d", serv_cfg->server_port);
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }

            serv->addr = serv->addr_udp = storage;
            serv->addr_len = serv->addr_udp_len = (int) get_sockaddr_len((struct sockaddr *) storage);
            serv->port = serv->udp_port = serv_cfg->server_port;

            // set udp port
            if (serv_cfg->server_udp_port != 0 && serv_cfg->server_udp_port != serv_cfg->server_port) {
                storage = ss_malloc(sizeof(struct sockaddr_storage));
                snprintf(port, sizeof(port), "%d", serv_cfg->server_udp_port);
                if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                    FATAL("failed to resolve the provided hostname");
                }
                serv->addr_udp = storage;
                serv->addr_udp_len = (int) get_sockaddr_len((struct sockaddr *) storage);
                serv->udp_port = serv_cfg->server_udp_port;
            }
            serv->host = ss_strdup(host);
            if (hostnames[i]) {
                serv->hostname = hostnames[i];
            }
            // Setup keys
            LOGI("initializing ciphers... %s", serv_cfg->method);
            enc_init(&serv->cipher, serv_cfg->password, serv_cfg->method);
            serv->psw = ss_strdup(serv_cfg->password);
            if (serv_cfg->protocol && strcmp(serv_cfg->protocol, "verify_sha1") == 0) {
                ss_free(serv_cfg->protocol);
            }

            cork_dllist_init(&serv->connections);

            // init obfs
            init_obfs(serv, serv_cfg->protocol, serv_cfg->protocol_param, serv_cfg->obfs, serv_cfg->obfs_param);

            serv->enable = serv_cfg->enable;
            serv->id = ss_strdup(serv_cfg->id);
            serv->group = ss_strdup(serv_cfg->group);
            serv->udp_over_tcp = serv_cfg->udp_over_tcp;
        }
    } else {
        listener->server_num = remote_num;
        for(i = 0; i < remote_num; i++) {
            struct server_env_t *serv = &listener->servers[i];
            char *host = remote_addr[i].host;
            char *port = remote_addr[i].port ? remote_addr[i].port : remote_port;

            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }
            serv->host = ss_strdup(host);
            if (hostnames[i]) {
                serv->hostname = hostnames[i];
            }
            serv->addr = serv->addr_udp = storage;
            serv->addr_len = serv->addr_udp_len = (int) get_sockaddr_len((struct sockaddr *)storage);
            serv->port = serv->udp_port = atoi(port);

            // Setup keys
            LOGI("initializing ciphers... %s", method);
            enc_init(&serv->cipher, password, method);
            serv->psw = ss_strdup(password);

            cork_dllist_init(&serv->connections);

            // init obfs
            init_obfs(serv, protocol, protocol_param, obfs, obfs_param);

            serv->enable = 1;
        }
    }

    // Init listeners
    cork_dllist_init(&inactive_listeners);
    current_listener = listener;

    uv_loop_t *loop = uv_default_loop();

    // Setup signal handler
    uv_signal_t sigint_watcher;
    uv_signal_t sigterm_watcher;
    uv_signal_init(loop, &sigint_watcher);
    uv_signal_init(loop, &sigterm_watcher);
    uv_signal_start(&sigint_watcher, signal_cb, SIGINT);
    uv_signal_start(&sigterm_watcher, signal_cb, SIGTERM);

    struct listener_t *listen_ctx = current_listener;

    uv_tcp_t *listener_socket = &listen_ctx->socket;

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
#ifdef HAVE_LAUNCHD
        listenfd = launch_or_create(local_addr, local_port, loop, listener_socket);
#else
        listenfd = create_and_bind(local_addr, local_port, loop, listener_socket);
#endif
        if (listenfd != 0) {
            FATAL("bind() error");
        }

        if (uv_listen((uv_stream_t*)listener_socket, 128, accept_cb) != 0) {
            FATAL("listen() error");
        }
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        init_udprelay(loop, local_addr, local_port, (struct sockaddr*)listen_ctx->servers[0].addr_udp,
                      listen_ctx->servers[0].addr_udp_len, tunnel_addr, mtu, listen_ctx->timeout, listener->iface, &listen_ctx->servers[0].cipher, listen_ctx->servers[0].protocol_name, listen_ctx->servers[0].protocol_param);
    }

#ifdef HAVE_LAUNCHD
    if (local_port == NULL) {
        LOGI("listening through launchd");
    } else
#endif
    {
        if (strcmp(local_addr, ":") > 0) {
            LOGI("listening at [%s]:%s", local_addr, local_port);
        } else {
            LOGI("listening at %s:%s", local_addr, local_port);
        }
    }
    // setuid
    if (user != NULL && ! run_as(user)) {
        FATAL("failed to switch user");
    }

#ifndef __MINGW32__
    if (geteuid() == 0){
        LOGI("running from root user");
    }
#endif

    cork_dllist_init(&all_connections);

    free_jconf(conf);

    // Enter the loop
    uv_run(listener_socket->loop, UV_RUN_DEFAULT);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (mode != TCP_ONLY) {
        free_udprelay(); // udp relay use some data from listener, so we need to release udp first
    }

    if (mode != UDP_ONLY) {
        // uv_stop(listener_socket->loop);
        free_connections(); // after this, all inactive listener should be released already, so we only need to release the current_listener
        listener_release(current_listener);
    }

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return 0;
}

#else

int
start_ss_local_server(struct config_t listener)
{
    srand(time(NULL));

    char *remote_host = listener.remote_host;
    char *local_addr  = listener.local_addr;
    char *method      = listener.method;
    char *password    = listener.password;
    char *log         = listener.log;
    int remote_port   = listener.remote_port;
    int local_port    = listener.local_port;
    int timeout       = listener.timeout;
    int mtu           = 0;
    int mptcp         = 0;

    struct ss_host_port tunnel_addr = { .host = NULL, .port = NULL };

    mode      = listener.mode;
    fast_open = listener.fast_open;
    verbose   = listener.verbose;
    mtu       = listener.mtu;
    mptcp     = listener.mptcp;

    char local_port_str[16];
    char remote_port_str[16];
    sprintf(local_port_str, "%d", local_port);
    sprintf(remote_port_str, "%d", remote_port);

    USE_LOGFILE(log);

    if (listener.acl != NULL) {
        acl = !init_acl(listener.acl);
    }

    if (local_addr == NULL) {
        local_addr = "127.0.0.1";
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    struct ev_signal sigint_watcher;
    struct ev_signal sigterm_watcher;
    ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ev_signal_start(EV_DEFAULT, &sigint_watcher);
    ev_signal_start(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
    struct ev_signal sigusr1_watcher;
    ev_signal_init(&sigusr1_watcher, signal_cb, SIGUSR1);
    ev_signal_start(EV_DEFAULT, &sigusr1_watcher);
#endif

    struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
    memset(storage, 0, sizeof(struct sockaddr_storage));
    if (get_sockaddr(remote_host, remote_port_str, storage, 0, ipv6first) == -1) {
        return -1;
    }

    // Setup proxy context
    struct ev_loop *loop = EV_DEFAULT;

    struct listener_t listen_ctx;
    listen_ctx.server_num     = 1;
    struct server_env_t *serv = &listen_ctx.servers[0];
    ss_server_t server_cfg;
    ss_server_t *serv_cfg = &server_cfg;
    server_cfg.protocol = 0;
    server_cfg.protocol_param = 0;
    server_cfg.obfs = 0;
    server_cfg.obfs_param = 0;
    serv->addr = serv->addr_udp = storage;
    serv->addr_len = serv->addr_udp_len = get_sockaddr_len((struct sockaddr *) storage);
    listen_ctx.timeout        = timeout;
    listen_ctx.iface          = NULL;
    listen_ctx.mptcp          = mptcp;

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
        listenfd = create_and_bind(local_addr, local_port_str);
        if (listenfd == -1) {
            ERROR("bind()");
            return -1;
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            ERROR("listen()");
            return -1;
        }
        setnonblocking(listenfd);

        listen_ctx.fd = listenfd;

        ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx.io);
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        init_udprelay(loop, local_addr, local_port_str, (struct sockaddr*)listen_ctx.servers[0].addr_udp,
                      listen_ctx.servers[0].addr_udp_len, tunnel_addr, mtu, listen_ctx.timeout, listen_ctx.iface, &listen_ctx.servers[0].cipher, listen_ctx.servers[0].protocol_name, listen_ctx.servers[0].protocol_param);
    }

    if (strcmp(local_addr, ":") > 0) {
        LOGI("listening at [%s]:%s", local_addr, local_port_str);
    } else {
        LOGI("listening at %s:%s", local_addr, local_port_str);
    }

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    enc_init(&serv->cipher, password, method);

    // init obfs
    init_obfs(serv, serv_cfg->protocol, serv_cfg->protocol_param, serv_cfg->obfs, serv_cfg->obfs_param);

    // Init connections
    cork_dllist_init(&serv->connections);

    cork_dllist_init(&inactive_listeners); //

    // Enter the loop
    ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (mode != TCP_ONLY) {
        free_udprelay();
    }

    if (mode != UDP_ONLY) {
        ev_io_stop(loop, &listen_ctx.io);
        free_connections(loop);
        close(listen_ctx.fd);
    }

    ss_free(serv->addr);

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    ev_signal_stop(EV_DEFAULT, &sigterm_watcher);
#ifndef __MINGW32__
    ev_signal_stop(EV_DEFAULT, &sigusr1_watcher);
#endif

    // cannot reach here
    return 0;
}

#endif
