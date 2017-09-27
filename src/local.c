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
#include "utils.h"
#include "socks5.h"
#include "acl.h"
#include "http.h"
#include "tls.h"
#include "local.h"

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

static void server_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0);
static void server_send_cb(uv_write_t* req, int status);
static void remote_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0);
static void remote_send_cb(uv_write_t* req, int status);

static void remote_timeout_cb(uv_timer_t *handle);

static struct remote_t *create_remote(struct listen_ctx_t *profile, struct sockaddr *addr);
static void free_remote(struct remote_t *remote);
static void close_and_free_remote(struct remote_t *remote);
static void free_server(struct server_t *server);
static void close_and_free_server(struct server_t *server);

static struct remote_t *new_remote(uv_loop_t *loop, int timeout);
static struct server_t *new_server(struct listen_ctx_t *profile);

static struct cork_dllist inactive_profiles;
static struct listen_ctx_t *current_profile;
static struct cork_dllist all_connections;


void doAllocBuffer(size_t suggested_size, uv_buf_t *buf) {
    buf->base = calloc(suggested_size, sizeof(char));
    buf->len = suggested_size;
}

void doDeallocBuffer(uv_buf_t *buf) {
    free(buf->base);
    buf->base = NULL;
    buf->len = 0;
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    doAllocBuffer(suggested_size, buf);
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

void
remote_send_stop_n_server_recv_start(struct server_t* server, struct remote_t* remote)
{
    //ev_io_stop(EV_A_ & remote->send_ctx->io);
    uv_read_start((uv_stream_t *)&server->socket, on_alloc, server_recv_cb); //ev_io_start(EV_A_ & server->recv_ctx->io);
}

void
remote_recv_stop_n_server_send_start(struct server_t* server, struct remote_t* remote)
{
    uv_read_stop((uv_stream_t *)&remote->socket); //ev_io_stop(EV_A_ & remote->recv_ctx->io);
    //ev_io_start(EV_A_ & server->send_ctx->io);
}

void
server_recv_stop_n_remote_send_start(struct server_t* server, struct remote_t* remote)
{
    uv_read_stop((uv_stream_t *)&server->socket); //ev_io_stop(EV_A_ & server->recv_ctx->io);
    //ev_io_start(EV_A_ & remote->send_ctx->io);
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

        /*
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        int err = set_reuseport(listen_sock);
        if (err == 0) {
            LOGI("tcp port reuse enabled");
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            // We managed to bind successfully!
            break;
        } else {
            ERROR("bind");
        }

        close(listen_sock);
         */
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
        struct server_t *server = cork_container_of(curr, struct server_t, entries_all);
        struct remote_t *remote = server->remote;
        close_and_free_remote(remote);
        close_and_free_server(server);
    }
}

static void
remote_connected_cb(uv_connect_t* req, int status)
{
    struct remote_t *remote = cork_container_of(req, struct remote_t, connect);
    if (status == 0) {
        // wait on remote connected event
        server_recv_stop_n_remote_send_start(remote->server, remote);
        uv_timer_start(&remote->send_ctx->watcher, remote_timeout_cb, remote->send_ctx->watcher_interval * 1000, 0); // ev_timer_start(NULL, &remote->send_ctx->watcher);
    } else {
        close_and_free_remote(remote);
        close_and_free_server(remote->server);
    }
}

static void
server_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0)
{
    struct server_t *server = cork_container_of(stream, struct server_t, socket);
    struct remote_t *remote = server->remote;
    struct buffer_t *buf;

    if (remote == NULL) {
        buf = server->buf;
    } else {
        buf = remote->buf;
    }

    if (nread == UV_EOF) {
        // connection closed
        close_and_free_remote(remote);
        close_and_free_server(server);
        return;
    } else if (nread == 0) {
        // http://docs.libuv.org/en/v1.x/stream.html
        //if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
    } else if (nread < 0) {
            if (verbose) {
                ERROR("server recieve callback for recv");
            }
            close_and_free_remote(remote);
            close_and_free_server(server);
            return;
    }

    assert(nread <= (ssize_t)(BUF_SIZE - buf->len));

    memcpy(buf->buffer + buf->len, buf0->base, (size_t)nread);
    buf->len += nread;

    doDeallocBuffer((uv_buf_t *)buf0);

    if (server->stage == STAGE_INIT) {
        char *host = server->listener->tunnel_addr.host;
        char *port = server->listener->tunnel_addr.port;
        if (host && port) {
            char buffer[BUF_SIZE] = { 0 };
            size_t header_len = 0;
            struct socks5_request *hdr =
                    build_socks5_request(host, (uint16_t)atoi(port), buffer, sizeof(buffer), &header_len);

            memmove(buf->buffer + header_len, buf->buffer, buf->len);
            memmove(buf->buffer, hdr, header_len);
            buf->len += header_len;

            server->stage = STAGE_PARSE;
        }
    }
    while (1) {
        // local socks5 server
        if (server->stage == STAGE_STREAM) {
            if (remote == NULL) {
                LOGE("invalid remote");
                close_and_free_server(server);
                return;
            }

            // insert shadowsocks header
            {
                struct server_env_t *server_env = server->server_env;
                // SSR beg
                struct obfs_manager *protocol_plugin = server_env->protocol_plugin;
                struct buffer_t *buf = remote->buf;

                if (protocol_plugin && protocol_plugin->client_pre_encrypt) {
                    buf->len = (size_t) protocol_plugin->client_pre_encrypt(server->protocol, &buf->buffer, (int)buf->len, &buf->capacity);
                }
                int err = ss_encrypt(&server_env->cipher, buf, server->e_ctx, BUF_SIZE);

                if (err) {
                    LOGE("server invalid password or cipher");
                    close_and_free_remote(remote);
                    close_and_free_server(server);
                    return;
                }

                struct obfs_manager *obfs_plugin = server_env->obfs_plugin;
                if (obfs_plugin && obfs_plugin->client_encode) {
                    buf->len = obfs_plugin->client_encode(server->obfs, &buf->buffer, buf->len, &buf->capacity);
                }
                // SSR end
#ifdef ANDROID
                if (log_tx_rx) {
                    tx += buf->len;
                }
#endif
            }

            if (!remote->send_ctx_connected) {
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
                            close_and_free_remote(NULL, remote);
                            close_and_free_server(server);
                            return;
                        }
                    }
                }
#endif

                remote->buf->idx = 0;

                {
                    struct sockaddr *addr = (struct sockaddr*)&(remote->addr);
                    uv_tcp_connect(&remote->connect, &remote->socket, addr, remote_connected_cb);

                    /*
                    // connecting, wait until connected
                    int r = connect(remote->fd, (struct sockaddr *)&(remote->direct_addr.addr), remote->direct_addr.addr_len);

                    if (r == -1 && errno != CONNECT_IN_PROGRESS) {
                        ERROR("connect");
                        close_and_free_remote(remote);
                        close_and_free_server(server);
                        return;
                    }

                    // wait on remote connected event
                    server_recv_stop_n_remote_send_start(server, remote);
                    ev_timer_start(NULL, &remote->send_ctx->watcher);
                     */
                    return;
                }
            } else {
                if (nread > 0 && remote->buf->len == 0) {
                    remote->buf->idx = 0;
                    uv_read_stop((uv_stream_t *)&server->socket); //ev_io_stop(EV_A_ & server->recv_ctx->io);
                    return;
                }
                uv_buf_t tmp = uv_buf_init((char *)remote->buf->buffer, (unsigned int)remote->buf->len);
                uv_write(&remote->write_req, (uv_stream_t *)&remote->socket, &tmp, 1, remote_send_cb);
                /*
                int s = send(remote->fd, remote->buf->buffer, remote->buf->len, 0);
                if (s == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // no data, wait for send
                        remote->buf->idx = 0;
                        server_recv_stop_n_remote_send_start(NULL, server, remote);
                        return;
                    } else {
                        ERROR("server recieve callback for send");
                        close_and_free_remote(NULL, remote);
                        close_and_free_server(server);
                        return;
                    }
                } else if (s < (int)(remote->buf->len)) {
                    remote->buf->len -= s;
                    remote->buf->idx  = s;
                    server_recv_stop_n_remote_send_start(NULL, server, remote);
                    return;
                } else {
                    remote->buf->idx = 0;
                    remote->buf->len = 0;
                }
                 */
            }

            // all processed
            return;
        } else if (server->stage == STAGE_INIT) {
            struct method_select_request *request = (struct method_select_request *)buf->buffer;

            char buffer[BUF_SIZE] = { 0 };
            struct method_select_response *response =
                    build_socks5_method_select_response(SOCKS5_METHOD_NOAUTH, buffer, sizeof(buffer));

            //send(server->fd, response, sizeof(*response), 0);
            uv_buf_t tmp = uv_buf_init((char *)response, sizeof(*response));
            uv_write(&server->write_req, (uv_stream_t*)&server->socket, &tmp, 1, server_send_cb);

            server->stage = STAGE_HANDSHAKE;

            int off = (request->nmethods & 0xff) + sizeof(*request);
            if ((request->ver == SOCKS5_VERSION) && (off < (int)(buf->len))) {
                memmove(buf->buffer, buf->buffer + off, buf->len - off);
                buf->len -= off;
                continue;
            }

            buf->len = 0;

            return;
        } else if (server->stage == STAGE_HANDSHAKE || server->stage == STAGE_PARSE) {
            struct socks5_request *request = (struct socks5_request *)buf->buffer;

            struct sockaddr_in sock_addr = { 0 };

            int udp_assc = 0;

            if (request->cmd == SOCKS5_COMMAND_UDPASSOC) {
                udp_assc = 1;
                socklen_t addr_len = sizeof(sock_addr);
                getsockname(server->socket.u.fd, (struct sockaddr *)&sock_addr, &addr_len);
                if (verbose) {
                    LOGI("udp assc request accepted");
                }
            } else if (request->cmd != SOCKS5_COMMAND_CONNECT) {
                LOGE("unsupported cmd: %d", request->cmd);
                char buffer[BUF_SIZE] = { 0 };
                size_t size = 0;
                struct socks5_response *response =
                        build_socks5_response(SOCKS5_REPLY_CMDUNSUPP, SOCKS5_ADDRTYPE_IPV4,
                                              &sock_addr, buffer, sizeof(buffer), &size);

                //send(server->fd, response, size, 0);
                uv_buf_t tmp = uv_buf_init((char *)response, (unsigned int)size);
                uv_write(&server->write_req, (uv_stream_t*)&server->socket, &tmp, 1, server_send_cb);

                close_and_free_remote(remote);
                close_and_free_server(server);
                return;
            }

            // Fake reply
            if (server->stage == STAGE_HANDSHAKE) {
                char buffer[BUF_SIZE] = { 0 };
                size_t size = 0;
                struct socks5_response *response =
                        build_socks5_response(SOCKS5_REPLY_SUCCESS, SOCKS5_ADDRTYPE_IPV4,
                                              &sock_addr, buffer, sizeof(buffer), &size);

                //ssize_t s = send(server->fd, response, size, 0);
                uv_buf_t tmp = uv_buf_init((char *)response, (unsigned int)size);
                int s = uv_try_write((uv_stream_t*)&server->socket, &tmp, 1);

                if (s < (ssize_t) size) {
                    LOGE("failed to send fake reply");
                    close_and_free_remote(remote);
                    close_and_free_server(server);
                    return;
                }
                if (udp_assc) {
                    // Wait until client closes the connection
                    return;
                }
            }

            char host[257], ip[INET6_ADDRSTRLEN], port[16];

            struct buffer_t ss_addr_to_send;
            struct buffer_t *abuf = &ss_addr_to_send;
            buffer_alloc(abuf, BUF_SIZE);

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
                close_and_free_remote(remote);
                close_and_free_server(server);
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
                    server->stage = STAGE_PARSE;
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

            server->stage = STAGE_STREAM;

            buf->len -= (3 + abuf_len);
            if (buf->len > 0) {
                memmove(buf->buffer, buf->buffer + 3 + abuf_len, buf->len);
            }

            if (acl) {
                if (outbound_block_match_host(host) == 1) {
                    if (verbose) {
                        LOGI("outbound blocked %s", host);
                    }
                    close_and_free_remote(remote);
                    close_and_free_server(server);
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
                        err = get_sockaddr(host, port, &storage, 0, ipv6first);
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
                        close_and_free_remote(remote);
                        close_and_free_server(server);
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
                        remote = create_remote(server->listener, (struct sockaddr *)&storage);
                    }
                }
            }

            // Not match ACL
            if (remote == NULL) {
                // pick a server
                struct listen_ctx_t *profile = server->listener;
                int index = rand() % profile->server_num;
                struct server_env_t *server_env = &profile->servers[index];

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

                server->server_env = server_env;

                remote = create_remote(profile, (struct sockaddr *) server_env->addr);
            }

            if (remote == NULL) {
                buffer_free(abuf);
                LOGE("invalid remote addr");
                close_and_free_server(server);
                return;
            }

            {
                struct server_env_t *server_env = server->server_env;

                // expelled from eden
                cork_dllist_remove(&server->entries);
                cork_dllist_add(&server_env->connections, &server->entries);

                // init server cipher
                if (server_env->cipher.enc_method > TABLE) {
                    server->e_ctx = ss_malloc(sizeof(struct enc_ctx));
                    server->d_ctx = ss_malloc(sizeof(struct enc_ctx));
                    enc_ctx_init(&server_env->cipher, server->e_ctx, 1);
                    enc_ctx_init(&server_env->cipher, server->d_ctx, 0);
                } else {
                    server->e_ctx = NULL;
                    server->d_ctx = NULL;
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
                server_info.iv = server->e_ctx->cipher_ctx.iv;
                server_info.iv_len = enc_get_iv_len(&server_env->cipher);
                server_info.key = enc_get_key(&server_env->cipher);
                server_info.key_len = enc_get_key_len(&server_env->cipher);
                server_info.tcp_mss = 1452;
                server_info.buffer_size = BUF_SIZE;
                server_info.cipher_env = &server_env->cipher;

                if (server_env->obfs_plugin) {
                    server->obfs = server_env->obfs_plugin->new_obfs();
                    server_env->obfs_plugin->set_server_info(server->obfs, &server_info);
                }

                server_info.param = server_env->protocol_param;
                server_info.g_data = server_env->protocol_global;

                if (server_env->protocol_plugin) {
                    server->protocol = server_env->protocol_plugin->new_obfs();
                    server_info.overhead = server_env->protocol_plugin->get_overhead(server->protocol)
                        + (server_env->obfs_plugin ? server_env->obfs_plugin->get_overhead(server->obfs) : 0);
                    server_env->protocol_plugin->set_server_info(server->protocol, &server_info);
                }
                // SSR end

                size_t total_len = abuf->len + buf->len;
                buffer_realloc(remote->buf, total_len, BUF_SIZE);
                remote->buf->len = total_len;

                memcpy(remote->buf->buffer, abuf->buffer, abuf->len);
                if (buf->len > 0) {
                    memcpy(remote->buf->buffer + abuf->len, buf->buffer, buf->len);
                }
            }

            server->remote = remote;
            remote->server = server;

            buffer_free(abuf);
        }
    }
}

static void
server_send_cb(uv_write_t* req, int status)
{
    struct server_t *server = cork_container_of(req, struct server_t, write_req);
    struct remote_t *remote = server->remote;

    //assert(status == 0);
    if (status == UV_EAGAIN) {
        // no data, wait for send
        server->buf->idx = 0;
        remote_recv_stop_n_server_send_start(server, remote);
    } else if (status < 0) {
        LOGE("server_send_cb: %s", uv_strerror(status));
        close_and_free_remote(remote);
        close_and_free_server(server);
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
remote_timeout_cb(uv_timer_t *handle)
{
    struct remote_ctx_t *remote_ctx
        = cork_container_of(handle, struct remote_ctx_t, watcher);

    struct remote_t *remote = remote_ctx->remote;
    struct server_t *server = remote->server;

    if (verbose) {
        LOGI("TCP connection timeout");
    }

    close_and_free_remote(remote);
    close_and_free_server(server);
}

static void
remote_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0)
{
    //struct remote_ctx_t *remote_recv_ctx = cork_container_of(w, struct remote_ctx_t, io);
    //struct remote_t *remote = remote_recv_ctx->remote;
    struct remote_t *remote = cork_container_of(stream, struct remote_t, socket);
    struct server_t *server = remote->server;
    struct server_env_t *server_env = server->server_env;

    uv_timer_again(&remote->recv_ctx->watcher); // ev_timer_again(NULL, & remote->recv_ctx->watcher);

#ifdef ANDROID
    stat_update_cb();
#endif

    //ssize_t r = recv(remote->fd, server->buf->buffer, BUF_SIZE, 0);

    if (nread == UV_EOF) {
        // connection closed
        close_and_free_remote(remote);
        close_and_free_server(server);
        return;
    } else if (nread == 0) {
        //if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
    } else if (nread < 0) {
        if (verbose) {
            ERROR("remote_recv_cb_recv");
        }
            close_and_free_remote(remote);
            close_and_free_server(server);
            return;
    }

    assert(nread <= (ssize_t)BUF_SIZE);

    memcpy(server->buf->buffer, buf0->base, (size_t)nread);
    server->buf->len = (size_t) nread;

    doDeallocBuffer((uv_buf_t *)buf0);

    {
#ifdef ANDROID
        if (log_tx_rx) {
            rx += server->buf->len;
        }
#endif
        if ( nread == 0 ) {
            return;
        }
        // SSR beg
        if (server_env->obfs_plugin) {
            struct obfs_manager *obfs_plugin = server_env->obfs_plugin;
            if (obfs_plugin->client_decode) {
                int needsendback;
                server->buf->len = obfs_plugin->client_decode(server->obfs, &server->buf->buffer, server->buf->len, &server->buf->capacity, &needsendback);
                if ((int)server->buf->len < 0) {
                    LOGE("client_decode");
                    close_and_free_remote(remote);
                    close_and_free_server(server);
                    return;
                }
                if (needsendback) {
                    if (obfs_plugin->client_encode) {
                        remote->buf->len = obfs_plugin->client_encode(server->obfs, &remote->buf->buffer, 0, &remote->buf->capacity);
                        uv_buf_t tmp = uv_buf_init(remote->buf->buffer, (unsigned int)remote->buf->len);
                        uv_write(&remote->write_req, (uv_stream_t *)&remote->socket, &tmp, 1, remote_send_cb);
                        /*
                        ssize_t s = send(remote->fd, remote->buf->buffer, remote->buf->len, 0);
                        if (s == -1) {
                            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                                ERROR("remote_recv_cb_send");
                                // close and free
                                close_and_free_remote(NULL, remote);
                                close_and_free_server(server);
                            }
                            return;
                        } else if (s < (ssize_t)(remote->buf->len)) {
                            // partly sent, move memory, wait for the next time to send
                            remote->buf->len -= s;
                            remote->buf->idx += s;
                            return;
                        } else {
                            // all sent out, wait for reading
                            remote->buf->len = 0;
                            remote->buf->idx = 0;
                            remote_send_stop_n_server_recv_start(EV_A_ server, remote);
                        }
                         */
                    }
                }
            }
        }
        if (server->buf->len > 0) {
            int err = ss_decrypt(&server_env->cipher, server->buf, server->d_ctx, BUF_SIZE);
            if (err) {
                LOGE("remote invalid password or cipher");
                close_and_free_remote(remote);
                close_and_free_server(server);
                return;
            }
        }
        if (server_env->protocol_plugin) {
            struct obfs_manager *protocol_plugin = server_env->protocol_plugin;
            if (protocol_plugin->client_post_decrypt) {
                server->buf->len = (size_t) protocol_plugin->client_post_decrypt(server->protocol, &server->buf->buffer, (int)server->buf->len, &server->buf->capacity);
                if ((int)server->buf->len < 0) {
                    LOGE("client_post_decrypt");
                    close_and_free_remote(remote);
                    close_and_free_server(server);
                    return;
                }
                if ( server->buf->len == 0 ) {
                    return;
                }
            }
        }
        // SSR end
    }

    // TODO: uv_try_write instead of uv_write

    uv_buf_t buf = uv_buf_init(server->buf->buffer, (unsigned int)server->buf->len);
    int s = uv_write(&server->write_req, (uv_stream_t*)&server->socket, &buf, 1, server_send_cb);
    if (s != 0) {
        close_and_free_remote(remote);
        close_and_free_server(server);
    }

    /*
    int s = send(server->fd, server->buf->buffer, server->buf->len, 0);
    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            remote_recv_stop_n_server_send_start(EV_A_ server, remote);
        } else {
            ERROR("remote_recv_cb_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        }
    } else if (s < (int)(server->buf->len)) {
        server->buf->len -= s;
        server->buf->idx  = (size_t)s;
        remote_recv_stop_n_server_send_start(EV_A_ server, remote);
    }
     */
}

static void
remote_send_cb(uv_write_t* req, int status)
{
    struct remote_t *remote = cork_container_of(req, struct remote_t, write_req);
    struct server_t *server = remote->server;
    struct buffer_t *buf = remote->buf;

    if (status != 0) {
        close_and_free_remote(remote);
        close_and_free_server(server);
        return;
    }

    buf->len = 0;

    if (!remote->send_ctx_connected) {
        int err_no = 0;
        socklen_t len = sizeof(err_no);
        int r = getsockopt(remote->socket.u.fd, SOL_SOCKET, SO_ERROR, (char *)&err_no, &len);
        if (r == 0 && err_no == 0) {
            remote->send_ctx_connected = 1;
            uv_timer_stop(&remote->send_ctx->watcher); // ev_timer_stop(NULL, & remote->send_ctx->watcher);
            uv_timer_start(&remote->recv_ctx->watcher, remote_timeout_cb, remote->recv_ctx->watcher_interval * 1000, 0); // ev_timer_start(NULL, & remote->recv_ctx->watcher);
            uv_read_start((uv_stream_t *)&remote->socket, on_alloc, remote_recv_cb); // ev_io_start(EV_A_ & remote->recv_ctx->io);

            // no need to send any data
            if (buf->len == 0) {
                remote_send_stop_n_server_recv_start(server, remote);
                return;
            }
        } else {
            // not connected
            LOGE("getsockopt error code %d %d", r, err_no);
            ERROR("getsockopt");
            close_and_free_remote(remote);
            close_and_free_server(server);
            return;
        }
    } else {
        buf->len = 0;
        buf->idx = 0;
        remote_send_stop_n_server_recv_start(server, remote);
    }

    /*
    if (buf->len == 0) {
        // close and free
        close_and_free_remote(NULL, remote);
        close_and_free_server(server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, buf->buffer + buf->idx, buf->len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_cb_send");
                // close and free
                close_and_free_remote(NULL, remote);
                close_and_free_server(server);
            }
            return;
        } else if (s < (ssize_t)(buf->len)) {
            // partly sent, move memory, wait for the next time to send
            buf->len -= s;
            buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            buf->len = 0;
            buf->idx = 0;
            remote_send_stop_n_server_recv_start(EV_A_ server, remote);
        }
    }
     */
}

static struct remote_t *
new_remote(uv_loop_t *loop, int timeout)
{
    struct remote_t *remote = ss_malloc(sizeof(struct remote_t));

    uv_tcp_init(loop, &remote->socket);

    remote->buf                 = ss_malloc(sizeof(struct buffer_t));
    remote->recv_ctx            = ss_malloc(sizeof(struct remote_ctx_t));
    remote->send_ctx            = ss_malloc(sizeof(struct remote_ctx_t));
    buffer_alloc(remote->buf, BUF_SIZE);
    //remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    //ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    //ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);

    int timeMax = min(MAX_CONNECT_TIMEOUT, timeout);
    //ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb, timeMax, 0);
    //ev_timer_init(&remote->recv_ctx->watcher, remote_timeout_cb, timeout, timeout);
    uv_timer_init(loop, &remote->send_ctx->watcher);
    remote->send_ctx->watcher_interval = (uint64_t) timeMax;

    uv_timer_init(loop, &remote->recv_ctx->watcher);
    remote->recv_ctx->watcher_interval = (uint64_t) timeout;

    return remote;
}

static void
free_remote(struct remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        buffer_free(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
remote_after_close_cb(uv_handle_t* handle)
{
    struct remote_t *remote = cork_container_of(handle, struct remote_t, socket);
    free_remote(remote);
}

static void
close_and_free_remote(struct remote_t *remote)
{
    if (remote != NULL) {
        uv_timer_stop(&remote->send_ctx->watcher); //ev_timer_stop(EV_A_ & remote->send_ctx->watcher);
        uv_timer_stop(&remote->recv_ctx->watcher); //ev_timer_stop(EV_A_ & remote->recv_ctx->watcher);
        //ev_io_stop(EV_A_ & remote->send_ctx->io);
        uv_read_stop((uv_stream_t *)&remote->socket); //ev_io_stop(EV_A_ & remote->recv_ctx->io);
        uv_close((uv_handle_t *)&remote->socket, remote_after_close_cb); // close(remote->fd);
        //free_remote(remote);
    }
}

static struct server_t *
new_server(struct listen_ctx_t *profile)
{
    assert(profile);

    struct server_t *server = ss_malloc(sizeof(struct server_t));

    server->listener = profile;
    server->buf                 = ss_malloc(sizeof(struct buffer_t));
    buffer_alloc(server->buf, BUF_SIZE);
    server->stage               = STAGE_INIT;

    //ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);

    cork_dllist_add(&profile->connections_eden, &server->entries);
    cork_dllist_add(&all_connections, &server->entries_all);

    return server;
}

static void
release_profile(struct listen_ctx_t *profile)
{
    int i;

    ss_free(profile->iface);

    for(i = 0; i < profile->server_num; i++) {
        struct server_env_t *server_env = &profile->servers[i];

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
    ss_free(profile);
}

static void
check_and_free_profile(struct listen_ctx_t *profile)
{
    int i;

    if(profile == current_profile) {
        return;
    }
    // if this connection is created from an inactive profile, then we need to free the profile
    // when the last connection of that profile is colsed
    if(!cork_dllist_is_empty(&profile->connections_eden)) {
        return;
    }

    for(i = 0; i < profile->server_num; i++) {
        if(!cork_dllist_is_empty(&profile->servers[i].connections)) {
            return;
        }
    }

    // No connections anymore
    cork_dllist_remove(&profile->entries);
    release_profile(profile);
}

static void
free_server(struct server_t *server)
{
    struct listen_ctx_t *profile = server->listener;
    struct server_env_t *server_env = server->server_env;

    cork_dllist_remove(&server->entries);
    cork_dllist_remove(&server->entries_all);

    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->buf != NULL) {
        buffer_free(server->buf);
        ss_free(server->buf);
    }

    if(server_env) {
        if (server->e_ctx != NULL) {
            enc_ctx_release(&server_env->cipher, server->e_ctx);
            ss_free(server->e_ctx);
        }
        if (server->d_ctx != NULL) {
            enc_ctx_release(&server_env->cipher, server->d_ctx);
            ss_free(server->d_ctx);
        }
        // SSR beg
        if (server_env->obfs_plugin) {
            server_env->obfs_plugin->dispose(server->obfs);
            server->obfs = NULL;
        }
        if (server_env->protocol_plugin) {
            server_env->protocol_plugin->dispose(server->protocol);
            server->protocol = NULL;
        }
        // SSR end
    }

    ss_free(server);

    // after free server, we need to check the profile
    check_and_free_profile(profile);
}

static void
server_after_close_cb(uv_handle_t* handle)
{
    struct server_t *server = cork_container_of(handle, struct server_t, socket);
    free_server(server);
}

static void
close_and_free_server(struct server_t *server)
{
    if (server != NULL) {
        uv_read_stop((uv_stream_t *)&server->socket); //ev_io_stop(EV_A_ & server->recv_ctx->io);
        uv_close((uv_handle_t *)&server->socket, server_after_close_cb); //close(server->fd);
        //free_server(server);
    }
}

static struct remote_t *
create_remote(struct listen_ctx_t *profile, struct sockaddr *addr)
{
    uv_loop_t *loop = profile->listen_socket.loop;
    struct remote_t *remote = new_remote(loop, profile->timeout);

    /*
    int remotefd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

    if (remotefd == -1) {
        ERROR("socket");
        return NULL;
    }

    int opt = 1;
    setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    if (profile->mptcp == 1) {
        int err = setsockopt(remotefd, SOL_TCP, MPTCP_ENABLED, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable multipath TCP");
        }
    }

    // Setup
    setnonblocking(remotefd);
    */
#ifdef SET_INTERFACE
    if (profile->iface) {
        if (setinterface(remote->socket.u.fd, profile->iface) == -1) {
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
    //if (revents & EV_SIGNAL) {
        switch (signum) {
        case SIGINT:
        case SIGTERM:
#ifndef __MINGW32__
        case SIGUSR1:
#endif
            keep_resolving = 0;
            uv_stop(handle->loop); // ev_unloop(EV_A_ EVUNLOOP_ALL);
        default:
            assert(0);
        }
    //}
    exit(EXIT_SUCCESS);
}

void
accept_cb(uv_stream_t* server, int status)
{
    struct listen_ctx_t *listener = cork_container_of(server, struct listen_ctx_t, listen_socket);

    assert(status == 0);

    struct server_t *local_server = new_server(listener);

    int r = uv_tcp_init(server->loop, &local_server->socket);
    if (r != 0) {
        LOGE("uv_tcp_init error: %s\n", uv_strerror(r));
        return;
    }

    r = uv_accept(server, (uv_stream_t*)&local_server->socket);
    if (r) {
        LOGE("uv_accept: %s\n", uv_strerror(r));
        return;
    }

    uv_read_start((uv_stream_t*)&local_server->socket, on_alloc, server_recv_cb);

    /*
    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    struct server_t *server = new_server(serverfd, listener);

    ev_io_start(EV_A_ & server->recv_ctx->io);
     */
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
    ss_host_port remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;
    int use_new_profile = 0;
    jconf_t *conf = NULL;

    ss_host_port tunnel_addr = { .host = NULL, .port = NULL };
    char *tunnel_addr_str = NULL;

    int option_index                    = 0;
    static struct option long_options[] = {
            { "fast-open", no_argument,       0, 0 },
            { "acl",       required_argument, 0, 0 },
            { "mtu",       required_argument, 0, 0 },
            { "mptcp",     no_argument,       0, 0 },
            { "help",      no_argument,       0, 0 },
            { "host",      required_argument, 0, 0 },
            {           0,                 0, 0, 0 }
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
            use_new_profile = 1;
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

    // Setup profiles
    struct listen_ctx_t *profile = (struct listen_ctx_t *)ss_malloc(sizeof(struct listen_ctx_t));

    cork_dllist_init(&profile->connections_eden);

    profile->timeout = atoi(timeout);
    profile->iface = ss_strdup(iface);
    profile->mptcp = mptcp;
    profile->tunnel_addr = tunnel_addr;

    if(use_new_profile) {
        char port[6];

        ss_server_new_1_t *servers = &conf->server_new_1;
        profile->server_num = servers->server_num;
        for(i = 0; i < servers->server_num; i++) {
            struct server_env_t *serv = &profile->servers[i];
            ss_server_t *serv_cfg = &servers->servers[i];

            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));

            char *host = serv_cfg->server;
            snprintf(port, sizeof(port), "%d", serv_cfg->server_port);
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }

            serv->addr = serv->addr_udp = storage;
            serv->addr_len = serv->addr_udp_len = get_sockaddr_len((struct sockaddr *) storage);
            serv->port = serv->udp_port = serv_cfg->server_port;

            // set udp port
            if (serv_cfg->server_udp_port != 0 && serv_cfg->server_udp_port != serv_cfg->server_port) {
                storage = ss_malloc(sizeof(struct sockaddr_storage));
                snprintf(port, sizeof(port), "%d", serv_cfg->server_udp_port);
                if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                    FATAL("failed to resolve the provided hostname");
                }
                serv->addr_udp = storage;
                serv->addr_udp_len = get_sockaddr_len((struct sockaddr *) storage);
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
        profile->server_num = remote_num;
        for(i = 0; i < remote_num; i++) {
            struct server_env_t *serv = &profile->servers[i];
            char *host = remote_addr[i].host;
            char *port = remote_addr[i].port ? : remote_port;

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

    // Init profiles
    cork_dllist_init(&inactive_profiles);
    current_profile = profile;

    uv_loop_t *loop = uv_default_loop();

    // Setup signal handler
    uv_signal_t sigint_watcher; // struct ev_signal sigint_watcher;
    uv_signal_t sigterm_watcher; // struct ev_signal sigterm_watcher;
    uv_signal_init(loop, &sigint_watcher); // ev_signal_init(&sigint_watcher, signal_cb, SIGINT);
    uv_signal_init(loop, &sigterm_watcher); // ev_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    uv_signal_start(&sigint_watcher, signal_cb, SIGINT); // ev_signal_start(EV_DEFAULT, &sigint_watcher);
    uv_signal_start(&sigterm_watcher, signal_cb, SIGTERM); // ev_signal_start(EV_DEFAULT, &sigterm_watcher);

    //struct ev_loop *loop = EV_DEFAULT;

    struct listen_ctx_t *listen_ctx = current_profile;

    uv_tcp_t *server = &listen_ctx->listen_socket;

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
#ifdef HAVE_LAUNCHD
        listenfd = launch_or_create(local_addr, local_port, loop, server);
#else
        listenfd = create_and_bind(local_addr, local_port, loop, server);
#endif
        if (listenfd != 0) {
            FATAL("bind() error");
        }

        if (uv_listen((uv_stream_t*)server, 128, accept_cb) != 0) {
            FATAL("listen() error");
        }

        /*
        if (listen(listenfd, SOMAXCONN) == -1) {
            FATAL("listen() error");
        }
        setnonblocking(listenfd);

        listen_ctx->fd = listenfd;

        ev_io_init(&listen_ctx->io, accept_cb, listenfd, EV_READ);
        ev_io_start(loop, &listen_ctx->io);
         */
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        init_udprelay(local_addr, local_port, (struct sockaddr*)listen_ctx->servers[0].addr_udp,
                      listen_ctx->servers[0].addr_udp_len, tunnel_addr, mtu, listen_ctx->timeout, profile->iface, &listen_ctx->servers[0].cipher, listen_ctx->servers[0].protocol_name, listen_ctx->servers[0].protocol_param);
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
    uv_run(server->loop, UV_RUN_DEFAULT); // ev_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (mode != TCP_ONLY) {
        free_udprelay(); // udp relay use some data from profile, so we need to release udp first
    }

    if (mode != UDP_ONLY) {
        uv_stop(server->loop); // ev_io_stop(loop, &listen_ctx->io);
        free_connections(); // after this, all inactive profile should be released already, so we only need to release the current_profile
        release_profile(current_profile);
    }

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    //ev_signal_stop(EV_DEFAULT, &sigint_watcher);
    //ev_signal_stop(EV_DEFAULT, &sigterm_watcher);

    return 0;
}

#else

int
start_ss_local_server(struct config_t profile)
{
    srand(time(NULL));

    char *remote_host = profile.remote_host;
    char *local_addr  = profile.local_addr;
    char *method      = profile.method;
    char *password    = profile.password;
    char *log         = profile.log;
    int remote_port   = profile.remote_port;
    int local_port    = profile.local_port;
    int timeout       = profile.timeout;
    int mtu           = 0;
    int mptcp         = 0;

    ss_host_port tunnel_addr = { .host = NULL, .port = NULL };

    mode      = profile.mode;
    fast_open = profile.fast_open;
    verbose   = profile.verbose;
    mtu       = profile.mtu;
    mptcp     = profile.mptcp;

    char local_port_str[16];
    char remote_port_str[16];
    sprintf(local_port_str, "%d", local_port);
    sprintf(remote_port_str, "%d", remote_port);

    USE_LOGFILE(log);

    if (profile.acl != NULL) {
        acl = !init_acl(profile.acl);
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

    struct listen_ctx_t listen_ctx;
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
        init_udprelay(local_addr, local_port_str, (struct sockaddr*)listen_ctx.servers[0].addr_udp,
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

    cork_dllist_init(&inactive_profiles); //

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
