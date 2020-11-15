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

#if defined(USE_CRYPTO_OPENSSL)
#include <openssl/opensslv.h>
#define USING_CRYPTO OPENSSL_VERSION_TEXT
#elif defined(USE_CRYPTO_MBEDTLS)
#define USING_CRYPTO "MBEDTLS_VERSION_TEXT"
#endif

#if !defined(__MINGW32__) && !defined(_WIN32)
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

#include <assert.h>
#include <uv.h>

#ifdef __MINGW32__
#include "win32.h"
#endif

#include "ssrutils.h"
#include "socks5.h"
#include "http.h"
#include "tls.h"
#include "local.h"
#include "udprelay.h"
#include "ssrbuffer.h"
#include "sockaddr_universal.h"
#include "ssr_executive.h"

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

int verbose = 0;
int keep_resolving = 1;

#ifdef ANDROID
int log_tx_rx  = 0;
int vpn        = 0;
uint64_t tx    = 0;
uint64_t rx    = 0;
uint64_t last = 0;
char *prefix;
#endif

#include "includeobfs.h" // I don't want to modify makefile
#include "jconf.h"
#include "local_api.h"

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
static void local_send_data(struct local_t *local, const char *data, unsigned int size);
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

static struct listener_t *current_listener;


void do_alloc_uv_buffer(size_t suggested_size, uv_buf_t *buf) {
    char *tmp = (char *) calloc(suggested_size, sizeof(char));
    *buf = uv_buf_init(tmp, (unsigned int)suggested_size);
}

void do_dealloc_uv_buffer(uv_buf_t *buf) {
    free(buf->base);
    buf->base = NULL;
    buf->len = 0;
}

static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    (void)handle;
    do_alloc_uv_buffer(suggested_size, buf);
}

#if !defined(__MINGW32__) && !defined(_WIN32)
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

static int uv_stream_fd(const uv_tcp_t *handle) {
#if defined(_WIN32)
    return (int) handle->socket;
#elif defined(__APPLE__)
    int uv___stream_fd(const uv_stream_t* handle);
    return uv___stream_fd((const uv_stream_t *)handle);
#else
    return (handle)->io_watcher.fd;
#endif
}

static uint16_t get_socket_port(const uv_tcp_t *tcp) {
    union sockaddr_universal tmp = { {0} };
    int len = sizeof(tmp);
    if (uv_tcp_getsockname(tcp, &tmp.addr, &len) != 0) {
        return 0;
    } else {
        return ntohs(tmp.addr4.sin_port);
    }
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
create_and_bind(const char *addr, unsigned short port, uv_loop_t *loop, uv_tcp_t *tcp)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result = NULL, *rp;
    int s, listen_sock = 0;
    char str_port[256] = { 0 };

    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    sprintf(str_port, "%d", port);

    s = getaddrinfo(addr, str_port, &hints, &result);
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
        LOGE("%s", "Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, unsigned short port, uv_loop_t *loop, uv_tcp_t *tcp)
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
        //if (port == NULL) {
        //    usage(VERSION, USING_CRYPTO);
        //    exit(EXIT_FAILURE);
        //}
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
    // TODO: release activate connections.
    // foreach: tunnel_close_and_free(remote, local);
}

int _tunnel_encrypt(struct local_t *local, struct buffer_t *buf) {
    struct server_env_t *env;
    struct obfs_t *protocol_plugin;
    int err;
    struct obfs_t *obfs_plugin;
    size_t capacity = buffer_get_capacity(buf);

    assert(capacity >= SSR_BUFF_SIZE);

    env = local->server_env;
    // SSR beg
    protocol_plugin = local->protocol;

    if (protocol_plugin && protocol_plugin->client_pre_encrypt) {
        size_t buf_len = 0;
        uint8_t *buf_buffer = (uint8_t *) buffer_raw_clone(buf, &malloc, &buf_len, &capacity);
        buf_len = (size_t)protocol_plugin->client_pre_encrypt(
            local->protocol, (char **)&buf_buffer, (int)buf_len, &capacity);
        buffer_store(buf, buf_buffer, buf_len);
        free(buf_buffer);
    }
    err = ss_encrypt(env->cipher, buf, local->e_ctx, SSR_BUFF_SIZE);
    if (err != 0) {
        return -1;
    }

    obfs_plugin = local->obfs;
    if (obfs_plugin && obfs_plugin->client_encode) {
        struct buffer_t *tmp = obfs_plugin->client_encode(local->obfs, buf);
        buffer_replace(buf, tmp); buffer_release(tmp);
    }
    // SSR end
    return 0;
}

int _tunnel_decrypt(struct local_t *local, struct buffer_t *buf, struct buffer_t **feedback)
{
    struct server_env_t *env;
    struct obfs_t *obfs_plugin;
    struct obfs_t *protocol_plugin;

    assert(buffer_get_length(buf) <= SSR_BUFF_SIZE);

    env = local->server_env;

    // SSR beg
    obfs_plugin = local->obfs;
    if (obfs_plugin && obfs_plugin->client_decode) {
        bool needsendback = 0;
        struct buffer_t *tmp = obfs_plugin->client_decode(local->obfs, buf, &needsendback);
        if (tmp == NULL) {
            return -1;
        }
        buffer_replace(buf, tmp); buffer_release(tmp);
        if (needsendback && obfs_plugin->client_encode) {
            struct buffer_t *empty = buffer_create_from((const uint8_t *)"", 0);
            struct buffer_t *sendback = obfs_plugin->client_encode(local->obfs, empty);
            assert(feedback);
            *feedback = sendback;
            buffer_release(empty);
        }
    }
    if (buffer_get_length(buf) > 0) {
        int err = ss_decrypt(env->cipher, buf, local->d_ctx, SSR_BUFF_SIZE);
        if (err != 0) {
            return -1;
        }
    }
    protocol_plugin = local->protocol;
    if (protocol_plugin && protocol_plugin->client_post_decrypt) {
        ssize_t len;
        size_t buf_len = 0, capacity;
        uint8_t *buf_buffer = (uint8_t *) buffer_raw_clone(buf, &malloc, &buf_len, &capacity);
        len = (size_t)protocol_plugin->client_post_decrypt(
            local->protocol, (char **)&buf_buffer, (int)buf_len, &capacity);
        if (len < 0) {
            free(buf_buffer);
            return -1;
        }
        buffer_store(buf, buf_buffer, (size_t)len);
        free(buf_buffer);
    }
    // SSR end
    return 0;
}


static void
local_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0)
{
    struct local_t *local = CONTAINER_OF(stream, struct local_t, socket);
    struct remote_t *remote = local->remote;
    struct buffer_t *buf = NULL;

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
        buffer_store(buf, (const uint8_t*)buf0->base, (size_t)nread);
    }

    do_dealloc_uv_buffer((uv_buf_t *)buf0);

    if (nread <= 0) {
        if (nread < 0) {
            if (nread != UV_EOF) {
                LOGE("local_recv_cb \"%s\"", uv_strerror((int)nread));
            }
            tunnel_close_and_free(remote, local);
        }
        return;
    }

    if (local->stage == STAGE_INIT) {
        char *host = local->listener->tunnel_addr.host;
        char *port = local->listener->tunnel_addr.port;
        if (host && port) {
            uint8_t *buffer = (uint8_t *) calloc(SSR_BUFF_SIZE, sizeof(*buffer));
            size_t header_len = 0;
            struct socks5_request *hdr =
                build_socks5_request(host, (uint16_t)atoi(port), buffer, SSR_BUFF_SIZE, &header_len);

            buffer_insert(buf, 0, (uint8_t*)hdr, header_len);

            free(buffer);

            local->stage = STAGE_PARSE;
        }
    }
    while (1) {
        // local socks5 server
        if (local->stage == STAGE_STREAM) {
            int r;

            assert(remote);

            // insert shadowsocks header
            r = _tunnel_encrypt(local, remote->buf);
            if (r < 0) {
                LOGE("%s", "local invalid password or cipher");
                tunnel_close_and_free(remote, local);
                return;
            }
#ifdef ANDROID
            if (log_tx_rx) {
                tx += buffer_get_length(buf);
            }
#endif
            if (!remote->connected) {
                uv_connect_t *connect;
                struct sockaddr *addr;
#ifdef ANDROID
                if (vpn) {
                    int not_protect = 0;
                    if (remote->addr.addr4.sin_family == AF_INET) {
                        struct sockaddr_in *s = (struct sockaddr_in *)&remote->addr.addr4;
                        if (s->sin_addr.s_addr == inet_addr("127.0.0.1")) {
                            not_protect = 1;
                        }
                    }
                    if (!not_protect) {
                        if (protect_socket( uv_stream_fd(&remote->socket)) == -1) {
                            SS_ERROR("protect_socket");
                            tunnel_close_and_free(remote, local);
                            return;
                        }
                    }
                }
#endif
                local_read_stop(local);

                connect = (uv_connect_t *)calloc(1, sizeof(uv_connect_t));
                connect->data = remote;

                addr = (struct sockaddr*)&(remote->addr);
                uv_tcp_connect(connect, &remote->socket, addr, remote_connected_cb);
                return;
            } else {
                if (buffer_get_length(remote->buf) == 0) {
                    local_read_stop(local);
                    return;
                }
                remote_send_data(remote);
            }

            // all processed
            return;
        } else if (local->stage == STAGE_INIT) {
            int off;
            size_t buf_len;
            const uint8_t *buf_buffer = buffer_get_data(buf, &buf_len);
            struct method_select_request *request = (struct method_select_request *)buf_buffer;

            uint8_t *buffer = (uint8_t *) calloc(SSR_BUFF_SIZE, sizeof(*buffer));
            struct method_select_response *response =
                build_socks5_method_select_response(SOCKS5_METHOD_NOAUTH, (char *)buffer, SSR_BUFF_SIZE);

            local_send_data(local, (char *)response, sizeof(*response));

            free(buffer);

            local->stage = STAGE_HANDSHAKE;

            off = (request->nmethods & 0xff) + (sizeof(*request) - 1);
            if ((request->ver == SOCKS5_VERSION) && (off < (int)(buf_len))) {
                buffer_shortened_to(buf, off, buf_len - off);
                continue;
            }

            buffer_reset(buf);

            return;
        } else if (local->stage == STAGE_HANDSHAKE || local->stage == STAGE_PARSE) {
            struct socks5_request *request = (struct socks5_request *) buffer_get_data(buf, NULL);

            struct sockaddr_in sock_addr = { 0 };

            int udp_assc = 0;
            char host[257], ip[INET6_ADDRSTRLEN], port[16];
            uint8_t *abuf_buffer;
            char addr_type;
            uint8_t *addr_n_port;
            size_t abuf_len;
            int sni_detected;

            if (request->cmd == SOCKS5_COMMAND_UDPASSOC) {
                socklen_t addr_len;
                udp_assc = 1;
                addr_len = sizeof(sock_addr);
                getsockname(uv_stream_fd(&local->socket), (struct sockaddr *)&sock_addr, &addr_len);
                if (verbose) {
                    LOGI("%s", "udp assc request accepted");
                }
            } else if (request->cmd != SOCKS5_COMMAND_CONNECT) {
                uint8_t *buffer = (uint8_t *) calloc(SSR_BUFF_SIZE, sizeof(*buffer));
                size_t size = 0;
                struct socks5_response *response =
                    build_socks5_response(SOCKS5_REPLY_CMDUNSUPP, SOCKS5_ADDRTYPE__IPV4,
                    &sock_addr, buffer, SSR_BUFF_SIZE, &size);

                LOGE("unsupported cmd: 0x%02X", (uint8_t)request->cmd);

                local_send_data(local, (char *)response, (unsigned int)size);

                free(buffer);

                tunnel_close_and_free(remote, local);
                return;
            }

            // Fake reply
            if (local->stage == STAGE_HANDSHAKE) {
                uint8_t *buffer = (uint8_t *) calloc(SSR_BUFF_SIZE, sizeof(*buffer));
                size_t size = 0;
                struct socks5_response *response =
                    build_socks5_response(SOCKS5_REPLY_SUCCESS, SOCKS5_ADDRTYPE__IPV4,
                    &sock_addr, buffer,SSR_BUFF_SIZE, &size);

                local_send_data(local, (char *)response, (unsigned int)size);

                free(buffer);

                if (udp_assc) {
                    // Wait until client closes the connection
                    return;
                }
            }

            abuf_buffer = (uint8_t *) calloc(SSR_BUFF_SIZE, sizeof(*abuf_buffer));
            abuf_len = 0;

            addr_type = request->addr_type;

            abuf_buffer[abuf_len++] = addr_type;

            addr_n_port = request->addr_n_port;

            // get remote addr and port
            if (addr_type == SOCKS5_ADDRTYPE__IPV4) {
                // IP V4
                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(abuf_buffer + abuf_len, addr_n_port, in_addr_len + 2);
                abuf_len += in_addr_len + 2;
                /*
                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(addr_n_port + in_addr_len));
                    dns_ntop(AF_INET, (const void *)(addr_n_port), ip, INET_ADDRSTRLEN);
                    sprintf(port, "%d", p);
                }
                */
            } else if (addr_type == SOCKS5_ADDRTYPE__NAME) {
                // Domain name
                uint8_t name_len = *(uint8_t *)addr_n_port;
                abuf_buffer[abuf_len++] = name_len;
                memcpy(abuf_buffer + abuf_len, addr_n_port + 1, name_len + 2);
                abuf_len += name_len + 2;

                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(addr_n_port + 1 + name_len));
                    memcpy(host, addr_n_port + 1, name_len);
                    host[name_len] = '\0';
                    sprintf(port, "%d", p);
                }
            } else if (addr_type == SOCKS5_ADDRTYPE__IPV6) {
                // IP V6
                size_t in6_addr_len = sizeof(struct in6_addr);
                memcpy(abuf_buffer + abuf_len, addr_n_port, in6_addr_len + 2);
                abuf_len += in6_addr_len + 2;
                /*
                if (acl || verbose) {
                    uint16_t p = ntohs(*(uint16_t *)(addr_n_port + in6_addr_len));
                    dns_ntop(AF_INET6, (const void *)addr_n_port, ip, INET6_ADDRSTRLEN);
                    sprintf(port, "%d", p);
                }
                */
            } else {
                free(abuf_buffer);
                LOGE("unsupported addrtype: 0x%02X", (uint8_t)addr_type);
                tunnel_close_and_free(remote, local);
                return;
            }

            abuf_len  = abuf_len;
            sni_detected = 0;

            if (addr_type == SOCKS5_ADDRTYPE__IPV4 || addr_type == SOCKS5_ADDRTYPE__IPV6) {
                char *hostname = NULL;
                uint16_t p = ntohs(*(uint16_t *)(abuf_buffer + abuf_len - 2));
                int ret    = 0;
                if (p == http_protocol->default_port) {
                    const char *data = (const char *)(buffer_get_data(buf, NULL) + 3 + abuf_len);
                    size_t data_len  = buffer_get_length(buf)    - 3 - abuf_len;
                    ret = http_protocol->parse_packet(data, data_len, &hostname);
                } else if (p == tls_protocol->default_port) {
                    const char *data = (const char *)(buffer_get_data(buf, NULL) + 3 + abuf_len);
                    size_t data_len  = buffer_get_length(buf)    - 3 - abuf_len;
                    ret = tls_protocol->parse_packet(data, data_len, &hostname);
                }
                if (ret == -1 && buffer_get_length(buf) < SSR_BUFF_SIZE) {
                    local->stage = STAGE_PARSE;
                    free(abuf_buffer);
                    return;
                } else if (ret > 0) {
                    sni_detected = 1;

                    // Reconstruct address buffer
                    abuf_len                = 0;
                    abuf_buffer[abuf_len++] = 3;
                    abuf_buffer[abuf_len++] = ret;
                    memcpy(abuf_buffer + abuf_len, hostname, ret);
                    abuf_len += ret;
                    p          = htons(p);
                    memcpy(abuf_buffer + abuf_len, &p, 2);
                    abuf_len += 2;

                    if (acl || verbose) {
                        memcpy(host, hostname, ret);
                        host[ret] = '\0';
                    }

                    safe_free(hostname);
                } else {
                    strncpy(host, ip, sizeof(host)-1);
                }
            }

            local->stage = STAGE_STREAM;

            if (buffer_get_length(buf) >= (3 + abuf_len)) {
                buffer_shortened_to(buf, (3 + abuf_len), buffer_get_length(buf) - (3 + abuf_len));
            } else {
                buffer_reset(buf);
            }
            /*
            if (acl) {
                int host_match;
                int bypass;
                int resolved;
                struct sockaddr_storage storage;
                int err;

                if (outbound_block_match_host(host) == 1) {
                    if (verbose) {
                        LOGI("outbound blocked %s", host);
                    }
                    tunnel_close_and_free(remote, local);
                    return;
                }

                host_match = acl_match_host(host);
                bypass = 0;
                resolved = 0;
                memset(&storage, 0, sizeof(struct sockaddr_storage));

                if (verbose) {
                    LOGI("acl_match_host %s result %d", host, host_match);
                }
                if (host_match > 0) {
                    bypass = 0;                 // bypass hostnames in black list
                } else if (host_match < 0) {
                    bypass = 1;                 // proxy hostnames in white list
                } else {
                    int ip_match;
#ifndef ANDROID
                    if (addr_type == SOCKS5_ADDRTYPE__NAME) {            // resolve domain so we can bypass domain with geoip
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

                    ip_match = acl_match_host(ip);// -1 if IP in white list or 1 if IP in black list
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
                    struct sockaddr_storage storage;
                    ssize_t err;

                    if (verbose) {
                        if (sni_detected || addr_type == SOCKS5_ADDRTYPE__NAME) {
                            LOGI("bypass %s:%s", host, port);
                        } else if (addr_type == SOCKS5_ADDRTYPE__IPV4) {
                            LOGI("bypass %s:%s", ip, port);
                        } else if (addr_type == SOCKS5_ADDRTYPE__IPV6) {
                            LOGI("bypass [%s]:%s", ip, port);
                        }
                    }
                    memset(&storage, 0, sizeof(struct sockaddr_storage));
#ifndef ANDROID
                    if (addr_type == SOCKS5_ADDRTYPE__NAME && resolved != 1) {
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
            */

            // Not match ACL
            if (remote == NULL) {
                // pick a server
                struct listener_t *listener = local->listener;
                int index = rand() % listener->server_num;
                struct server_env_t *server_env = &listener->servers[index];

                if (verbose) {
                    if (sni_detected || addr_type == SOCKS5_ADDRTYPE__NAME) {
                        LOGI("connect to %s:%s via %s:%d",
                             host, port, server_env->host, server_env->port);
                    } else if (addr_type == SOCKS5_ADDRTYPE__IPV4) {
                        LOGI("connect to %s:%s via %s:%d",
                             ip, port, server_env->host, server_env->port);
                    } else if (addr_type == SOCKS5_ADDRTYPE__IPV6) {
                        LOGI("connect to [%s]:%s via %s:%d",
                             ip, port, server_env->host, server_env->port);
                    }
                }

                local->server_env = server_env;

                remote = remote_object_with_addr(listener, (struct sockaddr *) server_env->addr);
            }

            if (remote == NULL) {
                free(abuf_buffer);
                LOGE("%s", "invalid remote addr");
                tunnel_close_and_free(remote, local);
                return;
            }

            {
                struct server_env_t *server_env = local->server_env;
                struct server_info_t server_info;
                size_t total_len;

                // init server cipher
                if (cipher_env_enc_method(server_env->cipher) > ss_cipher_table) {
                    local->e_ctx = enc_ctx_new_instance(server_env->cipher, 1);
                    local->d_ctx = enc_ctx_new_instance(server_env->cipher, 0);
                } else {
                    local->e_ctx = NULL;
                    local->d_ctx = NULL;
                }
                // SSR beg
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
                server_info.head_len = get_s5_head_size(abuf_buffer, 320, 30);
                server_info.iv_len = enc_get_iv_len(server_env->cipher);
                memcpy(server_info.iv, enc_ctx_get_iv(local->e_ctx), server_info.iv_len);
                server_info.key = enc_get_key(server_env->cipher);
                server_info.key_len = enc_get_key_len(server_env->cipher);
                server_info.tcp_mss = 1452;
                server_info.buffer_size = SSR_BUFF_SIZE;
                server_info.cipher_env = server_env->cipher;

                local->obfs = obfs_instance_create(server_env->obfs_name);
                if (local->obfs) {
                    local->obfs->set_server_info(local->obfs, &server_info);
                }

                server_info.param = server_env->protocol_param;
                server_info.g_data = server_env->protocol_global;

                local->protocol = protocol_instance_create(server_env->protocol_name);
                if (local->protocol) {
                    server_info.overhead = (uint16_t)(local->protocol->get_overhead(local->protocol)
                        + (local->obfs ? local->obfs->get_overhead(local->obfs) : 0));
                    local->protocol->set_server_info(local->protocol, &server_info);
                }
                // SSR end

                total_len = abuf_len + buffer_get_length(buf);
                buffer_realloc(remote->buf, total_len * 2);

                buffer_store(remote->buf, abuf_buffer, abuf_len);
                buffer_concatenate2(remote->buf, buf);
            }

            local->remote = remote;
            remote->local = local;

            free(abuf_buffer);
            continue; // return;
        }
    } // while (1)
}

static void
local_send_cb(uv_write_t* req, int status)
{
    struct local_t *local = CONTAINER_OF(req->handle, struct local_t, socket);
    uint8_t *tmp_data = (uint8_t *) req->data;
    struct remote_t *remote;

    assert(local);
    remote = local->remote;

    free(tmp_data);
    free(req);

    if (local->dying || (remote && remote->dying) ) {
        return;
    }

    if (status < 0) {
        LOGE("local_send_cb: %s", uv_strerror(status));
        tunnel_close_and_free(remote, local);
    } else if (status == 0) {
        buffer_reset(local->buf);
    }
}

#ifdef ANDROID
static void
stat_update_cb()
{
    if (log_tx_rx) {
        uint64_t _now = uv_hrtime();
        if (_now - last > 1000) {
            send_traffic_stat(tx, rx);
            last = _now;
        }
    }
}
#endif

static void
remote_connected_cb(uv_connect_t* req, int status)
{
    struct remote_t *remote = (struct remote_t *)req->data;
    struct local_t *local;

    assert(remote);
    local = remote->local;

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
        char addr[256] = { 0 };
        int p = (int)ntohs(remote->addr.addr4.sin_port);
        uv_ip4_name(&remote->addr.addr4, addr, sizeof(addr));
        LOGE("connecting \"%s:%d\" failed because \"%s\"", addr, p, uv_strerror(status));
        tunnel_close_and_free(remote, local);
    }
}

static void
remote_timeout_cb(uv_timer_t *handle)
{
    struct remote_ctx_t *remote_ctx
        = CONTAINER_OF(handle, struct remote_ctx_t, watcher);

    struct remote_t *remote = remote_ctx->remote;
    struct local_t *local = remote->local;

    if (local==NULL || local->dying || remote->dying) {
        return;
    }

    if (verbose) {
        LOGI("%s", "TCP connection timeout");
    }

    tunnel_close_and_free(remote, local);
}

static void
remote_recv_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf0)
{
    struct remote_t *remote = CONTAINER_OF(stream, struct remote_t, socket);
    struct local_t *local;
    struct server_env_t *server_env;
    size_t FIXED_BUFF_SIZE;
    char *guard;
    char *iter;

    assert(remote);
    local = remote->local;
    server_env = local->server_env;

    (void)server_env;

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
            LOGE("remote_recv_cb \"%s\"", uv_strerror((int)nread));
            tunnel_close_and_free(remote, local);
        }
        return;
    }

    FIXED_BUFF_SIZE = SSR_BUFF_SIZE;

    buffer_realloc(local->buf, FIXED_BUFF_SIZE);

    guard = buf0->base + nread;

    iter = NULL;
    for (iter = buf0->base; iter < guard; iter += FIXED_BUFF_SIZE) {
        size_t remain = guard - iter;
        size_t len = remain > FIXED_BUFF_SIZE ? FIXED_BUFF_SIZE : remain;
        struct buffer_t *feedback;
        int r;

        buffer_store(local->buf, (const uint8_t*)iter, (size_t)len);

#ifdef ANDROID
        if (log_tx_rx) {
            rx += buffer_get_length(local->buf);
        }
#endif
        feedback = NULL;
        r = _tunnel_decrypt(local, local->buf, &feedback);
        if (feedback != NULL) {
            buffer_replace(remote->buf, feedback);
            buffer_release(feedback);

            remote_send_data(remote);
            local_read_start(local);
        }
        if (r < 0) {
            tunnel_close_and_free(remote, local);
            break;
        }
        if (buffer_get_length(local->buf) == 0) {
            continue;
        }

        local_send_data(local, (char *)buffer_get_data(local->buf, NULL), (unsigned int)buffer_get_length(local->buf));
    } // for loop

    do_dealloc_uv_buffer((uv_buf_t *)buf0);
}

static void
remote_send_cb(uv_write_t* req, int status)
{
    struct remote_t *remote = CONTAINER_OF(req->handle, struct remote_t, socket);
    uint8_t *data = (uint8_t *)req->data;
    struct local_t *local;
    struct buffer_t *buf;

    assert(data);
    assert(remote);
    local = remote->local;
    buf = remote->buf;

    free(data);
    free(req);

    if (local==NULL || local->dying || remote->dying) {
        return;
    }

    uv_timer_stop(&remote->send_ctx->watcher);

    if (status != 0) {
        tunnel_close_and_free(remote, local);
        return;
    }

    buffer_reset(buf);
}

static void
remote_send_data(struct remote_t *remote)
{
    size_t len = 0, capacity = 0;
    uint8_t *data = buffer_raw_clone(remote->buf, &malloc, &len, &capacity);
    uv_buf_t tmp = uv_buf_init((char *)data, (unsigned int)len);

    uv_write_t *write_req = (uv_write_t *)calloc(1, sizeof(uv_write_t));
    write_req->data = data;

    uv_write(write_req, (uv_stream_t *)&remote->socket, &tmp, 1, remote_send_cb);
    uv_timer_start(&remote->send_ctx->watcher, remote_timeout_cb, remote->send_ctx->watcher_interval, 0);
}

static void 
local_send_data(struct local_t *local, const char *data, unsigned int size)
{
    uv_write_t *write_req = (uv_write_t *)calloc(1, sizeof(uv_write_t));
    uint8_t *tmp_buf = (uint8_t *) calloc((size_t)size, sizeof(*tmp_buf));
    uv_buf_t buf = uv_buf_init((char*)tmp_buf, size);

    memmove(tmp_buf, data, (ssize_t)size);
    write_req->data = tmp_buf;

    uv_write(write_req, (uv_stream_t*)&local->socket, &buf, 1, local_send_cb);
}


static struct remote_t *
remote_new_object(uv_loop_t *loop, int timeout)
{
    struct remote_t *remote = (struct remote_t *)calloc(1, sizeof(struct remote_t));
    int timeMax;

    uv_tcp_init(loop, &remote->socket);

    remote->buf                 = buffer_create(SSR_BUFF_SIZE);
    remote->recv_ctx            = (struct remote_ctx_t *)calloc(1, sizeof(struct remote_ctx_t));
    remote->send_ctx            = (struct remote_ctx_t *)calloc(1, sizeof(struct remote_ctx_t));
    remote->recv_ctx->remote    = remote;
    remote->send_ctx->remote    = remote;

    timeMax = min(CONNECT_TIMEOUT_MAX * MILLISECONDS_PER_SECOND, timeout);
    uv_timer_init(loop, &remote->send_ctx->watcher);
    remote->send_ctx->watcher_interval = (uint64_t) timeMax;

    uv_timer_init(loop, &remote->recv_ctx->watcher);
    remote->recv_ctx->watcher_interval = (uint64_t) timeout;

    return remote;
}

static void
remote_destroy(struct remote_t *remote)
{
    //LOGI("remote object destroyed");

    if (remote->local != NULL) {
        remote->local->remote = NULL;
    }
    if (remote->buf != NULL) {
        buffer_release(remote->buf);
    }
    safe_free(remote->recv_ctx);
    safe_free(remote->send_ctx);
    safe_free(remote);
}

static void
remote_close_done_cb(uv_handle_t* handle)
{
    struct remote_t *remote = (struct remote_t *) handle->data;
    --remote->ref_count;
    if (remote->ref_count == 0) {
        remote_destroy(remote);
    }
}

static void
remote_close_and_free(struct remote_t *remote)
{
    if (remote != NULL) {
        remote->dying = true;

        remote->send_ctx->watcher.data = remote;
        uv_close((uv_handle_t *)&remote->send_ctx->watcher, remote_close_done_cb);
        ++remote->ref_count;

        remote->recv_ctx->watcher.data = remote;
        uv_close((uv_handle_t *)&remote->recv_ctx->watcher, remote_close_done_cb);
        ++remote->ref_count;

        uv_read_stop((uv_stream_t *)&remote->socket);
        remote->socket.data = remote;
        uv_close((uv_handle_t *)&remote->socket, remote_close_done_cb);
        ++remote->ref_count;
    }
}

static struct local_t *
local_new_object(struct listener_t *listener)
{
    struct local_t *local;

    assert(listener);

    local = (struct local_t *) calloc(1, sizeof(struct local_t));

    local->listener = listener;
    local->buf = buffer_create(SSR_BUFF_SIZE);
    local->stage = STAGE_INIT;

    return local;
}

static void
listener_release(struct listener_t *listener)
{
    size_t i = 0;
    safe_free(listener->iface);
    for(i = 0; i < listener->server_num; i++) {
        struct server_env_t *server_env = &listener->servers[i];

        safe_free(server_env->host);

        if(server_env->addr != server_env->addr_udp) {
            safe_free(server_env->addr_udp);
        }
        safe_free(server_env->addr);

        safe_free(server_env->psw);

        safe_free(server_env->protocol_name);
        safe_free(server_env->obfs_name);
        safe_free(server_env->protocol_param);
        safe_free(server_env->obfs_param);
        safe_free(server_env->protocol_global);
        safe_free(server_env->obfs_global);
        safe_free(server_env->id);
        safe_free(server_env->group);

        cipher_env_release(server_env->cipher);
    }
    safe_free(listener);
}

static void
local_destroy(struct local_t *local)
{
    struct listener_t *listener = local->listener;
    struct server_env_t *server_env = local->server_env;

    (void)listener;
    // LOGI("local object destroyed");

    if (local->remote != NULL) {
        local->remote->local = NULL;
    }
    if (local->buf != NULL) {
        buffer_release(local->buf);
    }

    if(server_env) {
        if (local->e_ctx != NULL) {
            enc_ctx_release_instance(server_env->cipher, local->e_ctx);
        }
        if (local->d_ctx != NULL) {
            enc_ctx_release_instance(server_env->cipher, local->d_ctx);
        }
    }

    // SSR beg
    obfs_instance_destroy(local->obfs);
    local->obfs = NULL;

    obfs_instance_destroy(local->protocol);
    local->protocol = NULL;
    // SSR end

    safe_free(local);
}

static void
local_close_done_cb(uv_handle_t* handle)
{
    struct local_t *local = (struct local_t *) handle->data;

    --local->ref_count;
    if (local->ref_count == 0) {
        local_destroy(local);
    }
}

static void
local_close_and_free(struct local_t *local)
{
    if (local != NULL) {
        local->dying = true;

        local_read_stop(local);
        local->socket.data = local;
        uv_close((uv_handle_t *)&local->socket, local_close_done_cb);

        ++local->ref_count;
    }
}

static void
tunnel_close_and_free(struct remote_t *remote, struct local_t *local)
{
    remote_close_and_free(remote);
    local_close_and_free(local);
}

static size_t get_sockaddr_len(struct sockaddr* addr) {
    if (addr->sa_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}

static struct remote_t *
remote_object_with_addr(struct listener_t *listener, struct sockaddr *addr)
{
    uv_loop_t *loop = listener->socket.loop;
    struct remote_t *remote = remote_new_object(loop, listener->timeout);

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
#if !defined(__MINGW32__) && !defined(_WIN32)
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
    struct listener_t *listener = CONTAINER_OF(server, struct listener_t, socket);
    struct local_t *local;
    int r;

    assert(status == 0);

    local = local_new_object(listener);

    r = uv_tcp_init(server->loop, &local->socket);
    if (r != 0) {
        LOGE("uv_tcp_init error: %s\n", uv_strerror(r));
        return;
    }

    r = uv_accept(server, (uv_stream_t*)&local->socket);
    if (r != 0) {
        LOGE("uv_accept: %s\n", uv_strerror(r));
        return;
    }

    local_read_start(local);
}

static void
init_obfs(struct server_env_t *env, const char *protocol, const char *protocol_param, const char *obfs, const char *obfs_param)
{
    struct obfs_t *obfs_plugin;
    struct obfs_t *protocol_plugin;
    env->protocol_name = ss_strdup(protocol);
    env->protocol_param = ss_strdup(protocol_param);
    env->obfs_name = ss_strdup(obfs);
    env->obfs_param = ss_strdup(obfs_param);

    obfs_plugin = obfs_instance_create(obfs);
    if (obfs_plugin) {
        env->obfs_global = obfs_plugin->generate_global_init_data();
        obfs_instance_destroy(obfs_plugin);
    }

    protocol_plugin = protocol_instance_create(protocol);
    if (protocol_plugin) {
        env->protocol_global = protocol_plugin->generate_global_init_data();
        obfs_instance_destroy(protocol_plugin);
    }
}

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
    struct ss_host_port remote_addr[MAX_REMOTE_NUM] = { {NULL} };
    char *remote_port = NULL;
    int use_new_listener = 0;
    jconf_t *conf = NULL;

    struct ss_host_port tunnel_addr = { NULL, NULL };
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

    (void)use_new_listener; (void)hostnames; (void)iface;
    MEM_CHECK_BEGIN();
    MEM_CHECK_BREAK_ALLOC(63);
    MEM_CHECK_BREAK_ALLOC(64);

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
                    /*
                    LOGI("%s", "initializing acl...");
                    acl = !init_acl(optarg);
                    */
                } else if (option_index == 2) {
                    mtu = atoi(optarg);
                    LOGI("set MTU to %d", mtu);
                } else if (option_index == 3) {
                    mptcp = 1;
                    LOGI("%s", "enable multipath TCP");
                } else if (option_index == 4) {
                    usage(VERSION, USING_CRYPTO);
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
                usage(VERSION, USING_CRYPTO);
                exit(EXIT_SUCCESS);
            case 'A':
                LOGI("%s", "The 'A' argument is deprecate! Ignored.");
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
        usage(VERSION, USING_CRYPTO);
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
                remote_num = conf->server_type.server_legacy.remote_num;
                for (i = 0; i < remote_num; i++) {
                    remote_addr[i] = conf->server_type.server_legacy.remote_addr[i];
                }
            }
            if (remote_port == NULL) {
                remote_port = conf->server_type.server_legacy.remote_port;
            }
            if (local_addr == NULL) {
                local_addr = conf->server_type.server_legacy.local_addr;
            }
            if (local_port == NULL) {
                local_port = conf->server_type.server_legacy.local_port;
            }
            if (password == NULL) {
                password = conf->server_type.server_legacy.password;
            }
            // SSR beg
            if (protocol == NULL) {
                protocol = conf->server_type.server_legacy.protocol;
                LOGI("protocol %s", protocol);
            }
            if (protocol_param == NULL) {
                protocol_param = conf->server_type.server_legacy.protocol_param;
                LOGI("protocol_param %s", protocol_param);
            }
            if (method == NULL) {
                method = conf->server_type.server_legacy.method;
                LOGI("method %s", method);
            }
            if (obfs == NULL) {
                obfs = conf->server_type.server_legacy.obfs;
                LOGI("obfs %s", obfs);
            }
            if (obfs_param == NULL) {
                obfs_param = conf->server_type.server_legacy.obfs_param;
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
        LOGI("%s", "The verify_sha1 protocol is deprecate! Fallback to origin protocol.");
        protocol = NULL;
    }

    if (remote_num == 0 || remote_port == NULL || password == NULL
#ifndef HAVE_LAUNCHD
        || local_port == NULL
#endif
        )
    {
        usage(VERSION, USING_CRYPTO);
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
        LOGI("%s", "using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (ipv6first) {
        LOGI("%s", "resolving hostname to IPv6 address first");
    }
    srand((unsigned int)time(NULL));

    // parse tunnel addr
    if (tunnel_addr_str) {
        ASSERT(!"Not support now!");
        parse_addr(tunnel_addr_str, &tunnel_addr);
    }

    {
        struct server_config *local_config = config_create();

        local_config->idle_timeout = (unsigned int)atoi(timeout);

        if (remote_num > 0) {
            string_safe_assign(&local_config->remote_host, remote_addr[0].host);
        }
        local_config->remote_port = (unsigned short)atoi(remote_port);

        string_safe_assign(&local_config->listen_host, local_addr);
        local_config->listen_port = (unsigned short)atoi(local_port);

        local_config->udp = false; // (mode==TCP_AND_UDP || mode==UDP_ONLY);

        string_safe_assign(&local_config->method, method);
        string_safe_assign(&local_config->password, password);
        string_safe_assign(&local_config->protocol, protocol);
        string_safe_assign(&local_config->protocol_param, protocol_param);
        string_safe_assign(&local_config->obfs, obfs);
        string_safe_assign(&local_config->obfs_param, obfs_param);

        i = ssr_local_main_loop(local_config, NULL, NULL);

        config_release(local_config);
    }
    free_jconf(conf);

    MEM_CHECK_DUMP_LEAKS();

    return i;
}

static ssize_t get_sockaddr(char *host, char *port, struct sockaddr_storage *storage, int block, int ipv6first) {
    union sockaddr_universal addr = { {0} };
    universal_address_from_string(host, (uint16_t)atoi(port), true, &addr);
    *storage = addr.addr_stor;
    (void)block; (void)ipv6first;
    return 0;
}

struct ssr_local_state {
    int listen_fd;
};

int ssr_Local_listen_socket_fd(struct ssr_local_state *state) {
    return state->listen_fd;
}

int ssr_local_main_loop(const struct server_config *config, void(*feedback_state)(struct ssr_local_state *state, void *p), void *p) {
    //struct ss_host_port tunnel_addr = { NULL, NULL };
    struct listener_t *listener;
    uv_loop_t *loop;
    uv_signal_t sigint_watcher;
    uv_signal_t sigterm_watcher;
    struct listener_t *listen_ctx;
    uv_tcp_t *listener_socket;
    int listenfd;
    uint16_t port;
    //struct udp_listener_ctx_t *udp_server;

#ifdef __MINGW32__
    winsock_init();
#endif

    // Setup listeners
    listener = (struct listener_t *)calloc(1, sizeof(struct listener_t));

    listener->timeout = config->idle_timeout * MILLISECONDS_PER_SECOND;
    //listener->iface = ss_strdup(config->iface);
    //listener->mptcp = config->mptcp;
    /*
    listener->tunnel_addr = tunnel_addr;

    if(use_new_listener) {
        char port[6];

        ss_server_new_1_t *servers = &conf->server_new_1;
        listener->server_num = servers->server_num;
        for(i = 0; i < servers->server_num; i++) {
            struct server_env_t *serv = &listener->servers[i];
            ss_server_t *serv_cfg = &servers->servers[i];

            struct sockaddr_storage *storage = calloc(1, sizeof(struct sockaddr_storage));

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
                storage = calloc(1, sizeof(struct sockaddr_storage));
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
            serv->cipher = (struct cipher_env_t *) cipher_env_new_instance(serv_cfg->password, serv_cfg->method);
            serv->psw = ss_strdup(serv_cfg->password);
            if (serv_cfg->protocol && strcmp(serv_cfg->protocol, "verify_sha1") == 0) {
                safe_free(serv_cfg->protocol);
            }

            // init obfs
            init_obfs(serv, serv_cfg->protocol, serv_cfg->protocol_param, serv_cfg->obfs, serv_cfg->obfs_param);

            serv->enable = serv_cfg->enable;
            serv->id = ss_strdup(serv_cfg->id);
            serv->group = ss_strdup(serv_cfg->group);
            serv->udp_over_tcp = serv_cfg->udp_over_tcp;
        }
    } else
     */
    {
        size_t i = 0;
        listener->server_num = 1; // config->remote_num;
        for(i = 0; i < listener->server_num; i++) {
            char swap_buff[257] = { 0 };
            struct server_env_t *serv = &listener->servers[i];
            char *host = config->remote_host;
            char *port;
            struct sockaddr_storage *storage;

            sprintf(swap_buff, "%d", config->remote_port);
            port = swap_buff;

            storage = (struct sockaddr_storage *) calloc(1, sizeof(struct sockaddr_storage));
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }
            serv->host = ss_strdup(host);
            serv->addr = serv->addr_udp = storage;
            serv->addr_len = serv->addr_udp_len = (int) get_sockaddr_len((struct sockaddr *)storage);
            serv->port = serv->udp_port = config->remote_port;

            // Setup keys
            LOGI("initializing ciphers... %s", config->method);
            serv->cipher = (struct cipher_env_t *) cipher_env_new_instance(config->password, config->method);
            serv->psw = ss_strdup(config->password);

            // init obfs
            init_obfs(serv, config->protocol, config->protocol_param, config->obfs, config->obfs_param);

            serv->enable = 1;
        }
    }

    // Init listeners
    current_listener = listener;

    loop = uv_default_loop();

    // Setup signal handler
    uv_signal_init(loop, &sigint_watcher);
    uv_signal_init(loop, &sigterm_watcher);
    uv_signal_start(&sigint_watcher, signal_cb, SIGINT);
    uv_signal_start(&sigterm_watcher, signal_cb, SIGTERM);

    listen_ctx = current_listener;

    listener_socket = &listen_ctx->socket;

    {
        // Setup socket
#ifdef HAVE_LAUNCHD
        listenfd = launch_or_create(config->listen_host, config->listen_port, loop, listener_socket);
#else
        listenfd = create_and_bind(config->listen_host, config->listen_port, loop, listener_socket);
#endif
        if (listenfd != 0) {
            FATAL("bind() error");
        }

        if (uv_listen((uv_stream_t*)listener_socket, 128, accept_cb) != 0) {
            FATAL("listen() error");
        }
    }

    listenfd = uv_stream_fd(listener_socket);

    port = get_socket_port(listener_socket);

    //udp_server = NULL;
    // Setup UDP
    if (config->udp) {
        //LOGI("%s", "udprelay enabled");
        //udp_server = udprelay_begin(loop, config->listen_host, port, (union sockaddr_universal *)listen_ctx->servers[0].addr_udp,
        //    &tunnel_addr, 0, listen_ctx->timeout, listen_ctx->servers[0].cipher, listen_ctx->servers[0].protocol_name, listen_ctx->servers[0].protocol_param);
    }

#ifdef HAVE_LAUNCHD
    //if (config->local_port == NULL) {
    //    LOGI("listening through launchd");
    //} else
#endif
    {
        if (strcmp(config->listen_host, ":") > 0) {
            LOGI("listening at [%s]:%d", config->listen_host, port);
        } else {
            LOGI("listening at %s:%d", config->listen_host, port);
        }
    }
    // setuid
    //if (config->user != NULL && ! run_as(config->user)) {
    //    FATAL("failed to switch user");
    //}

#if !defined(__MINGW32__) && !defined(_WIN32)
    if (geteuid() == 0){
        LOGI("%s", "running from root user");
    }
#endif

    if (feedback_state) {
        struct ssr_local_state *state = (struct ssr_local_state *)calloc(1, sizeof(*state));
        state->listen_fd = listenfd;
        feedback_state(state, p);
        free(state);
    }

    // Enter the loop
    uv_run(listener_socket->loop, UV_RUN_DEFAULT);

    if (verbose) {
        LOGI("%s", "closed gracefully");
    }

    // Clean up
    if (config->udp) {
        //udprelay_shutdown(udp_server); // udp relay use some data from listener, so we need to release udp first
    }

    {
        // uv_stop(listener_socket->loop);
        free_connections(); // after this, all inactive listener should be released already, so we only need to release the current_listener
        listener_release(current_listener);
    }

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return 0;
}
