#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "utils.h"
#include "udprelay.h"
#include "cache.h"

#ifdef UDPRELAY_REMOTE
struct udprelay_header {
    uint8_t atyp;
}
#else
#ifdef UDPRELAY_LOCAL
struct udprelay_header {
    uint16_t rsv;
    uint8_t frag;
}
struct remote *remote = NULL;
#else
#error "No UDPRELAY defined"
#endif
#endif

#ifdef UDPRELAY_REMOTE
#ifdef UDPRELAY_LOCAL
#error "Both UDPRELAY_REMOTE and UDPRELAY_LOCAL defined"
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define BLOCK_SIZE MAX_UDP_PACKET_SIZE

static int verbose = 0;
static int remote_conn = 0;
static int server_conn = 0;

int setnonblocking(int fd) {
    int flags;
    if (-1 ==(flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#ifdef SET_INTERFACE
int setinterface(int socket_fd, const char* interface_name)
{
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(struct ifreq));
    return res;
}
#endif

int create_remote_socket(int ipv6) {
    int s, remote_sock;

    if (ipv6) {
        // Try to bind IPv6 first
        struct sockaddr_in6 addr_in6;
        memset(&addr, 0, sizeof(addr_in6));
        addr_in6.sin_family = AF_INET6;
        addr_in6.sin_addr.s_addr = htonl(IN6ADDR_ANY);
        addr_in6.sin_port = htons(0);
        remote_sock = socket(AF_INET6, SOCK_DGRAM , 0);
        if (remote_sock != -1) {
            if (bind(remote_sock, &addr_in6, sizeof(addr_in6)) != -1) {
                return remote_sock;
            }
        }
    }

    // Then bind to IPv4
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);
    remote_sock = socket(AF_INET, SOCK_DGRAM , 0);
    if (remote_sock == -1) {
        ERROR("Cannot create socket.");
        return -1;
    }

    if (bind(remote_sock, &addr, sizeof(addr)) != 0) {
        FATAL("Cannot bind remote.");
        return -1;
    }

    return remote_sock;
}

int create_server_socket(const char *host, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, server_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM; /* We want a UDP socket */

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        server_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (server_sock == -1)
            continue;

        int opt = 1;
        setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(server_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

        s = bind(server_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        close(server_sock);
    }

    if (rp == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return server_sock;
}

struct remote *send_to_remote(struct addrinfo *res, const char *iface) {
    connect(sockfd, res->ai_addr, res->ai_addrlen);

    return remote;
}

static void server_send_cb (EV_P_ ev_io *w, int revents) {
    struct server_ctx *server_send_ctx = (struct server_ctx *)w;
    struct server *server = server_send_ctx->server;
    struct remote *remote = server->remote;

    if (remote == NULL) {
        LOGE("invalid server.");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (server->buf_len == 0) {
        // close and free
        if (verbose) {
            LOGD("server_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf + server->buf_idx,
                server->buf_len, 0);
        if (s < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("server_send_send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < server->buf_len) {
            // partly sent, move memory, wait for the next time to send
            server->buf_len -= s;
            server->buf_idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf_len = 0;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &server_send_ctx->io);
            if (remote != NULL) {
                ev_io_start(EV_A_ &remote->recv_ctx->io);
                return;
            } else {
                LOGE("invalid remote.");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }
}

static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents) {
    struct server *server = (struct server *) (((void*)watcher)
            - sizeof(ev_timer));
    struct remote *remote = server->remote;

    LOGE("UDP connection timeout");

    ev_timer_stop(EV_A_ watcher);

    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void query_resolve_cb(EV_P_ ev_timer *watcher, int revents) {
    int err;
    struct addrinfo *result, *rp;
    struct quert_ctx *query_ctx = (struct quert_ctx *)((void*)watcher);
    asyncns_t *asyncns = query_ctx->asyncns;
    asyncns_query_t *query = query_ctx->query;

    if (asyncns == NULL || query == NULL) {
        LOGE("invalid dns query.");
        close_and_free_server(EV_A_ server);
        return;
    }

    if (asyncns_wait(asyncns, 0) == -1) {
        // asyncns error
        FATAL("asyncns exit unexpectedly.");
    }

    if (!asyncns_isdone(asyncns, query)) {
        // wait for reolver
        return;
    }

    if (verbose) {
        LOGD("asyncns resolved.");
    }

    ev_timer_stop(EV_A_ watcher);

    err = asyncns_getaddrinfo_done(asyncns, query, &result);

    if (err) {
        ERROR("getaddrinfo");
    } else {
        // Use IPV4 address if possible
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET) break;
        }

        if (rp == NULL) {
            rp = result;
        }

        int opt = 1;

        int remotefd = create_remote_socket(rp->ai_family == AF_INET6);
        if (remotefd < 0) {
            ERROR("socket");
            close(remotefd);
            // release addrinfo
            asyncns_freeaddrinfo(result);
            return;
        }
        setnonblocking(remotefd);

#ifdef SO_NOSIGPIPE
        setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
#ifdef SET_INTERFACE
        if (iface) setinterface(remotefd, iface);
#endif

        struct remote_ctx *remote_ctx = new_remote_ctx(remotefd);

        server->remote = remote;
        remote->server = server;

        // listen to remote connected event
        ev_io_start(EV_A_ &remote->send_ctx->io);
    }

    // release addrinfo
    asyncns_freeaddrinfo(result);
}

static void remote_recv_cb (EV_P_ ev_io *w, int revents) {
    struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_recv_ctx->remote;
    struct server *server = remote->server;

    if (server == NULL) {
        LOGE("invalid server.");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ev_timer_again(EV_A_ &server->recv_ctx->watcher);

    ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        if (verbose) {
            LOGD("remote_recv close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf = ss_encrypt(server->buf, &r, server->e_ctx);

    if (server->buf == NULL) {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }

    int s = send(server->fd, server->buf, r, 0);

    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // no data, wait for send
            server->buf_len = r;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &remote_recv_ctx->io);
            ev_io_start(EV_A_ &server->send_ctx->io);
        } else {
            ERROR("remote_recv_send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
        }
        return;
    } else if (s < r) {
        server->buf_len = r - s;
        server->buf_idx = s;
        ev_io_stop(EV_A_ &remote_recv_ctx->io);
        ev_io_start(EV_A_ &server->send_ctx->io);
        return;
    }
}

static void remote_send_cb (EV_P_ ev_io *w, int revents) {
    struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_send_ctx->remote;
    struct server *server = remote->server;

    if (server == NULL) {
        LOGE("invalid server.");
        close_and_free_remote(EV_A_ remote);
        return;
    }

    if (!remote_send_ctx->connected) {

        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r = getpeername(remote->fd, (struct sockaddr*)&addr, &len);
        if (r == 0) {
            if (verbose) {
                LOGD("remote connected.");
            }
            remote_send_ctx->connected = 1;

            if (remote->buf_len == 0) {
                server->stage = 5;
                ev_io_stop(EV_A_ &remote_send_ctx->io);
                ev_io_start(EV_A_ &server->recv_ctx->io);
                ev_io_start(EV_A_ &remote->recv_ctx->io);
                return;
            }

        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    if (remote->buf_len == 0) {
        // close and free
        if (verbose) {
            LOGD("remote_send close the connection");
        }
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(remote->fd, remote->buf + remote->buf_idx,
                remote->buf_len, 0);
        if (s == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ERROR("remote_send_send");
                // close and free
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        } else if (s < remote->buf_len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf_len -= s;
            remote->buf_idx += s;
            return;
        } else {
            // all sent out, wait for reading
            remote->buf_len = 0;
            remote->buf_idx = 0;
            ev_io_stop(EV_A_ &remote_send_ctx->io);
            if (server != NULL) {
                ev_io_start(EV_A_ &server->recv_ctx->io);
                if (server->stage == 4) {
                    server->stage = 5;
                    ev_io_start(EV_A_ &remote->recv_ctx->io);
                }
            } else {
                LOGE("invalid server.");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
    }
}

struct remote_ctx *new_remote_ctx(int fd) {
    struct remote_ctx *ctx = malloc(sizeof(struct remote_ctx));
    ctx->buf = malloc(BUF_SIZE);
    ctx->buf_len = 0;
    ctx->server_ctx = NULL;
    ctx->fd = fd;
    return ctx;
}

struct server_ctx * new_server_ctx(int fd) {
    struct server_ctx *ctx = malloc(sizeof(struct server_ctx));
    ctx->remote_ctx = NULL;
    ctx->fd = fd;
    return ctx;
}

#ifdef UDPRELAY_REMOTE
struct query_ctx *new_query_ctx(asyncns_query_t *query,
        const uint8_t *buf, const int buf_len) {
    struct query_ctx *ctx = malloc(sizeof(struct query_ctx))
    ctx->buf = malloc(buf_len);
    ctx->buf_len = buf_len;
    memcpy(ctx->buf, buf, buf_len);
    ctx->query = query;
    ev_timer_init(&ctx->watcher, query_resolve_cb, 0.2, 0.5);
    return ctx;
}

void close_and_free_query(EN_P_ struct query_ctx *ctx) {
    if (ctx != NULL) {
        ev_timer_stop(EV_A_ &ctx->watcher);
        if (ctx->buf != NULL) {
            free(ctx->buf);
        }
        free(ctx);
    }
}
#endif

static void server_recv_cb (EV_P_ ev_io *w, int revents) {
    struct server_ctx *server_ctx = (struct server_ctx *)w;
    struct udprelay_header *header;
    uint8_t *buf = malloc(BUF_SIZE);

    int addr_len = sizeof(server->src_addr);
    int offset = 0;

    ssize_t r = recvfrom(server_ctx->fd, buf, BUF_SIZE, 
            0, &server->src_addr, &addr_len);

    if (r == -1) {
        // error on recv
        // simply drop that packet
        if (verbose) {
            ERROR("udprelay_server_recvfrom");
        }
        return;
    }

    if (verbose) {
        LOGD("receive a packet.");
    }

#ifdef UDPRELAY_REMOTE
    server->buf = ss_decrypt_all(BUF_SIZE, buf, &r, server_ctx->method);
#endif

    header = (struct udprelay_header *)buf;
    offset += sizeof(struct udprelay_header);

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

#ifdef UDPRELAY_LOCAL 

    struct remote_ctx *remote_ctx = server_ctx->remote_ctx;

    if (header->frag) {
        LOGE("drop a message since frag is not 0");
        return;
    }

    r -= offset;
    memmove(buf, buf + offset, r);

    ss_encrypt_all(BLOCK_SIZE, buf, &r, server_ctx->method);

    int w = sendto(server_ctx->fd, buf, r, 0, &remote_ctx->addr, sizeof(remote_ctx->addr));

    if (w == -1) {
        ERROR("udprelay_server_sendto");
    }

#else

    char host[256] = {0};
    char port[64] = {0};

    // get remote addr and port
    if (header->atyp == 1) {
        // IP V4
        size_t in_addr_len = sizeof(struct in_addr);
        if (r > in_addr_len) {
            inet_ntop(AF_INET, (const void *)(server->buf + offset),
                    host, INET_ADDRSTRLEN);
            offset += in_addr_len;
        }
    } else if (header->atyp == 3) {
        // Domain name
        uint8_t name_len = *(uint8_t *)(server->buf + offset);
        if (name_len < r && name_len < 255 && name_len > 0) {
            memcpy(host, server->buf + offset + 1, name_len);
            offset += name_len + 1;
        }
    } else if (header->atyp == 4) {
        // IP V6
        size_t in6_addr_len = sizeof(struct in6_addr);
        if (r > in6_addr_len) {
            inet_ntop(AF_INET6, (const void*)(server->buf + offset), 
                    host, INET6_ADDRSTRLEN);
            offset += in6_addr_len;
        }
    }

    if (offset == sizeof(struct udprelay_header)) {
        LOGE("invalid header with addr type %d", atyp);
        close_and_free_server(EV_A_ server);
        return;
    }

    sprintf(port, "%d", 
            ntohs(*(uint16_t *)(server->buf + offset)));
    offset += 2;

    r -= offset;
    memmove(server->buf, server->buf + offset, r);
    server->buf_len = r;

    if (verbose) {
        LOGD("send to: %s:%s", host, port);
    }

    struct addrinfo hints;
    asyncns_query_t *query;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    query = asyncns_getaddrinfo(server_ctx->asyncns,
            host, port, &hints);

    if (query == NULL) {
        ERROR("udp_asyncns_getaddrinfo");
        return;
    }

    struct query_ctx *query_ctx = new_query_ctx(query, server->buf, server->buf_len);
    query_ctx->server_ctx = server_ctx;

    ev_timer_start(EV_A_ &query_ctx->watcher);
#endif

    free(buf);
}

int udprelay(const char *server_host, const char *server_port,
#ifdef UDPRELAY_LOCAL
        const char *remote_host, const char *remote_port, 
#endif
        int method, const char *iface) {

    // inilitialize ev loop
    struct ev_loop *loop = EV_DEFAULT;

    //////////////////////////////////////////////////
    // Setup server context

    // Bind to port
    int serverfd = create_server_socket(host, server_port);
    if (serverfd < 0) {
        FATAL("udprelay bind() error..");
    }
    setnonblocking(serverfd);
    struct server_ctx *server_ctx = new_server_ctx(serverfd); 
    server_ctx->method = method;
    server_ctx->iface = iface;
    server_ctx->asyncns = asyncns;

    ev_io_init(&server_ctx.io, server_recv_cb, serverfd, EV_READ);
    ev_io_start(loop, &server_ctx.io);

#ifdef UDPRELAY_LOCAL
    //////////////////////////////////////////////////
    // Setup remote context
    
    // Bind to any port
    int remotefd = create_remote_socket(1);
    if (remotefd < 0) {
        FATAL("udprelay bind() error..");
    }
    setnonblocking(remotefd);

    struct remote_ctx *remote_ctx = new_remote_ctx(remotefd);

    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM; /* We want a UDP socket */

    int s = getaddrinfo(remote_host, remote_port, &hints, &result);
    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }
    remote_ctx->addr = *result->ai_addr;
    freeaddrinfo(result);

    server_ctx->remote_ctx = remote_ctx;
    remote_ctx->server_ctx = server_ctx;

    ev_io_init(&remote_ctx->io, remote_recv_cb, remotefd, EV_READ);
    ev_io_start(loop, &remote_ctx->io);
#endif

    return 0;
}

