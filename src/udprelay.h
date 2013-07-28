#ifndef _SERVER_H
#define _SERVER_H

#include <ev.h>
#include <time.h>

#include "encrypt.h"
#include "jconf.h"
#include "asyncns.h"

#define MAX_UDP_PACKET_SIZE (64 * 1024)

struct server_ctx {
    ev_io io;
    int fd;
    int method;
    char *iface;
    struct sockaddr_in src_addr;
    struct remote *remote;
#ifdef UDPRELAY_REMOTE
    asyncns_t *asyncns;
#endif
};

#ifdef UDPRELAY_LOCAL
struct query_ctx {
    ev_timer resolve_watcher;
    asyncns_query_t *query;
    int buf_len;
    char *buf; // server send from, remote recv into
    struct server_ctx *server_ctx;
}
#endif

struct remote_ctx {
    ev_io io;
    int fd;
    int buf_len;
    char *buf; // remote send from, server recv into
    struct sockaddr addr;
    struct server *server;
#ifdef UDPRELAY_REMOTE
    ev_timer watcher;
#endif
};

static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void server_send_cb (EV_P_ ev_io *w, int revents);
static void remote_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_send_cb (EV_P_ ev_io *w, int revents);
static void server_resolve_cb(EV_P_ ev_timer *watcher, int revents);

struct remote* new_remote(int fd);
struct remote *connect_to_remote(struct addrinfo *res, const char *iface);
void free_remote(struct remote *remote);
void close_and_free_remote(EV_P_ struct remote *remote);
struct server* new_server(int fd, struct listen_ctx *listener);
void free_server(struct server *server);
void close_and_free_server(EV_P_ struct server *server);

#endif // _SERVER_H
