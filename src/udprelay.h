#ifndef _SERVER_H
#define _SERVER_H

#include <ev.h>
#include <time.h>

#include "encrypt.h"
#include "jconf.h"
#include "asyncns.h"

struct server_ctx {
    ev_io io;
    ev_timer watcher;
    int connected;
    struct server *server;
};

struct server {
    int fd;
    int buf_len;
    int buf_idx;
    int timeout;
    int method;
    char *iface;
    char *buf; // server send from, client recv into
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    asyncns_query_t *query;
    struct client *client;
};

struct client_ctx {
    ev_io io;
    struct client *client;
};

struct client {
    int fd;
    int buf_len;
    int buf_idx;
    char *buf; // client send from, server recv into
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct client_ctx *recv_ctx;
    struct client_ctx *send_ctx;
    struct server *server;
};

static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void server_send_cb (EV_P_ ev_io *w, int revents);
static void client_recv_cb (EV_P_ ev_io *w, int revents);
static void client_send_cb (EV_P_ ev_io *w, int revents);
static void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);
static void server_resolve_cb(EV_P_ ev_timer *watcher, int revents);

struct client* new_client(int fd);
struct client *connect_to_client(struct addrinfo *res, const char *iface);
void free_client(struct client *client);
void close_and_free_client(EV_P_ struct client *client);
struct server* new_server(int fd, struct listen_ctx *listener);
void free_server(struct server *server);
void close_and_free_server(EV_P_ struct server *server);

#endif // _SERVER_H
