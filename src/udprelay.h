#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <ev.h>
#include <time.h>

#include "encrypt.h"
#include "jconf.h"

#ifdef UDPRELAY_REMOTE
#include "asyncns.h"
#endif

#include "cache.h"

#include "include.h"

#define MAX_UDP_PACKET_SIZE (64 * 1024)

struct server_ctx
{
    ev_io io;
    int fd;
    int method;
    int timeout;
    const char *iface;
    struct cache *conn_cache;
    char *buf; // server send from, remote recv into
#ifdef UDPRELAY_REMOTE
    asyncns_t *asyncns;
#endif
#ifdef UDPRELAY_LOCAL
    const char *remote_host;
    const char *remote_port;
#endif
};

#ifdef UDPRELAY_REMOTE
struct query_ctx
{
    ev_timer watcher;
    asyncns_query_t *query;
    struct sockaddr src_addr;
    int buf_len;
    char *buf; // server send from, remote recv into
    int addr_header_len;
    char addr_header[384];
    struct server_ctx *server_ctx;
};
#endif

struct remote_ctx
{
    ev_io io;
    ev_timer watcher;
    int fd;
    int addr_header_len;
    char addr_header[384];
    struct sockaddr src_addr;
    struct sockaddr dst_addr;
    struct server_ctx *server_ctx;
};

static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents);
static char *hash_key(const char *header, const int header_len, const struct sockaddr *addr);
#ifdef UDPRELAY_REMOTE
static void query_resolve_cb(EV_P_ ev_timer *watcher, int revents);
#endif
static void close_and_free_remote(EV_P_ struct remote_ctx *ctx);

static struct remote_ctx* new_remote(int fd, struct server_ctx* server_ctx);

#endif // _UDPRELAY_H
