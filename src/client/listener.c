/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "defs.h"
//#include <netinet/in.h>  /* INET6_ADDRSTRLEN */
#include <stdlib.h>
#include <string.h>

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 63
#endif

struct server_state {
    struct server_config *config;
    struct listener_ctx *listeners;
};

static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void listen_incoming_connection_cb(uv_stream_t *server, int status);

int listener_run(struct server_config *cf, uv_loop_t *loop) {
    struct addrinfo hints;
    struct server_state *state;
    int err;

    state = (struct server_state *) calloc(1, sizeof(*state));
    state->listeners = NULL;
    state->config = cf;

    /* Resolve the address of the interface that we should bind to.
    * The getaddrinfo callback starts the server and everything else.
    */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    uv_getaddrinfo_t *req = (uv_getaddrinfo_t *)malloc(sizeof(*req));
    req->data = state;

    err = uv_getaddrinfo(loop, req, getaddrinfo_done_cb, cf->bind_host, NULL, &hints);
    if (err != 0) {
        pr_err("getaddrinfo: %s", uv_strerror(err));
        return err;
    }

    /* Start the event loop.  Control continues in getaddrinfo_done_cb(). */
    if (uv_run(loop, UV_RUN_DEFAULT)) {
        abort();
    }

    /* Please Valgrind. */
    uv_loop_delete(loop);

    free(state->config->bind_host);
    free(state->config);
    free(state->listeners);
    free(state);

    return 0;
}

/* Bind a server to each address that getaddrinfo() reported. */
static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    char addrbuf[INET6_ADDRSTRLEN + 1];
    unsigned int ipv4_naddrs;
    unsigned int ipv6_naddrs;
    struct server_state *state;
    const struct server_config *cf;
    struct addrinfo *ai;
    const void *addrv = NULL;
    const char *what;
    uv_loop_t *loop;
    struct listener_ctx *lx;
    unsigned int n;
    int err;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } s;

    loop = req->loop;

    state = (struct server_state *) req->data;
    ASSERT(state);
    cf = state->config;

    free(req);

    if (status < 0) {
        pr_err("getaddrinfo(\"%s\"): %s", cf->bind_host, uv_strerror(status));
        uv_freeaddrinfo(addrs);
        return;
    }

    ipv4_naddrs = 0;
    ipv6_naddrs = 0;
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            ipv4_naddrs += 1;
        } else if (ai->ai_family == AF_INET6) {
            ipv6_naddrs += 1;
        }
    }

    if (ipv4_naddrs == 0 && ipv6_naddrs == 0) {
        pr_err("%s has no IPv4/6 addresses", cf->bind_host);
        uv_freeaddrinfo(addrs);
        return;
    }

    state->listeners = xmalloc((ipv4_naddrs + ipv6_naddrs) * sizeof(state->listeners[0]));

    n = 0;
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
            continue;
        }

        if (ai->ai_family == AF_INET) {
            s.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
            s.addr4.sin_port = htons(cf->bind_port);
            addrv = &s.addr4.sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            s.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
            s.addr6.sin6_port = htons(cf->bind_port);
            addrv = &s.addr6.sin6_addr;
        } else {
            UNREACHABLE();
        }

        if (uv_inet_ntop(s.addr.sa_family, addrv, addrbuf, sizeof(addrbuf))) {
            UNREACHABLE();
        }

        lx = state->listeners + n;
        lx->idle_timeout = state->config->idle_timeout;
        CHECK(0 == uv_tcp_init(loop, &lx->tcp_handle));

        what = "uv_tcp_bind";
        err = uv_tcp_bind(&lx->tcp_handle, &s.addr, 0);
        if (err == 0) {
            what = "uv_listen";
            err = uv_listen((uv_stream_t *)&lx->tcp_handle, 128, listen_incoming_connection_cb);
        }

        if (err != 0) {
            pr_err("%s(\"%s:%hu\"): %s", what, addrbuf, cf->bind_port, uv_strerror(err));
            while (n > 0) {
                n -= 1;
                uv_close((uv_handle_t *)(&lx->tcp_handle), NULL);
            }
            break;
        }

        pr_info("listening on %s:%hu", addrbuf, cf->bind_port);
        n += 1;
    }

    uv_freeaddrinfo(addrs);
}

static void listen_incoming_connection_cb(uv_stream_t *server, int status) {
    struct listener_ctx *lx;

    CHECK(status == 0);
    lx = CONTAINER_OF(server, struct listener_ctx, tcp_handle);

    tunnel_initialize(lx);
}

bool can_auth_none(const struct listener_ctx *lx, const struct tunnel_ctx *cx) {
    return true;
}

bool can_auth_passwd(const struct listener_ctx *lx, const struct tunnel_ctx *cx) {
    return false;
}

bool can_access(const struct listener_ctx *lx, const struct tunnel_ctx *cx, const struct sockaddr *addr) {
    const struct sockaddr_in6 *addr6;
    const struct sockaddr_in *addr4;
    const uint32_t *p;
    uint32_t a, b, c, d;

    /* TODO(bnoordhuis) Implement proper access checks.  For now, just reject
    * traffic to localhost.
    */
    if (addr->sa_family == AF_INET) {
        addr4 = (const struct sockaddr_in *) addr;
        d = ntohl(addr4->sin_addr.s_addr);
        return (d >> 24) != 0x7F;
    }

    if (addr->sa_family == AF_INET6) {
        addr6 = (const struct sockaddr_in6 *) addr;
        p = (const uint32_t *)&addr6->sin6_addr.s6_addr;
        a = ntohl(p[0]);
        b = ntohl(p[1]);
        c = ntohl(p[2]);
        d = ntohl(p[3]);
        if (a == 0 && b == 0 && c == 0 && d == 1) {
            return false;  /* "::1" style address. */
        }
        if (a == 0 && b == 0 && c == 0xFFFF && (d >> 24) == 0x7F) {
            return false;  /* "::ffff:127.x.x.x" style address. */
        }
        return true;
    }

    return false;
}
