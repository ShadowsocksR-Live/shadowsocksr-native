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
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* A connection is modeled as an abstraction on top of two simple state
 * machines, one for reading and one for writing.  Either state machine
 * is, when active, in one of three states: busy, done or stop; the fourth
 * and final state, dead, is an end state and only relevant when shutting
 * down the connection.  A short overview:
 *
 *                          busy                  done           stop
 *  ----------|---------------------------|--------------------|------|
 *  readable  | waiting for incoming data | have incoming data | idle |
 *  writable  | busy writing out data     | completed write    | idle |
 *
 * We could remove the done state from the writable state machine. For our
 * purposes, it's functionally equivalent to the stop state.
 *
 * When the connection with upstream has been established, the struct tunnel_ctx
 * moves into a state where incoming data from the client is sent upstream
 * and vice versa, incoming data from upstream is sent to the client.  In
 * other words, we're just piping data back and forth.  See socket_cycle()
 * for details.
 *
 * An interesting deviation from libuv's I/O model is that reads are discrete
 * rather than continuous events.  In layman's terms, when a read operation
 * completes, the connection stops reading until further notice.
 *
 * The rationale for this approach is that we have to wait until the data
 * has been sent out again before we can reuse the read buffer.
 *
 * It also pleasingly unifies with the request model that libuv uses for
 * writes and everything else; libuv may switch to a request model for
 * reads in the future.
 */

static bool tunnel_is_dead(struct tunnel_ctx *tunnel);
static void tunnel_add_ref(struct tunnel_ctx *tunnel);
static void tunnel_release(struct tunnel_ctx *tunnel);
static void do_next(struct tunnel_ctx *tunnel);
static void do_handshake(struct tunnel_ctx *tunnel);
static void do_handshake_auth(struct tunnel_ctx *tunnel);
static void do_req_start(struct tunnel_ctx *tunnel);
static void do_req_parse(struct tunnel_ctx *tunnel);
static void do_req_lookup(struct tunnel_ctx *tunnel);
static void do_req_connect_start(struct tunnel_ctx *tunnel);
static void do_req_connect(struct tunnel_ctx *tunnel);
static void do_proxy_start(struct tunnel_ctx *tunnel);
static void do_proxy(struct tunnel_ctx *tunnel);
static void do_kill(struct tunnel_ctx *tunnel);
static int socket_cycle(const char *who, struct socket_ctx *a, struct socket_ctx *b);
static void socket_timer_reset(struct socket_ctx *c);
static void socket_timer_expire_cb(uv_timer_t *handle);
static void socket_getaddrinfo(struct socket_ctx *c, const char *hostname);
static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai);
static int socket_connect(struct socket_ctx *c);
static void socket_connect_done_cb(uv_connect_t *req, int status);
static void socket_read(struct socket_ctx *c);
static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void socket_write(struct socket_ctx *c, const void *data, size_t len);
static void socket_write_done_cb(uv_write_t *req, int status);
static void socket_close(struct socket_ctx *c);
static void socket_close_done_cb(uv_handle_t *handle);

int tunnel_count = 0;

static bool tunnel_is_dead(struct tunnel_ctx *tunnel) {
    return (tunnel->state == session_dead);
}

static void tunnel_add_ref(struct tunnel_ctx *tunnel) {
    tunnel->ref_count++;
}

static void tunnel_release(struct tunnel_ctx *tunnel) {
    tunnel->ref_count--;
    if (tunnel->ref_count == 0) {
        tunnel_count--;
        if (tunnel_count == 0) {
            pr_info("Great! tunnel count is zero.");
        }
        free(tunnel);
    }
}

/* |incoming| has been initialized by listener.c when this is called. */
void tunnel_initialize(struct listener_ctx *lx) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    struct tunnel_ctx *tunnel;
    uv_stream_t *server = (uv_stream_t *)&lx->tcp_handle;
    uv_loop_t *loop = server->loop;

    tunnel_count++;

    tunnel = xmalloc(sizeof(*tunnel));

    tunnel->lx = lx;
    tunnel->state = session_handshake;
    tunnel->ref_count = 0;
    s5_init(&tunnel->parser);

    incoming = &tunnel->incoming;
    incoming->tunnel = tunnel;
    incoming->result = 0;
    incoming->rdstate = socket_stop;
    incoming->wrstate = socket_stop;
    incoming->idle_timeout = lx->idle_timeout;
    CHECK(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    CHECK(0 == uv_accept(server, &incoming->handle.stream));
    CHECK(0 == uv_timer_init(loop, &incoming->timer_handle));

    outgoing = &tunnel->outgoing;
    outgoing->tunnel = tunnel;
    outgoing->result = 0;
    outgoing->rdstate = socket_stop;
    outgoing->wrstate = socket_stop;
    outgoing->idle_timeout = lx->idle_timeout;
    CHECK(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    CHECK(0 == uv_timer_init(loop, &outgoing->timer_handle));

    /* Wait for the initial packet. */
    socket_read(incoming);
}

/* This is the core state machine that drives the client <-> upstream proxy.
 * We move through the initial handshake and authentication steps first and
 * end up (if all goes well) in the proxy state where we're just proxying
 * data between the client and upstream.
 */
static void do_next(struct tunnel_ctx *tunnel) {
    switch (tunnel->state) {
    case session_handshake:
        do_handshake(tunnel);
        break;
    case session_handshake_auth:
        do_handshake_auth(tunnel);
        break;
    case session_req_start:
        do_req_start(tunnel);
        break;
    case session_req_parse:
        do_req_parse(tunnel);
        break;
    case session_req_lookup:
        do_req_lookup(tunnel);
        break;
    case session_req_connect:
        do_req_connect(tunnel);
        break;
    case session_proxy_start:
        do_proxy_start(tunnel);
        break;
    case session_proxy:
        do_proxy(tunnel);
        break;
    case session_kill:
        do_kill(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}

static void do_handshake(struct tunnel_ctx *tunnel) {
    enum s5_auth_method methods;
    struct socket_ctx *incoming;
    s5_ctx *parser;
    uint8_t *data;
    size_t size;
    enum s5_err err;

    parser = &tunnel->parser;
    incoming = &tunnel->incoming;
    ASSERT(incoming->rdstate == socket_done);
    ASSERT(incoming->wrstate == socket_stop);
    incoming->rdstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        do_kill(tunnel);
        return;
    }

    data = (uint8_t *)incoming->t.buf;
    size = (size_t)incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_ok) {
        socket_read(incoming);
        tunnel->state = session_handshake;  /* Need more data. */
        return;
    }

    if (size != 0) {
        /* Could allow a round-trip saving shortcut here if the requested auth
        * method is s5_auth_none (provided unauthenticated traffic is allowed.)
        * Requires client support however.
        */
        pr_err("junk in handshake");
        do_kill(tunnel);
        return;
    }

    if (err != s5_auth_select) {
        pr_err("handshake error: %s", s5_strerror(err));
        do_kill(tunnel);
        return;
    }

    methods = s5_auth_methods(parser);
    if ((methods & s5_auth_none) && can_auth_none(tunnel->lx, tunnel)) {
        s5_select_auth(parser, s5_auth_none);
        socket_write(incoming, "\5\0", 2);  /* No auth required. */
        tunnel->state = session_req_start;
        return;
    }

    if ((methods & s5_auth_passwd) && can_auth_passwd(tunnel->lx, tunnel)) {
        /* TODO(bnoordhuis) Implement username/password auth. */
        do_kill(tunnel);
        return;
    }

    socket_write(incoming, "\5\377", 2);  /* No acceptable auth. */
    tunnel->state = session_kill;
}

/* TODO(bnoordhuis) Implement username/password auth. */
static void do_handshake_auth(struct tunnel_ctx *tunnel) {
    UNREACHABLE();
    do_kill(tunnel);
}

static void do_req_start(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;

    incoming = &tunnel->incoming;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_done);
    incoming->wrstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        do_kill(tunnel);
        return;
    }

    socket_read(incoming);
    tunnel->state = session_req_parse;
}

static void do_req_parse(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    s5_ctx *parser;
    uint8_t *data;
    size_t size;
    enum s5_err err;

    parser = &tunnel->parser;
    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_done);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);
    incoming->rdstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        do_kill(tunnel);
        return;
    }

    data = (uint8_t *)incoming->t.buf;
    size = (size_t)incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_ok) {
        socket_read(incoming);
        tunnel->state = session_req_parse;  /* Need more data. */
        return;
    }

    if (size != 0) {
        pr_err("junk in request %u", (unsigned)size);
        do_kill(tunnel);
        return;
    }

    if (err != s5_exec_cmd) {
        pr_err("request error: %s", s5_strerror(err));
        do_kill(tunnel);
        return;
    }

    if (parser->cmd == s5_cmd_tcp_bind) {
        /* Not supported but relatively straightforward to implement. */
        pr_warn("BIND requests are not supported.");
        do_kill(tunnel);
        return;
    }

    if (parser->cmd == s5_cmd_udp_assoc) {
        /* Not supported.  Might be hard to implement because libuv has no
        * functionality for detecting the MTU size which the RFC mandates.
        */
        pr_warn("UDP ASSOC requests are not supported.");
        do_kill(tunnel);
        return;
    }
    ASSERT(parser->cmd == s5_cmd_tcp_connect);

    if (parser->atyp == s5_atyp_host) {
        socket_getaddrinfo(outgoing, (const char *)parser->daddr);
        tunnel->state = session_req_lookup;
        return;
    }

    if (parser->atyp == s5_atyp_ipv4) {
        memset(&outgoing->t.addr4, 0, sizeof(outgoing->t.addr4));
        outgoing->t.addr4.sin_family = AF_INET;
        outgoing->t.addr4.sin_port = htons(parser->dport);
        memcpy(&outgoing->t.addr4.sin_addr,
            parser->daddr,
            sizeof(outgoing->t.addr4.sin_addr));
    } else if (parser->atyp == s5_atyp_ipv6) {
        memset(&outgoing->t.addr6, 0, sizeof(outgoing->t.addr6));
        outgoing->t.addr6.sin6_family = AF_INET6;
        outgoing->t.addr6.sin6_port = htons(parser->dport);
        memcpy(&outgoing->t.addr6.sin6_addr,
            parser->daddr,
            sizeof(outgoing->t.addr6.sin6_addr));
    } else {
        UNREACHABLE();
    }

    do_req_connect_start(tunnel);
}

static void do_req_lookup(struct tunnel_ctx *tunnel) {
    s5_ctx *parser;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    parser = &tunnel->parser;
    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (outgoing->result < 0) {
        /* TODO(bnoordhuis) Escape control characters in parser->daddr. */
        pr_err("lookup error for \"%s\": %s",
            parser->daddr,
            uv_strerror((int)outgoing->result));
        /* Send back a 'Host unreachable' reply. */
        socket_write(incoming, "\5\4\0\1\0\0\0\0\0\0", 10);
        tunnel->state = session_kill;
        return;
    }

    /* Don't make assumptions about the offset of sin_port/sin6_port. */
    switch (outgoing->t.addr.sa_family) {
    case AF_INET:
        outgoing->t.addr4.sin_port = htons(parser->dport);
        break;
    case AF_INET6:
        outgoing->t.addr6.sin6_port = htons(parser->dport);
        break;
    default:
        UNREACHABLE();
    }

    do_req_connect_start(tunnel);
}

/* Assumes that cx->outgoing.t.sa contains a valid AF_INET/AF_INET6 address. */
static void do_req_connect_start(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    int err;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (!can_access(tunnel->lx, tunnel, &outgoing->t.addr)) {
        pr_warn("connection not allowed by ruleset");
        /* Send a 'Connection not allowed by ruleset' reply. */
        socket_write(incoming, "\5\2\0\1\0\0\0\0\0\0", 10);
        tunnel->state = session_kill;
        return;
    }

    err = socket_connect(outgoing);
    if (err != 0) {
        pr_err("connect error: %s\n", uv_strerror(err));
        do_kill(tunnel);
        return;
    }

    tunnel->state = session_req_connect;
}

static void do_req_connect(struct tunnel_ctx *tunnel) {
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;
    char addr_storage[sizeof(*in6)];
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    uint8_t *buf;
    int addrlen;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    /* Build and send the reply.  Not very pretty but gets the job done. */
    buf = (uint8_t *)incoming->t.buf;
    if (outgoing->result == 0) {
        /* The RFC mandates that the SOCKS server must include the local port
        * and address in the reply.  So that's what we do.
        */
        addrlen = sizeof(addr_storage);
        CHECK(0 == uv_tcp_getsockname(&outgoing->handle.tcp,
            (struct sockaddr *) addr_storage,
            &addrlen));
        buf[0] = 5;  /* Version. */
        buf[1] = 0;  /* Success. */
        buf[2] = 0;  /* Reserved. */
        if (addrlen == sizeof(*in)) {
            buf[3] = 1;  /* IPv4. */
            in = (const struct sockaddr_in *) &addr_storage;
            memcpy(buf + 4, &in->sin_addr, 4);
            memcpy(buf + 8, &in->sin_port, 2);
            socket_write(incoming, buf, 10);
        } else if (addrlen == sizeof(*in6)) {
            buf[3] = 4;  /* IPv6. */
            in6 = (const struct sockaddr_in6 *) &addr_storage;
            memcpy(buf + 4, &in6->sin6_addr, 16);
            memcpy(buf + 20, &in6->sin6_port, 2);
            socket_write(incoming, buf, 22);
        } else {
            UNREACHABLE();
        }
        tunnel->state = session_proxy_start;
        return;
    } else {
        s5_ctx *parser = &tunnel->parser;
        char *addr = NULL;

        if (parser->atyp == s5_atyp_host) {
            addr = parser->daddr;
        } else if (parser->atyp == s5_atyp_ipv4) {
            addr = inet_ntoa(*(struct in_addr *)parser->daddr);
        } else {
            ASSERT(!"not support ipv6 yet."); // inet_ntop()
        }
        const char *fmt = "upstream connection \"%s\" error: %s\n";
        pr_err(fmt, addr, uv_strerror((int)outgoing->result));
        /* Send a 'Connection refused' reply. */
        socket_write(incoming, "\5\5\0\1\0\0\0\0\0\0", 10);
        tunnel->state = session_kill;
        return;
    }

    UNREACHABLE();
    do_kill(tunnel);
}

static void do_proxy_start(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    incoming = &tunnel->incoming;
    outgoing = &tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_done);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);
    incoming->wrstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        do_kill(tunnel);
        return;
    }

    socket_read(incoming);
    socket_read(outgoing);
    tunnel->state = session_proxy;
}

/* Proxy incoming data back and forth. */
static void do_proxy(struct tunnel_ctx *tunnel) {
    if (socket_cycle("client", &tunnel->incoming, &tunnel->outgoing) != 0) {
        do_kill(tunnel);
        return;
    }

    if (socket_cycle("upstream", &tunnel->outgoing, &tunnel->incoming) != 0) {
        do_kill(tunnel);
        return;
    }

    tunnel->state = session_proxy;
}

static void do_kill(struct tunnel_ctx *tunnel) {
    ASSERT(tunnel_is_dead(tunnel) == false);

    /* Try to cancel the request. The callback still runs but if the
    * cancellation succeeded, it gets called with status=UV_ECANCELED.
    */
    if (tunnel->state == session_req_lookup) {
        uv_cancel(&tunnel->outgoing.t.req);
    }

    socket_close(&tunnel->incoming);
    socket_close(&tunnel->outgoing);

    tunnel->state = session_dead;
}

static int socket_cycle(const char *who, struct socket_ctx *a, struct socket_ctx *b) {
    if (a->result < 0) {
        if (a->result != UV_EOF) {
            pr_err("%s error: %s", who, uv_strerror((int)a->result));
        }
        return -1;
    }

    if (b->result < 0) {
        return -1;
    }

    if (a->wrstate == socket_done) {
        a->wrstate = socket_stop;
    }

    /* The logic is as follows: read when we don't write and write when we don't
    * read.  That gives us back-pressure handling for free because if the peer
    * sends data faster than we consume it, TCP congestion control kicks in.
    */
    if (a->wrstate == socket_stop) {
        if (b->rdstate == socket_stop) {
            socket_read(b);
        } else if (b->rdstate == socket_done) {
            socket_write(a, b->t.buf, b->result);
            b->rdstate = socket_stop;  /* Triggers the call to socket_read() above. */
        }
    }

    return 0;
}

static void socket_timer_reset(struct socket_ctx *c) {
    CHECK(0 == uv_timer_start(&c->timer_handle,
        socket_timer_expire_cb,
        c->idle_timeout,
        0));
}

static void socket_timer_expire_cb(uv_timer_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(handle, struct socket_ctx, timer_handle);
    c->result = UV_ETIMEDOUT;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    do_kill(tunnel);
}

static void socket_getaddrinfo(struct socket_ctx *c, const char *hostname) {
    struct addrinfo hints;
    struct tunnel_ctx *tunnel;

    tunnel = c->tunnel;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    CHECK(0 == uv_getaddrinfo(tunnel->lx->tcp_handle.loop,
        &c->t.addrinfo_req,
        socket_getaddrinfo_done_cb,
        hostname,
        NULL,
        &hints));
    socket_timer_reset(c);
}

static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, t.addrinfo_req);
    c->result = status;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    if (status == 0) {
        /* FIXME(bnoordhuis) Should try all addresses. */
        if (ai->ai_family == AF_INET) {
            c->t.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        } else if (ai->ai_family == AF_INET6) {
            c->t.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        } else {
            UNREACHABLE();
        }
    }

    uv_freeaddrinfo(ai);
    do_next(tunnel);
}

/* Assumes that c->t.sa contains a valid AF_INET or AF_INET6 address. */
static int socket_connect(struct socket_ctx *c) {
    ASSERT(c->t.addr.sa_family == AF_INET || c->t.addr.sa_family == AF_INET6);
    socket_timer_reset(c);
    return uv_tcp_connect(&c->t.connect_req,
        &c->handle.tcp,
        &c->t.addr,
        socket_connect_done_cb);
}

static void socket_connect_done_cb(uv_connect_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, t.connect_req);
    c->result = status;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    if (status == UV_ECANCELED || status == UV_ECONNREFUSED) {
        do_kill(tunnel);
        return;  /* Handle has been closed. */
    }

    do_next(tunnel);
}

static void socket_read(struct socket_ctx *c) {
    ASSERT(c->rdstate == socket_stop);
    CHECK(0 == uv_read_start(&c->handle.stream, socket_alloc_cb, socket_read_done_cb));
    c->rdstate = socket_busy;
    socket_timer_reset(c);
}

static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(handle, struct socket_ctx, handle);
    tunnel = c->tunnel;

    uv_read_stop(&c->handle.stream);

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    if (nread <= 0) {
        // http://docs.libuv.org/en/v1.x/stream.html
        ASSERT(nread == UV_EOF || nread == UV_ECONNRESET);
        if (nread < 0) { do_kill(tunnel); }
        return;
    }

    ASSERT(c->t.buf == buf->base);
    ASSERT(c->rdstate == socket_busy);
    c->rdstate = socket_done;
    c->result = nread;

    do_next(tunnel);
}

static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    struct socket_ctx *c;

    c = CONTAINER_OF(handle, struct socket_ctx, handle);
    ASSERT(c->rdstate == socket_busy);
    buf->base = c->t.buf;
    buf->len = sizeof(c->t.buf);
}

static void socket_write(struct socket_ctx *c, const void *data, size_t len) {
    uv_buf_t buf;

    ASSERT(c->wrstate == socket_stop || c->wrstate == socket_done);
    c->wrstate = socket_busy;

    /* It's okay to cast away constness here, uv_write() won't modify the
    * memory.
    */
    buf = uv_buf_init((char *)data, (unsigned int)len);

    CHECK(0 == uv_write(&c->write_req, &c->handle.stream, &buf, 1, socket_write_done_cb));
    socket_timer_reset(c);
}

static void socket_write_done_cb(uv_write_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, write_req);
    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    if (status == UV_ECANCELED) {
        do_kill(tunnel);
        return;  /* Handle has been closed. */
    }

    ASSERT(c->wrstate == socket_busy);
    c->wrstate = socket_done;
    c->result = status;
    do_next(tunnel);
}

static void socket_close(struct socket_ctx *c) {
    struct tunnel_ctx *tunnel = c->tunnel;
    ASSERT(c->rdstate != socket_dead);
    ASSERT(c->wrstate != socket_dead);
    c->rdstate = socket_dead;
    c->wrstate = socket_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;

    tunnel_add_ref(tunnel);
    uv_close(&c->handle.handle, socket_close_done_cb);
    tunnel_add_ref(tunnel);
    uv_close((uv_handle_t *)&c->timer_handle, socket_close_done_cb);
}

static void socket_close_done_cb(uv_handle_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = handle->data;
    tunnel = c->tunnel;

    tunnel_release(tunnel);
}
