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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "common.h"
#include "tunnel.h"
#include "dump_info.h"

#if !defined(ARRAY_SIZE)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))
#endif

static void tunnel_shutdown(struct tunnel_ctx *tunnel);
static void socket_timer_expire_cb(uv_timer_t *handle);
static void socket_timer_start(struct socket_ctx *c);
static void socket_timer_stop(struct socket_ctx *c);
static void socket_connect_done_cb(uv_connect_t *req, int status);
static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai);
static void socket_write_done_cb(uv_write_t *req, int status);
static void socket_close(struct socket_ctx *c);
static void socket_close_done_cb(uv_handle_t *handle);

socket_fd uv_stream_fd(const uv_tcp_t *handle) {
#if defined(_WIN32)
    return handle->socket;
#elif defined(__APPLE__)
    int uv___stream_fd(const uv_stream_t* handle);
    return uv___stream_fd((const uv_stream_t *)handle);
#else
    return (handle)->io_watcher.fd;
#endif
}

uint16_t get_socket_port(const uv_tcp_t *tcp) {
    union sockaddr_universal tmp = { {0} };
    int len = sizeof(tmp);
    if (uv_tcp_getsockname(tcp, &tmp.addr, &len) != 0) {
        return 0;
    } else {
        return ntohs(tmp.addr4.sin_port);
    }
}

size_t _update_tcp_mss(struct socket_ctx *socket) {
    socket_fd fd = uv_stream_fd(&socket->handle.tcp);
    return get_fd_tcp_mss(fd);
}

//
// Maximum segment size
// https://en.wikipedia.org/wiki/Maximum_segment_size
//
size_t get_fd_tcp_mss(socket_fd fd) {
#define NETWORK_MTU 1500
#define SS_TCP_MSS (NETWORK_MTU - 40)

    size_t _tcp_mss = SS_TCP_MSS;

    int mss = 0;
    socklen_t len = sizeof(mss);

    getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, (char *)&mss, &len);
    if (50 < mss && mss <= NETWORK_MTU) {
        _tcp_mss = (size_t) mss;
    }
    return _tcp_mss;
}

size_t socket_arrived_data_size(struct socket_ctx *socket, size_t suggested_size) {
    socket_fd fd = uv_stream_fd(&socket->handle.tcp);
    size_t data_size;

    char *tmp = (char *)calloc(suggested_size + 1, sizeof(*tmp));
    data_size = (size_t) recv(fd, tmp, (int)suggested_size, MSG_PEEK);
    if (data_size == 0) { data_size = suggested_size; }
    if (data_size >= 65536) { data_size = 65536/2; }
    free(tmp);

    return data_size;
}

bool tunnel_is_dead(struct tunnel_ctx *tunnel) {
    return (tunnel->terminated != false);
}

void tunnel_add_ref(struct tunnel_ctx *tunnel) {
    tunnel->ref_count++;
}

#if !defined(NDEBUG)
#define SSR_DUMP_TUNNEL_COUNT
#endif

#ifdef SSR_DUMP_TUNNEL_COUNT
int tunnel_count = 0;
#endif // SSR_DUMP_TUNNEL_COUNT

struct socket_ctx * socket_context_create(struct tunnel_ctx *tunnel, unsigned int idle_timeout) {
    struct socket_ctx *ctx = (struct socket_ctx *) calloc(1, sizeof(*ctx));
    ctx->tunnel = tunnel;
    ctx->result = 0;
    ctx->rdstate = socket_state_stop;
    ctx->wrstate = socket_state_stop;
    ctx->idle_timeout = idle_timeout;
    VERIFY(0 == uv_timer_init(tunnel->loop, &ctx->timer_handle));
    VERIFY(0 == uv_tcp_init(tunnel->loop, &ctx->handle.tcp));
    return ctx;
}

void socket_context_release(struct socket_ctx *ctx) {
    free(ctx);
}

void tunnel_release(struct tunnel_ctx *tunnel) {
    tunnel->ref_count--;
    ASSERT(tunnel->ref_count >= 0);
    if (tunnel->ref_count > 0) {
        return;
    }

    if (tunnel->tunnel_dying) {
        tunnel->tunnel_dying(tunnel);
    }

#ifdef SSR_DUMP_TUNNEL_COUNT
    pr_info("==== tunnel destroyed   count %3d ====", --tunnel_count);
#endif // SSR_DUMP_TUNNEL_COUNT

    socket_context_release(tunnel->incoming);

    socket_context_release(tunnel->outgoing);

    free(tunnel->desired_addr);

    memset(tunnel, 0, sizeof(*tunnel));
    free(tunnel);
}

/* |incoming| has been initialized by listener.c when this is called. */
struct tunnel_ctx * tunnel_initialize(uv_loop_t *loop, uv_tcp_t *listener, unsigned int idle_timeout, tunnel_init_done_cb init_done_cb, void *p) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    struct tunnel_ctx *tunnel;
    bool success = false;

    if (listener) {
        VERIFY(loop == listener->loop);
    }
#ifdef SSR_DUMP_TUNNEL_COUNT
    pr_info("==== tunnel created     count %3d ====", ++tunnel_count);
#endif // SSR_DUMP_TUNNEL_COUNT

    tunnel = (struct tunnel_ctx *) calloc(1, sizeof(*tunnel));

    tunnel->loop = loop;
    tunnel->ref_count = 0;
    tunnel->desired_addr = (struct socks5_address *)calloc(1, sizeof(struct socks5_address));

    incoming = socket_context_create(tunnel, idle_timeout);
    if (listener) {
        VERIFY(0 == uv_accept((uv_stream_t *)listener, &incoming->handle.stream));
    }
    tunnel->incoming = incoming;

    outgoing = socket_context_create(tunnel, idle_timeout);
    tunnel->outgoing = outgoing;

    tunnel->tunnel_shutdown = &tunnel_shutdown;

    if (init_done_cb) {
        success = init_done_cb(tunnel, p);
    }

    tunnel_add_ref(tunnel);

    if (success) {
        if (listener) {
            /* Wait for the initial packet. */
            socket_read(incoming, true);
        }
    } else {
        tunnel->tunnel_shutdown(tunnel);
        tunnel = NULL;
    }
    return tunnel;
}

static void tunnel_shutdown(struct tunnel_ctx *tunnel) {
    if (tunnel_is_dead(tunnel) != false) {
        return;
    }
    tunnel->terminated = true;

    /* Try to cancel the request. The callback still runs but if the
    * cancellation succeeded, it gets called with status=UV_ECANCELED.
    */
    if (tunnel->getaddrinfo_pending) {
        uv_cancel(&tunnel->outgoing->req.req);
    }

    socket_close(tunnel->incoming);
    socket_close(tunnel->outgoing);

    tunnel_release(tunnel);
}

//
// The logic is as follows: read when we don't write and write when we don't read.
// That gives us back-pressure handling for free because if the peer
// sends data faster than we consume it, TCP congestion control kicks in.
//
void tunnel_traditional_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *current_socket = socket;
    struct socket_ctx *target_socket = NULL;

    // 当前 网口 肯定是 入网口 或者 出网口 .
    ASSERT(current_socket == tunnel->incoming || current_socket == tunnel->outgoing);

    // 目标 网口 肯定是 当前 网口 的对立面，非此即彼 .
    target_socket = ((current_socket == tunnel->incoming) ? tunnel->outgoing : tunnel->incoming);

    // 当前 网口 的状态肯定是 写妥了 或者 读妥了，二者必居其一，但不可能同时既是读妥又是写妥 .
    ASSERT((current_socket->wrstate == socket_state_done && current_socket->rdstate != socket_state_done) ||
           (current_socket->wrstate != socket_state_done && current_socket->rdstate == socket_state_done));

    // 目标 网口 的读状态肯定不是读妥，写状态肯定不是写妥，而只可能是忙碌或者已停止 .
    ASSERT(target_socket->wrstate != socket_state_done && target_socket->rdstate != socket_state_done);

    if (current_socket->wrstate == socket_state_done) {
        // 如果 当前 网口 的写状态是 写妥 :
        current_socket->wrstate = socket_state_stop;
        if (target_socket->rdstate == socket_state_stop) {
            // 目标网口 的读状态如果是已停止，则开始读目标网口 .
            // 只对读取 出网口 做超时断开处理, 而对读取 入网口 不处理超时 .
            // 这很重要, 否则可能数据传输不完整即被断开 .
            socket_read(target_socket, (target_socket == tunnel->outgoing));
        }
    }
    else if (current_socket->rdstate == socket_state_done) {
        // 当前 网口 的读状态是 读妥 :
        current_socket->rdstate = socket_state_stop;

        // 目标 网口 的写状态 肯定 是 已停止, 可以再次写入了 .
        ASSERT(target_socket->wrstate == socket_state_stop);
        {
            size_t len = 0;
            uint8_t *buf = NULL;
            ASSERT(tunnel->tunnel_extract_data);
            buf = tunnel->tunnel_extract_data(current_socket, &malloc, &len);
            if (buf /* && len > 0 */) {
                // 从当前 网口 提取数据然后写入 目标 网口 .
                socket_write(target_socket, buf, len);
            } else {
                tunnel->tunnel_shutdown(tunnel);
            }
            free(buf);
        }
    }
    else {
        ASSERT(false);
    }
}

static void socket_timer_start(struct socket_ctx *c) {
    VERIFY(0 == uv_timer_start(&c->timer_handle,
        socket_timer_expire_cb,
        c->idle_timeout,
        0));
}

static void socket_timer_stop(struct socket_ctx *c) {
    VERIFY(0 == uv_timer_stop(&c->timer_handle));
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

    if (tunnel->tunnel_timeout_expire_done) {
        tunnel->tunnel_timeout_expire_done(tunnel, c);
    }

    tunnel->tunnel_shutdown(tunnel);
}

/* Assumes that c->t.sa contains a valid AF_INET or AF_INET6 address. */
int socket_connect(struct socket_ctx *c) {
    ASSERT(c->addr.addr.sa_family == AF_INET || c->addr.addr.sa_family == AF_INET6);
    socket_timer_start(c);
    return uv_tcp_connect(&c->req.connect,
        &c->handle.tcp,
        &c->addr.addr,
        socket_connect_done_cb);
}

static void socket_connect_done_cb(uv_connect_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, req.connect);
    c->result = status;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0 /*status == UV_ECANCELED || status == UV_ECONNREFUSED*/) {
        socket_dump_error_info("connect failed", c);
        tunnel->tunnel_shutdown(tunnel);
        return;  /* Handle has been closed. */
    }

    ASSERT(tunnel->tunnel_outgoing_connected_done);
    tunnel->tunnel_outgoing_connected_done(tunnel, c);
}

bool socket_is_readable(struct socket_ctx *sc) {
    return sc ? (sc->rdstate == socket_state_stop) : false;
}

bool socket_is_writeable(struct socket_ctx *sc) {
    return sc ? (sc->wrstate == socket_state_stop) : false;
}

void socket_read(struct socket_ctx *c, bool check_timeout) {
    ASSERT(c->rdstate == socket_state_stop);
    VERIFY(0 == uv_read_start(&c->handle.stream, socket_alloc_cb, socket_read_done_cb));
    c->rdstate = socket_state_busy;
    if (check_timeout) {
        socket_timer_start(c);
    }
}

static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    do {
        c = CONTAINER_OF(handle, struct socket_ctx, handle);
        c->result = nread;
        tunnel = c->tunnel;

        if (tunnel_is_dead(tunnel)) {
            break;
        }

        if (nread == 0) {
            // NOT indicate an error or EOF.
            // This is equivalent to EAGAIN or EWOULDBLOCK under read(2).
            break;
        }

        uv_read_stop(&c->handle.stream);
        socket_timer_stop(c);

        if (nread < 0) {
            ASSERT(c->rdstate == socket_state_busy);
            c->rdstate = socket_state_stop;

            // http://docs.libuv.org/en/v1.x/stream.html
            if (nread != UV_EOF) {
                socket_dump_error_info("receive data failed", c);
            }
            if ((nread == UV_EOF) && tunnel->tunnel_arrive_end_of_file) {
                tunnel->tunnel_arrive_end_of_file(tunnel, c);
            } else {
                tunnel->tunnel_shutdown(tunnel);
            }
            break;
        }

        c->buf = buf;
        ASSERT(c->rdstate == socket_state_busy);
        c->rdstate = socket_state_done;

        ASSERT(tunnel->tunnel_read_done);
        tunnel->tunnel_read_done(tunnel, c);
    } while (0);

    if (buf->base) {
        free(buf->base); // important!!!
    }
    c->buf = NULL;
}

static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    struct socket_ctx *ctx;
    struct tunnel_ctx *tunnel;

    ctx = CONTAINER_OF(handle, struct socket_ctx, handle);
    tunnel = ctx->tunnel;

    ASSERT(ctx->rdstate == socket_state_busy);

    if (tunnel->tunnel_get_alloc_size) {
        size = tunnel->tunnel_get_alloc_size(tunnel, ctx, size);
    }

    *buf = uv_buf_init((char *)calloc(size, sizeof(char)), (unsigned int)size);
}

void socket_getaddrinfo(struct socket_ctx *c, const char *hostname) {
    struct addrinfo hints;
    struct tunnel_ctx *tunnel;
    uv_loop_t *loop;

    tunnel = c->tunnel;
    loop = tunnel->loop;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    VERIFY(0 == uv_getaddrinfo(loop,
        &c->req.getaddrinfo,
        socket_getaddrinfo_done_cb,
        hostname,
        NULL,
        &hints));
    socket_timer_start(c);
    tunnel->getaddrinfo_pending = true;
}

static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, req.getaddrinfo);
    c->result = status;

    tunnel = c->tunnel;
    tunnel->getaddrinfo_pending = false;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0) {
        socket_dump_error_info("resolve address failed", c);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (status == 0) {
        /* FIXME(bnoordhuis) Should try all addresses. */
        uint16_t port = c->addr.addr4.sin_port;
        if (ai->ai_family == AF_INET) {
            c->addr.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        } else if (ai->ai_family == AF_INET6) {
            c->addr.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        } else {
            UNREACHABLE();
        }
        c->addr.addr4.sin_port = port;
    }

    uv_freeaddrinfo(ai);

    ASSERT(tunnel->tunnel_getaddrinfo_done);
    tunnel->tunnel_getaddrinfo_done(tunnel, c);
}

void socket_write(struct socket_ctx *c, const void *data, size_t len) {
    uv_buf_t buf;
    struct tunnel_ctx *tunnel = c->tunnel;
    char *write_buf = NULL;
    uv_write_t *req;

    (void)tunnel;
    ASSERT(c->wrstate == socket_state_stop);
    c->wrstate = socket_state_busy;

    // It's okay to cast away constness here, uv_write() won't modify the memory.
    write_buf = (char *)calloc(len + 1, sizeof(*write_buf));
    memcpy(write_buf, data, len);
    buf = uv_buf_init(write_buf, (unsigned int)len);

    req = (uv_write_t *)calloc(1, sizeof(uv_write_t));
    req->data = write_buf;

    VERIFY(0 == uv_write(req, &c->handle.stream, &buf, 1, socket_write_done_cb));
    socket_timer_start(c);
}

static void socket_write_done_cb(uv_write_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;
    char *write_buf = NULL;

    c = CONTAINER_OF(req->handle, struct socket_ctx, handle.stream);

    VERIFY((write_buf = (char *)req->data));
    free(write_buf);

    c->result = status;
    free(req);
    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0 /*status == UV_ECANCELED*/) {
        c->wrstate = socket_state_stop;
        socket_dump_error_info("send data failed", c);
        tunnel->tunnel_shutdown(tunnel);
        return;  /* Handle has been closed. */
    }

    ASSERT(c->wrstate == socket_state_busy);
    c->wrstate = socket_state_done;

    ASSERT(tunnel->tunnel_write_done);
    tunnel->tunnel_write_done(tunnel, c);
}

static void socket_close(struct socket_ctx *c) {
    struct tunnel_ctx *tunnel = c->tunnel;
    ASSERT(c->rdstate != socket_state_dead);
    ASSERT(c->wrstate != socket_state_dead);
    c->rdstate = socket_state_dead;
    c->wrstate = socket_state_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;

    uv_read_stop(&c->handle.stream);
    socket_timer_stop(c);

    tunnel_add_ref(tunnel);
    uv_close(&c->handle.handle, socket_close_done_cb);
    tunnel_add_ref(tunnel);
    uv_close((uv_handle_t *)&c->timer_handle, socket_close_done_cb);
}

static void socket_close_done_cb(uv_handle_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = (struct socket_ctx *) handle->data;
    tunnel = c->tunnel;

    tunnel_release(tunnel);
}

void socket_dump_error_info(const char *title, struct socket_ctx *socket) {
    struct tunnel_ctx *tunnel = socket->tunnel;
    int error = (int)socket->result;
    char addr[256] = { 0 };
    const char *from = NULL;
    if (socket == tunnel->outgoing) {
        socks5_address_to_string(tunnel->desired_addr, addr, sizeof(addr));
        from = "_server_";
    } else {
        union sockaddr_universal tmp = { {0} };
        int len = sizeof(tmp);
        uv_tcp_getpeername(&socket->handle.tcp, &tmp.addr, &len);
        universal_address_to_string(&tmp, addr, sizeof(addr));
        if ((strcmp(addr, "127.0.0.1") == 0) || (strlen(addr) == 0)) {
            socks5_address_to_string(tunnel->desired_addr, addr, sizeof(addr));
            sprintf(addr + strlen(addr), ":%d", (int)tunnel->desired_addr->port);
        }
        from = "_client_";
    }
    pr_err("%s about %s \"%s\": %s", title, from, addr, uv_strerror(error));
}
