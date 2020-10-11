/* Copyright @ssrlive. All rights reserved.
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

#include "tunnel.h"
#include "common.h"
#include "dump_info.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#if !defined(ARRAY_SIZE)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*(arr)))
#endif

static void socket_ctx_timer_start(struct socket_ctx* socket);
static void socket_ctx_timer_stop(struct socket_ctx* socket);

static void tunnel_socket_ctx_on_getaddrinfo_cb(struct socket_ctx* socket, int status, const struct addrinfo* ai, void* p);
static void tunnel_socket_ctx_on_connect_cb(struct socket_ctx* socket, int status, void* p);
static size_t tunnel_socket_ctx_on_alloc_cb(struct socket_ctx* socket, size_t size, void* p);
static void tunnel_socket_ctx_on_read_cb(struct socket_ctx* socket, int status, const uv_buf_t* buf, void* p);
static void tunnel_socket_ctx_on_written_cb(struct socket_ctx* socket, int status, void* p);
static void tunnel_socket_ctx_on_timeout_cb(struct socket_ctx* socket, void* p);

uv_os_sock_t uv_stream_fd(const uv_tcp_t* handle) {
    uv_os_fd_t fd = (uv_os_fd_t)-1;
    if (handle) {
        uv_fileno((const uv_handle_t*)handle, &fd);
    }
    return (uv_os_sock_t)fd;
}

uint16_t get_socket_port(const uv_tcp_t* tcp) {
    union sockaddr_universal tmp = { { 0 } };
    int len = sizeof(tmp);
    if (uv_tcp_getsockname(tcp, &tmp.addr, &len) != 0) {
        return 0;
    } else {
        return ntohs(tmp.addr4.sin_port);
    }
}

size_t update_tcp_mss(struct socket_ctx* socket) {
    uv_os_sock_t fd = uv_stream_fd(&socket->handle.tcp);
    return get_fd_tcp_mss(fd);
}

//
// Maximum segment size
// https://en.wikipedia.org/wiki/Maximum_segment_size
//
size_t get_fd_tcp_mss(uv_os_sock_t fd) {
#define NETWORK_MTU 1500
#define SS_TCP_MSS (NETWORK_MTU - 40)

    size_t tcp__mss = SS_TCP_MSS;

    int mss = 0;
    socklen_t len = sizeof(mss);

    getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, (char*)&mss, &len);
    if (50 < mss && mss <= NETWORK_MTU) {
        tcp__mss = (size_t)mss;
    }
    return tcp__mss;
}

size_t socket_arrived_data_size(struct socket_ctx* socket, size_t suggested_size) {
    uv_os_sock_t fd = uv_stream_fd(&socket->handle.tcp);
    size_t data_size;

    char* tmp = (char*)calloc(suggested_size + 1, sizeof(*tmp));
    data_size = (size_t)recv(fd, tmp, (int)suggested_size, MSG_PEEK);
    if (data_size == 0) { data_size = suggested_size; }
    if (data_size >= 65536) { data_size = 65536 / 2; }
    free(tmp);

    return data_size;
}

#ifdef __PRINT_INFO__
int tunnel_count = 0;
#endif // __PRINT_INFO__

struct socket_ctx* socket_context_create(uv_loop_t* loop, unsigned int idle_timeout) {
    struct socket_ctx* socket = (struct socket_ctx*)calloc(1, sizeof(*socket));
    socket->result = 0;
    socket->rdstate = socket_state_stop;
    socket->wrstate = socket_state_stop;
    socket->idle_timeout = idle_timeout;
    VERIFY(0 == uv_timer_init(loop, &socket->timer_handle));
    VERIFY(0 == uv_tcp_init(loop, &socket->handle.tcp));
    socket_ctx_add_ref(socket);
    return socket;
}

void socket_context_free_internal(struct socket_ctx* socket) {
    free(socket);
}

REF_COUNT_ADD_REF_IMPL(socket_ctx)
REF_COUNT_RELEASE_IMPL(socket_ctx, socket_context_free_internal)

static void uv_socket_connect_done_cb(uv_connect_t* req, int status) {
    struct socket_ctx* socket = CONTAINER_OF(req, struct socket_ctx, req.connect);
    socket->result = status;

    socket_ctx_timer_stop(socket);
    if (socket->on_connect) {
        socket->on_connect(socket, status, socket->on_connect_p);
    }
}

/* Assumes that c->t.sa contains a valid AF_INET or AF_INET6 address. */
int socket_ctx_connect(struct socket_ctx* socket) {
    int result;
    ASSERT(socket->addr.addr.sa_family == AF_INET || socket->addr.addr.sa_family == AF_INET6);
    result = uv_tcp_connect(&socket->req.connect,
        &socket->handle.tcp,
        &socket->addr.addr,
        uv_socket_connect_done_cb);
    if (result == 0) {
        socket_ctx_timer_start(socket);
    }
    return result;
}

static void uv_socket_timer_expire_cb(uv_timer_t* handle) {
    struct socket_ctx* socket = CONTAINER_OF(handle, struct socket_ctx, timer_handle);
    socket->result = UV_ETIMEDOUT;
    socket_ctx_add_ref(socket);
    if (socket->on_timeout) {
        socket->on_timeout(socket, socket->on_timeout_p);
    }
    socket_ctx_release(socket);
}

static void socket_ctx_timer_start(struct socket_ctx* socket) {
    VERIFY(0 == uv_timer_start(&socket->timer_handle, uv_socket_timer_expire_cb, socket->idle_timeout, 0));
}

static void socket_ctx_timer_stop(struct socket_ctx* socket) {
    VERIFY(0 == uv_timer_stop(&socket->timer_handle));
}

bool socket_ctx_is_readable(struct socket_ctx* socket) {
    return socket ? (socket->rdstate == socket_state_stop) : false;
}

bool socket_ctx_is_writeable(struct socket_ctx* socket) {
    return socket ? (socket->wrstate == socket_state_stop) : false;
}

static void uv_socket_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
    struct socket_ctx* socket = CONTAINER_OF(handle, struct socket_ctx, handle);
    if (socket->on_alloc) {
        size = socket->on_alloc(socket, size, socket->on_alloc_p);
    }
    *buf = uv_buf_init((char*)calloc(size, sizeof(char)), (unsigned int)size);
}

static void uv_socket_read_done_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    struct socket_ctx* socket = CONTAINER_OF(handle, struct socket_ctx, handle);
    socket->result = (int)nread;
    do {
        if (nread == 0) {
            // http://docs.libuv.org/en/v1.x/stream.html
            // NOT indicate an error or EOF.
            // This is equivalent to EAGAIN or EWOULDBLOCK under read(2).
            break;
        }
        if (socket->on_read) {
            uv_buf_t tmp = uv_buf_init(buf->base, (unsigned int)(nread > 0 ? nread : 0));
            socket->on_read(socket, (int)nread, &tmp, socket->on_read_p);
        }
    } while (false);
    if (buf->base) {
        free(buf->base); // important!!!
    }
}

void socket_ctx_read(struct socket_ctx* socket, bool check_timeout) {
    ASSERT(socket->rdstate == socket_state_stop);
    VERIFY(0 == uv_read_start(&socket->handle.stream, uv_socket_alloc_cb, uv_socket_read_done_cb));
    socket->rdstate = socket_state_busy;
    socket->check_timeout = check_timeout;
    if (check_timeout) {
        socket_ctx_timer_start(socket);
    }
}

static void uv_socket_on_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* ai) {
    struct socket_ctx* socket = CONTAINER_OF(req, struct socket_ctx, req.getaddrinfo);
    socket->result = status;

    socket->on_getaddrinfo_pending = false;

    socket_ctx_timer_stop(socket);

    if (status == 0) {
        uint16_t port = socket->addr.addr4.sin_port;
#if 0
        bool found = false;
        struct addrinfo* iter;
        for (iter = ai; iter != NULL; iter = iter->ai_next) {
            if (iter->ai_family == AF_INET) {
                socket->addr.addr4 = *(const struct sockaddr_in*)iter->ai_addr;
                found = true;
                break;
            }
        }
        if (found == false) {
            for (iter = ai; iter != NULL; iter = iter->ai_next) {
                if (iter->ai_family == AF_INET6) {
                    socket->addr.addr6 = *(const struct sockaddr_in6*)iter->ai_addr;
                    found = true;
                    break;
                }
            }
        }
        ASSERT(found);
#else
        if (ai->ai_family == AF_INET) {
            socket->addr.addr4 = *(const struct sockaddr_in*)ai->ai_addr;
        } else if (ai->ai_family == AF_INET6) {
            socket->addr.addr6 = *(const struct sockaddr_in6*)ai->ai_addr;
        } else {
            UNREACHABLE();
        }
#endif
        socket->addr.addr4.sin_port = port;
    }

    if (socket->on_getaddrinfo) {
        socket->on_getaddrinfo(socket, status, ai, socket->on_getaddrinfo_p);
    }

    uv_freeaddrinfo(ai);
}

void socket_ctx_getaddrinfo(struct socket_ctx* socket, const char* hostname, uint16_t port) {
    uv_loop_t* loop = socket->handle.tcp.loop;

    socket->addr.addr4.sin_port = htons(port);

    VERIFY(0 == uv_getaddrinfo(loop, &socket->req.getaddrinfo, uv_socket_on_getaddrinfo_cb, hostname, NULL, NULL));
    socket_ctx_timer_start(socket);
    socket->on_getaddrinfo_pending = true;
}

static void uv_socket_write_done_cb(uv_write_t* req, int status) {
    struct socket_ctx* socket = CONTAINER_OF(req->handle, struct socket_ctx, handle.stream);
    char* write_buf = NULL;

    VERIFY((write_buf = (char*)req->data));
    free(write_buf);

    free(req);

    socket->result = status;

    if (socket->on_written) {
        socket->on_written(socket, status, socket->on_written_p);
    }
}

void socket_ctx_write(struct socket_ctx* socket, const void* data, size_t len) {
    uv_buf_t buf;
    char* write_buf = NULL;
    uv_write_t* req;

    socket->wrstate = socket_state_busy;

    // It's okay to cast away constness here, uv_write() won't modify the memory.
    write_buf = (char*)calloc(len + 1, sizeof(*write_buf));
    memcpy(write_buf, data, len);
    buf = uv_buf_init(write_buf, (unsigned int)len);

    req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
    req->data = write_buf;

    VERIFY(0 == uv_write(req, &socket->handle.stream, &buf, 1, uv_socket_write_done_cb));
}

bool socket_ctx_is_terminated(struct socket_ctx* socket) {
    if (socket == NULL) { return true; }
    return (socket->is_terminated != false);
}

static void uv_socket_close_done_cb(uv_handle_t* handle) {
    struct socket_ctx* socket = (struct socket_ctx*)handle->data;
    if ((--socket->closing_count) <= 0) {
        ASSERT(socket->closing_count == 0);
        if (socket->on_closed) {
            socket->on_closed(socket, socket->on_closed_p);
            socket->on_closed = NULL;
            socket->on_closed_p = NULL;
        }
    }
    socket_ctx_release(socket);
}

void socket_ctx_close(struct socket_ctx* socket, socket_ctx_on_closed_cb on_closed, void* p) {
    if (socket_ctx_is_terminated(socket)) {
        on_closed(socket, p);
        return;
    }
    socket->is_terminated = true;

    ASSERT(socket->rdstate != socket_state_dead);
    ASSERT(socket->wrstate != socket_state_dead);
    socket->rdstate = socket_state_dead;
    socket->wrstate = socket_state_dead;
    socket->timer_handle.data = socket;
    socket->handle.handle.data = socket;

    if (socket->on_getaddrinfo_pending) {
        uv_cancel(&socket->req.req);
    }

    uv_read_stop(&socket->handle.stream);
    socket_ctx_timer_stop(socket);

    socket_ctx_add_ref(socket);
    uv_close(&socket->handle.handle, uv_socket_close_done_cb);
    socket_ctx_add_ref(socket);
    uv_close((uv_handle_t*)&socket->timer_handle, uv_socket_close_done_cb);
    socket->closing_count = 2;

    socket->on_closed = on_closed;
    socket->on_closed_p = p;
}

void socket_ctx_set_on_getaddrinfo_cb(struct socket_ctx* socket, socket_ctx_on_getaddrinfo_cb on_getaddrinfo, void* p) {
    if (socket) {
        socket->on_getaddrinfo = on_getaddrinfo;
        socket->on_getaddrinfo_p = p;
    }
}

void socket_ctx_set_on_connect_cb(struct socket_ctx* socket, socket_ctx_on_connect_cb on_connect, void* p) {
    if (socket) {
        socket->on_connect = on_connect;
        socket->on_connect_p = p;
    }
}

void socket_ctx_set_on_alloc_cb(struct socket_ctx* socket, socket_ctx_on_alloc_cb on_alloc, void* p) {
    if (socket) {
        socket->on_alloc = on_alloc;
        socket->on_alloc_p = p;
    }
}

void socket_ctx_set_on_read_cb(struct socket_ctx* socket, socket_ctx_on_read_cb on_read, void* p) {
    if (socket) {
        socket->on_read = on_read;
        socket->on_read_p = p;
    }
}

void socket_ctx_set_on_written_cb(struct socket_ctx* socket, socket_ctx_on_written_cb on_written, void* p) {
    if (socket) {
        socket->on_written = on_written;
        socket->on_written_p = p;
    }
}

void socket_ctx_set_on_timeout_cb(struct socket_ctx* socket, socket_ctx_on_timeout_cb on_timeout, void* p) {
    if (socket) {
        socket->on_timeout = on_timeout;
        socket->on_timeout_p = p;
    }
}

////////////////////////////////// struct tunnel_ctx ////////////////////////////

static void tunnel_shutdown(struct tunnel_ctx* tunnel);
static bool tunnel_is_terminated(struct tunnel_ctx* tunnel);

void tunnel_destroy_internal(struct tunnel_ctx* tunnel) {
    if (tunnel->tunnel_destroying) {
        tunnel->tunnel_destroying(tunnel);
    }

#ifdef __PRINT_INFO__
    pr_info("==== tunnel destroyed   count %3d ====", --tunnel_count);
#endif // __PRINT_INFO__

    socket_ctx_release(tunnel->incoming);

    socket_ctx_release(tunnel->outgoing);

    free(tunnel->desired_addr);

    memset(tunnel, 0, sizeof(*tunnel));
    free(tunnel);
}

REF_COUNT_ADD_REF_IMPL(tunnel_ctx)

REF_COUNT_RELEASE_IMPL(tunnel_ctx, tunnel_destroy_internal)

static void tunnel_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    ASSERT(!"You must override this function!");
    (void)tunnel; (void)socket;
}

static bool tunnel_is_in_streaming(struct tunnel_ctx* tunnel) {
    ASSERT(!"You must override this function!");
    (void)tunnel;
    return false;
}

/* |incoming| has been initialized by listener.c when this is called. */
struct tunnel_ctx* tunnel_initialize(uv_loop_t* loop, uv_tcp_t* listener, unsigned int idle_timeout, tunnel_init_done_cb init_done_cb, void* p) {
    struct socket_ctx* incoming;
    struct socket_ctx* outgoing;
    struct tunnel_ctx* tunnel;
    bool success = false;

    if (listener) {
        VERIFY(loop == listener->loop);
    }
#ifdef __PRINT_INFO__
    pr_info("==== tunnel created     count %3d ====", ++tunnel_count);
#endif // __PRINT_INFO__

    tunnel = (struct tunnel_ctx*)calloc(1, sizeof(*tunnel));

    tunnel->loop = loop;
    tunnel->desired_addr = (struct socks5_address*)calloc(1, sizeof(struct socks5_address));

    incoming = socket_context_create(loop, idle_timeout);
    socket_ctx_set_on_getaddrinfo_cb(incoming, tunnel_socket_ctx_on_getaddrinfo_cb, tunnel);
    socket_ctx_set_on_connect_cb(incoming, tunnel_socket_ctx_on_connect_cb, tunnel);
    socket_ctx_set_on_alloc_cb(incoming, tunnel_socket_ctx_on_alloc_cb, tunnel);
    socket_ctx_set_on_read_cb(incoming, tunnel_socket_ctx_on_read_cb, tunnel);
    socket_ctx_set_on_written_cb(incoming, tunnel_socket_ctx_on_written_cb, tunnel);
    socket_ctx_set_on_timeout_cb(incoming, tunnel_socket_ctx_on_timeout_cb, tunnel);

    if (listener) {
        VERIFY(0 == uv_accept((uv_stream_t*)listener, &incoming->handle.stream));
    }
    tunnel->incoming = incoming;

    outgoing = socket_context_create(loop, idle_timeout);
    socket_ctx_set_on_getaddrinfo_cb(outgoing, tunnel_socket_ctx_on_getaddrinfo_cb, tunnel);
    socket_ctx_set_on_connect_cb(outgoing, tunnel_socket_ctx_on_connect_cb, tunnel);
    socket_ctx_set_on_alloc_cb(outgoing, tunnel_socket_ctx_on_alloc_cb, tunnel);
    socket_ctx_set_on_read_cb(outgoing, tunnel_socket_ctx_on_read_cb, tunnel);
    socket_ctx_set_on_written_cb(outgoing, tunnel_socket_ctx_on_written_cb, tunnel);
    socket_ctx_set_on_timeout_cb(outgoing, tunnel_socket_ctx_on_timeout_cb, tunnel);

    tunnel->outgoing = outgoing;

    tunnel->tunnel_shutdown = &tunnel_shutdown;
    tunnel->tunnel_is_in_streaming = &tunnel_is_in_streaming;
    tunnel->tunnel_dispatcher = &tunnel_dispatcher;
    tunnel->tunnel_is_terminated = &tunnel_is_terminated;

    if (init_done_cb) {
        success = init_done_cb(tunnel, p);
    }

    tunnel_ctx_add_ref(tunnel);

    if (success) {
        if (listener) {
            /* Wait for the initial packet. */
            socket_ctx_read(incoming, true);
        }
    } else {
        tunnel->tunnel_shutdown(tunnel);
        tunnel = NULL;
    }
    return tunnel;
}

static bool tunnel_is_terminated(struct tunnel_ctx* tunnel) {
    if (tunnel == NULL) { return true; }
    assert(tunnel && (tunnel->is_terminated == false || tunnel->is_terminated == true));
    return (tunnel->is_terminated != false);
}

static void tunnel_socket_ctx_on_closed_cb(struct socket_ctx* socket, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)p;
    tunnel_ctx_release(tunnel);
    (void)socket;
}

static void tunnel_shutdown(struct tunnel_ctx* tunnel) {
    if (tunnel->is_terminated != false) {
        return;
    }
    tunnel->is_terminated = true;

    tunnel_ctx_add_ref(tunnel);
    socket_ctx_close(tunnel->incoming, tunnel_socket_ctx_on_closed_cb, tunnel);

    tunnel_ctx_add_ref(tunnel);
    socket_ctx_close(tunnel->outgoing, tunnel_socket_ctx_on_closed_cb, tunnel);

    tunnel_ctx_release(tunnel);
}

static void tunnel_socket_ctx_on_timeout_cb(struct socket_ctx* socket, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)p;

    if (tunnel->tunnel_is_terminated(tunnel)) {
        return;
    }

    if (tunnel->tunnel_timeout_expire_done) {
        tunnel->tunnel_timeout_expire_done(tunnel, socket);
    }

    tunnel->tunnel_shutdown(tunnel);
}

static void tunnel_socket_ctx_on_connect_cb(struct socket_ctx* socket, int status, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)p;

    if (tunnel->tunnel_is_terminated(tunnel)) {
        return;
    }

    if (status < 0 /*status == UV_ECANCELED || status == UV_ECONNREFUSED*/) {
        tunnel_dump_error_info(tunnel, socket, "connect failed");
        tunnel->tunnel_shutdown(tunnel);
        return; /* Handle has been closed. */
    }

    ASSERT(tunnel->tunnel_outgoing_connected_done);
    if (tunnel->tunnel_outgoing_connected_done) {
        tunnel->tunnel_outgoing_connected_done(tunnel, socket);
    }
}

static void tunnel_socket_ctx_on_read_cb(struct socket_ctx* socket, int status, const uv_buf_t* buf, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)p;
    do {
        if (tunnel->tunnel_is_terminated(tunnel)) {
            break;
        }

        if (tunnel->tunnel_is_in_streaming(tunnel) == false) {
            uv_read_stop(&socket->handle.stream);
        }

        socket_ctx_timer_stop(socket);

        if (status < 0) {
            if (tunnel->tunnel_is_in_streaming(tunnel) == false) {
                ASSERT(socket->rdstate == socket_state_busy);
            }
            socket->rdstate = socket_state_stop;

            // http://docs.libuv.org/en/v1.x/stream.html
            if (status != UV_EOF) {
                tunnel_dump_error_info(tunnel, socket, "receive data failed");
            }
            if ((status == UV_EOF) && tunnel->tunnel_arrive_end_of_file) {
                tunnel->tunnel_arrive_end_of_file(tunnel, socket);
            } else {
                tunnel->tunnel_shutdown(tunnel);
            }
            break;
        }

        socket->buf = buf;
        if (tunnel->tunnel_is_in_streaming(tunnel) == false) {
            ASSERT(socket->rdstate == socket_state_busy);
        }
        socket->rdstate = socket_state_done;

        ASSERT(tunnel->tunnel_read_done);
        if (tunnel->tunnel_read_done) {
            tunnel->tunnel_read_done(tunnel, socket);
        }
        socket->buf = NULL;

        if (tunnel->tunnel_is_in_streaming(tunnel) && socket->check_timeout) {
            socket_ctx_timer_start(socket);
        }
    } while (0);
}

static size_t tunnel_socket_ctx_on_alloc_cb(struct socket_ctx* socket, size_t size, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)p;

    if (tunnel->tunnel_is_in_streaming(tunnel) == false) {
        ASSERT(socket->rdstate == socket_state_busy);
    }

    if (tunnel->tunnel_get_alloc_size) {
        size = tunnel->tunnel_get_alloc_size(tunnel, socket, size);
    }
    return size;
}

static void tunnel_socket_ctx_on_getaddrinfo_cb(struct socket_ctx* socket, int status, const struct addrinfo* ai, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)p;
    if (tunnel->tunnel_is_terminated(tunnel)) {
        return;
    }

    if (status < 0) {
        tunnel_dump_error_info(tunnel, socket, "resolve address failed");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    ASSERT(tunnel->tunnel_on_getaddrinfo_done);
    if (tunnel->tunnel_on_getaddrinfo_done) {
        tunnel->tunnel_on_getaddrinfo_done(tunnel, socket, ai);
    }
}

static void tunnel_socket_ctx_on_written_cb(struct socket_ctx* socket, int status, void* p) {
    struct tunnel_ctx* tunnel = (struct tunnel_ctx*)p;

    if (tunnel->tunnel_is_terminated(tunnel)) {
        return;
    }

    if (status < 0 /*status == UV_ECANCELED*/) {
        socket->wrstate = socket_state_stop;
        tunnel_dump_error_info(tunnel, socket, "send data failed");
        tunnel->tunnel_shutdown(tunnel);
        return; /* Handle has been closed. */
    }

    if (tunnel->tunnel_is_in_streaming(tunnel) == false) {
        ASSERT(socket->wrstate == socket_state_busy);
    }
    socket->wrstate = socket_state_done;

    ASSERT(tunnel->tunnel_write_done);
    if (tunnel->tunnel_write_done) {
        tunnel->tunnel_write_done(tunnel, socket);
    }
}

void tunnel_socket_ctx_write(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const void* data, size_t len) {
    if (tunnel->tunnel_is_in_streaming(tunnel) == false) {
        ASSERT(socket->wrstate == socket_state_stop);
    }
    socket_ctx_write(socket, data, len);
}

void tunnel_dump_error_info(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const char* title) {
    int error = (int)socket->result;
    char* addr;
    const char* from = NULL;
    if (socket == tunnel->outgoing) {
        addr = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
        from = "_server_";
    } else {
        union sockaddr_universal tmp = { { 0 } };
        int len = sizeof(tmp);
        uv_tcp_getpeername(&socket->handle.tcp, &tmp.addr, &len);
        addr = universal_address_to_string(&tmp, &malloc, false);
        if ((strcmp(addr, "127.0.0.1") == 0) || (strlen(addr) == 0)) {
            free(addr);
            addr = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
        }
        from = "_client_";
    }
    pr_err("%s about %s \"%s\": %s - %s", title, from, addr, uv_strerror(error), tunnel->extra_info);
    free(addr);
}
