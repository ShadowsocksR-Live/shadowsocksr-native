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

#ifndef DEFS_H_
#define DEFS_H_

#include "s5.h"
#include <uv.h>

#if defined(_WIN32)
typedef ULONG uv_buf_len_t;
#else
typedef size_t uv_buf_len_t;
#endif // defined(_WIN32)


#include <assert.h>
#include <stddef.h>      /* size_t, ssize_t */
#include <stdint.h>
#if defined(_MSC_VER)
#include <winsock2.h>
#else
#include <netinet/in.h>  /* sockaddr_in, sockaddr_in6 */
#include <sys/socket.h>  /* sockaddr */
#endif // defined(_MSC_VER)

#if !defined(_MSC_VER)
#include <stdbool.h>
#endif

struct server_config {
    char *bind_host;
    unsigned short bind_port;
    unsigned int idle_timeout;
};

struct listener_ctx {
    unsigned int idle_timeout;  /* Connection idle timeout in ms. */
    uv_tcp_t tcp_handle;
};

enum socket_state {
    socket_stop,  /* Stopped. */
    socket_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    socket_done,  /* Done; read incoming data or write finished. */
    socket_dead,
};

struct socket_ctx {
    enum socket_state rdstate;
    enum socket_state wrstate;
    unsigned int idle_timeout;
    struct tunnel_ctx *tunnel;  /* Backlink to owning tunnel context. */
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_timer_t timer_handle;  /* For detecting timeouts. */
    uv_write_t write_req;
    /* We only need one of these at a time so make them share memory. */
    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
        char buf[2048];  /* Scratch space. Used to read data into. */
    } t;
};

/* Session states. */
enum session_state {
    session_handshake,        /* Wait for client handshake. */
    session_handshake_auth,   /* Wait for client authentication data. */
    session_req_start,        /* Start waiting for request data. */
    session_req_parse,        /* Wait for request data. */
    session_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    session_req_connect,      /* Wait for uv_tcp_connect() to complete. */
    session_proxy_start,      /* Connected. Start piping data. */
    session_proxy,            /* Connected. Pipe data back and forth. */
    session_kill,             /* Tear down session. */
    session_dead,             /* Dead. Safe to free now. */
};

struct tunnel_ctx {
    enum session_state state;
    struct listener_ctx *lx;  /* Backlink to owning listener context. */
    s5_ctx parser;  /* The SOCKS protocol parser. */
    struct socket_ctx incoming;  /* Connection with the SOCKS client. */
    struct socket_ctx outgoing;  /* Connection with upstream. */
    int ref_count;
};

/* listener.c */
int listener_run(struct server_config *cf, uv_loop_t *loop);
bool can_auth_none(const struct listener_ctx *lx, const struct tunnel_ctx *cx);
bool can_auth_passwd(const struct listener_ctx *lx, const struct tunnel_ctx *cx);
bool can_access(const struct listener_ctx *lx, const struct tunnel_ctx *cx, const struct sockaddr *addr);

/* tunnel.c */
void tunnel_initialize(struct listener_ctx *lx);

/* util.c */
#if defined(__GNUC__)
# define ATTRIBUTE_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
# define ATTRIBUTE_FORMAT_PRINTF(a, b)
#endif
void pr_info(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_warn(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_err(const char *fmt, ...) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void *xmalloc(size_t size);

/* main.c */
const char *_getprogname(void);

/* getopt.c */
#if !HAVE_UNISTD_H
extern char *optarg;
int getopt(int argc, char * const argv[], const char *options);
#endif

/* ASSERT() is for debug checks, CHECK() for run-time sanity checks.
* DEBUG_CHECKS is for expensive debug checks that we only want to
* enable in debug builds but still want type-checked by the compiler
* in release builds.
*/
#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)   do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif

#define UNREACHABLE() CHECK(!"Unreachable code reached.")

/* This macro looks complicated but it's not: it calculates the address
* of the embedding struct through the address of the embedded struct.
* In other words, if struct A embeds struct B, then we can obtain
* the address of A by taking the address of B and subtracting the
* field offset of B in A.
*/
#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#endif  /* DEFS_H_ */
