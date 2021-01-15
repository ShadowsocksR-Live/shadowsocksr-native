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
#include "dump_info.h"
#include "tunnel.h"
#include "ssr_executive.h"
#include "ssr_client_api.h"
#include "common.h"
#include "udprelay.h"

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 63
#endif

struct udp_listener_ctx_t;

struct listener_t {
    uv_tcp_t *tcp_server;
    struct udp_listener_ctx_t *udp_server;
};

enum running_state {
    running_state_living = 0,
    running_state_quit = 1,
    running_state_dead = 2,
};

struct ssr_client_state {
    struct server_env_t *env;

    uv_signal_t *sigint_watcher;
    uv_signal_t *sigterm_watcher;

    uv_timer_t* exit_flag_timer;

    enum running_state running_state_flag;
    bool force_quit;
    int force_quit_delay_ms;
    
    int listener_count;
    struct listener_t *listeners;

    void(*feedback_state)(struct ssr_client_state *state, void *p);
    void *ptr;

    int error_code;
};

extern void udp_on_recv_data(struct udp_listener_ctx_t *udp_ctx, const union sockaddr_universal *src_addr, const struct buffer_t *data, void*p);

static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void listen_incoming_connection_cb(uv_stream_t *server, int status);
static void signal_quit(uv_signal_t* handle, int signum);
static void idler_watcher_cb(uv_timer_t* handle);

int ssr_run_loop_begin(struct server_config *cf, void(*feedback_state)(struct ssr_client_state *state, void *p), void *p) {
    uv_loop_t * loop = NULL;
    struct addrinfo hints;
    struct ssr_client_state *state;
    int err;
    uv_getaddrinfo_t *req;

    config_ssrot_revision(cf);

    loop = (uv_loop_t *) calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    state = (struct ssr_client_state *) calloc(1, sizeof(*state));
    state->force_quit_delay_ms = 3000;
    state->listeners = NULL;
    state->env = ssr_cipher_env_create(cf, state);
    state->feedback_state = feedback_state;
    state->ptr = p;

    loop->data = state->env;

    /* Resolve the address of the interface that we should bind to.
    * The getaddrinfo callback starts the server and everything else.
    */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    req = (uv_getaddrinfo_t *)calloc(1, sizeof(*req));

    err = uv_getaddrinfo(loop, req, getaddrinfo_done_cb, cf->listen_host, NULL, &hints);
    if (err != 0) {
        pr_err("getaddrinfo: %s", uv_strerror(err));
        if (state->feedback_state) {
            state->error_code = err;
            state->feedback_state(state, state->ptr);
        }
        return err;
    }

    // Setup signal handler
    state->sigint_watcher = (uv_signal_t *) calloc(1, sizeof(uv_signal_t));
    uv_signal_init(loop, state->sigint_watcher);
    uv_signal_start(state->sigint_watcher, signal_quit, SIGINT);

    state->sigterm_watcher = (uv_signal_t *) calloc(1, sizeof(uv_signal_t));
    uv_signal_init(loop, state->sigterm_watcher);
    uv_signal_start(state->sigterm_watcher, signal_quit, SIGTERM);

    state->exit_flag_timer = (uv_timer_t*) calloc(1, sizeof(uv_timer_t));
    uv_timer_init(loop, state->exit_flag_timer);
    uv_timer_start(state->exit_flag_timer, idler_watcher_cb, 0, 500);

    /* Start the event loop.  Control continues in getaddrinfo_done_cb(). */
    err = uv_run(loop, UV_RUN_DEFAULT);
    if (err != 0) {
        pr_err("uv_run: %s", uv_strerror(err));
    }

    if (uv_loop_close(loop) != 0) {
        if (state->force_quit == false) {
            ASSERT(false);
        }
    }

    ssr_cipher_env_release(state->env);

    if (state->listeners) {
        free(state->listeners);
    }

    free(state->sigint_watcher);
    free(state->sigterm_watcher);
    free(state->exit_flag_timer);

    free(state);

    free(loop);
    
    return err;
}

static void tcp_close_done_cb(uv_handle_t* handle) {
    free((void *)((uv_tcp_t *)handle));
}

void state_set_force_quit(struct ssr_client_state *state, bool force_quit, int delay_ms) {
    state->force_quit = force_quit;
    state->force_quit_delay_ms = delay_ms;
}

void force_quit_timer_close_cb(uv_handle_t* handle) {
    // For some reason, uv_close may NOT always be work fine. 
    // sometimes uv_close_cb perhaps never called. 
    // so we have to call uv_stop to force exit the loop.
    // it can caused memory leaking. but who cares it?
    uv_stop(handle->loop);
    free(handle);
}

void force_quit_timer_cb(uv_timer_t* handle) {
    uv_close((uv_handle_t*)handle, force_quit_timer_close_cb);
}

void ssr_run_loop_shutdown(struct ssr_client_state *state) {
    if (state==NULL) {
        return;
    }
    
    if (state->running_state_flag != running_state_living) {
        return;
    }
    state->running_state_flag = running_state_quit;
}

void _ssr_run_loop_shutdown(struct ssr_client_state* state) {
    ASSERT(state->running_state_flag != running_state_living);
    state->running_state_flag = running_state_dead;

    uv_signal_stop(state->sigint_watcher);
    uv_close((uv_handle_t*)state->sigint_watcher, NULL);
    uv_signal_stop(state->sigterm_watcher);
    uv_close((uv_handle_t*)state->sigterm_watcher, NULL);

    uv_timer_stop(state->exit_flag_timer);
    uv_close((uv_handle_t*)state->exit_flag_timer, NULL);

    if (state->listeners && state->listener_count) {
        size_t n = 0;
        for (n = 0; n < (size_t) state->listener_count; ++n) {
            struct udp_listener_ctx_t *udp_server;
            struct listener_t *listener = state->listeners + n;

            uv_tcp_t *tcp_server = listener->tcp_server;
            if (tcp_server) {
                uv_close((uv_handle_t *)tcp_server, tcp_close_done_cb);
            }

            udp_server = listener->udp_server;
            if (udp_server) {
                udprelay_shutdown(udp_server);
            }
        }
    }

    client_env_shutdown(state->env);

    pr_info(" ");
    pr_info("terminated.\n");

    if (state->force_quit) {
        uv_timer_t *t = (uv_timer_t*) calloc(1, sizeof(*t));
        uv_timer_init(state->sigint_watcher->loop, t);
        uv_timer_start(t, force_quit_timer_cb, state->force_quit_delay_ms, 0); // wait 3 seconds.
    }
}

int ssr_get_listen_socket_fd(struct ssr_client_state *state) {
    if (state==NULL || state->listener_count==0 || state->listeners==NULL) {
        return 0;
    }
    ASSERT(state->listener_count == 1);
    return (int) uv_stream_fd(state->listeners[0].tcp_server);
}

int ssr_get_client_error_code(struct ssr_client_state *state) {
    return state->error_code;
}

/* Bind a server to each address that getaddrinfo() reported. */
static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    char addrbuf[INET6_ADDRSTRLEN + 1];
    unsigned int ipv4_naddrs;
    unsigned int ipv6_naddrs;
    struct ssr_client_state *state;
    struct server_env_t *env;
    const struct server_config *cf;
    struct addrinfo *ai;
    const void *addrv = NULL;
    const char *what;
    uv_loop_t *loop;
    unsigned int n;
    int err;
    union sockaddr_universal s = { {0} };

    loop = req->loop;

    env = (struct server_env_t *) loop->data;
    state = (struct ssr_client_state *) env->data;
    ASSERT(state);
    cf = env->config;

    free(req);

    if (status < 0) {
        pr_err("getaddrinfo(\"%s\"): %s", cf->listen_host, uv_strerror(status));
        uv_freeaddrinfo(addrs);
        if (state->feedback_state) {
            state->error_code = status;
            state->feedback_state(state, state->ptr);
        }
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
        pr_err("%s has no IPv4/6 addresses", cf->listen_host);
        uv_freeaddrinfo(addrs);
        return;
    }

    state->listener_count = (ipv4_naddrs + ipv6_naddrs);
    state->listeners = (struct listener_t *) calloc(state->listener_count, sizeof(state->listeners[0]));

    n = 0;
    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        struct listener_t *listener;
        uv_tcp_t *tcp_server;
        uint16_t port;

        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
            continue;
        }

        if (ai->ai_family == AF_INET) {
            s.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
            s.addr4.sin_port = htons(cf->listen_port);
            addrv = &s.addr4.sin_addr;
        } else if (ai->ai_family == AF_INET6) {
            s.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
            s.addr6.sin6_port = htons(cf->listen_port);
            addrv = &s.addr6.sin6_addr;
        } else {
            UNREACHABLE();
        }

        if (uv_inet_ntop(s.addr.sa_family, addrv, addrbuf, sizeof(addrbuf)) != 0) {
            UNREACHABLE();
        }

        listener = state->listeners + n;

        listener->tcp_server = (uv_tcp_t *)calloc(1, sizeof(listener->tcp_server[0]));
        tcp_server = listener->tcp_server;
        VERIFY(0 == uv_tcp_init(loop, tcp_server));

        what = "uv_tcp_bind";
        err = uv_tcp_bind(tcp_server, &s.addr, 0);
        if (err == 0) {
            // https://unix.stackexchange.com/questions/180492/is-it-possible-to-connect-to-tcp-port-0
            what = "uv_listen";
            err = uv_listen((uv_stream_t *)tcp_server, 128, listen_incoming_connection_cb);
        }

        if (state->feedback_state) {
            state->error_code = err;
            state->feedback_state(state, state->ptr);
        }

        if (err != 0) {
            pr_err("%s(\"%s:%hu\"): %s", what, addrbuf, cf->listen_port, uv_strerror(err));
            ssr_run_loop_shutdown(state);
            break;
        }

        port = get_socket_port(tcp_server);

        if (s.addr6.sin6_family == AF_INET6) {
            pr_info("listening on     [%s]:%hu\n", addrbuf, port);
        } else {
            pr_info("listening on     %s:%hu\n", addrbuf, port);
        }

        if (cf->udp) {
            union sockaddr_universal remote_addr = { {0} };
            universal_address_from_string(cf->remote_host, cf->remote_port, true, &remote_addr);

            listener->udp_server = udprelay_begin(loop, cf->listen_host, port, &remote_addr, state->env->cipher);

            udp_relay_set_udp_on_recv_data_callback(listener->udp_server, &udp_on_recv_data, NULL);
        }

        n += 1;
    }

    uv_freeaddrinfo(addrs);
}

static void listen_incoming_connection_cb(uv_stream_t *server, int status) {
    uv_loop_t *loop = server->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    VERIFY(status == 0);
    client_tunnel_initialize((uv_tcp_t *)server, env->config->idle_timeout);
}

static void signal_quit(uv_signal_t* handle, int signum) {
    switch (signum) {
    case SIGINT:
    case SIGTERM:
#if !defined(__MINGW32__) && !defined(_WIN32)
    case SIGUSR1:
#endif
    {
        struct server_env_t *env;
        struct ssr_client_state *state;
        ASSERT(handle);
        env = (struct server_env_t *)handle->loop->data;
        state = (struct ssr_client_state *)env->data;
        ASSERT(state);
        ssr_run_loop_shutdown(state);
    }
        break;
    default:
        ASSERT(0);
        break;
    }
}

static void idler_watcher_cb(uv_timer_t* handle) {
    struct server_env_t* env;
    struct ssr_client_state* state;
    ASSERT(handle);
    env = (struct server_env_t*)handle->loop->data;
    state = (struct ssr_client_state*)env->data;
    ASSERT(state);
    if (state->running_state_flag == running_state_quit) {
        _ssr_run_loop_shutdown(state);
    }
}
