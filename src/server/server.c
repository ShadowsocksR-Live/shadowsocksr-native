#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <string.h>

#include "common.h"
#include "dump_info.h"
#include "obfsutil.h"
#include "ssrbuffer.h"
#include "ssr_executive.h"
#include "config_json.h"
#include "sockaddr_universal.h"
#include "udprelay.h"
#include "tunnel.h"
#include "daemon_wrapper.h"
#include "cmd_line_parser.h"
#include "exe_file_path.h"
#include "ssrutils.h"
#include "websocket_basic.h"
#include "http_parser_wrapper.h"
#include "ip_addr_cache.h"
#include "s5.h"
#include "base64.h"
#include "cstl_lib.h"

#ifndef SSR_MAX_CONN
#define SSR_MAX_CONN 1024
#endif

struct ssr_server_state {
    struct server_env_t *env;

    uv_signal_t *sigint_watcher;
    uv_signal_t *sigterm_watcher;

    bool shutting_down;
    bool force_quit;

    uv_tcp_t *tcp_listener;
    struct ip_addr_cache *resolved_ip_cache;
};

#define TUNNEL_STAGE_MAP(V)                                                             \
    V(0, tunnel_stage_initial,                  "tunnel_stage_initial")                 \
    V(1, tunnel_stage_obfs_receipt_done,        "tunnel_stage_obfs_receipt_done")       \
    V(2, tunnel_stage_client_feedback_coming,   "tunnel_stage_client_feedback_coming")  \
    V(3, tunnel_stage_protocol_confirm_done,    "tunnel_stage_protocol_confirm_done")   \
    V(4, tunnel_stage_resolve_host,             "tunnel_stage_resolve_host")            \
    V(5, tunnel_stage_connect_host,             "tunnel_stage_connect_host")            \
    V(6, tunnel_stage_launch_streaming,         "tunnel_stage_launch_streaming")        \
    V(7, tunnel_stage_tls_client_feedback,      "tunnel_stage_tls_client_feedback")     \
    V(8, tunnel_stage_normal_response,          "tunnel_stage_normal_response")         \
    V(9, tunnel_stage_streaming,                "tunnel_stage_streaming")               \
    V(10, tunnel_stage_udp_streaming,            "tunnel_stage_udp_streaming")          \

enum tunnel_stage {
#define TUNNEL_STAGE_GEN(code, name, _) name = code,
    TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
#undef TUNNEL_STAGE_GEN
    tunnel_stage_max,
};

static const char * tunnel_stage_string(enum tunnel_stage stage) {
#define TUNNEL_STAGE_GEN(_, name, name_str) case name: return name_str;
    switch (stage) {
        TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
    default:
        return "Unknown stage.";
    }
#undef TUNNEL_STAGE_GEN
}

struct server_ctx {
    struct server_env_t *env; // __weak_ptr
    struct tunnel_cipher_ctx *cipher;
    struct buffer_t *init_pkg;
    enum tunnel_stage stage;
    size_t tcp_mss;
    size_t _overhead;
    size_t _recv_buffer_size;
    size_t _recv_d_max_size;
    char *sec_websocket_key;
    bool ws_tls_beginning;
    bool ws_close_frame_sent;
    struct buffer_t *client_delivery_cache;
    struct tunnel_ctx *tunnel; // __weak_ptr
    struct udp_remote_ctx_t *udp_relay;
    struct cstl_deque* udp_recv_deque;
};

static int ssr_server_run_loop(struct server_config *config, bool force_quit);
void ssr_server_shutdown(struct ssr_server_state *state);

void server_tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout);
void server_shutdown(struct server_env_t *env);

void signal_quit_cb(uv_signal_t *handle, int signum);
void tunnel_incoming_connection_established_cb(uv_stream_t *server, int status);

static void tunnel_destroying(struct tunnel_ctx* tunnel);
static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_arrive_end_of_file(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_on_getaddrinfo_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const struct addrinfo* ai);
static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size);
static bool tunnel_is_in_streaming(struct tunnel_ctx* tunnel);
static uint8_t* tunnel_extract_data(struct tunnel_ctx* tunnel, struct socket_ctx* socket, void* (*allocator)(size_t size), size_t* size);
static void tunnel_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket);

static bool is_incoming_ip_legal(struct tunnel_ctx *tunnel);
static bool is_header_complete(const struct buffer_t *buf);
static size_t _get_read_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size);
static void do_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *incoming);
static void do_prepare_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_handle_client_feedback(struct tunnel_ctx *tunnel, struct socket_ctx *incoming);
static void do_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_resolve_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_connect_host_start(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_connect_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket);

static void do_tls_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static size_t _tls_get_read_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size);
static void do_tls_client_feedback(struct tunnel_ctx *tunnel);
static void do_tls_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_server_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void do_udp_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_udp_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static struct buffer_t * build_websocket_frame_from_raw(struct server_ctx *ctx, struct buffer_t *src);
static struct buffer_t * extract_data_from_assembled_websocket_frame(struct server_ctx *ctx, struct buffer_t *src);

void print_server_info(const struct server_config *config);
static void svr_usage(void);

void on_atexit(void) {
    MEM_CHECK_DUMP_LEAKS();
}

#if defined(__unix__) || defined(__linux__)
#include <signal.h>
void sighandler(int sig) {
    pr_err("signal %d", sig);
}
#endif // defined(__unix__) || defined(__linux__)

int main(int argc, char * const argv[]) {
    struct server_config *config = NULL;
    int err = -1;
    struct cmd_line_info *cmds = NULL;

    #if (defined(__unix__) || defined(__linux__)) && !defined(__mips)
    struct sigaction sa = { {&sighandler}, {{0}}, 0, NULL };
    sigaction(SIGPIPE, &sa, NULL);
    #endif // defined(__unix__) || defined(__linux__)

    MEM_CHECK_BEGIN();
    MEM_CHECK_BREAK_ALLOC(63);
    MEM_CHECK_BREAK_ALLOC(64);
    atexit(on_atexit);

    do {
        set_app_name(argv[0]);

        cmds = cmd_line_info_create(argc, argv);

        if (cmds == NULL) {
            break;
        }

        if (cmds->help_flag) {
            break;
        }

        if (cmds->cfg_file == NULL) {
            string_safe_assign(&cmds->cfg_file, DEFAULT_CONF_PATH);
        }

        if ((config = parse_config_file(true, cmds->cfg_file)) == NULL) {
            char* separ = NULL;
            char* cfg_file = exe_file_path(&malloc);
            if (cfg_file && ((separ = strrchr(cfg_file, PATH_SEPARATOR)))) {
                ++separ;
                strcpy(separ, CFG_JSON);
                config = parse_config_file(true, cfg_file);
            }
            free(cfg_file);
            if (config == NULL) {
                break;
            }
        }

        config_ssrot_revision(config);

        config_parse_protocol_param(config, config->protocol_param);

        if (config->method == NULL || config->password == NULL) {
            break;
        }

        if (cmds->daemon_flag) {
            char param[257] = { 0 };
            sprintf(param, "-c \"%s\"", cmds->cfg_file);
            daemon_wrapper(argv[0], param);
        }

        print_server_info(config);

        ssr_server_run_loop(config, cmds->force_quit);

        err = 0;
    } while (0);

    cmd_line_info_destroy(cmds);

    config_release(config);

    if (err != 0) {
        svr_usage();
    }
    return 0;
}

static int ssr_server_run_loop(struct server_config *config, bool force_quit) {
    uv_loop_t *loop = NULL;
    struct ssr_server_state *state = NULL;
    int r = 0;

    loop = (uv_loop_t *) calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    config_ssrot_revision(config);

    state = (struct ssr_server_state *) calloc(1, sizeof(*state));
    state->force_quit = force_quit;
    state->env = ssr_cipher_env_create(config, state);
    loop->data = state->env;

    {
        union sockaddr_universal addr = { {0} };
        int error;
        uv_tcp_t *listener = (uv_tcp_t *) calloc(1, sizeof(uv_tcp_t));

        uv_tcp_init(loop, listener);

        if (universal_address_from_string(config->listen_host, config->listen_port, true, &addr) != 0) {
            PRINT_ERR("universal_address_from_string( %s ).\n", config->listen_host);
            return -1;
        }
        error = uv_tcp_bind(listener, &addr.addr, 0);
        if (error != 0) {
            PRINT_ERR("uv_tcp_bind: %s", uv_strerror(error));
            return error;
        }

        error = uv_listen((uv_stream_t *)listener, SSR_MAX_CONN, tunnel_incoming_connection_established_cb);

        if (error != 0) {
            char* addr_str = universal_address_to_string(&addr, &malloc, true);
            PRINT_ERR("Error on listening \"%s\": %s.\n", addr_str, uv_strerror(error));
            free(addr_str);
            return error;
        }
        state->tcp_listener = listener;

        state->resolved_ip_cache = ip_addr_cache_create(IP_CACHE_EXPIRE_INTERVAL_MIN);
    }

    {
        // Setup signal handler
        state->sigint_watcher = (uv_signal_t *)calloc(1, sizeof(uv_signal_t));
        uv_signal_init(loop, state->sigint_watcher);
        uv_signal_start(state->sigint_watcher, signal_quit_cb, SIGINT);

        state->sigterm_watcher = (uv_signal_t *)calloc(1, sizeof(uv_signal_t));
        uv_signal_init(loop, state->sigterm_watcher);
        uv_signal_start(state->sigterm_watcher, signal_quit_cb, SIGTERM);
    }

    r = uv_run(loop, UV_RUN_DEFAULT);
    if (r != 0) {
        pr_err("uv_run: %s", uv_strerror(r));
    }

    if (uv_loop_close(loop) != 0) {
        if (state->force_quit == false) {
            ASSERT(false);
        }
    }

    {
        ssr_cipher_env_release(state->env);

        free(state->sigint_watcher);
        free(state->sigterm_watcher);

        ip_addr_cache_destroy(state->resolved_ip_cache);

        free(state);
    }

    free(loop);

    return r;
}

static void listener_close_done_cb(uv_handle_t* handle) {
    free((void *)((uv_tcp_t *)handle));
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

void ssr_server_shutdown(struct ssr_server_state *state) {
    if (state == NULL) {
        return;
    }

    if (state->shutting_down) {
        return;
    }
    state->shutting_down = true;

    uv_signal_stop(state->sigint_watcher);
    uv_close((uv_handle_t*)state->sigint_watcher, NULL);
    uv_signal_stop(state->sigterm_watcher);
    uv_close((uv_handle_t*)state->sigterm_watcher, NULL);

    if (state->tcp_listener) {
        uv_close((uv_handle_t *)state->tcp_listener, listener_close_done_cb);
    }

    server_shutdown(state->env);

    pr_info("\n");
    pr_info("terminated.\n");

    if (state->force_quit) {
        uv_timer_t *t = (uv_timer_t*) calloc(1, sizeof(*t));
        uv_timer_init(state->sigint_watcher->loop, t);
        uv_timer_start(t, force_quit_timer_cb, 3000, 0); // wait 3 seconds.
    }
}

static int deque_compare_e_ptr(const void* left, const void* right) {
    struct buffer_t* l = *((struct buffer_t**)left);
    struct buffer_t* r = *((struct buffer_t**)right);
    return (int)((ssize_t)l - (ssize_t)r);
}

static void deque_free_e(void* ptr) {
    if (ptr) {
        struct buffer_t* p = *((struct buffer_t**)ptr);
        buffer_release(p);
    }
}

bool _init_done_cb(struct tunnel_ctx *tunnel, void *p) {
    struct server_env_t *env = (struct server_env_t *)p;

    struct server_ctx *ctx = (struct server_ctx *) calloc(1, sizeof(*ctx));
    ctx->env = env;
    ctx->init_pkg = buffer_create(SSR_BUFF_SIZE);
    ctx->_recv_buffer_size = TCP_BUF_SIZE_MAX;
    ctx->tunnel = tunnel;
    tunnel->data = ctx;

    tunnel->tunnel_destroying = &tunnel_destroying;
    tunnel->tunnel_timeout_expire_done = &tunnel_timeout_expire_done;
    tunnel->tunnel_outgoing_connected_done = &tunnel_outgoing_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_arrive_end_of_file = &tunnel_arrive_end_of_file;
    tunnel->tunnel_on_getaddrinfo_done = &tunnel_on_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_get_alloc_size = &tunnel_get_alloc_size;
    tunnel->tunnel_is_in_streaming = &tunnel_is_in_streaming;
    tunnel->tunnel_extract_data = &tunnel_extract_data;
    tunnel->tunnel_dispatcher = &tunnel_dispatcher;

    cstl_set_container_add(ctx->env->tunnel_set, tunnel);

    ctx->cipher = NULL;
    ctx->stage = tunnel_stage_initial;

#define SOCKET_DATA_BUFFER_SIZE 0x8000
    ctx->client_delivery_cache = buffer_create(SOCKET_DATA_BUFFER_SIZE);

    ctx->udp_recv_deque = cstl_deque_new(10, deque_compare_e_ptr, deque_free_e);

    return is_incoming_ip_legal(tunnel);
}

void server_tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout) {
    uv_loop_t *loop = listener->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    tunnel_initialize(loop, listener, idle_timeout, &_init_done_cb, env);
}

static void _do_shutdown_tunnel(struct cstl_set *set, const void *obj, bool *stop, void *p) {
    struct tunnel_ctx *tunnel = (struct tunnel_ctx *)obj;
    tunnel->tunnel_shutdown(tunnel);
    (void)set; (void)stop; (void)p;
}

void server_shutdown(struct server_env_t *env) {
    cstl_set_container_traverse(env->tunnel_set, &_do_shutdown_tunnel, NULL);
}

void signal_quit_cb(uv_signal_t *handle, int signum) {
    struct server_env_t *env;
    ASSERT(handle);
    env = (handle && handle->loop) ? (struct server_env_t *)handle->loop->data : NULL;
    switch (signum) {
    case SIGINT:
    case SIGTERM:
#if !defined(__MINGW32__) && !defined(_WIN32)
    case SIGUSR1:
#endif
    {
    struct ssr_server_state *state = env ? (struct ssr_server_state *)env->data : NULL;
        ASSERT(state);
        ssr_server_shutdown(state);
    }
    break;
    default:
        ASSERT(0);
        break;
    }
}

void tunnel_incoming_connection_established_cb(uv_stream_t *server, int status) {
    uv_loop_t *loop = server->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    VERIFY(status == 0);
    server_tunnel_initialize((uv_tcp_t *)server, env->config->idle_timeout);
}

static void tunnel_destroying(struct tunnel_ctx* tunnel) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;

    udp_remote_set_dying_callback(ctx->udp_relay, NULL, NULL);
    udp_remote_destroy(ctx->udp_relay);

    cstl_set_container_remove(ctx->env->tunnel_set, tunnel);
    if (ctx->cipher) {
        tunnel_cipher_release(ctx->cipher);
    }
    buffer_release(ctx->init_pkg);
    object_safe_free((void**)&ctx->sec_websocket_key);
    buffer_release(ctx->client_delivery_cache);
    cstl_deque_delete(ctx->udp_recv_deque);
    free(ctx);
}

static void tunnel_dispatcher(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    bool done = false;
    struct server_ctx *ctx = (struct server_ctx *)tunnel->data;
    struct server_config *config = ctx->env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    const char *info = tunnel_stage_string(ctx->stage); (void)info;
    (void)done;
#if defined(__PRINT_INFO__)
    if (tunnel_is_in_streaming(tunnel)) {
        if (tunnel->in_streaming == false) {
            tunnel->in_streaming = true;
            pr_info("%s ...", info);
        }
    } else {
        pr_info("%s", info);
    }
#endif
    strncpy(tunnel->extra_info, info, 0x100 - 1);
    switch (ctx->stage) {
    case tunnel_stage_initial:
        ASSERT(incoming == socket);
        ASSERT(incoming->rdstate == socket_state_done);
        ASSERT(incoming->wrstate == socket_state_stop);
        incoming->rdstate = socket_state_stop;
        if (config->over_tls_enable) {
            do_tls_init_package(tunnel, incoming);
            break;
        }
        do_init_package(tunnel, incoming);
        break;
    case tunnel_stage_obfs_receipt_done:
        ASSERT(incoming == socket);
        ASSERT(incoming->rdstate == socket_state_stop);
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        socket_ctx_read(incoming, true);
        ctx->stage = tunnel_stage_client_feedback_coming;
        break;
    case tunnel_stage_client_feedback_coming:
        ASSERT(incoming == socket);
        ASSERT(incoming->rdstate == socket_state_done);
        ASSERT(incoming->wrstate == socket_state_stop);
        incoming->rdstate = socket_state_stop;
        do_handle_client_feedback(tunnel, incoming);
        break;
    case tunnel_stage_protocol_confirm_done:
        ASSERT(incoming == socket);
        ASSERT(incoming->rdstate == socket_state_stop);
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        do_prepare_parse(tunnel, incoming);
        break;
    case tunnel_stage_resolve_host:
        do_resolve_host_done(tunnel, socket);
        break;
    case tunnel_stage_connect_host:
        do_connect_host_done(tunnel, socket);
        break;
    case tunnel_stage_launch_streaming:
        do_launch_streaming(tunnel, socket);
        break;
    case tunnel_stage_tls_client_feedback:
        ASSERT(incoming == socket);
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        if (ctx->udp_relay) {
            do_udp_launch_streaming(tunnel, socket);
        } else {
            do_tls_launch_streaming(tunnel, socket);
        }
        break;
    case tunnel_stage_normal_response:
        // after send the normal HTTP response, shutdown the tunnel.
        tunnel->tunnel_shutdown(tunnel);
        break;
    case tunnel_stage_streaming:
        tunnel_server_streaming(tunnel, socket);
        break;
    case tunnel_stage_udp_streaming:
        tunnel_udp_streaming(tunnel, socket);
        break;
    default:
        UNREACHABLE();
        break;
    }
}

static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    if (incoming == socket) {
        if (ctx->stage < tunnel_stage_resolve_host) {
            // report_addr(server->fd, SUSPICIOUS); // collect MALICIOUS IPs.
        }
    }
}

static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    tunnel->tunnel_dispatcher(tunnel, socket);
}

static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    tunnel->tunnel_dispatcher(tunnel, socket);
}

static void tunnel_arrive_end_of_file(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct server_config *config = ctx->env->config;

    if (socket == incoming) {
        tunnel->tunnel_shutdown(tunnel);
    } else if (socket == outgoing) {
        if (config->over_tls_enable) {
            uint8_t *p = NULL;
            size_t frame_size = 0;

            ASSERT(outgoing->rdstate == socket_state_stop);
            //ASSERT(incoming->wrstate == socket_state_stop);

            p = websocket_build_close_frame(false, WS_CLOSE_REASON_NORMAL, NULL, &malloc, &frame_size);
            if (p) {
                tunnel_socket_ctx_write(tunnel, incoming, p, frame_size);
                ctx->ws_close_frame_sent = true;
                free(p);
            } else {
                tunnel->tunnel_shutdown(tunnel);
            }
        } else {
            tunnel->tunnel_shutdown(tunnel);
        }
    }
}

static void tunnel_on_getaddrinfo_done(struct tunnel_ctx* tunnel, struct socket_ctx* socket, const struct addrinfo* ai) {
    tunnel->tunnel_dispatcher(tunnel, socket);
    (void)ai;
}

static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct server_config *config = ctx->env->config;
    if (config->over_tls_enable && socket==incoming && ctx->ws_close_frame_sent) {
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        tunnel->tunnel_shutdown(tunnel);
    } else {
        tunnel->tunnel_dispatcher(tunnel, socket);
    }
}

static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    if (socket == tunnel->incoming) {
        return TCP_BUF_SIZE_MAX;
    } else if (socket == tunnel->outgoing) {
        if (config->over_tls_enable) {
            return _tls_get_read_size(tunnel, socket, suggested_size);
        } else {
            return _get_read_size(tunnel, socket, ctx->_recv_buffer_size);
        }
    } else {
        ASSERT(false);
    }
    return suggested_size;
}

static bool tunnel_is_in_streaming(struct tunnel_ctx* tunnel) {
#if 1
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    if (ctx->udp_relay != NULL) {
        return (ctx->stage == tunnel_stage_udp_streaming);
    } else {
        return (ctx->stage == tunnel_stage_streaming);
    }
#else
    (void)tunnel;
    return false;
#endif
}

static bool is_incoming_ip_legal(struct tunnel_ctx *tunnel) {
    uv_tcp_t *tcp = &tunnel->incoming->handle.tcp;
    // TODO: check incoming ip.
    (void)tcp;
    return true;
}

static bool is_legal_header(const struct buffer_t *buf) {
    bool result = false;
    enum SOCKS5_ADDRTYPE addr_type;
    do {
        if (buf == NULL) {
            break;
        }
        addr_type = (enum SOCKS5_ADDRTYPE) buffer_get_data(buf, NULL)[0];
        switch (addr_type) {
        case SOCKS5_ADDRTYPE_IPV4:
        case SOCKS5_ADDRTYPE_DOMAINNAME:
        case SOCKS5_ADDRTYPE_IPV6:
            result = true;
            break;
        default:
            break;
        }
    } while (0);
    return result;
}

static bool is_header_complete(const struct buffer_t *buf) {
    struct socks5_address addr = { {{0}}, 0, SOCKS5_ADDRTYPE_INVALID };
    return socks5_address_parse(buffer_get_data(buf, NULL), buffer_get_length(buf), &addr);
}

static size_t _get_read_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size) {
    // https://github.com/ShadowsocksR-Live/shadowsocksr/blob/manyuser/shadowsocks/tcprelay.py#L812
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    size_t buffer_size;
    size_t frame_size;
    if (ctx->_overhead) {
        return suggested_size;
    }
    buffer_size = socket_arrived_data_size(socket, suggested_size);

    frame_size = ctx->tcp_mss - ctx->_overhead;

    buffer_size = min(buffer_size, ctx->_recv_d_max_size);
    ctx->_recv_d_max_size = min(ctx->_recv_d_max_size + frame_size, TCP_BUF_SIZE_MAX);

    if (buffer_size == suggested_size) {
        return buffer_size;
    }
    if (buffer_size > frame_size) {
        buffer_size = (buffer_size / frame_size) * frame_size;
    }
    return buffer_size;
}

static void do_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *incoming) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct buffer_t *obfs_receipt = NULL;
    struct buffer_t *proto_confirm = NULL;
    struct buffer_t *result = NULL;
    struct buffer_t *buf = buffer_create_from((uint8_t *)incoming->buf->base, incoming->result);
    do {
        size_t tcp_mss = update_tcp_mss(incoming);

        ASSERT(incoming == tunnel->incoming);

        if (incoming->result < 0) {
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        ASSERT(ctx->cipher == NULL);
        ctx->cipher = tunnel_cipher_create(ctx->env, tcp_mss);
        ctx->tcp_mss = tcp_mss;

        result = tunnel_cipher_server_decrypt(ctx->cipher, buf, &obfs_receipt, &proto_confirm);

        if (obfs_receipt) {
            ASSERT(proto_confirm == NULL);
            tunnel_socket_ctx_write(tunnel, incoming, buffer_get_data(obfs_receipt, NULL), buffer_get_length(obfs_receipt));
            ctx->stage = tunnel_stage_obfs_receipt_done;
            break;
        }

        if (result == NULL) {
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        buffer_replace(ctx->init_pkg, result);

        if (proto_confirm) {
            ASSERT(obfs_receipt == NULL);
            tunnel_socket_ctx_write(tunnel, incoming, buffer_get_data(proto_confirm, NULL), buffer_get_length(proto_confirm));
            ctx->stage = tunnel_stage_protocol_confirm_done;
            break;
        }

        do_prepare_parse(tunnel, incoming);
        break;
    } while (0);

    buffer_release(buf);
    buffer_release(obfs_receipt);
    buffer_release(proto_confirm);
    buffer_release(result);
}

static void do_prepare_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct buffer_t *init_pkg = ctx->init_pkg;
    do {
        struct server_info_t *info;
        struct obfs_t *protocol = NULL;
        struct obfs_t *obfs = NULL;

        protocol = ctx->cipher->protocol;
        obfs = ctx->cipher->obfs;

        pre_parse_header(init_pkg);

        info = protocol ? protocol->get_server_info(protocol) : (obfs ? obfs->get_server_info(obfs) : NULL);
        if (info) {
            info->head_len = (int) get_s5_head_size(buffer_get_data(init_pkg, NULL), buffer_get_length(init_pkg), 30);
            ctx->_overhead = info->overhead;
            ctx->_recv_buffer_size = info->buffer_size;
        }
        ctx->_recv_d_max_size = TCP_BUF_SIZE_MAX;

        if (is_legal_header(init_pkg) == false) {
            // report_addr(server->fd, MALFORMED);
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        if (is_header_complete(init_pkg) == false) {
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        do_parse(tunnel, socket);
    } while (0);
}

static void do_handle_client_feedback(struct tunnel_ctx *tunnel, struct socket_ctx *incoming) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct buffer_t *buf = buffer_create_from((uint8_t *)incoming->buf->base, incoming->result);
    struct buffer_t *result = NULL;
    struct buffer_t *obfs_receipt = NULL;
    struct buffer_t *proto_confirm = NULL;
    do {
        ASSERT(incoming == tunnel->incoming);

        if (incoming->result < 0) {
            pr_err("write error: %s", uv_strerror((int)incoming->result));
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        result = tunnel_cipher_server_decrypt(ctx->cipher, buf, &obfs_receipt, &proto_confirm);
        ASSERT(obfs_receipt == NULL);
        if (result==NULL || buffer_get_length(result)==0) {
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        buffer_concatenate2(ctx->init_pkg, result);

        if (proto_confirm) {
            tunnel_socket_ctx_write(tunnel, incoming, buffer_get_data(proto_confirm, NULL), buffer_get_length(proto_confirm));
            ctx->stage = tunnel_stage_protocol_confirm_done;
            break;
        }

        do_prepare_parse(tunnel, incoming);
        break;
    } while(0);
    buffer_release(buf);
    buffer_release(result);
    buffer_release(obfs_receipt);
    buffer_release(proto_confirm);
}

static void do_parse(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    /*
     * Shadowsocks TCP Relay Header, same as SOCKS5:
     *
     *    +------+----------+----------+
     *    | ATYP | DST.ADDR | DST.PORT |
     *    +------+----------+----------+
     *    |  1   | Variable |    2     |
     *    +------+----------+----------+
     */

    /*
     * TCP Relay's payload
     *
     *    +-------------+------+
     *    |    DATA     |      ...
     *    +-------------+------+
     *    |  Variable   |      ...
     *    +-------------+------+
     */

    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *outgoing = tunnel->outgoing;
    size_t offset     = 0;
    char* host = NULL;
    struct socks5_address *s5addr;
    union sockaddr_universal target = { {0} };
    bool ipFound = false;
    struct buffer_t *init_pkg = ctx->init_pkg;

    ASSERT(socket == tunnel->incoming);

    // get remote addr and port
    s5addr = tunnel->desired_addr;
    memset(s5addr, 0, sizeof(*s5addr));
    if (socks5_address_parse(buffer_get_data(init_pkg, NULL), buffer_get_length(init_pkg), s5addr) == false) {
        // report_addr(server->fd, MALFORMED);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    offset = socks5_address_size(s5addr);
    buffer_shortened_to(init_pkg, offset, buffer_get_length(init_pkg) - offset);

    host = socks5_address_to_string(s5addr, &malloc, false);

    {
        struct ssr_server_state *state = (struct ssr_server_state *)ctx->env->data;
        union sockaddr_universal *addr = ip_addr_cache_retrieve_address(state->resolved_ip_cache, host, &malloc);
        if (addr) {
            target = *addr;
            target.addr4.sin_port = htons(s5addr->port);
            free(addr);
            ipFound = true;
        }
    }

    if (ipFound == false) {
        ctx->stage = tunnel_stage_resolve_host;
        socket_ctx_getaddrinfo(outgoing, host, s5addr->port);
    } else {
        outgoing->addr = target;
        do_connect_host_start(tunnel, outgoing);
    }
    free(host);
}

static void do_resolve_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;
    ASSERT(outgoing == socket);
    ASSERT(incoming->rdstate == socket_state_stop || incoming->rdstate == socket_state_done);
    ASSERT(incoming->wrstate == socket_state_stop || incoming->wrstate == socket_state_done);
    ASSERT(outgoing->rdstate == socket_state_stop || outgoing->rdstate == socket_state_done);
    ASSERT(outgoing->wrstate == socket_state_stop || outgoing->wrstate == socket_state_done);

    if (outgoing->result < 0) {
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    {
        char* host = socks5_address_to_string(tunnel->desired_addr, &malloc, false);
        struct ssr_server_state* state = (struct ssr_server_state*)ctx->env->data;
        if (ip_addr_cache_is_address_exist(state->resolved_ip_cache, host) == false) {
            ip_addr_cache_add_address(state->resolved_ip_cache, host, &outgoing->addr);
        }
        free(host);
    }

    do_connect_host_start(tunnel, socket);
}

static void do_connect_host_start(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    int err;
    char* addr;

    (void)socket;
    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);
    ASSERT(socket == outgoing);

    ctx->stage = tunnel_stage_connect_host;
    err = socket_ctx_connect(outgoing);

    addr = socks5_address_to_string(tunnel->desired_addr, &malloc, true);
    if (err != 0) {
        u_short sa_family = socket->addr.addr.sa_family;
        char* sf = (sa_family == AF_INET) ? "IPv4" : ((sa_family == AF_INET6) ? "IPv6" : "unknown");
        pr_err("connect \"%s\" (%s) error: %s", addr, sf, uv_strerror(err));

        {
            char* host = socks5_address_to_string(tunnel->desired_addr, &malloc, false);
            struct ssr_server_state* state = (struct ssr_server_state*)ctx->env->data;
            if (ip_addr_cache_is_address_exist(state->resolved_ip_cache, host)) {
                ip_addr_cache_remove_address(state->resolved_ip_cache, host);
            }
            free(host);
        }

        tunnel->tunnel_shutdown(tunnel);
    } else {
#if defined(__PRINT_INFO__)
        pr_info("connecting \"%s\" ...", addr);
#endif
    }
    free(addr);
}

static void do_connect_host_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;

    ASSERT(outgoing == socket);
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (config->over_tls_enable) {
        ASSERT(buffer_get_length(ctx->init_pkg) == 0);
        do_tls_client_feedback(tunnel);
        return;
    }

    if (outgoing->result == 0) {
        size_t len = 0;
        const uint8_t *data = buffer_get_data(ctx->init_pkg, &len);
        if (len > 0) {
            tunnel_socket_ctx_write(tunnel, outgoing, data, len);
            ctx->stage = tunnel_stage_launch_streaming;
        } else {
            outgoing->wrstate = socket_state_done;
            do_launch_streaming(tunnel, socket);
        }
        return;
    } else {
        tunnel_dump_error_info(tunnel, socket, "upstream connection");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
}

static void do_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;

    ASSERT(outgoing == socket);
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_done);
    outgoing->wrstate = socket_state_stop;

    if (outgoing->result < 0) {
        pr_err("write error: %s", uv_strerror((int)outgoing->result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    socket_ctx_read(incoming, false);
    socket_ctx_read(outgoing, true);
    ctx->stage = tunnel_stage_streaming;
}

void udp_remote_on_data_arrived(struct udp_remote_ctx_t *remote_ctx, const uint8_t*data, size_t len, void*p) {
    struct server_ctx *ctx = (struct server_ctx *) p;
    struct tunnel_ctx *tunnel = ctx->tunnel;
    struct socket_ctx *socket = tunnel->incoming;
    struct buffer_t *src = buffer_create_from(data, len);
    struct buffer_t *dst = build_websocket_frame_from_raw(ctx, src);
    tunnel_socket_ctx_write(tunnel, socket, buffer_get_data(dst, NULL), buffer_get_length(dst));
    buffer_release(src);
    buffer_release(dst);
    (void)remote_ctx;
}

void udp_remote_on_dying(struct udp_remote_ctx_t *remote_ctx, void*p) {
    struct server_ctx *ctx = (struct server_ctx *) p;
    struct tunnel_ctx *tunnel = ctx->tunnel;
    tunnel->tunnel_shutdown(tunnel);
    (void)remote_ctx;
}

void do_normal_response(struct tunnel_ctx* tunnel) {
    struct server_ctx* ctx = (struct server_ctx*)tunnel->data;
    struct server_config* config = ctx->env->config;
    struct socket_ctx* incoming = tunnel->incoming;
    char* http_ok = ws_normal_response(&malloc, config->over_tls_server_domain);

    ASSERT(config->over_tls_enable);

    tunnel_socket_ctx_write(tunnel, incoming, http_ok, strlen(http_ok));
    free(http_ok);

    ctx->stage = tunnel_stage_normal_response;
}

static void do_tls_init_package(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct buffer_t *obfs_receipt = NULL;
    struct buffer_t *proto_confirm = NULL;
    struct buffer_t *result = NULL;
    struct http_headers *hdrs = NULL;
    do {
        uint8_t *indata = (uint8_t *)socket->buf->base;
        size_t len = (size_t)socket->result;
        size_t tcp_mss = update_tcp_mss(socket);
        const char* udp_field;

        ASSERT(socket == tunnel->incoming);
        ASSERT(config->over_tls_enable); (void)config;

        if (socket->result < 0) {
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        ASSERT(ctx->cipher == NULL);
        ctx->cipher = tunnel_cipher_create(ctx->env, tcp_mss);
        ctx->tcp_mss = tcp_mss;

        hdrs = http_headers_parse(true, indata, len);
        {
            const char *key = http_headers_get_field_val(hdrs, SEC_WEBSOKET_KEY);
            const char *url = http_headers_get_url(hdrs);
            if (key==NULL || url==NULL || 0 != strcmp(url, config->over_tls_path)) {
                do_normal_response(tunnel);
                break;
            }
            string_safe_assign(&ctx->sec_websocket_key, key);
        }
        {
            uint8_t* addr_p;
            size_t p_len = 0;
            const char* addr_field = http_headers_get_field_val(hdrs, "Target-Address");
            if (addr_field == NULL) {
                do_normal_response(tunnel);
                break;
            }
            addr_p = std_base64_decode_alloc(addr_field, &malloc, &p_len);
            if (addr_p == NULL) {
                do_normal_response(tunnel);
                break;
            }
            result = buffer_create_from(addr_p, p_len);
            free(addr_p);
        }
        ASSERT(obfs_receipt == NULL);
        ASSERT(proto_confirm == NULL);

        udp_field = http_headers_get_field_val(hdrs, "UDP");
        if (udp_field != NULL) {
            uv_loop_t *loop = socket->handle.tcp.loop;
            struct socks5_address target_addr = { {{0}}, 0, SOCKS5_ADDRTYPE_INVALID };
            size_t data_len = 0, p_len = 0;
            const uint8_t *data_p = buffer_get_data(result, &data_len);
            struct udp_remote_ctx_t *udp_ctx;
            uint8_t* addr_p;

            buffer_store(ctx->init_pkg, data_p, data_len);

            addr_p = url_safe_base64_decode_alloc(udp_field, &malloc, &p_len);
            if (socks5_address_parse(addr_p, p_len, &target_addr) == false) {
                free(addr_p);
                do_normal_response(tunnel);
                break;
            }
            free(addr_p);

            udp_ctx = udp_remote_launch_begin(loop, config->udp_timeout, &target_addr);
            udp_remote_set_data_arrived_callback(udp_ctx, udp_remote_on_data_arrived, ctx);
            udp_remote_set_dying_callback(udp_ctx, udp_remote_on_dying, ctx);

            ctx->udp_relay = udp_ctx;

            *tunnel->desired_addr = target_addr;

            do_tls_client_feedback(tunnel);
            break;
        }

        if (result==NULL || is_legal_header(result) == false) {
            do_normal_response(tunnel);
            break;
        }
        buffer_replace(ctx->init_pkg, result);

        do_prepare_parse(tunnel, socket);
        break;
    } while (0);
    http_headers_destroy(hdrs);
    buffer_release(result);
}

static size_t _tls_get_read_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    size_t data_size, read_size, frame_size;

    data_size = socket_arrived_data_size(socket, suggested_size);
    frame_size = websocket_frame_size(false, data_size);
    if (frame_size >= ctx->tcp_mss) {
        read_size = ctx->tcp_mss - (2 + sizeof(uint16_t) + 0);
    } else {
        read_size = data_size;
    }

    return read_size;
}

static void do_tls_client_feedback(struct tunnel_ctx *tunnel) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    char *tls_ok = websocket_connect_response(ctx->sec_websocket_key, &malloc);

    ASSERT(config->over_tls_enable); (void)config;

    tunnel_socket_ctx_write(tunnel, incoming, tls_ok, strlen(tls_ok));
    free(tls_ok);

    ctx->stage = tunnel_stage_tls_client_feedback;
}

static void do_tls_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

    ASSERT(config->over_tls_enable); (void)config;

    ASSERT(incoming == socket);
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    socket_ctx_read(incoming, false);
    socket_ctx_read(outgoing, true);
    ctx->stage = tunnel_stage_streaming;
}

static void tunnel_server_streaming(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    struct socket_ctx* current_socket = socket;
    struct socket_ctx* target_socket = NULL;

    ASSERT(current_socket == tunnel->incoming || current_socket == tunnel->outgoing);

    target_socket = ((current_socket == tunnel->incoming) ? tunnel->outgoing : tunnel->incoming);

    ASSERT((current_socket->wrstate == socket_state_done) || (current_socket->rdstate == socket_state_done));
    ASSERT((target_socket->wrstate != socket_state_done) && (target_socket->rdstate != socket_state_done));

    if (current_socket->wrstate == socket_state_done) {
        current_socket->wrstate = socket_state_stop;
    } else if (current_socket->rdstate == socket_state_done) {
        current_socket->rdstate = socket_state_stop;
        {
            size_t len = 0;
            uint8_t* buf = NULL;
            ASSERT(tunnel->tunnel_extract_data);
            buf = tunnel->tunnel_extract_data(tunnel, current_socket, &malloc, &len);
            if (buf /* && len > 0 */) {
                tunnel_socket_ctx_write(tunnel, target_socket, buf, len);
            } else {
                tunnel->tunnel_shutdown(tunnel);
            }
            free(buf);
        }
    } else {
        ASSERT(false);
    }
}

static void do_udp_launch_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

    ASSERT(config->over_tls_enable); (void)config;

    ASSERT(incoming == socket);
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    ASSERT(ctx->udp_relay);

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    {
        size_t p_len = 0;
        const uint8_t *p = buffer_get_data(ctx->init_pkg, &p_len);
        udp_remote_send_data(ctx->udp_relay, p, p_len);
    }

    socket_ctx_read(incoming, true);
    ctx->stage = tunnel_stage_udp_streaming;
}

static void tunnel_udp_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

    ASSERT(config->over_tls_enable); (void)config;

    ASSERT(incoming == socket);
    ASSERT(incoming->rdstate == socket_state_done || incoming->wrstate == socket_state_done);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    ASSERT(ctx->udp_relay);

    if (socket->rdstate == socket_state_done) {
        struct buffer_t *src, *buf;
        size_t p_len = 0;
        const uint8_t *p;

        socket->rdstate = socket_state_stop;

        src = buffer_create_from((uint8_t *)socket->buf->base, (size_t)socket->result);
        buf = extract_data_from_assembled_websocket_frame(ctx, src);

        do {
            const struct buffer_t* tmp;
            const void* udp_pkg = cstl_deque_front(ctx->udp_recv_deque);
            if (udp_pkg == NULL) {
                break;
            }
            tmp = *((struct buffer_t**)udp_pkg);

            p = buffer_get_data(tmp, &p_len);
            udp_remote_send_data(ctx->udp_relay, p, p_len);

            cstl_deque_pop_front(ctx->udp_recv_deque);
        } while (true);

        buffer_release(src);
        buffer_release(buf);
    } else if (socket->wrstate == socket_state_done) {
        socket->wrstate = socket_state_stop;
    } else {
        UNREACHABLE();
    }
}

static struct buffer_t * build_websocket_frame_from_raw(struct server_ctx *ctx, struct buffer_t *src) {
    struct tunnel_cipher_ctx *cipher_ctx = ctx->cipher;
    ws_frame_info info = { WS_OPCODE_BINARY, false, false, WS_CLOSE_REASON_UNKNOWN, 0, 0 };
    struct buffer_t *tmp = tunnel_cipher_server_encrypt(cipher_ctx, src);
    uint8_t *frame;
    struct buffer_t *buf;
    if (!ctx->ws_tls_beginning) {
        ctx->ws_tls_beginning = true;
        ws_frame_binary_first(false, &info);
    } else {
        ws_frame_binary_continuous(false, &info);
    }
    frame = websocket_build_frame(&info, buffer_get_data(tmp, NULL), buffer_get_length(tmp), &malloc);
    buf = buffer_create_from(frame, info.frame_size);
    free(frame);
    buffer_release(tmp);
    return buf;
}

// Assemble the fragments into WebSocket frames.
static struct buffer_t * extract_data_from_assembled_websocket_frame(struct server_ctx *ctx, struct buffer_t *src) {
    struct tunnel_cipher_ctx *cipher_ctx = ctx->cipher;
    struct buffer_t *buf = buffer_create(SOCKET_DATA_BUFFER_SIZE);
    buffer_concatenate2(ctx->client_delivery_cache, src);
    do {
        ws_frame_info info = { WS_OPCODE_BINARY, 0, 0, WS_CLOSE_REASON_UNKNOWN, 0, 0 };
        uint8_t *payload;
        size_t buf_len = 0;
        const uint8_t *buf_data;
        struct buffer_t *pb, *tmp;
        struct buffer_t *obfs_receipt = NULL;
        struct buffer_t *proto_confirm = NULL;

        buf_data = buffer_get_data(ctx->client_delivery_cache, &buf_len);

        payload = websocket_retrieve_payload(buf_data, buf_len, &malloc, &info);
        if (payload == NULL) {
            break;
        }
        buffer_shortened_to(ctx->client_delivery_cache, info.frame_size, buf_len - info.frame_size);

        pb = buffer_create_from(payload, info.payload_size);
        tmp = tunnel_cipher_server_decrypt(cipher_ctx, pb, &obfs_receipt, &proto_confirm);
        buffer_release(pb);

        ASSERT(obfs_receipt == NULL);
        ASSERT(proto_confirm == NULL);

        if (ctx->udp_relay) {
            struct buffer_t* t2 = buffer_clone(tmp);
            cstl_deque_push_back(ctx->udp_recv_deque, &t2, sizeof(struct buffer_t*));
        }

        buffer_concatenate2(buf, tmp);

        buffer_release(tmp);
        free(payload);
    } while (true);
    return buf;
}

static uint8_t* tunnel_extract_data(struct tunnel_ctx* tunnel, struct socket_ctx* socket, void* (*allocator)(size_t size), size_t* size)
{
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct tunnel_cipher_ctx *cipher_ctx = ctx->cipher;
    enum ssr_error error = ssr_error_client_decode;
    struct buffer_t *buf = NULL;
    uint8_t *result = NULL;

    (void)error;
    if (socket==NULL || allocator==NULL || size==NULL) {
        return result;
    }
    *size = 0;

    {
        struct buffer_t *src = buffer_create_from((uint8_t *)socket->buf->base, (size_t)socket->result);
        if (socket == tunnel->outgoing) {
            if (config->over_tls_enable) {
                buf = build_websocket_frame_from_raw(ctx, src);
            } else {
                buf = tunnel_cipher_server_encrypt(cipher_ctx, src);
            }
        } else if (socket == tunnel->incoming) {
            if (config->over_tls_enable) {
                buf = extract_data_from_assembled_websocket_frame(ctx, src);
            } else {
                struct buffer_t *obfs_receipt = NULL;
                struct buffer_t *proto_confirm = NULL;
                buf = tunnel_cipher_server_decrypt(cipher_ctx, src, &obfs_receipt, &proto_confirm);
                ASSERT(obfs_receipt == NULL);
                ASSERT(proto_confirm == NULL);
            }
        } else {
            ASSERT(0);
        }
        buffer_release(src);
    }

    if (buf) {
        size_t len = 0;
        const uint8_t *p = buffer_get_data(buf, &len);
        *size = len;
        result = (uint8_t *)allocator(len + 1);
        memcpy(result, p, len);

        buffer_release(buf);
    }

    return result;
}

void print_server_info(const struct server_config *config) {
    union sockaddr_universal listen_addr = { { 0 } };
    universal_address_from_string_no_dns(config->listen_host, config->listen_port, &listen_addr);

    pr_info("ShadowsocksR native server\n");
    if (listen_addr.addr6.sin6_family == AF_INET6) {
        pr_info("listen address   [%s]:%hu", config->listen_host, config->listen_port);
    } else {
        pr_info("listen address   %s:%hu", config->listen_host, config->listen_port);
    }
    pr_info(" ");
    pr_info("method           %s", config->method);
    pr_info("password         %s", config->password);
    pr_info("protocol         %s", config->protocol);
    if (config->protocol_param && strlen(config->protocol_param)) {
        pr_info("protocol_param   %s", config->protocol_param);
    }
    pr_info("obfs             %s", config->obfs);
    if (config->obfs_param && strlen(config->obfs_param)) {
        pr_info("obfs_param       %s", config->obfs_param);
    }
    if (config->over_tls_enable) {
        pr_info(" ");
        pr_warn("over TLS         %s", config->over_tls_enable ? "yes" : "no");
        pr_info("over TLS domain  %s", config->over_tls_server_domain);
        pr_info("over TLS path    %s", config->over_tls_path);
        pr_info(" ");
    }
    pr_info("udp relay        %s\n", config->udp ? "yes" : "no");
}

static void svr_usage(void) {
    printf("\nShadowsocksR native server\n"
        "\n"
        "Usage:\n"
        "\n"
        "  %s [-d] [-c <config file>] [-h]\n"
        "\n"
        "Options:\n"
        "\n"
        "  -d                     Run in background as a daemon.\n"
        "  -c <config file>       Configure file path. Default: " DEFAULT_CONF_PATH "\n"
        "  -f                     Force quit the program.\n"
        "  -h                     Show this help message.\n"
        "\n",
        get_app_name());
}
