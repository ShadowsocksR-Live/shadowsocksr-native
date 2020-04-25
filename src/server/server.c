#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include "common.h"
#include "dump_info.h"
#include "netutils.h"
#include "obfsutil.h"
#include "ssrbuffer.h"
#include "ssr_executive.h"
#include "config_json.h"
#include "sockaddr_universal.h"
#include "udprelay.h"
#include "tunnel.h"
#include "daemon_wrapper.h"
#include "cmd_line_parser.h"
#include "ssrutils.h"
#include "ws_tls_basic.h"
#include "http_parser_wrapper.h"

#ifndef SSR_MAX_CONN
#define SSR_MAX_CONN 1024
#endif

struct ssr_server_state {
    struct server_env_t *env;

    uv_signal_t *sigint_watcher;
    uv_signal_t *sigterm_watcher;

    bool shutting_down;

    uv_tcp_t *tcp_listener;
    struct udp_listener_ctx_t *udp_listener;
    struct cstl_map *resolved_ips;
};

enum tunnel_stage {
    tunnel_stage_initial = 0,  /* Initial stage                    */
    tunnel_stage_obfs_receipt_done,
    tunnel_stage_client_feedback_coming,
    tunnel_stage_proto_confirm_done,
    tunnel_stage_resolve_host = 4,  /* Resolve the hostname             */
    tunnel_stage_connect_host,
    tunnel_stage_launch_streaming,
    tunnel_stage_tls_client_feedback,
    tunnel_stage_streaming,  /* Stream between client and server */
};

struct server_ctx {
    struct server_env_t *env; // __weak_ptr
    struct tunnel_cipher_ctx *cipher;
    struct buffer_t *init_pkg;
    enum tunnel_stage stage;
    size_t _tcp_mss;
    size_t _overhead;
    size_t _recv_buffer_size;
    size_t _recv_d_max_size;
    char *sec_websocket_key;
    bool ws_tls_beginning;
    bool ws_close_frame_sent;
    struct buffer_t *client_delivery_cache;
};

struct address_timestamp {
    union sockaddr_universal address;
    time_t timestamp;
};

static int ssr_server_run_loop(struct server_config *config);
void ssr_server_shutdown(struct ssr_server_state *state);

void server_tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout);
void server_shutdown(struct server_env_t *env);

void signal_quit_cb(uv_signal_t *handle, int signum);
void tunnel_incoming_connection_established_cb(uv_stream_t *server, int status);

static void tunnel_dying(struct tunnel_ctx *tunnel);
static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_arrive_end_of_file(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size);
static uint8_t* tunnel_extract_data(struct socket_ctx *socket, void*(*allocator)(size_t size), size_t *size);

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

static int resolved_ips_compare_key(const void *left, const void *right);
static void resolved_ips_destroy_object(void *obj);

void print_server_info(const struct server_config *config);
static void svr_usage(void);

void on_atexit(void) {
    MEM_CHECK_DUMP_LEAKS();
}

int main(int argc, char * const argv[]) {
    struct server_config *config = NULL;
    int err = -1;
    struct cmd_line_info *cmds = NULL;

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

        config = config_create();
        if (parse_config_file(true, cmds->cfg_file, config) == false) {
            break;
        }

        config_ssrot_revision(config);

        config_parse_protocol_param(config, config->protocol_param);

#ifndef UDP_RELAY_ENABLE
        config->udp = false;
#endif // UDP_RELAY_ENABLE

        if (config->method == NULL || config->password == NULL) {
            break;
        }

        if (cmds->daemon_flag) {
            char param[257] = { 0 };
            sprintf(param, "-c \"%s\"", cmds->cfg_file);
            daemon_wrapper(argv[0], param);
        }

        print_server_info(config);

        ssr_server_run_loop(config);

        err = 0;
    } while (0);

    cmd_line_info_destroy(cmds);

    config_release(config);

    if (err != 0) {
        svr_usage();
    }
    return 0;
}

#if defined(__AUTO_EXIT__)
uv_timer_t timer_4_unix_debug = { 0 };
#ifndef __AUTO_EXIT_TIMEOUT__
#define __AUTO_EXIT_TIMEOUT__ 5000
#endif

static void socket_timer_expire_cb(uv_timer_t *handle) {
    struct server_env_t *env = (struct server_env_t *)handle->loop->data;
    struct ssr_server_state *state = (struct ssr_server_state *)env->data;
    ASSERT(state);
    ssr_server_shutdown(state);
}
#endif // __AUTO_EXIT__

static int ssr_server_run_loop(struct server_config *config) {
    uv_loop_t *loop = NULL;
    struct ssr_server_state *state = NULL;
    int r = 0;

    loop = (uv_loop_t *) calloc(1, sizeof(uv_loop_t));
    uv_loop_init(loop);

    state = (struct ssr_server_state *) calloc(1, sizeof(*state));
    state->env = ssr_cipher_env_create(config, state);
    loop->data = state->env;

    {
        union sockaddr_universal addr = { {0} };
        int error;
        uv_tcp_t *listener = (uv_tcp_t *) calloc(1, sizeof(uv_tcp_t));

        uv_tcp_init(loop, listener);

        addr.addr4.sin_family = AF_INET;
        addr.addr4.sin_port = htons(config->listen_port);
        addr.addr4.sin_addr.s_addr = htonl(INADDR_ANY);
        uv_tcp_bind(listener, &addr.addr, 0);

        error = uv_listen((uv_stream_t *)listener, SSR_MAX_CONN, tunnel_incoming_connection_established_cb);

        if (error != 0) {
            return fprintf(stderr, "Error on listening: %s.\n", uv_strerror(error));
        }
        state->tcp_listener = listener;

        state->resolved_ips = obj_map_create(resolved_ips_compare_key,
                                             resolved_ips_destroy_object,
                                             resolved_ips_destroy_object);
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

#if defined(__AUTO_EXIT__)
    VERIFY(0 == uv_timer_init(loop, &timer_4_unix_debug));
    VERIFY(0 == uv_timer_start(&timer_4_unix_debug, socket_timer_expire_cb, __AUTO_EXIT_TIMEOUT__, 0));
#endif // __AUTO_EXIT__

    r = uv_run(loop, UV_RUN_DEFAULT);

    VERIFY(uv_loop_close(loop) == 0);

    {
        ssr_cipher_env_release(state->env);

        free(state->sigint_watcher);
        free(state->sigterm_watcher);

        obj_map_destroy(state->resolved_ips);

        free(state);
    }

    free(loop);

    return r;
}

static void listener_close_done_cb(uv_handle_t* handle) {
    free((void *)((uv_tcp_t *)handle));
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

#if UDP_RELAY_ENABLE
    if (state->udp_listener) {
        // udprelay_shutdown(state->udp_listener);
    }
#endif // UDP_RELAY_ENABLE

    server_shutdown(state->env);

#if defined(__AUTO_EXIT__)
    VERIFY(0 == uv_timer_stop(&timer_4_unix_debug));
    uv_close((uv_handle_t *)&timer_4_unix_debug, NULL);
#endif // __AUTO_EXIT__

    pr_info("\n");
    pr_info("terminated.\n");
}

bool _init_done_cb(struct tunnel_ctx *tunnel, void *p) {
    struct server_env_t *env = (struct server_env_t *)p;

    struct server_ctx *ctx = (struct server_ctx *) calloc(1, sizeof(*ctx));
    ctx->env = env;
    ctx->init_pkg = buffer_create(SSR_BUFF_SIZE);
    ctx->_recv_buffer_size = TCP_BUF_SIZE_MAX;
    tunnel->data = ctx;

    tunnel->tunnel_dying = &tunnel_dying;
    tunnel->tunnel_timeout_expire_done = &tunnel_timeout_expire_done;
    tunnel->tunnel_outgoing_connected_done = &tunnel_outgoing_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_arrive_end_of_file = &tunnel_arrive_end_of_file;
    tunnel->tunnel_getaddrinfo_done = &tunnel_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_get_alloc_size = &tunnel_get_alloc_size;
    tunnel->tunnel_extract_data = &tunnel_extract_data;

    cstl_set_container_add(ctx->env->tunnel_set, tunnel);

    ctx->cipher = NULL;
    ctx->stage = tunnel_stage_initial;

#define SOCKET_DATA_BUFFER_SIZE 0x8000
    ctx->client_delivery_cache = buffer_create(SOCKET_DATA_BUFFER_SIZE);

    return is_incoming_ip_legal(tunnel);
}

void server_tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout) {
    uv_loop_t *loop = listener->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    tunnel_initialize(loop, listener, idle_timeout, &_init_done_cb, env);
}

static void _do_shutdown_tunnel(const void *obj, void *p) {
    struct tunnel_ctx *tunnel = (struct tunnel_ctx *)obj;
    tunnel->tunnel_shutdown(tunnel);
    (void)p;
}

void server_shutdown(struct server_env_t *env) {
    cstl_set_container_traverse(env->tunnel_set, &_do_shutdown_tunnel, NULL);
}

void signal_quit_cb(uv_signal_t *handle, int signum) {
    struct server_env_t *env;
    ASSERT(handle);
    env = (struct server_env_t *)handle->loop->data;
    switch (signum) {
    case SIGINT:
    case SIGTERM:
#ifndef __MINGW32__
    case SIGUSR1:
#endif
    {
    struct ssr_server_state *state = (struct ssr_server_state *)env->data;
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

static void tunnel_dying(struct tunnel_ctx *tunnel) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;

    cstl_set_container_remove(ctx->env->tunnel_set, tunnel);
    if (ctx->cipher) {
        tunnel_cipher_release(ctx->cipher);
    }
    buffer_release(ctx->init_pkg);
    if (ctx->sec_websocket_key) { free(ctx->sec_websocket_key); }
    buffer_release(ctx->client_delivery_cache);
    free(ctx);
}

static void do_next(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    bool done = false;
    struct server_ctx *ctx = (struct server_ctx *)tunnel->data;
    struct server_config *config = ctx->env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    (void)done;
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
        socket_read(incoming, true);
        ctx->stage = tunnel_stage_client_feedback_coming;
        break;
    case tunnel_stage_client_feedback_coming:
        ASSERT(incoming == socket);
        ASSERT(incoming->rdstate == socket_state_done);
        ASSERT(incoming->wrstate == socket_state_stop);
        incoming->rdstate = socket_state_stop;
        do_handle_client_feedback(tunnel, incoming);
        break;
    case tunnel_stage_proto_confirm_done:
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
        do_tls_launch_streaming(tunnel, socket);
        break;
    case tunnel_stage_streaming:
        tunnel_traditional_streaming(tunnel, socket);
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
    do_next(tunnel, socket);
}

static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
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
            ASSERT(incoming->wrstate == socket_state_stop);

            p = websocket_build_close_frame(false, WS_CLOSE_REASON_NORMAL, NULL, &malloc, &frame_size);
            if (p) {
                socket_write(incoming, p, frame_size);
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

static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
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
        do_next(tunnel, socket);
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
    struct socks5_address addr;
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

    frame_size = ctx->_tcp_mss - ctx->_overhead;

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
        size_t tcp_mss = _update_tcp_mss(incoming);

        ASSERT(incoming == tunnel->incoming);

        if (incoming->result < 0) {
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        ASSERT(ctx->cipher == NULL);
        ctx->cipher = tunnel_cipher_create(ctx->env, tcp_mss);
        ctx->_tcp_mss = tcp_mss;

        result = tunnel_cipher_server_decrypt(ctx->cipher, buf, &obfs_receipt, &proto_confirm);

        if (obfs_receipt) {
            ASSERT(proto_confirm == NULL);
            socket_write(incoming, buffer_get_data(obfs_receipt, NULL), buffer_get_length(obfs_receipt));
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
            socket_write(incoming, buffer_get_data(proto_confirm, NULL), buffer_get_length(proto_confirm));
            ctx->stage = tunnel_stage_proto_confirm_done;
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
            socket_write(incoming, buffer_get_data(proto_confirm, NULL), buffer_get_length(proto_confirm));
            ctx->stage = tunnel_stage_proto_confirm_done;
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
    const char *host = NULL;
    struct socks5_address *s5addr;
    union sockaddr_universal target;
    bool ipFound = true;
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

    host = s5addr->addr.domainname;

    if (socks5_address_to_universal(s5addr, &target) == false) {
        ASSERT(s5addr->addr_type == SOCKS5_ADDRTYPE_DOMAINNAME);

        if (uv_ip4_addr(host, s5addr->port, &target.addr4) != 0) {
            if (uv_ip6_addr(host, s5addr->port, &target.addr6) != 0) {
                ipFound = false;
            }
        }
    }

    if (ipFound == false) {
        struct ssr_server_state *state = (struct ssr_server_state *)ctx->env->data;
        struct address_timestamp **addr = NULL;
        addr = (struct address_timestamp **)obj_map_find(state->resolved_ips, &host);
        if (addr && *addr) {
            target = (*addr)->address;
            target.addr4.sin_port = htons(s5addr->port);
            ipFound = true;
        }
    }

    if (ipFound == false) {
        if (!validate_hostname(host, strlen(host))) {
            // report_addr(server->fd, MALFORMED);
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
        ctx->stage = tunnel_stage_resolve_host;
        outgoing->addr.addr4.sin_port = htons(s5addr->port);
        socket_getaddrinfo(outgoing, host);
    } else {
        outgoing->addr = target;
        do_connect_host_start(tunnel, outgoing);
    }
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
        char *host = tunnel->desired_addr->addr.domainname;
        struct ssr_server_state *state = (struct ssr_server_state *)ctx->env->data;
        if (obj_map_exists(state->resolved_ips, &host) == false) {
            struct address_timestamp *addr = NULL;
            addr = (struct address_timestamp *)calloc(1, sizeof(struct address_timestamp));
            addr->address = outgoing->addr;
            addr->timestamp = time(NULL);
            host = strdup(host);
            obj_map_add(state->resolved_ips, &host, sizeof(void *), &addr, sizeof(void *));
        }
    }

    do_connect_host_start(tunnel, socket);
}

static void do_connect_host_start(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct server_ctx *ctx = (struct server_ctx *) tunnel->data;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    int err;

    (void)socket;
    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    ctx->stage = tunnel_stage_connect_host;
    err = socket_connect(outgoing);

    if (err != 0) {
        pr_err("connect error: %s", uv_strerror(err));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }
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
            socket_write(outgoing, data, len);
            ctx->stage = tunnel_stage_launch_streaming;
        } else {
            outgoing->wrstate = socket_state_done;
            do_launch_streaming(tunnel, socket);
        }
        return;
    } else {
        socket_dump_error_info("upstream connection", socket);
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

    socket_read(incoming, false);
    socket_read(outgoing, true);
    ctx->stage = tunnel_stage_streaming;
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
        size_t tcp_mss = _update_tcp_mss(socket);

        ASSERT(socket == tunnel->incoming);
        ASSERT(config->over_tls_enable); (void)config;

        if (socket->result < 0) {
            tunnel->tunnel_shutdown(tunnel);
            break;
        }

        ASSERT(ctx->cipher == NULL);
        ctx->cipher = tunnel_cipher_create(ctx->env, tcp_mss);
        ctx->_tcp_mss = tcp_mss;

        hdrs = http_headers_parse(true, indata, len);
        {
            const char *key = http_headers_get_field_val(hdrs, SEC_WEBSOKET_KEY);
            const char *url = http_headers_get_url(hdrs);
            if (key==NULL || url==NULL || 0 != strcmp(url, config->over_tls_path)) {
                tunnel->tunnel_shutdown(tunnel);
                break;
            }
            ctx->sec_websocket_key = (char *) calloc(strlen(key) + 1, sizeof(char));
            strcpy(ctx->sec_websocket_key, key);
        }
        {
            size_t cb = http_headers_get_content_beginning(hdrs);
            struct buffer_t *buf = buffer_create_from(indata + cb, len - cb);
            result = tunnel_cipher_server_decrypt(ctx->cipher, buf, &obfs_receipt, &proto_confirm);
            buffer_release(buf);
        }
        ASSERT(obfs_receipt == NULL);
        ASSERT(proto_confirm == NULL);

        ASSERT(result /* && result->len!=0 */);
        if (is_legal_header(result) == false) {
            tunnel->tunnel_shutdown(tunnel);
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
    if (frame_size >= ctx->_tcp_mss) {
        // read_size = ctx->_tcp_mss - (2 + sizeof(uint64_t) + 0);
        read_size = ctx->_tcp_mss - (2 + sizeof(uint16_t) + 0);
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

    socket_write(incoming, tls_ok, strlen(tls_ok));
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

    socket_read(incoming, false);
    socket_read(outgoing, true);
    ctx->stage = tunnel_stage_streaming;
}

static uint8_t* tunnel_extract_data(struct socket_ctx *socket, void*(*allocator)(size_t size), size_t *size) {
    struct tunnel_ctx *tunnel = socket->tunnel;
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
                ws_frame_info info = { WS_OPCODE_BINARY, false, false, 0, 0, 0 };
                struct buffer_t *tmp = tunnel_cipher_server_encrypt(cipher_ctx, src);
                uint8_t *frame;
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
            } else {
                buf = tunnel_cipher_server_encrypt(cipher_ctx, src);
            }
        } else if (socket == tunnel->incoming) {
            struct buffer_t *obfs_receipt = NULL;
            struct buffer_t *proto_confirm = NULL;
            if (config->over_tls_enable) {
                buf = buffer_create(SOCKET_DATA_BUFFER_SIZE);
                buffer_concatenate2(ctx->client_delivery_cache, src);
                do {
                    ws_frame_info info = { WS_OPCODE_BINARY, 0, 0, 0, 0, 0 };
                    uint8_t *payload;
                    size_t buf_len = 0;
                    const uint8_t *buf_data;
                    struct buffer_t *pb, *tmp;

                    buf_data = buffer_get_data(ctx->client_delivery_cache, &buf_len);

                    payload = websocket_retrieve_payload(buf_data, buf_len, &malloc, &info);
                    if (payload == NULL) {
                        break;
                    }
                    buffer_shortened_to(ctx->client_delivery_cache, info.frame_size, buf_len - info.frame_size);

                    pb = buffer_create_from(payload, info.payload_size);
                    tmp = tunnel_cipher_server_decrypt(cipher_ctx, pb, &obfs_receipt, &proto_confirm);
                    buffer_release(pb);

                    buffer_concatenate2(buf, tmp);

                    buffer_release(tmp);
                    free(payload);
                } while (true);
                (void)buf;
            } else {
                buf = tunnel_cipher_server_decrypt(cipher_ctx, src, &obfs_receipt, &proto_confirm);
            }
            ASSERT(obfs_receipt == NULL);
            ASSERT(proto_confirm == NULL);
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

static int resolved_ips_compare_key(const void *left, const void *right) {
    char *l = *(char **)left;
    char *r = *(char **)right;
    return strcmp(l, r);
}

static void resolved_ips_destroy_object(void *obj) {
    if (obj) {
        void *str = *((void **)obj);
        if (str) {
            free(str);
        }
    }
}

void print_server_info(const struct server_config *config) {
    pr_info("ShadowsocksR native server\n");
    pr_info("listen port      %hu", config->listen_port);
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
        "  -h                     Show this help message.\n"
        "\n",
        get_app_name());
}
