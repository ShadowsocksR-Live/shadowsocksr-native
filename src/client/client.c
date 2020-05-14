#include "defs.h"
#include "common.h"
#include "s5.h"
#include "obfs.h"
#include "ssrbuffer.h"
#include "dump_info.h"
#include "ssr_executive.h"
#include "encrypt.h"
#include "tunnel.h"
#include "obfsutil.h"
#include "tls_cli.h"
#include "websocket_basic.h"
#include "http_parser_wrapper.h"
#include "udprelay.h"
#include "s5.h"
#include "base64.h"

/* Session states. */
#define TUNNEL_STAGE_MAP(V)                                                                                                                     \
    V( 0, tunnel_stage_handshake,                   "tunnel_stage_handshake -- Client App S5 handshake coming.")                                \
    V( 2, tunnel_stage_handshake_replied,           "tunnel_stage_handshake_replied -- Start waiting for request data.")                        \
    V( 3, tunnel_stage_s5_request_from_client_app,  "tunnel_stage_s5_request_from_client_app -- SOCKS5 Request data from client app.")          \
    V( 4, tunnel_stage_s5_udp_accoc,                "tunnel_stage_s5_udp_accoc")                                                                \
    V( 5, tunnel_stage_tls_connecting,              "tunnel_stage_tls_connecting")                                                              \
    V( 6, tunnel_stage_tls_websocket_upgrade,       "tunnel_stage_tls_websocket_upgrade")                                                       \
    V( 7, tunnel_stage_tls_streaming,               "tunnel_stage_tls_streaming")                                                               \
    V( 8, tunnel_stage_resolve_ssr_server_host_done,"tunnel_stage_resolve_ssr_server_host_done -- Upstream hostname DNS lookup has completed.") \
    V( 9, tunnel_stage_connect_ssr_server_done,     "tunnel_stage_connect_ssr_server_done -- Connect to server complete.")                      \
    V(10, tunnel_stage_ssr_auth_sent,               "tunnel_stage_ssr_auth_sent")                                                               \
    V(11, tunnel_stage_ssr_server_feedback_arrived, "tunnel_stage_ssr_server_feedback_arrived")                                                 \
    V(12, tunnel_stage_ssr_receipt_to_server_sent,  "tunnel_stage_ssr_receipt_to_server_sent")                                                  \
    V(13, tunnel_stage_auth_completion_done,        "tunnel_stage_auth_completion_done -- Auth succeeded. Can start piping data.")              \
    V(14, tunnel_stage_streaming,                   "tunnel_stage_streaming -- Pipe data back and forth.")                                      \
    V(15, tunnel_stage_kill,                        "tunnel_stage_kill -- Tear down session.")                                                  \

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

struct client_ctx;

struct udp_data_context {
    union sockaddr_universal src_addr;
    struct socks5_address target_addr;
    struct buffer_t *data;

    struct client_ctx *owner; // __weak_ptr
    struct udp_listener_ctx_t* udp_ctx; // __weak_ptr
};

struct udp_data_context * udp_data_context_create(void);
void udp_data_context_destroy(struct udp_data_context *ptr);

struct client_ctx {
    struct tunnel_ctx *tunnel; // __weak_ptr
    struct server_env_t *env; // __weak_ptr
    struct tunnel_cipher_ctx *cipher;
    struct buffer_t *init_pkg;
    struct s5_ctx *parser;  /* The SOCKS protocol parser. */
    enum tunnel_stage stage;
    void (*original_tunnel_shutdown)(struct tunnel_ctx *tunnel); /* ptr holder */
    char *sec_websocket_key;
    struct buffer_t *server_delivery_cache;
    struct buffer_t *local_write_cache;
    bool tls_is_eof;

    struct udp_data_context *udp_data_ctx;
};

static struct buffer_t * initial_package_create(const struct s5_ctx *parser);
static void dispatch_ssr_center(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void dispatch_tls_center(struct tunnel_ctx* tunnel, struct socket_ctx* socket);
static void do_handshake(struct tunnel_ctx *tunnel);
static void do_wait_client_app_s5_request(struct tunnel_ctx *tunnel);
static void do_parse_s5_request_from_client_app(struct tunnel_ctx *tunnel);
static void do_resolve_ssr_server_host_aftercare(struct tunnel_ctx *tunnel);
static void do_connect_ssr_server(struct tunnel_ctx *tunnel);
static void do_ssr_send_auth_package_to_server(struct tunnel_ctx *tunnel);
static void do_ssr_waiting_server_feedback(struct tunnel_ctx *tunnel);
static bool do_ssr_receipt_for_feedback(struct tunnel_ctx *tunnel);
static void do_socks5_reply_success(struct tunnel_ctx *tunnel);
static void do_launch_streaming(struct tunnel_ctx *tunnel);
static uint8_t* tunnel_extract_data(struct socket_ctx *socket, void*(*allocator)(size_t size), size_t *size);
static void tunnel_dying(struct tunnel_ctx *tunnel);
static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_arrive_end_of_file(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size);
static bool tunnel_is_in_streaming(struct tunnel_ctx* tunnel);
static void tunnel_tls_do_launch_streaming(struct tunnel_ctx *tunnel);
static void tunnel_tls_client_incoming_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_tls_on_connection_established(struct tunnel_ctx *tunnel);
static void tunnel_tls_on_data_received(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size);
static void tunnel_tls_on_shutting_down(struct tunnel_ctx *tunnel);

static bool can_auth_none(const struct tunnel_ctx *cx);
static bool can_auth_passwd(const struct tunnel_ctx *cx);
static bool can_access(const struct tunnel_ctx *cx, const struct sockaddr *addr);

static void client_tunnel_shutdown(struct tunnel_ctx *tunnel);

static bool init_done_cb(struct tunnel_ctx *tunnel, void *p) {
    struct server_env_t *env = (struct server_env_t *)p;
    struct server_config* config = env->config;

    struct client_ctx *ctx = (struct client_ctx *) calloc(1, sizeof(struct client_ctx));
    ctx->tunnel = tunnel;
    ctx->env = env;
    tunnel->data = ctx;

    /* override the origin function tunnel_shutdown */
    ctx->original_tunnel_shutdown = tunnel->tunnel_shutdown;
    tunnel->tunnel_shutdown = &client_tunnel_shutdown;

    tunnel->tunnel_dying = &tunnel_dying;
    tunnel->tunnel_timeout_expire_done = &tunnel_timeout_expire_done;
    tunnel->tunnel_outgoing_connected_done = &tunnel_outgoing_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_arrive_end_of_file = &tunnel_arrive_end_of_file;
    tunnel->tunnel_getaddrinfo_done = &tunnel_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_get_alloc_size = &tunnel_get_alloc_size;
    tunnel->tunnel_is_in_streaming = &tunnel_is_in_streaming;
    tunnel->tunnel_extract_data = &tunnel_extract_data;
    tunnel->tunnel_tls_on_connection_established = &tunnel_tls_on_connection_established;
    tunnel->tunnel_tls_on_data_received = &tunnel_tls_on_data_received;
    tunnel->tunnel_tls_on_shutting_down = &tunnel_tls_on_shutting_down;
    if (config->over_tls_enable) {
        tunnel->dispatch_center = &dispatch_tls_center;
    } else {
        tunnel->dispatch_center = &dispatch_ssr_center;
    }

    cstl_set_container_add(ctx->env->tunnel_set, tunnel);

    ctx->parser = s5_ctx_create();
    ctx->cipher = NULL;
    ctx->stage = tunnel_stage_handshake;

#define SOCKET_DATA_BUFFER_SIZE 0x8000
    ctx->server_delivery_cache = buffer_create(SOCKET_DATA_BUFFER_SIZE);
    ctx->local_write_cache = buffer_create(SOCKET_DATA_BUFFER_SIZE);

    return true;
}

struct tunnel_ctx * client_tunnel_initialize(uv_tcp_t *lx, unsigned int idle_timeout) {
    uv_loop_t *loop = lx->loop;
    struct server_env_t *env = (struct server_env_t *)loop->data;

    return tunnel_initialize(loop, lx, idle_timeout, &init_done_cb, env);
}

static void client_tunnel_connecting_print_info(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    char *tmp = socks5_address_to_string(tunnel->desired_addr, &malloc);
    const char *udp = ctx->udp_data_ctx ? "[UDP]" : "";
    pr_info("++++ connecting %s \"%s:%d\" ... ++++", udp, tmp, (int)tunnel->desired_addr->port);
    free(tmp);
}

static void client_tunnel_shutdown_print_info(struct tunnel_ctx *tunnel, bool success) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    char *tmp = socks5_address_to_string(tunnel->desired_addr, &malloc);
    const char *udp = (ctx->stage==tunnel_stage_s5_udp_accoc || ctx->udp_data_ctx) ? "[UDP]" : "";
    if (!success) {
        pr_err("---- disconnected %s \"%s:%d\" with failed. ---", udp, tmp, (int)tunnel->desired_addr->port);
    } else {
        if (udp && tunnel->desired_addr->port==0) {
            // It's UDP ASSOCIATE requests, don't inform the closing status. 
        } else {
            pr_info("---- disconnected %s \"%s:%d\" ----", udp, tmp, (int)tunnel->desired_addr->port);
        }
    }
    free(tmp);
}

static void client_tunnel_shutdown(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    assert(ctx);
    if (tunnel->tls_ctx) {
        tls_client_shutdown(tunnel);
    } else {
        client_tunnel_shutdown_print_info(tunnel, true);
        assert(ctx && ctx->original_tunnel_shutdown);
        if (ctx && ctx->original_tunnel_shutdown) {
            ctx->original_tunnel_shutdown(tunnel);
        }
    }
}

static void _do_shutdown_tunnel(struct cstl_set *set, const void *obj, bool *stop, void *p) {
    struct tunnel_ctx *tunnel = (struct tunnel_ctx *)obj;
    tunnel->tunnel_shutdown(tunnel);
    (void)set; (void)stop; (void)p;
}

void client_shutdown(struct server_env_t *env) {
    cstl_set_container_traverse(env->tunnel_set, &_do_shutdown_tunnel, NULL);
}

static struct buffer_t * initial_package_create(const struct s5_ctx *parser) {
    size_t s = 0;
    uint8_t *b = s5_address_package_create(parser, &malloc, &s);
    struct buffer_t *buffer = buffer_create_from(b, s);
    free(b);
    return buffer;
}

/* This is the core state machine that drives the client <-> upstream proxy.
* We move through the initial handshake and authentication steps first and
* end up (if all goes well) in the proxy state where we're just proxying
* data between the client and upstream.
*/
static void dispatch_ssr_center(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct server_env_t *env = ctx->env;
    struct server_config *config = env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    const char *info = tunnel_stage_string(ctx->stage); (void)info;
#if defined(__PRINT_INFO__)
    pr_info("%s", info);
#endif
    ASSERT(config->over_tls_enable == false);
    switch (ctx->stage) {
    case tunnel_stage_handshake:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_handshake(tunnel);
        break;
    case tunnel_stage_handshake_replied:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        do_wait_client_app_s5_request(tunnel);
        break;
    case tunnel_stage_s5_request_from_client_app:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_parse_s5_request_from_client_app(tunnel);
        break;
    case tunnel_stage_s5_udp_accoc:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        tunnel->tunnel_shutdown(tunnel);
        break;
    case tunnel_stage_resolve_ssr_server_host_done:
        do_resolve_ssr_server_host_aftercare(tunnel);
        break;
    case tunnel_stage_connect_ssr_server_done:
        do_ssr_send_auth_package_to_server(tunnel);
        break;
    case tunnel_stage_ssr_auth_sent:
        ASSERT(outgoing->wrstate == socket_state_done);
        outgoing->wrstate = socket_state_stop;
        do_ssr_waiting_server_feedback(tunnel);
        break;
    case tunnel_stage_ssr_server_feedback_arrived:
        ASSERT(outgoing->rdstate == socket_state_done);
        outgoing->rdstate = socket_state_stop;
        if (do_ssr_receipt_for_feedback(tunnel) == false) {
            do_socks5_reply_success(tunnel);
        }
        break;
    case tunnel_stage_ssr_receipt_to_server_sent:
        ASSERT(outgoing->wrstate == socket_state_done);
        outgoing->wrstate = socket_state_stop;
        do_socks5_reply_success(tunnel);
        break;
    case tunnel_stage_auth_completion_done:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        do_launch_streaming(tunnel);
        break;
    case tunnel_stage_streaming:
        tunnel_traditional_streaming(tunnel, socket);
        break;
    case tunnel_stage_kill:
        tunnel->tunnel_shutdown(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}

static void dispatch_tls_center(struct tunnel_ctx* tunnel, struct socket_ctx* socket) {
    struct client_ctx* ctx = (struct client_ctx*) tunnel->data;
    struct server_env_t* env = ctx->env;
    struct server_config* config = env->config;
    struct socket_ctx* incoming = tunnel->incoming;
    const char* info = tunnel_stage_string(ctx->stage); (void)info;
#if defined(__PRINT_INFO__)
    pr_info("%s", info);
#endif
    ASSERT(config->over_tls_enable);
    switch (ctx->stage) {
    case tunnel_stage_handshake:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_handshake(tunnel);
        break;
    case tunnel_stage_handshake_replied:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        do_wait_client_app_s5_request(tunnel);
        break;
    case tunnel_stage_s5_request_from_client_app:
        ASSERT(incoming->rdstate == socket_state_done);
        incoming->rdstate = socket_state_stop;
        do_parse_s5_request_from_client_app(tunnel);
        break;
    case tunnel_stage_s5_udp_accoc:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        tunnel->tunnel_shutdown(tunnel);
        break;
    case tunnel_stage_auth_completion_done:
        ASSERT(incoming->wrstate == socket_state_done);
        incoming->wrstate = socket_state_stop;
        tunnel_tls_do_launch_streaming(tunnel);
        break;
    case tunnel_stage_tls_streaming:
        tunnel_tls_client_incoming_streaming(tunnel, socket);
        break;
    case tunnel_stage_kill:
        tunnel->tunnel_shutdown(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}

static void do_handshake(struct tunnel_ctx *tunnel) {
    enum s5_auth_method methods;
    struct socket_ctx *incoming = tunnel->incoming;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct s5_ctx *parser = ctx->parser;
    uint8_t *data;
    size_t size;
    enum s5_result result;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t *)incoming->buf->base;
    size = (size_t)incoming->result;
    result = s5_parse(parser, &data, &size);
    if (result == s5_result_need_more) {
        /* Need more data. but we do NOT handle this situation */
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (size != 0) {
        /* Could allow a round-trip saving shortcut here if the requested auth
        * method is s5_auth_none (provided unauthenticated traffic is allowed.)
        * Requires client support however.
        */
        pr_err("junk in handshake");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (result != s5_result_auth_select) {
        pr_err("handshake error: %s", str_s5_result(result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    methods = s5_get_auth_methods(parser);
    if ((methods & s5_auth_none) && can_auth_none(tunnel)) {
        s5_select_auth(parser, s5_auth_none);
        socket_write(incoming, "\5\0", 2);  /* No auth required. */
        ctx->stage = tunnel_stage_handshake_replied;
        return;
    }

    if ((methods & s5_auth_passwd) && can_auth_passwd(tunnel)) {
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    socket_write(incoming, "\5\377", 2);  /* No acceptable auth. */
    ctx->stage = tunnel_stage_kill;
}

static void do_wait_client_app_s5_request(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    socket_read(incoming, true);
    ctx->stage = tunnel_stage_s5_request_from_client_app;
}

static void do_parse_s5_request_from_client_app(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct s5_ctx *parser = ctx->parser;
    uint8_t *data;
    size_t size;
    enum s5_result result;
    struct server_env_t *env = ctx->env;
    struct server_config *config = env->config;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t *)incoming->buf->base;
    size = (size_t)incoming->result;

    socks5_address_parse(data+3, size-3, tunnel->desired_addr);

    result = s5_parse(parser, &data, &size);
    if (result == s5_result_need_more) {
        pr_err("%s", "More data is needed, but we are not going to continue.");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (size != 0) {
        pr_err("junk in request %u", (unsigned)size);
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (result != s5_result_exec_cmd) {
        pr_err("request error: %s", str_s5_result(result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (s5_get_cmd(parser) == s5_cmd_tcp_bind) {
        /* Not supported but relatively straightforward to implement. */
        pr_warn("BIND requests are not supported.");
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (s5_get_cmd(parser) == s5_cmd_udp_assoc) {
        // UDP ASSOCIATE requests
        size_t len = 0;
        uint8_t *buf;

        union sockaddr_universal sockname;
        int namelen = sizeof(sockname);
        char *addr;
        uint16_t port = 0;

        VERIFY(0 == uv_tcp_getsockname(&incoming->handle.tcp, (struct sockaddr *)&sockname, &namelen));

        addr = universal_address_to_string(&sockname, &malloc);
        port = universal_address_get_port(&sockname);

        buf = s5_build_udp_assoc_package(config->udp, addr, port, &malloc, &len);
        free(addr);
        socket_write(incoming, buf, len);
        free(buf);
        ctx->stage = tunnel_stage_s5_udp_accoc;
        return;
    }

    ASSERT(s5_get_cmd(parser) == s5_cmd_tcp_connect);

    ctx->init_pkg = initial_package_create(parser);
    ctx->cipher = tunnel_cipher_create(ctx->env, 1452);

    {
        struct obfs_t *protocol = ctx->cipher->protocol;
        struct obfs_t *obfs = ctx->cipher->obfs;
        struct server_info_t *info;
        info = protocol ? protocol->get_server_info(protocol) : (obfs ? obfs->get_server_info(obfs) : NULL);
        if (info) {
            size_t s0 = 0;
            const uint8_t *p0 = buffer_get_data(ctx->init_pkg, &s0);
            info->buffer_size = SSR_BUFF_SIZE;
            info->head_len = (int) get_s5_head_size(p0, s0, 30);
        }
    }

    client_tunnel_connecting_print_info(tunnel);

    if (config->over_tls_enable) {
        ctx->stage = tunnel_stage_tls_connecting;
        tls_client_launch(tunnel, config);
        return;
    }
    else {
        union sockaddr_universal remote_addr = { {0} };
        if (universal_address_from_string(config->remote_host, config->remote_port, true, &remote_addr) != 0) {
            socket_getaddrinfo(outgoing, config->remote_host);
            ctx->stage = tunnel_stage_resolve_ssr_server_host_done;
            return;
        }

        outgoing->addr = remote_addr;

        do_connect_ssr_server(tunnel);
    }
}

static void do_resolve_ssr_server_host_aftercare(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct server_env_t *env = ctx->env;
    struct server_config *config = env->config;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) {
        /* TODO Escape control characters in parser->daddr. */
        pr_err("lookup error for \"%s\": %s", config->remote_host,
            uv_strerror((int)outgoing->result));
        /* Send back a 'Host unreachable' reply. */
        socket_write(incoming, "\5\4\0\1\0\0\0\0\0\0", 10);
        ctx->stage = tunnel_stage_kill;
        return;
    }

    /* Don't make assumptions about the offset of sin_port/sin6_port. */
    switch (outgoing->addr.addr.sa_family) {
    case AF_INET:
        outgoing->addr.addr4.sin_port = htons(config->remote_port);
        break;
    case AF_INET6:
        outgoing->addr.addr6.sin6_port = htons(config->remote_port);
        break;
    default:
        UNREACHABLE();
    }

    do_connect_ssr_server(tunnel);
}

/* Assumes that cx->outgoing.t.sa contains a valid AF_INET/AF_INET6 address. */
static void do_connect_ssr_server(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    int err;

    (void)config;
    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (!can_access(tunnel, &outgoing->addr.addr)) {
        pr_warn("connection not allowed by ruleset");
        /* Send a 'Connection not allowed by ruleset' reply. */
        socket_write(incoming, "\5\2\0\1\0\0\0\0\0\0", 10);
        ctx->stage = tunnel_stage_kill;
        return;
    }

    err = socket_connect(outgoing);
    if (err != 0) {
        pr_err("connect error: %s", uv_strerror(err));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    ctx->stage = tunnel_stage_connect_ssr_server_done;
}

static void do_ssr_send_auth_package_to_server(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result == 0) {
        const uint8_t *out_data = NULL; size_t out_data_len = 0;
        struct buffer_t *tmp = buffer_create(SSR_BUFF_SIZE); buffer_replace(tmp, ctx->init_pkg);
        if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) {
            buffer_release(tmp);
            tunnel->tunnel_shutdown(tunnel);
            return;
        }
        out_data = buffer_get_data(tmp, &out_data_len);
        socket_write(outgoing, out_data, out_data_len);
        buffer_release(tmp);

        ctx->stage = tunnel_stage_ssr_auth_sent;
        return;
    } else {
        socket_dump_error_info("upstream connection", outgoing);
        /* Send a 'Connection refused' reply. */
        socket_write(incoming, "\5\5\0\1\0\0\0\0\0\0", 10);
        ctx->stage = tunnel_stage_kill;
        return;
    }

    UNREACHABLE();
    tunnel->tunnel_shutdown(tunnel);
}

static void do_ssr_waiting_server_feedback(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) {
        pr_err("write error: %s", uv_strerror((int)outgoing->result));
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (tunnel_cipher_client_need_feedback(ctx->cipher)) {
        socket_read(outgoing, true);
        ctx->stage = tunnel_stage_ssr_server_feedback_arrived;
    } else {
        do_socks5_reply_success(tunnel);
    }
}

static bool do_ssr_receipt_for_feedback(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct tunnel_cipher_ctx *cipher_ctx = ctx->cipher;
    enum ssr_error error = ssr_error_client_decode;
    struct buffer_t *buf = NULL;
    struct buffer_t *feedback = NULL;
    bool done = false;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (outgoing->result < 0) {
        pr_err("read error: %s", uv_strerror((int)outgoing->result));
        tunnel->tunnel_shutdown(tunnel);
        return done;
    }

    buf = buffer_create_from((uint8_t *)outgoing->buf->base, (size_t)outgoing->result);
    error = tunnel_cipher_client_decrypt(cipher_ctx, buf, &feedback);
    ASSERT(error == ssr_ok);
    ASSERT(buffer_get_length(buf) == 0);

    if (feedback) {
        socket_write(outgoing, buffer_get_data(feedback, NULL), buffer_get_length(feedback));
        ctx->stage = tunnel_stage_ssr_receipt_to_server_sent;
        buffer_release(feedback);
        done = true;
    }

    buffer_release(buf);
    return done;
}

static void do_socks5_reply_success(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    uint8_t *buf;
    size_t size = 0;

    buf = s5_connect_response_package(ctx->parser, &malloc, &size);

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    socket_write(incoming, buf, size);
    free(buf);
    ctx->stage = tunnel_stage_auth_completion_done;
}

static void do_launch_streaming(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

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
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    struct tunnel_cipher_ctx *cipher_ctx = ctx->cipher;
    enum ssr_error error = ssr_error_client_decode;
    struct buffer_t *buf = NULL;
    uint8_t *result = NULL;

    if (socket==NULL || allocator==NULL || size==NULL) {
        return result;
    }
    *size = 0;

    buf = buffer_create(SSR_BUFF_SIZE);  buffer_store(buf, (uint8_t *)socket->buf->base, (size_t)socket->result);

    if (socket == tunnel->incoming) {
            error = tunnel_cipher_client_encrypt(cipher_ctx, buf);
    } else if (socket == tunnel->outgoing) {
        struct buffer_t *feedback = NULL;
        ASSERT(config->over_tls_enable == false);
        error = tunnel_cipher_client_decrypt(cipher_ctx, buf, &feedback);
        if (feedback) {
            ASSERT(false);
            buffer_release(feedback);
        }
    } else {
        ASSERT(false);
    }

    if (error == ssr_ok) {
        size_t len = buffer_get_length(buf);
        *size = len;
        result = (uint8_t *)allocator(len + 1);
        memcpy(result, buffer_get_data(buf, NULL), len);
        result[len] = 0;
    }

    buffer_release(buf);
    return result;
}

static void tunnel_dying(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;

    cstl_set_container_remove(ctx->env->tunnel_set, tunnel);
    if (ctx->cipher) {
        tunnel_cipher_release(ctx->cipher);
    }
    buffer_release(ctx->init_pkg);
    s5_ctx_release(ctx->parser);
    if (ctx->sec_websocket_key) { free(ctx->sec_websocket_key); }
    buffer_release(ctx->server_delivery_cache);
    buffer_release(ctx->local_write_cache);
    udp_data_context_destroy(ctx->udp_data_ctx);
    free(ctx);
}

static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    (void)tunnel;
    (void)socket;
}

static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    tunnel->dispatch_center(tunnel, socket);
}

static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    tunnel->dispatch_center(tunnel, socket);
}

static void tunnel_arrive_end_of_file(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    (void)socket;
    tunnel->tunnel_shutdown(tunnel);
}

static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    tunnel->dispatch_center(tunnel, socket);
}

static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    if (tunnel->tunnel_is_in_streaming(tunnel) == true) {
        // in streaming stage, do nothing and return.
        socket->wrstate = socket_state_stop;
        return;
    }
    tunnel->dispatch_center(tunnel, socket);
}

static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, struct socket_ctx *socket, size_t suggested_size) {
    (void)tunnel;
    (void)socket;
    (void)suggested_size;
    return SSR_BUFF_SIZE;
}

static bool tunnel_is_in_streaming(struct tunnel_ctx* tunnel) {
    // struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    // return (ctx->stage == tunnel_stage_streaming);
    (void)tunnel;
    return false;
}

static void tunnel_tls_do_launch_streaming(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    if (incoming->result < 0) {
        PRINT_ERR("write error: %s", uv_strerror((int)incoming->result));
        tunnel->tunnel_shutdown(tunnel);
    } else {
        socket_read(incoming, true);
        ctx->stage = tunnel_stage_tls_streaming;
    }
}

void tunnel_tls_send_websocket_data(struct tunnel_ctx* tunnel, const uint8_t* buf, size_t len) {
    ws_frame_info info = { WS_OPCODE_BINARY, true, true, 0, 0, 0 };
    uint8_t* frame;
    ws_frame_binary_alone(true, &info);
    frame = websocket_build_frame(&info, buf, len, &malloc);
    ASSERT(tunnel->tunnel_tls_send_data);
    if (tunnel->tunnel_tls_send_data) {
        tunnel->tunnel_tls_send_data(tunnel, frame, info.frame_size);
    }
    free(frame);
}

void tunnel_tls_client_incoming_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    ASSERT(socket == tunnel->incoming);

    ASSERT((socket->wrstate == socket_state_done && socket->rdstate != socket_state_done) ||
        (socket->wrstate != socket_state_done && socket->rdstate == socket_state_done));

    if (socket->wrstate == socket_state_done) {
        size_t len = 0;
        const uint8_t *buf = NULL;

        socket->wrstate = socket_state_stop;
        assert(socket_is_writeable(socket));

        if (buffer_get_length(ctx->local_write_cache)==0 && ctx->tls_is_eof) {
            tunnel->tunnel_shutdown(tunnel);
            return;
        }

        buf = buffer_get_data(ctx->local_write_cache, &len);
        if (len) {
            socket_write(socket, buf, len);
            buffer_reset(ctx->local_write_cache);
        }
    }
    else if (socket->rdstate == socket_state_done) {
        socket->rdstate = socket_state_stop;
        {
            size_t len = 0;
            uint8_t *buf = NULL;
            ASSERT(tunnel->tunnel_extract_data);
            buf = tunnel->tunnel_extract_data(socket, &malloc, &len);
            if (buf /* && size > 0 */) {
                tunnel_tls_send_websocket_data(tunnel, buf, len);
            } else {
                tunnel->tunnel_shutdown(tunnel);
            }
            free(buf);
        }
        socket_read(socket, false);
    }
    else {
        ASSERT(false);
    }
}

static void tunnel_tls_on_connection_established(struct tunnel_ctx *tunnel) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct server_config *config = ctx->env->config;
    
    if (tunnel_is_dead(tunnel) || ctx == NULL) {
        /* dirty code, insure calling to client_tunnel_shutdown -> tls_client_shutdown */
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    ASSERT(incoming->rdstate == socket_state_stop);
    ASSERT(incoming->wrstate == socket_state_stop);
    ASSERT(outgoing->rdstate == socket_state_stop);
    ASSERT(outgoing->wrstate == socket_state_stop);

    {
        struct buffer_t *tmp = buffer_create(SSR_BUFF_SIZE); buffer_replace(tmp, ctx->init_pkg);
        if (ctx->udp_data_ctx) {
            buffer_replace(tmp, ctx->udp_data_ctx->data);
        }
        if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, tmp)) {
            tunnel->tunnel_shutdown(tunnel);
        } else {
            const char *url_path = config->over_tls_path;
            const char *domain = config->over_tls_server_domain;
            unsigned short domain_port = config->remote_port;
            uint8_t *buf = NULL;
            size_t len = 0;
            size_t typ_len = 0;
            const uint8_t *typ = buffer_get_data(tmp, &typ_len);
            char *key = websocket_generate_sec_websocket_key(&malloc);
            ctx->sec_websocket_key = key;

            buf = websocket_connect_request(domain, domain_port, url_path, key, &malloc, &len);
            buf = http_header_set_payload_data(buf, &len, &realloc, typ, typ_len);
            if (ctx->udp_data_ctx) {
                size_t addr_len = 0;
                uint8_t* addr_p = socks5_address_binary(&ctx->udp_data_ctx->target_addr, &malloc, &addr_len);
                char *b64str = url_safe_base64_encode_alloc(addr_p, (int)addr_len, &malloc);
                static const char* udp_fmt = "UDP: %s\r\n";
                char* udp_field = (char*)calloc(strlen(udp_fmt) + strlen(b64str) + 1, sizeof(*udp_field));
                sprintf(udp_field, udp_fmt, b64str);
                buf = http_header_append_new_field(buf, &len, &realloc, udp_field);
                free(udp_field);
                free(b64str);
                free(addr_p);
            }
            ASSERT (tunnel->tunnel_tls_send_data);
            if (tunnel->tunnel_tls_send_data) {
                tunnel->tunnel_tls_send_data(tunnel, buf, len);
            }
            ctx->stage = tunnel_stage_tls_websocket_upgrade;

            free(buf);
        }
        buffer_release(tmp);
    }
}

static void tunnel_tls_on_data_received(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;

    if (tunnel_is_dead(tunnel)) {
        tunnel->tunnel_shutdown(tunnel);
        return;
    }

    if (ctx->stage == tunnel_stage_tls_websocket_upgrade) {
        struct http_headers *hdrs = http_headers_parse(false, data, size);
        const char *accept_val = http_headers_get_field_val(hdrs, SEC_WEBSOKET_ACCEPT);
        const char *ws_status = http_headers_get_status(hdrs);
        char *calc_val = websocket_generate_sec_websocket_accept(ctx->sec_websocket_key, &malloc);
        size_t pl = http_headers_get_parsed_length(hdrs);
        if (NULL == ws_status ||
            0 != strcmp(WEBSOCKET_STATUS, ws_status) ||
            NULL == accept_val || 
            NULL == calc_val ||
            pl != size ||
            0 != strcmp(accept_val, calc_val))
        {
            tunnel->tunnel_shutdown(tunnel);
        } else {
            if (ctx->udp_data_ctx) {
                // At this moment, the UDP over TLS connection have established.
                // We needn't send the client incoming data, because we have sent
                // it as payload of WebSocket authenticate package in function
                // `tunnel_tls_on_connection_established`.
                ctx->stage = tunnel_stage_tls_streaming;
            } else {
                do_socks5_reply_success(tunnel);
            }
        }
        http_headers_destroy(hdrs);
        free(calc_val);
        return;
    }
    else if (ctx->stage == tunnel_stage_tls_streaming) {

        buffer_concatenate(ctx->server_delivery_cache, data, size);
        do {
            ws_frame_info info = { WS_OPCODE_BINARY, 0, 0, 0, 0, 0 };
            struct buffer_t *tmp;
            enum ssr_error e;
            struct buffer_t *feedback = NULL;
            size_t buf_len = 0;
            const uint8_t *buf_data = buffer_get_data(ctx->server_delivery_cache, &buf_len);
            uint8_t *payload =  websocket_retrieve_payload(buf_data, buf_len, &malloc, &info);
            (void)e;
            if (payload == NULL) {
                break;
            }
            buffer_shortened_to(ctx->server_delivery_cache, info.frame_size, buf_len-info.frame_size);

            if (info.fin && info.masking==false && info.opcode==WS_OPCODE_CLOSE) {
                ws_close_reason reason = WS_CLOSE_REASON_UNKNOWN;
                if (info.payload_size >= sizeof(uint16_t)) {
                    reason = (ws_close_reason) ws_ntoh16( *((uint16_t *)payload) );
                }
                ASSERT(reason == WS_CLOSE_REASON_NORMAL);
                free(payload);
                ctx->tls_is_eof = true;
                break;
            }

            tmp = buffer_create_from(payload, info.payload_size);
            e = tunnel_cipher_client_decrypt(ctx->cipher, tmp, &feedback);
            assert(!feedback);

            buffer_concatenate2(ctx->local_write_cache, tmp);

            buffer_release(tmp);
            free(payload);
        } while(true);

        if ((buffer_get_length(ctx->local_write_cache) == 0) && ctx->tls_is_eof) {
            tunnel->tunnel_shutdown(tunnel);
            return;
        }

        if (ctx->udp_data_ctx) {
            // Write the received remote data back to the connected UDP client.
            struct udp_data_context* udp_data_ctx = ctx->udp_data_ctx;
            size_t s = 0;
            const uint8_t* p = buffer_get_data(ctx->local_write_cache, &s);
            udp_relay_send_data(udp_data_ctx->udp_ctx, &udp_data_ctx->src_addr, p, s);
            buffer_reset(ctx->local_write_cache);
            return;
        }

        if (socket_is_writeable(incoming)) {
            size_t s = 0;
            const uint8_t *p = buffer_get_data(ctx->local_write_cache, &s);
            if (s) {
                socket_write(incoming, p, s);
                buffer_reset(ctx->local_write_cache);
            }
        }
    }
    else {
        ASSERT(false);
    }
}

static void tunnel_tls_on_shutting_down(struct tunnel_ctx *tunnel) {
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    assert(ctx->original_tunnel_shutdown);
    client_tunnel_shutdown_print_info(tunnel, (tunnel->tls_ctx != NULL));
    ctx->original_tunnel_shutdown(tunnel);
}

static bool can_auth_none(const struct tunnel_ctx *cx) {
    (void)cx;
    return true;
}

static bool can_auth_passwd(const struct tunnel_ctx *cx) {
    (void)cx;
    return false;
}

static bool can_access(const struct tunnel_ctx *cx, const struct sockaddr *addr) {
    const struct sockaddr_in6 *addr6;
    const struct sockaddr_in *addr4;
    const uint32_t *p;
    uint32_t a, b, c, d;

    (void)cx; (void)addr;
#if !defined(NDEBUG)
    return true;
#endif

    /* TODO Implement proper access checks.  For now, just reject
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

struct udp_data_context * udp_data_context_create(void) {
    struct udp_data_context *ptr;
    ptr = (struct udp_data_context *) calloc(1, sizeof(*ptr));
    ptr->data = buffer_create(SSR_BUFF_SIZE);
    return ptr;
}

void udp_data_context_destroy(struct udp_data_context *ptr) {
    if (ptr) {
        buffer_release(ptr->data);
        free(ptr);
    }
}

static void _do_find_upd_tunnel(struct cstl_set *set, const void *obj, bool *stop, void *p) {
    struct tunnel_ctx *tunnel = (struct tunnel_ctx *)obj;
    struct client_ctx *ctx = (struct client_ctx *)tunnel->data;
    struct udp_data_context *query_data = (struct udp_data_context*)p;
    struct udp_data_context* iter = ctx->udp_data_ctx;
    if (iter) {
        if ((memcmp(&iter->src_addr, &query_data->src_addr, sizeof(union sockaddr_universal)) == 0) &&
            (memcmp(&iter->target_addr, &query_data->target_addr, sizeof(struct socks5_address)) == 0))
        {
            query_data->owner = ctx;
            if (stop) { *stop = true; }
        }
    }
    (void)set;
}

void udp_on_recv_data(struct udp_listener_ctx_t *udp_ctx, const union sockaddr_universal *src_addr, const struct buffer_t *data, void*p) {
    uv_loop_t *loop = udp_relay_context_get_loop(udp_ctx);
    struct server_env_t *env = (struct server_env_t *)loop->data;
    struct server_config *config = env->config;
    struct tunnel_ctx *tunnel = NULL;
    struct client_ctx *ctx = NULL;
    size_t data_len, frag_number;
    const uint8_t *data_p = buffer_get_data(data, &data_len);
    struct udp_data_context *query_data;
    const uint8_t *raw_p = NULL; size_t raw_len = 0;

    query_data = udp_data_context_create();
    if (src_addr) {
        query_data->src_addr = *src_addr;
    }

    raw_p = s5_parse_upd_package(data_p, data_len, &query_data->target_addr, &frag_number, &raw_len);
    if (frag_number != 0) {
        // We don't process fragmented UDP packages and just drop them.
        udp_data_context_destroy(query_data);
        return;
    }

    cstl_set_container_traverse(env->tunnel_set, &_do_find_upd_tunnel, query_data);
    if (query_data->owner) {
        struct buffer_t* out_ref;
        ctx = query_data->owner;
        ASSERT(ctx->udp_data_ctx);
        udp_data_context_destroy(query_data);
        ASSERT(ctx->stage > tunnel_stage_tls_connecting);
        out_ref = ctx->udp_data_ctx->data;
        buffer_store(out_ref, raw_p, raw_len);
        tunnel = ctx->tunnel;
        if (ssr_ok != tunnel_cipher_client_encrypt(ctx->cipher, out_ref)) {
            tunnel->tunnel_shutdown(tunnel);
        } else {
            size_t len = 0; const uint8_t* p = buffer_get_data(out_ref, &len);
            tunnel_tls_send_websocket_data(tunnel, p, len);
        }
    } else {
        tunnel = tunnel_initialize(loop, NULL, config->idle_timeout, &init_done_cb, env);
        ctx = (struct client_ctx *)tunnel->data;
        ctx->cipher = tunnel_cipher_create(ctx->env, 1452);
        ctx->udp_data_ctx = query_data;
        ctx->udp_data_ctx->udp_ctx = udp_ctx;

        *tunnel->desired_addr = query_data->target_addr;

        ctx->stage = tunnel_stage_tls_connecting;
        tls_client_launch(tunnel, config);

        client_tunnel_connecting_print_info(tunnel);

        buffer_store(ctx->udp_data_ctx->data, raw_p, raw_len);
    }
    (void)p;
}
