#include "ssr_executive.h"
#include "tls_cli.h"
#include <uv.h>
#include <uv-mbed/uv-mbed.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct tls_cli_ctx {
    struct server_config *config; /* weak pointer */
    uv_mbed_t *mbed;
    tls_cli_tcp_conn_cb tls_tcp_conn_cb;
    void *tls_tcp_conn_cb_p;

    tls_cli_on_connection_established_cb on_connection_established;
    void* on_connection_established_p;

    tls_cli_on_write_done_cb on_write_done;
    void* on_write_done_p;

    tls_cli_on_data_received_cb on_data_received;
    void* on_data_received_p;

    tls_cli_on_shutting_down_cb on_shutting_down;
    void* on_shutting_down_p;
};

static void _mbed_connect_done_cb(uv_mbed_t* mbed, int status, void *p);
static void _mbed_alloc_cb(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t* buf);
static void _mbed_data_received_cb(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p);
static void _mbed_write_done_cb(uv_mbed_t *mbed, int status, void *p);
static void _mbed_close_done_cb(uv_mbed_t *mbed, void *p);
static void _uv_mbed_tcp_connect_established_cb(uv_mbed_t* mbed, void *p);

struct tls_cli_ctx* tls_client_launch(uv_loop_t* loop, struct server_config* config) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)calloc(1, sizeof(*ctx));
    ctx->mbed = uv_mbed_init(loop, config->over_tls_server_domain, ctx, 0);
    ctx->config = config;

    uv_mbed_add_ref(ctx->mbed);
    uv_mbed_connect(ctx->mbed, config->remote_host, config->remote_port, config->connect_timeout_ms, _mbed_connect_done_cb, ctx);
    uv_mbed_set_tcp_connect_established_callback(ctx->mbed, &_uv_mbed_tcp_connect_established_cb, ctx);

    return ctx;
}

static void _uv_mbed_tcp_connect_established_cb(uv_mbed_t* mbed, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    if (ctx->tls_tcp_conn_cb) {
        ctx->tls_tcp_conn_cb(ctx, ctx->tls_tcp_conn_cb_p);
    }
    (void)mbed;
}

void tls_client_set_tcp_connect_callback(struct tls_cli_ctx *cli, tls_cli_tcp_conn_cb cb, void *p) {
    if (cli) {
        cli->tls_tcp_conn_cb = cb;
        cli->tls_tcp_conn_cb_p = p;
    }
}

uv_os_sock_t tls_client_get_tcp_fd(const struct tls_cli_ctx *cli) {
    if (cli) {
        return uv_mbed_get_stream_fd(cli->mbed);
    }
    return -1;
}

void tls_client_shutdown(struct tls_cli_ctx* ctx) {
    assert(ctx);
    if (ctx) {
        uv_mbed_close(ctx->mbed, _mbed_close_done_cb, ctx);
    }
}

bool tls_cli_is_closing(struct tls_cli_ctx* ctx) {
    return ctx && uv_mbed_is_closing(ctx->mbed);
}

static void _mbed_connect_done_cb(uv_mbed_t* mbed, int status, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    tls_cli_on_connection_established_cb on_connection_established_cache = ctx->on_connection_established;
    void* on_connection_established_p_cache = ctx->on_connection_established_p;

    if (status < 0) {
        uv_mbed_close(mbed, _mbed_close_done_cb, ctx);
        ctx = NULL;
    } else {
        uv_mbed_set_read_callback(mbed, _mbed_alloc_cb, _mbed_data_received_cb, p);
    }

    if (on_connection_established_cache) {
        on_connection_established_cache(ctx, status, on_connection_established_p_cache);
    }

    uv_mbed_release(mbed);
}

void tls_cli_set_on_connection_established_callback(struct tls_cli_ctx* tls_cli, tls_cli_on_connection_established_cb cb, void* p) {
    if (tls_cli) {
        tls_cli->on_connection_established = cb;
        tls_cli->on_connection_established_p = p;
    }
}

static void _mbed_alloc_cb(uv_mbed_t *mbed, size_t suggested_size, uv_buf_t* buf) {
    char *base = (char *)calloc(suggested_size, sizeof(char));
    *buf = uv_buf_init(base, (unsigned int)suggested_size);
    (void)mbed;
}

static void _mbed_data_received_cb(uv_mbed_t *mbed, ssize_t nread, uv_buf_t* buf, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    assert(ctx);
    assert(ctx->mbed == mbed);

    if (ctx->on_data_received) {
        ctx->on_data_received(ctx, (int)nread, (uint8_t*)buf->base, (size_t)nread, ctx->on_data_received_p);
    }

    if (nread < 0) {
        uv_mbed_close(mbed, _mbed_close_done_cb, p);
    }
    free(buf->base);
}

void tls_cli_set_on_write_done_callback(struct tls_cli_ctx* tls_cli, tls_cli_on_write_done_cb cb, void* p) {
    if (tls_cli) {
        tls_cli->on_write_done = cb;
        tls_cli->on_write_done_p = p;
    }
}

void tls_cli_set_on_data_received_callback(struct tls_cli_ctx* tls_cli, tls_cli_on_data_received_cb cb, void* p) {
    if (tls_cli) {
        tls_cli->on_data_received = cb;
        tls_cli->on_data_received_p = p;
    }
}

static void _mbed_write_done_cb(uv_mbed_t *mbed, int status, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    assert(ctx->mbed == mbed);

    if (ctx->on_write_done) {
        ctx->on_write_done(ctx, status, ctx->on_write_done_p);
    }

    if (status < 0) {
        if (uv_mbed_is_closing(mbed)) {
            return;
        }
        uv_mbed_close(mbed, _mbed_close_done_cb, p);
    }
}

static void _mbed_close_done_cb(uv_mbed_t *mbed, void *p) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)p;
    if (ctx && ctx->on_shutting_down) {
        ctx->on_shutting_down(ctx, ctx->on_shutting_down_p);
    }
    uv_mbed_release(mbed);
    free(ctx);
}

void tls_cli_set_shutting_down_callback(struct tls_cli_ctx* ctx, tls_cli_on_shutting_down_cb cb, void* p) {
    if (ctx) {
        ctx->on_shutting_down = cb;
        ctx->on_shutting_down_p = p;
    }
}

void tls_cli_send_data(struct tls_cli_ctx* ctx, const uint8_t* data, size_t size) {
    uv_buf_t o = uv_buf_init((char *)data, (unsigned int)size);
    assert(ctx);
    if (ctx) {
        uv_mbed_write(ctx->mbed, &o, &_mbed_write_done_cb, ctx);
    }
}
