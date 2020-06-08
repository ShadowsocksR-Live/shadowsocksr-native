#include <mbedtls/config.h>
#include <mbedtls/platform.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/timing.h>

#include "dump_info.h"
#include "ssr_executive.h"
#include "tunnel.h"
#include "tls_cli.h"
#include "ssrbuffer.h"
#include <uv.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "ssrutils.h"

#define MAX_REQUEST_SIZE      0x8000
#define handshake_retry_count_max 100000

enum tls_cli_state {
    tls_state_stopped,
    tls_state_connected,
    tls_state_data_arrived,
    tls_state_shutting_down,
};

struct tls_cli_ctx {
    struct tunnel_ctx *tunnel; /* weak pointer */
    struct server_config *config; /* weak pointer */
    struct uv_work_s *req;
    struct uv_async_s *async;

    enum tls_cli_state state;
    struct buffer_t *data_cache;
    struct buffer_t *app_incoming_cache;
    uv_mutex_t *mutex;

    bool force_exit;
    size_t handshake_retry_count;

    mbedtls_ssl_context *ssl_ctx;
    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_ssl_config *conf;
    mbedtls_x509_crt *cacert;
};

struct tls_cli_ctx * create_tls_cli_ctx(struct tunnel_ctx *tunnel, struct server_config *config);
void destroy_tls_cli_ctx(struct tls_cli_ctx *ctx);

static void tls_cli_worker_thread(uv_work_t *req);
static bool tunnel_tls_send_data_in_worker_thread(struct tls_cli_ctx *ctx);
static void tunnel_tls_send_data(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size);
static void tls_cli_state_changed_notice_async_cb(uv_async_t *handle);
static void tls_cli_after_cb(uv_work_t *req, int status);
static void tls_cli_state_changed_async_send(struct tls_cli_ctx *ctx, enum tls_cli_state state, const uint8_t *buf, size_t len);

#if 0
static void _uv_sleep(int msec) {
#if defined(WIN32) || defined(_WIN32)
    Sleep(msec);
#else
    int sec;
    int usec;

    sec = msec / 1000;
    usec = (msec % 1000) * 1000;
    if (sec > 0) {
        sleep(sec);
    }
    if (usec > 0) {
        usleep(usec);
    }
#endif
}
#endif

struct tls_cli_ctx* tls_client_launch(struct tunnel_ctx *tunnel, struct server_config *config) {
    uv_loop_t *loop = tunnel->listener->loop;
    struct tls_cli_ctx *ctx = create_tls_cli_ctx(tunnel, config);

    tunnel_add_ref(tunnel);
    uv_async_init(loop, ctx->async, tls_cli_state_changed_notice_async_cb);
    uv_queue_work(loop, ctx->req, tls_cli_worker_thread, tls_cli_after_cb);

    return ctx;
}

struct tls_cli_ctx * create_tls_cli_ctx(struct tunnel_ctx *tunnel, struct server_config *config) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)calloc(1, sizeof(*ctx));
    ctx->req = (struct uv_work_s *)calloc(1, sizeof(*ctx->req));
    ctx->req->data = ctx;
    ctx->async = (struct uv_async_s *)calloc(1, sizeof(*ctx->async));
    ctx->mutex = (uv_mutex_t *)calloc(1, sizeof(uv_mutex_t));
    ctx->data_cache = buffer_create(MAX_REQUEST_SIZE);
    ctx->app_incoming_cache = buffer_create(MAX_REQUEST_SIZE);
    ctx->ssl_ctx = (mbedtls_ssl_context *)calloc(1, sizeof(mbedtls_ssl_context));

    ctx->entropy = (mbedtls_entropy_context *)calloc(1, sizeof(mbedtls_entropy_context));
    ctx->ctr_drbg = (mbedtls_ctr_drbg_context *)calloc(1, sizeof(mbedtls_ctr_drbg_context));
    ctx->conf = (mbedtls_ssl_config *)calloc(1, sizeof(mbedtls_ssl_config));
    ctx->cacert = (mbedtls_x509_crt *)calloc(1, sizeof(mbedtls_x509_crt));

    ctx->tunnel = tunnel;
    ctx->config = config;

    ctx->async->data = ctx;
    tunnel->tls_ctx = ctx;
    tunnel->tunnel_tls_send_data = &tunnel_tls_send_data;

    uv_mutex_init(ctx->mutex);

    return ctx;
}

void tls_client_shutdown(struct tunnel_ctx *tunnel) {
    struct tls_cli_ctx *ctx = tunnel->tls_ctx;
    assert(ctx);
    if (ctx) {
        ctx->force_exit = true;
        // uv_cancel(ctx->req);
        // uv_mbed_close(ctx->mbed, _mbed_close_done_cb, ctx);
    }
}

void destroy_tls_cli_ctx(struct tls_cli_ctx *ctx) {
    if (ctx) {
        uv_mutex_destroy(ctx->mutex);

        free(ctx->req);
        free(ctx->async);
        free(ctx->mutex);
        buffer_release(ctx->data_cache);
        buffer_release(ctx->app_incoming_cache);

        free(ctx->ssl_ctx);
        free(ctx->entropy);
        free(ctx->ctr_drbg);
        free(ctx->conf);
        free(ctx->cacert);

        free(ctx);
    }
}

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    ((void) level);
    mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

static void tls_cli_worker_thread(uv_work_t* req) {
    /* this function is in queue work thread, NOT in main event-loop thread */

    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)req->data;
    struct server_config *config = ctx->config;

    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE, flags;
    mbedtls_net_context server_fd;
    char port[0x100] = { 0 };
    const unsigned char pers[] = "ssl_client1";
    unsigned char *read_buffer = NULL, *cert;

    mbedtls_debug_set_threshold( 0 ); // 0 = No debug, 1 = output error

    // 0. Initialize the RNG and the session data
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( ctx->ssl_ctx );
    mbedtls_ssl_config_init( ctx->conf );
    mbedtls_x509_crt_init( ctx->cacert );
    mbedtls_ctr_drbg_init( ctx->ctr_drbg );

    // Seeding the random number generator...

    mbedtls_entropy_init( ctx->entropy );
    ret = mbedtls_ctr_drbg_seed(ctx->ctr_drbg, mbedtls_entropy_func, ctx->entropy, pers, sizeof(pers));
    if ( ret != 0 ) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    // 0. Initialize certificates

    // Loading the CA root certificate
    cert = (unsigned char *)mbedtls_test_cas_pem;
    ret = mbedtls_x509_crt_parse(ctx->cacert, cert, mbedtls_test_cas_pem_len);
    if (ret < 0) {
        pr_info("failed! mbedtls_x509_crt_parse returned -0x%x", -ret);
        goto exit;
    }

    if (ctx->force_exit) { goto exit; }

    // 1. Start the connection

    // Connecting to tcp/%s/%s...", config->remote_host, config->remote_port

    sprintf(port, "%d", (int)config->remote_port);
    ret = mbedtls_net_connect(&server_fd, config->remote_host, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        pr_info("failed! mbedtls_net_connect returned -0x%x", -ret);
        goto exit;
    }

    if (ctx->force_exit) { goto exit; }

    // Setup stuff -- Setting up the SSL/TLS structure...

    ret = mbedtls_ssl_config_defaults(ctx->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf("failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    // OPTIONAL is not optimal for security,
    // but makes interop easier in this simplified example
    mbedtls_ssl_conf_authmode(ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(ctx->conf, ctx->cacert, NULL);
    mbedtls_ssl_conf_rng(ctx->conf, mbedtls_ctr_drbg_random, ctx->ctr_drbg);
    mbedtls_ssl_conf_dbg(ctx->conf, my_debug, stdout); // assert(0);

    if ((ret = mbedtls_ssl_setup(ctx->ssl_ctx, ctx->conf)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(ctx->ssl_ctx, config->over_tls_server_domain)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_net_set_nonblock(&server_fd);
    mbedtls_ssl_set_bio( ctx->ssl_ctx, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    if (ctx->force_exit) { goto exit; }

    // 4. Handshake
    // Performing the SSL/TLS handshake...

    while ((ret = mbedtls_ssl_handshake(ctx->ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            pr_err("failed! mbedtls_ssl_handshake returned -0x%x", -ret);
            goto exit;
        }
        if ((++ctx->handshake_retry_count) == handshake_retry_count_max) {
            goto exit;
        }
        if (ctx->force_exit) { goto exit; }
        mbedtls_net_usleep(10);
    }

    if (ctx->force_exit) { goto exit; }

    (void)flags;
#if 0
    // 5. Verify the server peer X.509 certificate...

    // In real life, we probably want to bail out when ret != 0
    if ((flags = mbedtls_ssl_get_verify_result( ctx->ssl_ctx ) ) != 0) {
        char vrfy_buf[512] = { 0 };
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);
    } else {
        mbedtls_printf( " ok\n" );
    }
#endif

    // Write the GET request
    tls_cli_state_changed_async_send(ctx, tls_state_connected, NULL, 0);

    // 7. Read the HTTP response -- < Read from server:

    read_buffer = (unsigned char *) calloc(MAX_REQUEST_SIZE, sizeof(*read_buffer));

    do {
        if (ctx->force_exit) { break; }

        if (tunnel_tls_send_data_in_worker_thread(ctx) == false) {
            goto exit;
        }

        len = MAX_REQUEST_SIZE;
        memset(read_buffer, 0, MAX_REQUEST_SIZE);
        ret = mbedtls_ssl_read(ctx->ssl_ctx, read_buffer, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_net_usleep(10);
            continue;
        }
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        }
        if (ret < 0) {
            pr_info("failed! mbedtls_ssl_read returned -0x%x", -ret);
            break;
        }
        if (ret == 0) {
            // pr_info("---- EOF ----");
            break;
        }

        tls_cli_state_changed_async_send(ctx, tls_state_data_arrived, read_buffer, ret);
    } while( true );

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    mbedtls_ssl_close_notify(ctx->ssl_ctx);

    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100] = { 0 };
        mbedtls_strerror(ret, error_buf, 100);
        pr_err("last error was: -0x%x - %s", -ret, error_buf);
    }

    mbedtls_net_free( &server_fd );

    mbedtls_x509_crt_free( ctx->cacert );
    mbedtls_ssl_free( ctx->ssl_ctx );
    mbedtls_ssl_config_free( ctx->conf );
    mbedtls_ctr_drbg_free( ctx->ctr_drbg );
    mbedtls_entropy_free( ctx->entropy );

    if (read_buffer) {
        free(read_buffer);
    }

    mbedtls_net_usleep(100);
    tls_cli_state_changed_async_send(ctx, tls_state_shutting_down, NULL, 0);
}

static bool tunnel_tls_send_data_in_worker_thread(struct tls_cli_ctx *ctx) {
    /* this function is in queue work thread, NOT in main event-loop thread */
    mbedtls_ssl_context *ssl_ctx = ctx->ssl_ctx;
    const uint8_t *buf;
    size_t len = 0;

    int written = 0, frags = 0, ret;
    bool result = false;

    uv_mutex_lock(ctx->mutex);
    buf = buffer_get_data(ctx->app_incoming_cache, &len);

    do {
        if (ctx->force_exit) { break; }
        if (buf==NULL || len==0) { break; }
        while ((ret = mbedtls_ssl_write(ssl_ctx, buf + written, (int)len - written)) < 0) {
            if (ctx->force_exit) { break; }
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
                ret != MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
            {
                pr_err("write failed! mbedtls_ssl_write returned -0x%x", -ret);
                goto __exit__;
            }
            mbedtls_net_usleep(10);
        }
        frags++;
        written += ret;
    } while (written < (int)len);
    result = true;
__exit__:
    buffer_reset(ctx->app_incoming_cache);
    uv_mutex_unlock(ctx->mutex);

    return result;
}

static void tunnel_tls_send_data(struct tunnel_ctx *tunnel, const uint8_t *data, size_t size) {
    /* this point is in main event-loop thread */
    struct tls_cli_ctx *ctx = tunnel->tls_ctx;

    uv_mutex_lock(ctx->mutex);
    buffer_concatenate(ctx->app_incoming_cache, data, size);
    uv_mutex_unlock(ctx->mutex);
}

static void tls_cli_state_changed_notice_async_cb(uv_async_t *handle) {
    /* this point is MUST in main event-loop thread */
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)handle->data;
    struct tunnel_ctx *tunnel;

    tunnel = ctx->tunnel;

    switch (ctx->state) {
    case tls_state_connected:
        if (tunnel->tunnel_tls_on_connection_established) {
            tunnel->tunnel_tls_on_connection_established(tunnel);
        }
        break;
    case tls_state_data_arrived:
        if (tunnel->tunnel_tls_on_data_received) {
            size_t s = 0;
            const uint8_t *p = buffer_get_data(ctx->data_cache, &s);
            if (p && s) {
                tunnel->tunnel_tls_on_data_received(tunnel, p, s);
            }
            buffer_reset(ctx->data_cache);
        }
        break;
    case tls_state_shutting_down:
        if (tunnel->tunnel_tls_on_shutting_down) {
            tunnel->tunnel_tls_on_shutting_down(tunnel);
        }
        break;
    default:
        assert(false);
        break;
    }
}

static void tls_async_close_cb(uv_handle_t *handle) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)handle->data;
    struct tunnel_ctx *tunnel = ctx->tunnel;

    destroy_tls_cli_ctx(ctx);

    tunnel->tls_ctx = NULL;
    tunnel->tunnel_shutdown(tunnel);
    tunnel_release(tunnel);
}

static void tls_cli_after_cb(uv_work_t *req, int status) {
    struct tls_cli_ctx *ctx = (struct tls_cli_ctx *)req->data;
    struct tunnel_ctx *tunnel = ctx->tunnel;
    {
        size_t s = 0;
        const uint8_t *p = buffer_get_data(ctx->data_cache, &s);
        if (s && p) {
            tunnel->tunnel_tls_on_data_received(tunnel, p, s);
        }
        buffer_reset(ctx->data_cache);
    }
    uv_close((uv_handle_t*) ctx->async, tls_async_close_cb);
}

static void tls_cli_state_changed_async_send(struct tls_cli_ctx *ctx,
    enum tls_cli_state state, const uint8_t *buf, size_t len)
{
    /* this point is MUST in queue work thread, NOT in main event-loop thread */

    uv_mutex_lock(ctx->mutex);
    ctx->state = state;
    if (buf && len) {
        buffer_concatenate(ctx->data_cache, buf, len);
    }
    uv_async_send(ctx->async);
    uv_mutex_unlock(ctx->mutex);
}
