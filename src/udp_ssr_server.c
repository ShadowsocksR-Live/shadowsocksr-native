#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <c_stl_lib.h>

#if !defined(__MINGW32__) && !defined(_WIN32)
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "ssrutils.h"
#include "cache.h"
#include "udprelay.h"
#include "encrypt.h"
#include "sockaddr_universal.h"
#include "ssrbuffer.h"

#include "obfs/obfs.h"

#include "common.h"
#include "sockaddr_universal.h"
#include "ssr_executive.h"
#include "dump_info.h"
#include "s5.h"
#include "ref_count_def.h"

#if !defined(MIN_UDP_TIMEOUT)
#define MIN_UDP_TIMEOUT 3 * 1000
#endif

#define MAX_UDP_CONN_NUM 512

#define MAX_UDP_PACKET_SIZE (65507)

#define DEFAULT_PACKET_SIZE MAX_UDP_PACKET_SIZE // 1492 - 1 - 28 - 2 - 64 = 1397, the default MTU for UDP relay

struct server_udp_listener_ctx {
    uv_udp_t udp;
    int timeout;
    struct cstl_set *connections;
    struct cipher_env_t *cipher_env;
    // SSR
    struct obfs_t *protocol_plugin;
    void *protocol_global;
};

struct server_udp_remote_ctx {
    uv_udp_t rmt_udp;
    uv_timer_t rmt_expire;
    struct server_udp_listener_ctx *listener_ctx; // weak ptr.
    union sockaddr_universal incoming_addr;
    union sockaddr_universal target_addr;
    struct buffer_t *request_data;
    uint64_t timeout;
    bool shutting_down;
    REF_COUNT_MEMBER;
};

static REF_COUNT_ADD_REF_DECL(server_udp_remote_ctx); // server_udp_remote_ctx_add_ref
static REF_COUNT_RELEASE_DECL(server_udp_remote_ctx); // server_udp_remote_ctx_release

static void server_udp_remote_ctx_free_internal(struct server_udp_remote_ctx *ctx) {
    free(ctx);
}

static REF_COUNT_ADD_REF_IMPL(server_udp_remote_ctx)
static REF_COUNT_RELEASE_IMPL(server_udp_remote_ctx, server_udp_remote_ctx_free_internal)


static void server_udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void server_udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void server_udp_remote_timeout_cb(uv_timer_t* handle);
static void common_restart_timer(uv_timer_t *timer, uint64_t timeout);

static size_t packet_size = DEFAULT_PACKET_SIZE;
static size_t buf_size = DEFAULT_PACKET_SIZE * 2;

static void server_udp_remote_close_done_cb(uv_handle_t* handle) {
    struct server_udp_remote_ctx *ctx = (struct server_udp_remote_ctx *)handle->data;
    server_udp_remote_ctx_release(ctx);
}

static void server_udp_remote_ctx_shutdown(struct server_udp_remote_ctx *remote_ctx) {
    char tmp1[SS_ADDRSTRLEN], tmp2[SS_ADDRSTRLEN];
    if (remote_ctx == NULL) {
        return;
    }
    if (remote_ctx->shutting_down) {
        return;
    }
    remote_ctx->shutting_down = true;

    cstl_set_container_remove(remote_ctx->listener_ctx->connections, remote_ctx);
    {
        uv_timer_t *timer = &remote_ctx->rmt_expire;
        uv_timer_stop(timer);
        uv_close((uv_handle_t *)timer, server_udp_remote_close_done_cb);
        server_udp_remote_ctx_add_ref(remote_ctx);
    }
    {
        uv_udp_t *udp = &remote_ctx->rmt_udp;
        uv_udp_recv_stop(udp);
        uv_close((uv_handle_t *)udp, server_udp_remote_close_done_cb);
        server_udp_remote_ctx_add_ref(remote_ctx);
    }

    pr_info("[udp] session %s <=> %s has nothing to do, shutting down",
        get_addr_str(&remote_ctx->incoming_addr.addr, tmp1, sizeof(tmp1)),
        get_addr_str(&remote_ctx->target_addr.addr, tmp2, sizeof(tmp2)));

    server_udp_remote_ctx_release(remote_ctx);
}

static void server_udp_remote_timeout_cb(uv_timer_t* handle) {
    struct server_udp_remote_ctx *remote_ctx;
    remote_ctx = CONTAINER_OF(handle, struct server_udp_remote_ctx, rmt_expire);

    server_udp_remote_ctx_shutdown(remote_ctx);
}

static void server_udp_request_incoming_cb(uv_udp_send_t* req, int status) {
    uv_udp_t *listener_udp = req->handle;
    struct server_udp_remote_ctx *remote_ctx = (struct server_udp_remote_ctx*)req->data;
    ASSERT(remote_ctx);
    ASSERT(&remote_ctx->listener_ctx->udp == listener_udp);

    buffer_release(remote_ctx->request_data);
    remote_ctx->request_data = NULL;

    free(req);

    (void)listener_udp;
    (void)status;
}

void server_udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* uvbuf, const struct sockaddr* addr, unsigned flags) {
    struct server_udp_remote_ctx *remote_ctx;
    struct server_udp_listener_ctx *listener_ctx;
    struct buffer_t *buf = NULL;
    size_t final_len;
    const uint8_t *final_data;
    int err;
    bool nead_more_action = false;
    char tmp1[SS_ADDRSTRLEN], tmp2[SS_ADDRSTRLEN];

    do {
        remote_ctx = CONTAINER_OF(handle, struct server_udp_remote_ctx, rmt_udp);
        ASSERT(remote_ctx);
        ASSERT(remote_ctx == handle->data);
        listener_ctx = remote_ctx->listener_ctx;

        if (addr) {
            ASSERT(memcmp(&remote_ctx->target_addr.addr, addr, sizeof(*addr)) == 0);
            (void)addr; (void)flags;
        }

        if (nread <= 0) {
            if (nread < 0) {
                pr_err("[udp] %s recv remote data error", __FUNCTION__);
            }
            break;
        }

        buf = buffer_create_from((const uint8_t *) uvbuf->base, (size_t)nread);

        pr_info("[udp] session %s <=> %s recv remote data length %ld",
            get_addr_str(&remote_ctx->incoming_addr.addr, tmp1, sizeof(tmp1)),
            get_addr_str(&remote_ctx->target_addr.addr, tmp2, sizeof(tmp2)),
            buffer_get_length(buf));

        {
            uint8_t *p;
            struct socks5_address s5addr;
            size_t len = 0;
            universal_address_to_socks5(&remote_ctx->target_addr, &s5addr);
            p = socks5_address_binary(&s5addr, &malloc, &len);
            buffer_insert_raw(buf, 0, p, len);
            free(p);
        }

        //SSR beg
        if (listener_ctx->protocol_plugin) {
            struct obfs_t *protoc = listener_ctx->protocol_plugin;
            if (protoc->server_udp_pre_encrypt) {
                if (protoc->server_udp_pre_encrypt(protoc, buf, 0) == false) {
                    pr_err("[udp] %s SSR protocol_plugin error", __FUNCTION__);
                    break;
                }
            }
        }
        // SSR end

        if (buffer_get_length(buf) == 0) {
            pr_err("[udp] %s received datagram is empty", __FUNCTION__);
            break;
        }

        err = ss_encrypt_all(listener_ctx->cipher_env, buf, buffer_get_length(buf));
        if (err) {
            // drop the packet silently
            pr_err("[udp] %s SS encrypt error", __FUNCTION__);
            break;
        }

        final_data = buffer_get_data(buf);
        final_len = buffer_get_length(buf);

        {
            uv_buf_t sndbuf;
            uv_udp_send_t *send_req;
            uv_udp_t *listener_udp = &remote_ctx->listener_ctx->udp;
            union sockaddr_universal *incoming_addr = &remote_ctx->incoming_addr;

            sndbuf = uv_buf_init((char *) final_data, (unsigned int) final_len);

            send_req = (uv_udp_send_t *) calloc(1, sizeof(*send_req));
            remote_ctx->request_data = buf;
            send_req->data = remote_ctx;
            uv_udp_send(send_req, listener_udp, &sndbuf, 1, &incoming_addr->addr, server_udp_request_incoming_cb);

            common_restart_timer(&remote_ctx->rmt_expire, remote_ctx->timeout);

            nead_more_action = true;
        }
    } while (0);
    udp_uv_release_buffer((uv_buf_t *)uvbuf);
    if (nead_more_action == false) {
        buffer_release(buf);
    }
}

static void server_udp_send_done_cb(uv_udp_send_t* req, int status) {
    struct buffer_t *buf = (struct buffer_t *)req->data;
    buffer_release(buf);
    free(req);
    (void)status;
}

static void common_restart_timer(uv_timer_t *timer, uint64_t timeout) {
    assert(timer);
    assert(timer->timer_cb != NULL);
    assert(timeout > 0);
    uv_timer_stop(timer);
    uv_timer_start(timer, timer->timer_cb, timeout, 0);
}

struct server_udp_remote_ctx * create_server_udp_remote(uv_loop_t* loop, uint64_t timeout, uv_timer_cb cb) {
    uv_udp_t *udp = NULL;
    uv_timer_t *timer;

    struct server_udp_remote_ctx *remote_ctx;
    remote_ctx = (struct server_udp_remote_ctx *) calloc(1, sizeof(*remote_ctx));
    remote_ctx->timeout = timeout;

    udp = &remote_ctx->rmt_udp;
    uv_udp_init(loop, udp);
    udp->data = remote_ctx;

    timer = &remote_ctx->rmt_expire;
    uv_timer_init(loop, timer);
    timer->data = remote_ctx;
    timer->timer_cb = cb;

    return remote_ctx;
}

struct matching_connect {
    union sockaddr_universal incoming_addr;
    union sockaddr_universal target_addr;
    struct server_udp_remote_ctx *remote_ctx;
};

static void find_matching_connection(struct cstl_set *set, const void *obj, cstl_bool *stop, void *p) {
    struct matching_connect *match = (struct matching_connect *)p;
    struct server_udp_remote_ctx *remote_ctx = (struct server_udp_remote_ctx *)obj;
    if (memcmp(&match->incoming_addr, &remote_ctx->incoming_addr, sizeof(match->incoming_addr)) == 0 &&
        memcmp(&match->target_addr, &remote_ctx->target_addr, sizeof(match->target_addr)) == 0)
    {
        match->remote_ctx = remote_ctx;
        if (stop) {
            *stop = cstl_true;
        }
    }
    (void)set;
}

static void 
server_udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* uvbuf, const struct sockaddr* addr, unsigned flags)
{
    struct server_udp_listener_ctx *listener_ctx;
    struct buffer_t *buf = NULL;

    union sockaddr_universal target_addr;
    int err;

    uv_loop_t *loop;
    struct server_env_t *env;
    bool nead_more_action = false;
    uint8_t *recv_iv = NULL;
    size_t iv_len = 0;

    do {
        loop = handle->loop;
        env = (struct server_env_t *) loop->data;

        ASSERT(env->config->over_tls_enable == false);

        if (NULL == addr) {
            break;
        }

        listener_ctx = CONTAINER_OF(handle, struct server_udp_listener_ctx, udp);
        ASSERT(listener_ctx);

        buf = buffer_create(max((size_t)buf_size, (size_t)nread));

        if (nread <= 0) {
            // error on recv, simply drop that packet
            if (nread < 0) {
                pr_err("[udp] %s recv incoming data error", __FUNCTION__);
            }
            break;
        } else if (nread > (ssize_t) packet_size) {
            pr_err("[udp] %s fragmentation", __FUNCTION__);
            break;
        }

        buffer_store(buf, (uint8_t *)uvbuf->base, (size_t)nread);

        /*
         * SOCKS5 UDP Request / Response
         * +----+------+------+----------+----------+----------+
         * |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
         * +----+------+------+----------+----------+----------+
         * | 2  |  1   |  1   | Variable |    2     | Variable |
         * +----+------+------+----------+----------+----------+
         *
         * Shadowsocks UDP Request / Response (before encrypted)
         *             +------+----------+----------+----------+
         *             | ATYP | DST.ADDR | DST.PORT |   DATA   |
         *             +------+----------+----------+----------+
         *             |  1   | Variable |    2     | Variable |
         *             +------+----------+----------+----------+
         *
         * Shadowsocks UDP Request / Response (after encrypted)
         * +-------+--------------+
         * |   IV  |    PAYLOAD   |
         * +-------+--------------+
         * | Fixed |   Variable   |
         * +-------+--------------+
         */

        iv_len = enc_get_iv_len(listener_ctx->cipher_env);
        if (iv_len > 0) {
            recv_iv = (uint8_t *) calloc(iv_len + 1, sizeof(*recv_iv));
            memcpy(recv_iv, buffer_get_data(buf), iv_len);
        }

        err = ss_decrypt_all(listener_ctx->cipher_env, buf, buffer_get_capacity(buf));
        if (err) {
            // drop the packet silently
            pr_err("[udp] error in %s decrypt data failed", __FUNCTION__);
            break;
        }

        // SSR beg
        if (listener_ctx->protocol_plugin) {
            struct obfs_t *protoc = listener_ctx->protocol_plugin;
            if (protoc->server_udp_post_decrypt) {
                uint32_t uid = 0;
                if (protoc->server_udp_post_decrypt(protoc, buf, &uid) == false) {
                    pr_err("[udp] %s error in SSR decrypt", __FUNCTION__);
                    break;
                }
            }
        }
        //SSR end

        {
            size_t addr_len = 0;
            size_t len = buffer_get_length(buf);
            const uint8_t *buffer = buffer_get_data(buf);

            memset(&target_addr, 0, sizeof(target_addr));
            addr_len = udprelay_parse_header(buffer, len,
                NULL, NULL, &target_addr.addr_stor);
            if (addr_len == 0) {
                pr_err("[udp] %s error in parse header", __FUNCTION__);
                break;
            }

            buffer_shortened_to(buf, addr_len, buffer_get_length(buf) - addr_len, true);
        }

        {
            struct server_udp_remote_ctx *remote_ctx;
            uv_buf_t tmp;
            uv_udp_send_t *req;
            char tmp1[SS_ADDRSTRLEN] = { 0 }, tmp2[SS_ADDRSTRLEN] = { 0 };
            struct matching_connect match = { {{0}}, {{0}}, 0 };

            match.incoming_addr.addr = *addr;
            match.target_addr = target_addr;
            cstl_set_container_traverse(listener_ctx->connections, &find_matching_connection, &match);
            remote_ctx = match.remote_ctx;

            pr_info(remote_ctx ? "[udp] session %s <=> %s reused, data length %ld" : "[udp] session %s <=> %s starting, data length %ld",
                get_addr_str(addr, tmp1, sizeof(tmp1)),
                get_addr_str(&target_addr.addr, tmp2, sizeof(tmp2)), (size_t)nread);

            if (remote_ctx == NULL) {
                remote_ctx = create_server_udp_remote(loop, listener_ctx->timeout, server_udp_remote_timeout_cb);
                server_udp_remote_ctx_add_ref(remote_ctx);
                remote_ctx->listener_ctx = listener_ctx;
                remote_ctx->incoming_addr.addr = *addr;
                remote_ctx->target_addr = target_addr;

                uv_udp_recv_start(&remote_ctx->rmt_udp, udp_uv_alloc_buffer, server_udp_remote_recv_cb);

                cstl_set_container_add(listener_ctx->connections, remote_ctx);
            }

            req = (uv_udp_send_t *)calloc(1, sizeof(uv_udp_send_t));
            req->data = buf;

            tmp = uv_buf_init((char *)buffer_get_data(buf), (unsigned int)buffer_get_length(buf));
            uv_udp_send(req, &remote_ctx->rmt_udp, &tmp, 1, &target_addr.addr, server_udp_send_done_cb);

            common_restart_timer(&remote_ctx->rmt_expire, remote_ctx->timeout);

            nead_more_action = true;
        }
    } while(0);

    free(recv_iv);

    udp_uv_release_buffer((uv_buf_t *)uvbuf);

    if (nead_more_action == false) {
        buffer_release(buf);
    }
    (void)flags;
}

static void server_udp_listener_close_cb(uv_handle_t* handle) {
    struct server_udp_listener_ctx *ctx = CONTAINER_OF(handle, struct server_udp_listener_ctx, udp);
    cstl_set_delete(ctx->connections);

    // SSR beg
    if (ctx->protocol_plugin) {
        object_safe_free(&ctx->protocol_global);
        obfs_instance_destroy(ctx->protocol_plugin);
        ctx->protocol_plugin = NULL;
    }
    // SSR end

    free(ctx);
}

static void connection_release(struct cstl_set *set, const void *obj, cstl_bool *stop, void *p) {
    (void)set; (void)obj; (void)stop; (void)p;
    server_udp_remote_ctx_shutdown((struct server_udp_remote_ctx *)obj);
}

void server_udprelay_shutdown(struct server_udp_listener_ctx *listener_ctx) {
    if (listener_ctx == NULL) {
        return;
    }
    cstl_set_container_traverse(listener_ctx->connections, &connection_release, NULL);
    uv_close((uv_handle_t *)&listener_ctx->udp, server_udp_listener_close_cb);
}

struct server_udp_listener_ctx *
server_udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
    struct cipher_env_t *cipher_env,
    int mtu, int timeout,
    const char *protocol, const char *protocol_param)
{
    struct server_udp_listener_ctx *listener_ctx;
    struct server_info_t server_info = { {0}, 0, 0, 0, {0}, 0, {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

    // Initialize MTU
    if (mtu > 0) {
        packet_size = mtu - 1 - 28 - 2 - 64;
        buf_size    = packet_size * 2;
    }

    (void)server_info; (void)protocol; (void)protocol_param;

    listener_ctx = (struct server_udp_listener_ctx *)calloc(1, sizeof(*listener_ctx));

    // Bind to port
    if (udp_create_listener(server_host, server_port, loop, &listener_ctx->udp) < 0) {
        FATAL("[udp] bind() error");
    }

    listener_ctx->cipher_env = cipher_env;
    listener_ctx->timeout = max(timeout, MIN_UDP_TIMEOUT);
    listener_ctx->connections = cstl_set_new(tunnel_ctx_compare_for_c_set, NULL);

    //SSR beg
    listener_ctx->protocol_plugin = protocol_instance_create(protocol);
    if (listener_ctx->protocol_plugin) {
        listener_ctx->protocol_global = listener_ctx->protocol_plugin->generate_global_init_data();
    }

    strcpy(server_info.host, server_host);
    server_info.port = server_port;
    server_info.g_data = listener_ctx->protocol_global;
    server_info.param = (char *)protocol_param;
    server_info.key = enc_get_key(cipher_env);
    server_info.key_len = (uint16_t) enc_get_key_len(cipher_env);

    if (listener_ctx->protocol_plugin) {
        listener_ctx->protocol_plugin->set_server_info(listener_ctx->protocol_plugin, &server_info);
    }
    //SSR end

    uv_udp_recv_start(&listener_ctx->udp, udp_uv_alloc_buffer, server_udp_listener_recv_cb);

    return listener_ctx;
}
