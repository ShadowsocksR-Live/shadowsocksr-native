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

struct client_udp_listener_ctx {
    uv_udp_t udp;
    int timeout;
    struct cstl_set *connections;
    union sockaddr_universal server_addr;
    struct cipher_env_t *cipher_env;
    // SSR
    struct obfs_t *protocol_plugin;
    void *protocol_global;
};

struct client_udp_remote_ctx {
    uv_udp_t rmt_udp;
    uv_timer_t rmt_expire;
    struct client_udp_listener_ctx *listener_ctx; // weak ptr.
    union sockaddr_universal incoming_addr;
    union sockaddr_universal target_addr;
    uint8_t *request_data;
    uint64_t timeout;
    bool shutting_down;
    REF_COUNT_MEMBER;
};

static REF_COUNT_ADD_REF_DECL(client_udp_remote_ctx); // client_udp_remote_ctx_add_ref
static REF_COUNT_RELEASE_DECL(client_udp_remote_ctx); // client_udp_remote_ctx_release

static void udp_remote_ctx_free_internal(struct client_udp_remote_ctx *ctx) {
    free(ctx);
}

static REF_COUNT_ADD_REF_IMPL(client_udp_remote_ctx)
static REF_COUNT_RELEASE_IMPL(client_udp_remote_ctx, udp_remote_ctx_free_internal)


static void client_udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void client_udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void client_udp_remote_timeout_cb(uv_timer_t* handle);
static void common_restart_timer(uv_timer_t *timer, uint64_t timeout);

static size_t packet_size = DEFAULT_PACKET_SIZE;
static size_t buf_size = DEFAULT_PACKET_SIZE * 2;

static void client_udp_remote_close_done_cb(uv_handle_t* handle) {
    struct client_udp_remote_ctx *ctx = (struct client_udp_remote_ctx *)handle->data;
    client_udp_remote_ctx_release(ctx);
}

static void client_udp_remote_ctx_shutdown(struct client_udp_remote_ctx *remote_ctx) {
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
        uv_close((uv_handle_t *)timer, client_udp_remote_close_done_cb);
        client_udp_remote_ctx_add_ref(remote_ctx);
    }
    {
        uv_udp_t *udp = &remote_ctx->rmt_udp;
        uv_udp_recv_stop(udp);
        uv_close((uv_handle_t *)udp, client_udp_remote_close_done_cb);
        client_udp_remote_ctx_add_ref(remote_ctx);
    }

    pr_info("[udp] session %s <=> %s has nothing to do, shutting down",
        get_addr_str(&remote_ctx->incoming_addr.addr, tmp1, sizeof(tmp1)),
        get_addr_str(&remote_ctx->target_addr.addr, tmp2, sizeof(tmp2)));

    client_udp_remote_ctx_release(remote_ctx);
}

static void client_udp_remote_timeout_cb(uv_timer_t* handle) {
    struct client_udp_remote_ctx *remote_ctx;
    remote_ctx = CONTAINER_OF(handle, struct client_udp_remote_ctx, rmt_expire);

    client_udp_remote_ctx_shutdown(remote_ctx);
}

static void client_udp_request_incoming_cb(uv_udp_send_t* req, int status) {
    uv_udp_t *listener_udp = req->handle;
    struct client_udp_remote_ctx *remote_ctx = (struct client_udp_remote_ctx*)req->data;
    ASSERT(remote_ctx);
    ASSERT(&remote_ctx->listener_ctx->udp == listener_udp);

    free(remote_ctx->request_data);
    remote_ctx->request_data = NULL;

    free(req);

    (void)listener_udp;
    (void)status;
}

void client_udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* uvbuf, const struct sockaddr* addr, unsigned flags) {
    struct client_udp_remote_ctx *remote_ctx;
    struct client_udp_listener_ctx *listener_ctx;
    struct buffer_t *buf = NULL;
    size_t addr_header_len, final_len;
    const uint8_t *final_data;
    int err;
    char tmp1[SS_ADDRSTRLEN], tmp2[SS_ADDRSTRLEN];

    do {
        remote_ctx = CONTAINER_OF(handle, struct client_udp_remote_ctx, rmt_udp);
        ASSERT(remote_ctx);
        ASSERT(remote_ctx == handle->data);
        listener_ctx = remote_ctx->listener_ctx;

        if (addr) {
            ASSERT(memcmp(&listener_ctx->server_addr, addr, sizeof(*addr)) == 0);
            (void)addr; (void)flags;
        }

        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            break;
        }

        buf = buffer_create_from((const uint8_t *) uvbuf->base, (size_t)nread);
        buffer_realloc(buf, (size_t)nread*2);

        pr_info("[udp] session %s <=> %s recv remote data length %ld",
            get_addr_str(&remote_ctx->incoming_addr.addr, tmp1, sizeof(tmp1)),
            get_addr_str(&remote_ctx->target_addr.addr, tmp2, sizeof(tmp2)),
            (long)buffer_get_length(buf));

        err = ss_decrypt_all(listener_ctx->cipher_env, buf, (size_t)nread*2);
        if (err) {
            // drop the packet silently
            break;
        }

        //SSR beg
        if (listener_ctx->protocol_plugin) {
            struct obfs_t *protocol_plugin = listener_ctx->protocol_plugin;
            if (protocol_plugin->client_udp_post_decrypt) {
                size_t len0 = 0, capacity = 0;
                uint8_t *p = (uint8_t *) buffer_raw_clone(buf, &malloc, &len0, &capacity);
                ssize_t sslen = protocol_plugin->client_udp_post_decrypt(protocol_plugin, &p, len0, &capacity);
                if (sslen < 0) {
                    pr_err("[udp] %s client decrypt error", __FUNCTION__);
                }
                buffer_store(buf, p, (sslen >= 0) ? (size_t)sslen : 0);
                free(p);
            }
        }
        // SSR end

        if (buffer_get_length(buf) == 0) {
            pr_err("%s", "received datagram is empty");
            break;
        }

#if __ANDROID__
        traffic_status_update(0, (uint64_t) nread);
#endif

        final_data = buffer_get_data(buf);
        final_len = buffer_get_length(buf);
        addr_header_len = udprelay_parse_header(final_data, final_len, NULL, NULL, NULL);
        if (addr_header_len == 0) {
            pr_err("%s", "[udp] error in parse header");
            break;
        }

        {
            size_t len = 0;
            uint8_t *udp_data;
            uv_buf_t sndbuf;
            uv_udp_send_t *send_req;
            uv_udp_t *listener_udp = &remote_ctx->listener_ctx->udp;
            union sockaddr_universal *incoming_addr = &remote_ctx->incoming_addr;
            struct socks5_address s5addr = { {{0}}, 0, SOCKS5_ADDRTYPE_INVALID };
            universal_address_to_socks5(incoming_addr, &s5addr);

            // Construct packet
            udp_data = s5_build_udp_datagram(&s5addr, final_data + addr_header_len, final_len - addr_header_len, &malloc, &len);
            sndbuf = uv_buf_init((char *) udp_data, (unsigned int) len);

            send_req = (uv_udp_send_t *) calloc(1, sizeof(*send_req));
            remote_ctx->request_data = udp_data;
            send_req->data = remote_ctx;
            uv_udp_send(send_req, listener_udp, &sndbuf, 1, &incoming_addr->addr, client_udp_request_incoming_cb);
        }
    } while (0);
    udp_uv_release_buffer((uv_buf_t *)uvbuf);
    buffer_release(buf);

    common_restart_timer(&remote_ctx->rmt_expire, remote_ctx->timeout);
}

static void client_udp_send_done_cb(uv_udp_send_t* req, int status) {
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

static void android_udp_protect_socket(uv_handle_t* handle, void* p) {
#if __ANDROID__
    uv_os_fd_t fd = -1;
    if (uv_fileno((uv_handle_t *)handle, &fd) != 0) {
        pr_err("%s", "[udp] can not retrieve socket fd");
        return;
    }
    if (protect_socket(fd) < 0) {
        pr_err("%s", "[udp] protect socket failed");
        return;
    }
#endif
    (void)handle; (void)p;
}

struct client_udp_remote_ctx *
create_client_udp_remote(uv_loop_t* loop, uint64_t timeout, uv_timer_cb cb) {
    uv_udp_t *udp = NULL;
    uv_timer_t *timer;

    struct client_udp_remote_ctx *remote_ctx;
    remote_ctx = (struct client_udp_remote_ctx *) calloc(1, sizeof(*remote_ctx));
    remote_ctx->timeout = timeout;

    udp = &remote_ctx->rmt_udp;

    uv_set_socket_create_cb((uv_handle_t*)udp, android_udp_protect_socket, remote_ctx);

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
    struct client_udp_remote_ctx *remote_ctx;
};

static void find_matching_connection(struct cstl_set *set, const void *obj, int *stop, void *p) {
    struct matching_connect *match = (struct matching_connect *)p;
    struct client_udp_remote_ctx *remote_ctx = (struct client_udp_remote_ctx *)obj;
    if (memcmp(&match->incoming_addr, &remote_ctx->incoming_addr, sizeof(match->incoming_addr)) == 0 &&
        memcmp(&match->target_addr, &remote_ctx->target_addr, sizeof(match->target_addr)) == 0)
    {
        match->remote_ctx = remote_ctx;
        if (stop) {
            *stop = 1;
        }
    }
    (void)set;
}

// http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_recv_cb

static void 
client_udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* uvbuf, const struct sockaddr* addr, unsigned flags)
{
    struct client_udp_listener_ctx *listener_ctx;
    struct buffer_t *buf = NULL;
    unsigned int offset;
    uint8_t frag = 0;

    union sockaddr_universal target_addr;
    int err;

    uv_loop_t *loop;
    struct server_env_t *env;
    bool nead_more_action = false;

    do {
        loop = handle->loop;
        env = (struct server_env_t *) loop->data;

        ASSERT(env->config->over_tls_enable == false);

        if (NULL == addr) {
            break;
        }

        listener_ctx = CONTAINER_OF(handle, struct client_udp_listener_ctx, udp);
        ASSERT(listener_ctx);

        offset = 0;

        if (nread <= 0) {
            // error on recv, simply drop that packet
            if (nread < 0) {
                pr_err("[udp] %s recv incoming data error", __FUNCTION__);
            }
            break;
        } else if (nread > (ssize_t) packet_size) {
            pr_err("[udp] %s recv incoming data fragmentation, dropping", __FUNCTION__);
            break;
        }

        buf = buffer_create(max((size_t)buf_size, (size_t)nread));
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

        {
            size_t addr_header_len   = 0;
            size_t len = buffer_get_length(buf);
            const uint8_t *buffer = buffer_get_data(buf);
            char port[32] = { 0 };

            frag = *(uint8_t *)(buffer + 2);
            offset += 3;

            addr_header_len = udprelay_parse_header((buffer + offset), len - offset,
                NULL, port, &target_addr.addr_stor);
            if (addr_header_len == 0) {
                // error in parse header
                break;
            }

            if (strcmp(port, "5353") == 0) {
                pr_err("[udp] %s do nothing with mDNS service (port 5353), dropped.", __FUNCTION__);
                break;
            }
        }

        if (frag) {
            LOGE("[udp] drop a message since frag is not 0, but %d", frag);
            break;
        }

        buffer_shortened_to(buf, offset, buffer_get_length(buf) - offset, true);

        // SSR beg
        if (listener_ctx->protocol_plugin) {
            struct obfs_t *protocol_plugin = listener_ctx->protocol_plugin;
            if (protocol_plugin->client_udp_pre_encrypt) {
                size_t len = 0, capacity = 0;
                uint8_t *buffer = (uint8_t *) buffer_raw_clone(buf, &malloc, &len, &capacity);
                len = (size_t) protocol_plugin->client_udp_pre_encrypt(protocol_plugin, &buffer, len, &capacity);
                buffer_store(buf, buffer, len);
                free(buffer);
            }
        }
        //SSR end

        err = ss_encrypt_all(listener_ctx->cipher_env, buf, buffer_get_capacity(buf));
        if (err) {
            // drop the packet silently
            break;
        }

        if (buffer_get_length(buf) > packet_size) {
            pr_err("[udp] %s fragmentation", __FUNCTION__);
            break;
        }
#ifdef ANDROID
        traffic_status_update((uint64_t)buffer_get_length(buf), 0);
#endif
        {
            const struct sockaddr *server_addr = &listener_ctx->server_addr.addr;
            struct client_udp_remote_ctx *remote_ctx = NULL;
            uv_buf_t tmp;
            uv_udp_send_t *req;
            char tmp1[SS_ADDRSTRLEN], tmp2[SS_ADDRSTRLEN];
            struct matching_connect match = { {{0}}, {{0}}, 0 };

            match.incoming_addr.addr = *addr;
            match.target_addr = target_addr;
            cstl_set_container_traverse(listener_ctx->connections, &find_matching_connection, &match);
            remote_ctx = match.remote_ctx;

            pr_info(remote_ctx ? "[udp] session %s <=> %s reused, data length %ld" : "[udp] session %s <=> %s starting, data length %ld",
                get_addr_str(addr, tmp1, sizeof(tmp1)),
                get_addr_str(&target_addr.addr, tmp2, sizeof(tmp2)), (long)nread);

            if (remote_ctx == NULL) {
                remote_ctx = create_client_udp_remote(loop, listener_ctx->timeout, client_udp_remote_timeout_cb);
                client_udp_remote_ctx_add_ref(remote_ctx);
                remote_ctx->listener_ctx = listener_ctx;
                remote_ctx->incoming_addr.addr = *addr;
                remote_ctx->target_addr = target_addr;

                uv_udp_recv_start(&remote_ctx->rmt_udp, udp_uv_alloc_buffer, client_udp_remote_recv_cb);

                cstl_set_container_add(listener_ctx->connections, remote_ctx);
            }

            req = (uv_udp_send_t *)calloc(1, sizeof(uv_udp_send_t));
            req->data = buf;

            tmp = uv_buf_init((char *)buffer_get_data(buf), (unsigned int)buffer_get_length(buf));
            uv_udp_send(req, &remote_ctx->rmt_udp, &tmp, 1, server_addr, client_udp_send_done_cb);

            common_restart_timer(&remote_ctx->rmt_expire, remote_ctx->timeout);

            nead_more_action = true;
        }
    } while(0);

    udp_uv_release_buffer((uv_buf_t *)uvbuf);

    if (nead_more_action == false) {
        buffer_release(buf);
    }
    (void)flags;
}

static void client_udp_listener_close_cb(uv_handle_t* handle) {
    struct client_udp_listener_ctx *ctx = CONTAINER_OF(handle, struct client_udp_listener_ctx, udp);
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

static void connection_release(struct cstl_set *set, const void *obj, int *stop, void *p) {
    (void)set; (void)obj; (void)stop; (void)p;
    client_udp_remote_ctx_shutdown((struct client_udp_remote_ctx *)obj);
}

void client_udprelay_shutdown(struct client_udp_listener_ctx *listener_ctx) {
    if (listener_ctx == NULL) {
        return;
    }
    cstl_set_container_traverse(listener_ctx->connections, &connection_release, NULL);
    uv_close((uv_handle_t *)&listener_ctx->udp, client_udp_listener_close_cb);
}

struct client_udp_listener_ctx *
client_udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
    const union sockaddr_universal *server_addr, struct cipher_env_t *cipher_env,
    int mtu, int timeout,
    const char *protocol, const char *protocol_param)
{
    struct client_udp_listener_ctx *listener_ctx;
    struct server_info_t server_info;

    // Initialize MTU
    if (mtu > 0) {
        packet_size = mtu - 1 - 28 - 2 - 64;
        buf_size    = packet_size * 2;
    }

    memset(&server_info, 0, sizeof(server_info));

    listener_ctx = (struct client_udp_listener_ctx *)calloc(1, sizeof(*listener_ctx));

    // Bind to port
    if (udp_create_listener(server_host, server_port, loop, &listener_ctx->udp) < 0) {
        FATAL("[udp] bind() error");
    }

    listener_ctx->cipher_env = cipher_env;
    listener_ctx->timeout = max(timeout, MIN_UDP_TIMEOUT);
    listener_ctx->connections = cstl_set_new(tunnel_ctx_compare_for_c_set, NULL);

    listener_ctx->server_addr = *server_addr;
    //SSR beg
    listener_ctx->protocol_plugin = protocol_instance_create(protocol);
    if (listener_ctx->protocol_plugin) {
        listener_ctx->protocol_global = listener_ctx->protocol_plugin->generate_global_init_data();
    }

    strcpy(server_info.host, server_host);
    server_info.port = server_port;
    server_info.g_data = listener_ctx->protocol_global;
    server_info.extra_param = (char *)protocol_param;
    server_info.key = enc_get_key(cipher_env);
    server_info.key_len = (uint16_t) enc_get_key_len(cipher_env);

    if (listener_ctx->protocol_plugin) {
        listener_ctx->protocol_plugin->set_server_info(listener_ctx->protocol_plugin, &server_info);
    }
    //SSR end

    uv_udp_recv_start(&listener_ctx->udp, udp_uv_alloc_buffer, client_udp_listener_recv_cb);

    return listener_ctx;
}
