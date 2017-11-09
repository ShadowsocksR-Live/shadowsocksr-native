/* Copyright SSRLIVE. All rights reserved.
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ssrcipher.h"
#include "defs.h"
#include "encrypt.h"
#include "util.h"
#include "obfsutil.h"
#include "ssrbuffer.h"

void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs);

const char * ssr_strerror(enum ssr_err err) {
#define SSR_ERR_GEN(_, name, errmsg) case (name): return errmsg;
    switch (err) {
        SSR_ERR_MAP(SSR_ERR_GEN)
    default:;  /* Silence ssr_max_errors -Wswitch warning. */
    }
#undef SSR_ERR_GEN
    return "Unknown error.";
}

struct server_env_t * ssr_cipher_env_create(struct server_config *config) {
    srand((unsigned int)time(NULL));

    struct server_env_t *env = calloc(1, sizeof(struct server_env_t));
    env->cipher = calloc(1, sizeof(struct cipher_env_t));
    env->config = config;

    enc_init(env->cipher, config->password, config->method);

    // init obfs
    init_obfs(env, config->protocol, config->obfs);

    return env;
}

void ssr_cipher_env_release(struct server_env_t *env) {
    object_safe_free(&env->protocol_global);
    object_safe_free(&env->obfs_global);
    if (env->protocol_plugin) {
        free_obfs_manager(env->protocol_plugin);
        env->protocol_plugin = NULL;
    }
    if (env->obfs_plugin) {
        free_obfs_manager(env->obfs_plugin);
        env->obfs_plugin = NULL;
    }
    enc_release(env->cipher);
    object_safe_free((void **)&env->cipher);

    object_safe_free((void **)&env);
}

void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs) {
    env->protocol_plugin = new_obfs_manager(protocol);
    if (env->protocol_plugin) {
        env->protocol_global = env->protocol_plugin->init_data();
    }

    env->obfs_plugin = new_obfs_manager(obfs);
    if (env->obfs_plugin) {
        env->obfs_global = env->obfs_plugin->init_data();
    }
}

struct tunnel_cipher_ctx * tunnel_cipher_create(struct server_env_t *env, const struct buffer_t *init_pkg) {
    struct server_config *config = env->config;

    struct tunnel_cipher_ctx *tc = calloc(1, sizeof(struct tunnel_cipher_ctx));

    tc->env = env;

    // init server cipher
    if (env->cipher->enc_method > TABLE) {
        tc->e_ctx = calloc(1, sizeof(struct enc_ctx));
        tc->d_ctx = calloc(1, sizeof(struct enc_ctx));
        enc_ctx_init(env->cipher, tc->e_ctx, 1);
        enc_ctx_init(env->cipher, tc->d_ctx, 0);
    }
    // SSR beg

    struct server_info_t server_info = { 0 };

    strcpy(server_info.host, config->remote_host);
    server_info.port = config->remote_port;
    server_info.param = config->obfs_param;
    server_info.g_data = env->obfs_global;
    server_info.head_len = get_head_size(init_pkg->buffer, (int)init_pkg->len, 30);
    server_info.iv = tc->e_ctx->cipher_ctx.iv;
    server_info.iv_len = enc_get_iv_len(env->cipher);
    server_info.key = enc_get_key(env->cipher);
    server_info.key_len = enc_get_key_len(env->cipher);
    server_info.tcp_mss = 1452;
    server_info.buffer_size = SSR_BUFF_SIZE;
    server_info.cipher_env = env->cipher;

    if (env->obfs_plugin) {
        tc->obfs = env->obfs_plugin->new_obfs();
        env->obfs_plugin->set_server_info(tc->obfs, &server_info);
    }

    server_info.param = config->protocol_param;
    server_info.g_data = env->protocol_global;

    if (env->protocol_plugin) {
        tc->protocol = env->protocol_plugin->new_obfs();
        int p_len = env->protocol_plugin->get_overhead(tc->protocol);
        int o_len = (env->obfs_plugin ? env->obfs_plugin->get_overhead(tc->obfs) : 0);
        server_info.overhead = p_len + o_len;
        env->protocol_plugin->set_server_info(tc->protocol, &server_info);
    }
    // SSR end

   return tc;
}

void tunnel_cipher_release(struct tunnel_cipher_ctx *tc) {
    assert(tc);
    struct server_env_t *env = tc->env;
    if (tc->e_ctx != NULL) {
        enc_ctx_release(env->cipher, tc->e_ctx);
        object_safe_free((void **)&tc->e_ctx);
    }
    if (tc->d_ctx != NULL) {
        enc_ctx_release(env->cipher, tc->d_ctx);
        object_safe_free((void **)&tc->d_ctx);
    }
    // SSR beg
    if (env->obfs_plugin) {
        env->obfs_plugin->dispose(tc->obfs);
        tc->obfs = NULL;
    }
    if (env->protocol_plugin) {
        env->protocol_plugin->dispose(tc->protocol);
        tc->protocol = NULL;
    }
    // SSR end

    free(tc);
}

// insert shadowsocks header
enum ssr_err tunnel_encrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf) {
    assert(buf->capacity >= SSR_BUFF_SIZE);

    struct server_env_t *env = tc->env;
    // SSR beg
    struct obfs_manager *protocol_plugin = env->protocol_plugin;

    if (protocol_plugin && protocol_plugin->client_pre_encrypt) {
        buf->len = (size_t)protocol_plugin->client_pre_encrypt(
            tc->protocol, &buf->buffer, (int)buf->len, &buf->capacity);
    }
    int err = ss_encrypt(env->cipher, buf, tc->e_ctx, SSR_BUFF_SIZE);
    if (err != 0) {
        // LOGE("local invalid password or cipher");
        // tunnel_close_and_free(remote, local);
        return ssr_invalid_password;
    }

    struct obfs_manager *obfs_plugin = env->obfs_plugin;
    if (obfs_plugin && obfs_plugin->client_encode) {
        buf->len = obfs_plugin->client_encode(
            tc->obfs, &buf->buffer, buf->len, &buf->capacity);
    }
    // SSR end
    return ssr_ok;
}

enum ssr_err tunnel_decrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf, fn_feedback feedback, void *ptr)
{
    assert(buf->len <= SSR_BUFF_SIZE);

    struct server_env_t *env = tc->env;

    // SSR beg
    struct obfs_manager *obfs_plugin = env->obfs_plugin;
    if (obfs_plugin && obfs_plugin->client_decode) {
        int needsendback = 0;
        ssize_t len = obfs_plugin->client_decode(tc->obfs, &buf->buffer, buf->len, &buf->capacity, &needsendback);
        if (len < 0) {
            //tunnel_close_and_free(remote, local);
            return ssr_client_decode;
        }
        buf->len = (size_t)len;
        if (needsendback && obfs_plugin->client_encode) {
            struct buffer_t *sendback = buffer_alloc(SSR_BUFF_SIZE);
            sendback->len = obfs_plugin->client_encode(tc->obfs, &sendback->buffer, 0, &sendback->capacity);
            assert(feedback);
            feedback(sendback, ptr);
            //remote_send_data(remote);
            //local_read_start(local);
            buffer_free(sendback);
        }
    }
    if (buf->len > 0) {
        int err = ss_decrypt(env->cipher, buf, tc->d_ctx, SSR_BUFF_SIZE);
        if (err != 0) {
            //LOGE("remote invalid password or cipher");
            //tunnel_close_and_free(remote, local);
            return ssr_invalid_password;
        }
    }
    struct obfs_manager *protocol_plugin = env->protocol_plugin;
    if (protocol_plugin && protocol_plugin->client_post_decrypt) {
        ssize_t len = (size_t)protocol_plugin->client_post_decrypt(
            tc->protocol, &buf->buffer, (int)buf->len, &buf->capacity);
        if (len < 0) {
            //tunnel_close_and_free(remote, local);
            return ssr_client_post_decrypt;
        }
        buf->len = (size_t)len;
        //if (buf->len == 0) {
        //    return 0; // continue; <========
        //}
    }
    // SSR end

    //if (buf->len) {
    //    //local_send_data(local, buf->buffer, (unsigned int)buf->len);
    //}
    return ssr_ok;
}

