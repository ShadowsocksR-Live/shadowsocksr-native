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
#include <time.h>

// for ntohs
#if defined(WIN32) || defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include "common.h"
#include "ssr_executive.h"
#include "encrypt.h"
#include "obfsutil.h"
#include "ssrbuffer.h"
#include "obfs.h"
#include "crc32.h"
#include "cstl_lib.h"

const char * ssr_strerror(enum ssr_error err) {
#define SSR_ERR_GEN(_, name, errmsg) case (name): return errmsg;
    switch (err) {
        SSR_ERR_MAP(SSR_ERR_GEN)
        default:;  /* Silence ssr_max_errors -Wswitch warning. */
    }
#undef SSR_ERR_GEN
    return "Unknown error.";
}

void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs);

void object_safe_free(void **obj) {
    if (obj && *obj) {
        free(*obj);
        *obj = NULL;
    }
}

void string_safe_assign(char **target, const char *value) {
    object_safe_free((void **)target);
    if (target && value) {
        *target = strdup(value);
    }
}

struct server_config * config_create(void) {
    struct server_config *config;

    config = (struct server_config *) calloc(1, sizeof(*config));
    string_safe_assign(&config->listen_host, DEFAULT_BIND_HOST);
    string_safe_assign(&config->method, DEFAULT_METHOD);
    config->listen_port = DEFAULT_BIND_PORT;
    config->idle_timeout = DEFAULT_IDLE_TIMEOUT;

    return config;
}

void config_release(struct server_config *cf) {
    if (cf == NULL) {
        return;
    }

    obj_map_destroy(cf->user_id_auth_key);

    object_safe_free((void **)&cf->listen_host);
    object_safe_free((void **)&cf->remote_host);
    object_safe_free((void **)&cf->password);
    object_safe_free((void **)&cf->method);
    object_safe_free((void **)&cf->protocol);
    object_safe_free((void **)&cf->protocol_param);
    object_safe_free((void **)&cf->obfs);
    object_safe_free((void **)&cf->obfs_param);
    object_safe_free((void **)&cf->over_tls_server_domain);
    object_safe_free((void **)&cf->over_tls_path);
    object_safe_free((void **)&cf->over_tls_root_cert_file);
    object_safe_free((void **)&cf->remarks);

    object_safe_free((void **)&cf);
}

static int uid_cmp(const void *left, const void *right) {
    char *l = *(char **)left;
    char *r = *(char **)right;
    return strcmp(l, r);
}

static void uid_destroy(void *obj) {
    if (obj) {
        void *str = *((void **)obj);
        if (str) {
            free(str);
        }
    }
}

/* "protocol_param":"64#12345:breakwa11,233:breakwa11", */
void config_parse_protocol_param(struct server_config *config, const char *param) {
    char *p0 = strdup(param), *user_id = p0, *iter, *auth_key;
    long int max_cli = 0;
    iter = strchr(p0, '#');
    if (iter) {
        *iter = '\0'; iter++;
        max_cli = strtol(p0, NULL, 10);
        user_id = iter;
    }
    config->max_client = (max_cli != 0) ? (unsigned int)max_cli : 64;

    do {
        iter = strchr(user_id, ',');
        if (iter) {
            *iter = '\0'; iter++;
        }

        auth_key = strchr(user_id, ':');
        if (auth_key) {
            *auth_key = '\0'; auth_key++;
            config_add_user_id_with_auth_key(config, user_id, auth_key);
        }

        if (iter) {
            user_id = iter;
        }
    } while (iter != NULL);

    free(p0);
}

void config_add_user_id_with_auth_key(struct server_config *config, const char *user_id, const char *auth_key) {
    char *u = strdup(user_id);
    char *a = strdup(auth_key);

    if (config->user_id_auth_key == NULL) {
        config->user_id_auth_key = obj_map_create(uid_cmp, uid_destroy, uid_destroy);
    }
    obj_map_add(config->user_id_auth_key, &u, sizeof(void *), &a, sizeof(void *));
}

bool config_is_user_exist(struct server_config *config, const char *user_id, const char **auth_key, bool *is_multi_user) {
    bool result = false;
    assert(config);
    assert(user_id);
    if (is_multi_user) {
        *is_multi_user = (config->user_id_auth_key != NULL);
    }
    result = obj_map_exists(config->user_id_auth_key, &user_id);
    if (result && auth_key) {
        *auth_key = *((const char **)obj_map_find(config->user_id_auth_key, &user_id));
    }
    return result;
}

int tunnel_ctx_compare_for_c_set(const void *left, const void *right) {
    struct tunnel_ctx *l = *(struct tunnel_ctx **)left;
    struct tunnel_ctx *r = *(struct tunnel_ctx **)right;
    if ( l < r ) {
        return -1;
    } else if ( l > r ) {
        return 1;
    } else {
        return 0;
    }
}

struct server_env_t * ssr_cipher_env_create(struct server_config *config, void *data) {
    struct server_env_t *env;
    srand((unsigned int)time(NULL));

    env = (struct server_env_t *) calloc(1, sizeof(struct server_env_t));
    env->cipher = cipher_env_new_instance(config->password, config->method);
    env->config = config;
    env->data = data;

    // init obfs
    init_obfs(env, config->protocol, config->obfs);

    env->tunnel_set = cstl_set_container_create(tunnel_ctx_compare_for_c_set, NULL);
    
    return env;
}

void ssr_cipher_env_release(struct server_env_t *env) {
    if (env == NULL) {
        return;
    }
    object_safe_free(&env->protocol_global);
    object_safe_free(&env->obfs_global);
    cipher_env_release(env->cipher);

    cstl_set_container_destroy(env->tunnel_set);
    
    object_safe_free((void **)&env);
}

bool is_completed_package(struct server_env_t *env, const uint8_t *data, size_t size) {
    (void)data;
    return size > (size_t)(enc_get_iv_len(env->cipher) + 1);
}

struct cstl_set * cstl_set_container_create(int(*compare_objs)(const void*,const void*), void(*destroy_obj)(void*)) {
    return cstl_set_new(compare_objs, destroy_obj);
}

void cstl_set_container_destroy(struct cstl_set *set) {
    cstl_set_delete(set);
}

void cstl_set_container_add(struct cstl_set *set, void *obj) {
    ASSERT(set && obj);
    cstl_set_insert(set, &obj, sizeof(void *));
}

void cstl_set_container_remove(struct cstl_set *set, void *obj) {
    ASSERT(cstl_true == cstl_set_exists(set, &obj));
    cstl_set_remove(set, &obj);
}

void cstl_set_container_traverse(struct cstl_set *set, void(*fn)(const void *obj, void *p), void *p) {
    struct cstl_iterator *iterator;
    const void *element;
    if (set==NULL || fn==NULL) {
        return;
    }
    iterator = cstl_set_new_iterator(set);
    while( (element = iterator->next(iterator)) ) {
        const void *obj = *((const void **) iterator->current_value(iterator));
        fn(obj, p);
    }
    cstl_set_delete_iterator(iterator);
}

struct cstl_list * obj_list_create(int(*compare_objs)(const void*,const void*), void (*destroy_obj)(void*)) {
    return cstl_list_new(destroy_obj, compare_objs);
}

void obj_list_destroy(struct cstl_list *list) {
    cstl_list_destroy(list);
}

void obj_list_clear(struct cstl_list *list) {
    cstl_list_clear(list);
}

void obj_list_insert(struct cstl_list* pList, size_t pos, void* elem, size_t elem_size) {
    cstl_list_insert(pList, pos, elem, elem_size);
}

void obj_list_for_each(struct cstl_list* pSlist, void (*fn)(const void *elem, void *p), void *p) {
    cstl_list_for_each (pSlist, fn, p);
}

const void * obj_list_element_at(struct cstl_list* pList, size_t pos) {
    return cstl_list_element_at(pList, pos);
}

size_t obj_list_size(struct cstl_list* pSlist) {
    return cstl_list_size(pSlist);
}


struct cstl_map * obj_map_create(int(*compare_key)(const void*,const void*), void (*destroy_key)(void*), void (*destroy_value)(void*)) {
    return cstl_map_new(compare_key, destroy_key, destroy_value);
}

void obj_map_destroy(struct cstl_map *map) {
    cstl_map_delete(map);
}

bool obj_map_add(struct cstl_map *map, void *key, size_t k_size, void *value, size_t v_size) {
    return CSTL_ERROR_SUCCESS == cstl_map_insert(map, key, k_size, value, v_size);
}

bool obj_map_exists(struct cstl_map *map, const void *key) {
    return cstl_map_exists(map, key) != cstl_false;
}

bool obj_map_replace(struct cstl_map *map, const void *key, const void *value, size_t v_size) {
    return CSTL_ERROR_SUCCESS == cstl_map_replace(map, key, value, v_size);
}

void obj_map_remove(struct cstl_map *map, const void *key) {
    cstl_map_remove(map, key);
}

const void * obj_map_find(struct cstl_map *map, const void *key) {
    return cstl_map_find(map, key);
}

void obj_map_traverse(struct cstl_map *map, void(*fn)(const void *key, const void *value, void *p), void *p) {
    struct cstl_iterator *iterator;
    const void *element;
    if (map==NULL || fn==NULL) {
        return;
    }
    iterator = cstl_map_new_iterator(map);
    while( (element = iterator->next(iterator)) ) {
        const void *key = iterator->current_key(iterator);
        const void *value = iterator->current_value(iterator);
        fn(key, value, p);
    }
    cstl_map_delete_iterator(iterator);
}

void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs) {
    struct obfs_t *protocol_plugin;
    struct obfs_t *obfs_plugin;
    protocol_plugin = obfs_instance_create(protocol);
    if (protocol_plugin) {
        env->protocol_global = protocol_plugin->generate_global_init_data();
        obfs_instance_destroy(protocol_plugin);
    }

    obfs_plugin = obfs_instance_create(obfs);
    if (obfs_plugin) {
        env->obfs_global = obfs_plugin->generate_global_init_data();
        obfs_instance_destroy(obfs_plugin);
    }
}

struct tunnel_cipher_ctx * tunnel_cipher_create(struct server_env_t *env, size_t tcp_mss) {
    struct server_info_t server_info = { {0}, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    struct server_config *config = env->config;

    struct tunnel_cipher_ctx *tc = (struct tunnel_cipher_ctx *) calloc(1, sizeof(struct tunnel_cipher_ctx));

    tc->env = env;

    // init server cipher
    if (cipher_env_enc_method(env->cipher) > ss_cipher_table) {
        tc->e_ctx = enc_ctx_new_instance(env->cipher, true);
        tc->d_ctx = enc_ctx_new_instance(env->cipher, false);
    }
    // SSR beg

    if (config->remote_host && strlen(config->remote_host)) {
        strcpy(server_info.host, config->remote_host);
    }
    server_info.config = config;
    server_info.port = config->remote_port;
    server_info.iv_len = enc_get_iv_len(env->cipher);
    memcpy(server_info.iv, enc_ctx_get_iv(tc->e_ctx), server_info.iv_len);
    server_info.key = enc_get_key(env->cipher);
    server_info.key_len = (uint16_t) enc_get_key_len(env->cipher);
    server_info.tcp_mss = (uint16_t) tcp_mss;
    server_info.buffer_size = SSR_BUFF_SIZE;
    server_info.cipher_env = env->cipher;
    {
        server_info.param = config->obfs_param;
        server_info.g_data = env->obfs_global;

        tc->obfs = obfs_instance_create(config->obfs);
        if (tc->obfs) {
            tc->obfs->set_server_info(tc->obfs, &server_info);
        }
    }
    {
        server_info.param = config->protocol_param;
        server_info.g_data = env->protocol_global;

        tc->protocol = obfs_instance_create(config->protocol);
        if (tc->protocol) {
            tc->protocol->set_server_info(tc->protocol, &server_info);
        }
    }

    {
        struct obfs_t *protocol = tc->protocol;
        struct obfs_t *obfs = tc->obfs;
        size_t total_overhead = 
            (protocol ? protocol->get_overhead(protocol) : 0) +
            (obfs ? obfs->get_overhead(obfs) : 0);

        if (protocol) {
            struct server_info_t *info = protocol->get_server_info(protocol);
            info->overhead = (uint16_t)total_overhead;
            info->buffer_size = (uint32_t)(TCP_BUF_SIZE_MAX - total_overhead);
        }
        if (obfs) {
            struct server_info_t *info = obfs->get_server_info(obfs);
            info->overhead = (uint16_t)total_overhead;
            info->buffer_size = (uint32_t)(TCP_BUF_SIZE_MAX - total_overhead);
        }
    }
    // SSR end

   return tc;
}

void tunnel_cipher_release(struct tunnel_cipher_ctx *tc) {
    struct server_env_t *env;
    if (tc == NULL) {
        return;
    }
    env = tc->env;
    if (tc->e_ctx != NULL) {
        enc_ctx_release_instance(env->cipher, tc->e_ctx);
    }
    if (tc->d_ctx != NULL) {
        enc_ctx_release_instance(env->cipher, tc->d_ctx);
    }

    obfs_instance_destroy(tc->protocol);
    obfs_instance_destroy(tc->obfs);

    free(tc);
}

bool tunnel_cipher_client_need_feedback(struct tunnel_cipher_ctx *tc) {
    bool protocol = false;
    bool obfs = false;
    struct server_env_t *env = tc->env;
    ASSERT(env);

    if (tc->protocol) {
        protocol = tc->protocol->need_feedback(tc->protocol);
    }
    if (tc->obfs) {
        obfs = tc->obfs->need_feedback(tc->obfs);
    }
    return (protocol || obfs);
}

// insert shadowsocks header
enum ssr_error tunnel_cipher_client_encrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf) {
    int err;
    struct obfs_t *obfs_plugin;
    struct server_env_t *env = tc->env;
    // SSR beg
    struct obfs_t *protocol_plugin = tc->protocol;
    ASSERT(buf->capacity >= SSR_BUFF_SIZE);
    if (protocol_plugin && protocol_plugin->client_pre_encrypt) {
        buf->len = (size_t)protocol_plugin->client_pre_encrypt(
            tc->protocol, (char **)&buf->buffer, (int)buf->len, &buf->capacity);
    }
    err = ss_encrypt(env->cipher, buf, tc->e_ctx, SSR_BUFF_SIZE);
    if (err != 0) {
        return ssr_error_invalid_password;
    }

    obfs_plugin = tc->obfs;
    if (obfs_plugin && obfs_plugin->client_encode) {
        struct buffer_t *tmp = obfs_plugin->client_encode(tc->obfs, buf);
        buffer_replace(buf, tmp); buffer_release(tmp);
    }
    // SSR end
    return ssr_ok;
}

enum ssr_error tunnel_cipher_client_decrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf, struct buffer_t **feedback)
{
    struct obfs_t *protocol_plugin;
    struct server_env_t *env = tc->env;

    // SSR beg
    struct obfs_t *obfs_plugin = tc->obfs;

    ASSERT(buf->len <= SSR_BUFF_SIZE);

    if (obfs_plugin && obfs_plugin->client_decode) {
        bool needsendback = 0;
        struct buffer_t *result = obfs_plugin->client_decode(tc->obfs, buf, &needsendback);
        if (result == NULL) {
            return ssr_error_client_decode;
        }
        buffer_replace(buf, result); buffer_release(result);
        if (needsendback && obfs_plugin->client_encode) {
            struct buffer_t *empty = buffer_create_from((const uint8_t *)"", 0);
            struct buffer_t *sendback = obfs_plugin->client_encode(tc->obfs, empty);
            ASSERT(feedback);
            *feedback = sendback;
            buffer_release(empty);
        }
    }
    if (buf->len > 0) {
        int err = ss_decrypt(env->cipher, buf, tc->d_ctx, SSR_BUFF_SIZE);
        if (err != 0) {
            return ssr_error_invalid_password;
        }
    }
    protocol_plugin = tc->protocol;
    if (protocol_plugin && protocol_plugin->client_post_decrypt) {
        ssize_t len = protocol_plugin->client_post_decrypt(
            tc->protocol, (char **)&buf->buffer, (int)buf->len, &buf->capacity);
        if (len < 0) {
            return ssr_error_client_post_decrypt;
        }
        buf->len = (size_t)len;
    }
    // SSR end
    return ssr_ok;
}

struct buffer_t * tunnel_cipher_server_encrypt(struct tunnel_cipher_ctx *tc, const struct buffer_t *buf) {
    int err;
    struct server_env_t *env = tc->env;
    struct obfs_t *obfs = tc->obfs;
    struct obfs_t *protocol = tc->protocol;
    struct buffer_t *ret = NULL;
    do {
        if (protocol && protocol->server_pre_encrypt) {
            ret = protocol->server_pre_encrypt(protocol, buf);
        } else {
            ret = buffer_clone(buf);
        }
        if (ret == NULL) {
            break;
        }
        err = ss_encrypt(env->cipher, ret, tc->e_ctx, SSR_BUFF_SIZE);
        if (err != 0) {
            ASSERT(false);
            buffer_release(ret); ret = NULL;
            break;
        }
        if (obfs && obfs->server_encode) {
            struct buffer_t *tmp = obfs->server_encode(obfs, ret);
            buffer_release(ret); ret = tmp;
        }
    } while (0);
    return ret;
}

struct buffer_t * 
tunnel_cipher_server_decrypt(struct tunnel_cipher_ctx *tc, 
                             const struct buffer_t *buf, 
                             struct buffer_t **receipt, 
                             struct buffer_t **confirm)
{
    bool need_decrypt = true;
    int err;
    struct server_env_t *env = tc->env;
    struct obfs_t *obfs = tc->obfs;
    struct obfs_t *protocol = tc->protocol;
    struct buffer_t *ret = NULL;

    if (receipt) { *receipt = NULL; }
    if (confirm) { *confirm = NULL; }

    if (obfs && obfs->server_decode) {
        bool need_feedback = false;
        ret = obfs->server_decode(obfs, buf, &need_decrypt, &need_feedback);
        if (ret == NULL) {
            return NULL;
        }
        if (need_feedback) {
            if (receipt) {
                struct buffer_t *empty = buffer_create_from((const uint8_t *)"", 0);
                *receipt = obfs->server_encode(obfs, empty);
                buffer_release(empty);
            }
            buffer_reset(ret);
            return ret;
        }
    } else {
        ret = buffer_clone(buf);
    }
    if (need_decrypt && ret && ret->len) {
        /*
        // TODO: check IV
        if (is_completed_package(env, ret->buffer, ret->len) == false) {
            buffer_release(ret);
            return NULL;
        }
        */
        if (protocol && protocol->server_info.recv_iv[0] == 0) {
            size_t iv_len = protocol->server_info.iv_len;
            memmove(protocol->server_info.recv_iv, ret->buffer, iv_len);
            protocol->server_info.recv_iv_len = iv_len;
        }

        err = ss_decrypt(env->cipher, ret, tc->d_ctx, max(SSR_BUFF_SIZE, ret->capacity));
        if (err != 0) {
            buffer_release(ret); ret = NULL;
            return ret;
        }
    }
    if (protocol && protocol->server_post_decrypt) {
        bool feedback = false;
        struct buffer_t *tmp = protocol->server_post_decrypt(protocol, ret, &feedback);
        buffer_release(ret); ret = tmp;
        if (feedback) {
            if (confirm) {
                struct buffer_t *empty = buffer_create_from((const uint8_t *)"", 0);
                *confirm  = tunnel_cipher_server_encrypt(tc, empty);
                buffer_release(empty);
            }
        }
    }
    return ret;
}

#define USING_PLAINTEXT_CIPHER 1

enum ssr_error tunnel_tls_cipher_client_encrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf) {
#if USING_PLAINTEXT_CIPHER
    return ssr_ok;
#else
    int err;
    struct server_env_t *env = tc->env;
    ASSERT(buf->capacity >= SSR_BUFF_SIZE);
    err = ss_encrypt(env->cipher, buf, tc->e_ctx, SSR_BUFF_SIZE);
    if (err != 0) {
        return ssr_error_invalid_password;
    }
    return ssr_ok;
#endif
}

enum ssr_error tunnel_tls_cipher_client_decrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf, struct buffer_t **feedback) {
#if USING_PLAINTEXT_CIPHER
    return ssr_ok;
#else
    struct server_env_t *env = tc->env;
    // ASSERT(buf->len <= SSR_BUFF_SIZE);
    if (feedback) { *feedback = NULL; }
    if (buf->len > 0) {
        int err = ss_decrypt(env->cipher, buf, tc->d_ctx, SSR_BUFF_SIZE);
        if (err != 0) {
            return ssr_error_invalid_password;
        }
    }
    return ssr_ok;
#endif
}

struct buffer_t * tunnel_tls_cipher_server_encrypt(struct tunnel_cipher_ctx *tc, const struct buffer_t *buf) {
#if USING_PLAINTEXT_CIPHER
    return buffer_clone(buf);
#else
    int err;
    struct server_env_t *env = tc->env;
    struct buffer_t *ret = NULL;
    do {
        ret = buffer_clone(buf);
        if (ret == NULL) {
            break;
        }
        err = ss_encrypt(env->cipher, ret, tc->e_ctx, SSR_BUFF_SIZE);
        if (err != 0) {
            ASSERT(false);
            buffer_release(ret); ret = NULL;
            break;
        }
    } while (0);
    return ret;
#endif
}

struct buffer_t * tunnel_tls_cipher_server_decrypt(struct tunnel_cipher_ctx *tc, const struct buffer_t *buf, struct buffer_t **receipt, struct buffer_t **confirm) {
#if USING_PLAINTEXT_CIPHER
    return buffer_clone(buf);
#else
    int err;
    struct server_env_t *env = tc->env;
    struct buffer_t *ret = NULL;

    if (receipt) { *receipt = NULL; }
    if (confirm) { *confirm = NULL; }

    ret = buffer_clone(buf);

    err = ss_decrypt(env->cipher, ret, tc->d_ctx, max(SSR_BUFF_SIZE, ret->capacity));
    if (err != 0) {
        buffer_release(ret); ret = NULL;
    }

    return ret;
#endif
}

bool pre_parse_header(struct buffer_t *data) {
    uint8_t datatype = 0;
    size_t rand_data_size = 0;
    size_t hdr_len = 0;

    if (data==NULL || data->buffer==NULL || data->len==0) {
        return false;
    }

    datatype = data->buffer[0];

    if (datatype == 0x80) {
        if (data->len <= 2) {
            return false;
        }
        rand_data_size = (size_t) data->buffer[1];
        hdr_len = rand_data_size + 2;
        if (hdr_len >= data->len) {
            // header too short, maybe wrong password or encryption method
            return false;
        }

        memmove(data->buffer, data->buffer + hdr_len, data->len - hdr_len);
        data->len -= hdr_len;

        return true;
    }
    if (datatype == 0x81) {
        hdr_len = 1;
        memmove(data->buffer, data->buffer + hdr_len, data->len - hdr_len);
        data->len -= hdr_len;
        return true;
    }
    if (datatype == 0x82) {
        if (data->len <= 3) {
            return false;
        }
        rand_data_size = (size_t) ntohs( *((uint16_t *)(data->buffer+1)) );
        hdr_len = rand_data_size + 3;
        if (hdr_len >= data->len) {
            // header too short, maybe wrong password or encryption method
            return false;
        }
        memmove(data->buffer, data->buffer + hdr_len, data->len - hdr_len);
        data->len -= hdr_len;
        return true;
    }
    if ((datatype == 0x88) || (~datatype == 0x88)) {
        uint32_t crc = 0;
        size_t data_size = 0;
        size_t start_pos = 0;
        size_t origin_len = data->len;
        if (data->len <= (7 + 7)) {
            return false;
        }
        data_size = (size_t) ntohs( *((uint16_t *)(data->buffer+1)) );
        crc = crc32_imp(data->buffer, data_size);
        if (crc != 0xffffffff) {
            // uncorrect CRC32, maybe wrong password or encryption method
            return false;
        }
        start_pos = (size_t)(3 + data->buffer[3]);

        data->len = data_size - (4 + start_pos);
        memmove(data->buffer, data->buffer + start_pos, data->len);

        if (data_size < origin_len) {
            size_t len2 = origin_len - data_size;
            memmove(data->buffer + data->len, data->buffer + data_size, len2);
            data->len += len2;
        }
        return true;
    }

    return true;
}

