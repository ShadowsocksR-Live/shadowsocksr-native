#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "obfs.h"

void rand_bytes(uint8_t *output, size_t len);

#include "obfsutil.h"
#include "crc32.h"
#include "http_simple.h"
#include "tls1.2_ticket.h"
#include "verify.h"
#include "auth.h"
#include "auth_chain.h"

#include "encrypt.h"
#include "ssrbuffer.h"
#include "ssr_executive.h"

void * generate_global_init_data(void) {
    return calloc(1, sizeof(char));
}

size_t
get_overhead(struct obfs_t *obfs)
{
    (void)obfs;
    return 0;
}

bool need_feedback_false(struct obfs_t *obfs) {
    (void)obfs;
    return false;
}

bool need_feedback_true(struct obfs_t *obfs) {
    (void)obfs;
    return true;
}

void
set_server_info(struct obfs_t *obfs, struct server_info_t *server)
{
    memmove(&obfs->server_info, server, sizeof(struct server_info_t));
}

struct server_info_t *
get_server_info(struct obfs_t *obfs)
{
    return &obfs->server_info;
}

struct buffer_t * generic_server_pre_encrypt(struct obfs_t *obfs, const struct buffer_t *buf) {
    (void)obfs;
    return buffer_clone(buf);
}

struct buffer_t * generic_server_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    (void)obfs;
    return buffer_clone(buf);
}

struct buffer_t * generic_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    (void)obfs;
    if (need_decrypt) { *need_decrypt = true; }
    if (need_feedback) { *need_feedback = false; }
    return buffer_clone(buf);
}

struct buffer_t * generic_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback) {
    (void)obfs;
    if (need_feedback) { *need_feedback = false; }
    return buffer_clone(buf);
}

void
dispose_obfs(struct obfs_t *obfs)
{
    free(obfs);
}

bool protocol_audit_incoming_user(struct obfs_t *obfs, const char *user_id, const char **auth_key, bool *is_multi_user) {
    bool result = false;
    struct server_config *config = obfs->server_info.config;
    result = config_is_user_exist(config, user_id, auth_key, is_multi_user);
    return result;
}

struct obfs_t * obfs_instance_create(const char *plugin_name) {
    struct obfs_t *plug_in = NULL;
    enum ssr_obfs obfs_type;

    init_crc32_table();
    init_shift128plus();

    obfs_type = ssr_obfs_type_of_name(plugin_name);

    switch(obfs_type) {
    case ssr_obfs_plain:
        // plain
        plug_in = NULL;
        break;
    case ssr_obfs_http_simple:
        // http_simple
        plug_in = http_simple_new_obfs();
        break;
    case ssr_obfs_http_post:
        // http_post
        plug_in = http_post_new_obfs();
        break;
    case ssr_obfs_http_mix:
        // http_mix
        plug_in = http_mix_new_obfs();
        break;
    case ssr_obfs_tls_1_2_ticket_auth:
        // tls1.2_ticket_auth
        plug_in = tls12_ticket_auth_new_obfs();
        break;
    case ssr_obfs_tls_1_2_ticket_fastauth:
        // tls1.2_ticket_fastauth
        plug_in = tls12_ticket_fastauth_new_obfs();
        break;
    default:
        assert(0); // LOGE("Load obfs '%s' failed", plugin_name);
        break;
    }

    return plug_in;
}

struct obfs_t * protocol_instance_create(const char *plugin_name) {
    struct obfs_t *plug_in = NULL;
    enum ssr_protocol protocol_type;

    init_crc32_table();
    init_shift128plus();
    protocol_type = ssr_protocol_type_of_name(plugin_name);

    switch(protocol_type) {
    case ssr_protocol_origin:
        // origin
        plug_in = NULL;
        break;
    case ssr_protocol_verify_simple:
        // verify_simple
        plug_in = verify_simple_new_obfs();
        break;
    case ssr_protocol_auth_simple:
        // auth_simple
        plug_in = auth_simple_new_obfs();
        break;
    case ssr_protocol_auth_sha1:
        // auth_sha1
        plug_in = auth_sha1_new_obfs();
        break;
    case ssr_protocol_auth_sha1_v2:
        // auth_sha1_v2
        plug_in = auth_sha1_v2_new_obfs();
        break;
    case ssr_protocol_auth_sha1_v4:
        // auth_sha1_v4
        plug_in = auth_sha1_v4_new_obfs();
        break;
    case ssr_protocol_auth_aes128_md5:
        // auth_aes128_md5
        plug_in = auth_aes128_md5_new_obfs();
        break;
    case ssr_protocol_auth_aes128_sha1:
        // auth_aes128_sha1
        plug_in = auth_aes128_sha1_new_obfs();
        break;
    case ssr_protocol_auth_chain_a:
        // auth_chain_a
        plug_in = auth_chain_a_new_obfs();
        break;
    case ssr_protocol_auth_chain_b:
        // auth_chain_b
        plug_in = auth_chain_b_new_obfs();
        break;
    case ssr_protocol_auth_chain_c:
        // auth_chain_c
        plug_in = auth_chain_c_new_obfs();
        break;
    case ssr_protocol_auth_chain_d:
        // auth_chain_d
        plug_in = auth_chain_d_new_obfs();
        break;
    case ssr_protocol_auth_chain_e:
        // auth_chain_e
        plug_in = auth_chain_e_new_obfs();
        break;
    case ssr_protocol_auth_chain_f:
        // auth_chain_f
        plug_in = auth_chain_f_new_obfs();
        break;
    default:
        assert(0); // LOGE("Load obfs '%s' failed", plugin_name);
        break;
    }

    if (plug_in) {
        plug_in->audit_incoming_user = &protocol_audit_incoming_user;
    }
    return plug_in;
}

void obfs_instance_destroy(struct obfs_t *plugin) {
    if (plugin) {
        plugin->dispose(plugin);
        //free(plugin);
    }
}
