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
    return 0;
}

bool need_feedback_false(struct obfs_t *obfs) {
    return false;
}

bool need_feedback_true(struct obfs_t *obfs) {
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
    return buffer_clone(buf);
}

struct buffer_t * generic_server_encode(struct obfs_t *obfs, const struct buffer_t *buf) {
    return buffer_clone(buf);
}

struct buffer_t * generic_server_decode(struct obfs_t *obfs, const struct buffer_t *buf, bool *need_decrypt, bool *need_feedback) {
    if (need_decrypt) { *need_decrypt = true; }
    if (need_feedback) { *need_feedback = false; }
    return buffer_clone(buf);
}

struct buffer_t * generic_server_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, bool *need_feedback) {
    if (need_feedback) { *need_feedback = false; }
    return buffer_clone(buf);
}

bool generic_server_udp_pre_encrypt(struct obfs_t *obfs, struct buffer_t *buf) {
    return true;
}

bool generic_server_udp_post_decrypt(struct obfs_t *obfs, struct buffer_t *buf, uint32_t *uid) {
    if (uid) { *uid = 0; }
    return true;
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
    enum ssr_protocol protocol_type;
    enum ssr_obfs obfs_type;
    if (plugin_name == NULL || strlen(plugin_name)==0) {
        return NULL;
    }

    protocol_type = ssr_protocol_type_of_name(plugin_name);
    obfs_type = ssr_obfs_type_of_name(plugin_name);

    if (ssr_protocol_origin == protocol_type) {
        // origin
        return NULL;
    }
    if (ssr_obfs_plain == obfs_type) {
        // plain
        return NULL;
    }
    init_crc32_table();
    init_shift128plus();
    if (ssr_obfs_http_simple == obfs_type) {
        // http_simple
        plug_in = http_simple_new_obfs();
    } else if (ssr_obfs_http_post == obfs_type) {
        // http_post
        plug_in = http_post_new_obfs();
    } else if (ssr_obfs_http_mix == obfs_type) {
        // http_mix
        plug_in = http_mix_new_obfs();
    } else if (ssr_obfs_tls_1_2_ticket_auth == obfs_type) {
        // tls1.2_ticket_auth
        plug_in = tls12_ticket_auth_new_obfs();
    } else if (ssr_obfs_tls_1_2_ticket_fastauth == obfs_type) {
        // tls1.2_ticket_fastauth
        plug_in = tls12_ticket_fastauth_new_obfs();
    } else if (ssr_protocol_verify_simple == protocol_type) {
        // verify_simple
        plug_in = verify_simple_new_obfs();
    } else if (ssr_protocol_auth_simple == protocol_type) {
        // auth_simple
        plug_in = auth_simple_new_obfs();
    } else if (ssr_protocol_auth_sha1 == protocol_type) {
        // auth_sha1
        plug_in = auth_sha1_new_obfs();
    } else if (ssr_protocol_auth_sha1_v2 == protocol_type) {
        // auth_sha1_v2
        plug_in = auth_sha1_v2_new_obfs();
    } else if (ssr_protocol_auth_sha1_v4 == protocol_type) {
        // auth_sha1_v4
        plug_in = auth_sha1_v4_new_obfs();
    } else if (ssr_protocol_auth_aes128_md5 == protocol_type) {
        // auth_aes128_md5
        plug_in = auth_aes128_md5_new_obfs();
    } else if (ssr_protocol_auth_aes128_sha1 == protocol_type) {
        // auth_aes128_sha1
        plug_in = auth_aes128_sha1_new_obfs();
    } else if (ssr_protocol_auth_chain_a == protocol_type) {
        // auth_chain_a
        plug_in = auth_chain_a_new_obfs();
    } else if (ssr_protocol_auth_chain_b == protocol_type) {
        // auth_chain_b
        plug_in = auth_chain_b_new_obfs();
    } else if (ssr_protocol_auth_chain_c == protocol_type) {
        // auth_chain_c
        plug_in = auth_chain_c_new_obfs();
    } else if (ssr_protocol_auth_chain_d == protocol_type) {
        // auth_chain_d
        plug_in = auth_chain_d_new_obfs();
    } else if (ssr_protocol_auth_chain_e == protocol_type) {
        // auth_chain_e
        plug_in = auth_chain_e_new_obfs();
    } else if (ssr_protocol_auth_chain_f == protocol_type) {
        // auth_chain_f
        plug_in = auth_chain_f_new_obfs();
    } else {
        assert(0); // LOGE("Load obfs '%s' failed", plugin_name);
    }
    plug_in->audit_incoming_user = &protocol_audit_incoming_user;
    return plug_in;
}

void obfs_instance_destroy(struct obfs_t *plugin) {
    if (plugin) {
        plugin->dispose(plugin);
        //free(plugin);
    }
}
