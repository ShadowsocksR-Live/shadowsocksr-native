#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "obfs.h"

int rand_bytes(uint8_t *output, int len);

#include "obfsutil.h"
#include "crc32.h"
#include "http_simple.h"
#include "tls1.2_ticket.h"
#include "verify.h"
#include "auth.h"
#include "auth_chain.h"

#include "encrypt.h"

void *
init_data()
{
    return malloc(1);
}

struct obfs_t *
new_obfs()
{
    struct obfs_t * obfs = (struct obfs_t*)malloc(sizeof(struct obfs_t));
    obfs->l_data = NULL;
    return obfs;
}

int
get_overhead(struct obfs_t *obfs)
{
    return 0;
}

void
set_server_info(struct obfs_t *obfs, struct server_info_t *server)
{
    memmove(&obfs->server, server, sizeof(struct server_info_t));
}

void
get_server_info(struct obfs_t *obfs, struct server_info_t *server)
{
    memmove(server, &obfs->server, sizeof(struct server_info_t));
}

void
dispose_obfs(struct obfs_t *obfs)
{
    free(obfs);
}

struct obfs_manager *
new_obfs_manager(const char *plugin_name)
{
    if (plugin_name == NULL) {
        return NULL;
    }
    if (strcmp(plugin_name, "origin") == 0) {
        return NULL;
    }
    if (strcmp(plugin_name, "plain") == 0) {
        return NULL;
    }
    init_crc32_table();
    init_shift128plus();
    if (strcmp(plugin_name, "http_simple") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = init_data;
        plugin->new_obfs = http_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = http_simple_dispose;

        plugin->client_encode = http_simple_client_encode;
        plugin->client_decode = http_simple_client_decode;

        return plugin;
    } else if (strcmp(plugin_name, "http_post") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = init_data;
        plugin->new_obfs = http_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = http_simple_dispose;

        plugin->client_encode = http_post_client_encode;
        plugin->client_decode = http_simple_client_decode;

        return plugin;
    } else if (strcmp(plugin_name, "tls1.2_ticket_auth") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = tls12_ticket_auth_init_data;
        plugin->new_obfs = tls12_ticket_auth_new_obfs;
        plugin->get_overhead = tls12_ticket_auth_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = tls12_ticket_auth_dispose;

        plugin->client_encode = tls12_ticket_auth_client_encode;
        plugin->client_decode = tls12_ticket_auth_client_decode;

        return plugin;
    /*} else if (strcmp(plugin_name, "verify_simple") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = init_data;
        plugin->new_obfs = verify_simple_new_obfs;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = verify_simple_dispose;

        plugin->client_pre_encrypt = verify_simple_client_pre_encrypt;
        plugin->client_post_decrypt = verify_simple_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, "auth_simple") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_simple_client_pre_encrypt;
        plugin->client_post_decrypt = auth_simple_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;*/
    } else if (strcmp(plugin_name, "auth_sha1") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_sha1_client_pre_encrypt;
        plugin->client_post_decrypt = auth_sha1_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, "auth_sha1_v2") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_sha1_v2_client_pre_encrypt;
        plugin->client_post_decrypt = auth_sha1_v2_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, "auth_sha1_v4") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = auth_simple_new_obfs;
        plugin->get_overhead = get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_sha1_v4_client_pre_encrypt;
        plugin->client_post_decrypt = auth_sha1_v4_client_post_decrypt;
        plugin->client_udp_pre_encrypt = NULL;
        plugin->client_udp_post_decrypt = NULL;

        return plugin;
    } else if (strcmp(plugin_name, "auth_aes128_md5") == 0 || strcmp(plugin_name, "auth_aes128_sha1") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_simple_init_data;
        plugin->new_obfs = strcmp(plugin_name, "auth_aes128_md5") == 0 ? auth_aes128_md5_new_obfs : auth_aes128_sha1_new_obfs;
        plugin->get_overhead = auth_aes128_sha1_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_simple_dispose;

        plugin->client_pre_encrypt = auth_aes128_sha1_client_pre_encrypt;
        plugin->client_post_decrypt = auth_aes128_sha1_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_aes128_sha1_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_aes128_sha1_client_udp_post_decrypt;

        return plugin;
    } else if (strcmp(plugin_name, "auth_chain_a") == 0) {
        struct obfs_manager * plugin = (struct obfs_manager*)malloc(sizeof(struct obfs_manager));
        plugin->init_data = auth_chain_a_init_data;
        plugin->new_obfs = auth_chain_a_new_obfs;
        plugin->get_overhead = auth_chain_a_get_overhead;
        plugin->get_server_info = get_server_info;
        plugin->set_server_info = set_server_info;
        plugin->dispose = auth_chain_a_dispose;

        plugin->client_pre_encrypt = auth_chain_a_client_pre_encrypt;
        plugin->client_post_decrypt = auth_chain_a_client_post_decrypt;
        plugin->client_udp_pre_encrypt = auth_chain_a_client_udp_pre_encrypt;
        plugin->client_udp_post_decrypt = auth_chain_a_client_udp_post_decrypt;

        return plugin;
    }
    assert(0); // LOGE("Load obfs '%s' failed", plugin_name);
    return NULL;
}

void
free_obfs_manager(struct obfs_manager *plugin)
{
    free(plugin);
}
