#if !defined(__SSR_CIPHER__)
#define __SSR_CIPHER__ 1


#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "obfs.h"

struct server_env_t {
    struct server_config *config; // __weak_ptr

    struct cipher_env_t *cipher;

    struct obfs_manager *protocol_plugin;
    struct obfs_manager *obfs_plugin;

    void *protocol_global;
    void *obfs_global;
};

struct tunnel_cipher_ctx {
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct obfs_t *protocol;
    struct obfs_t *obfs;
};

struct server_env_t * ssr_cipher_env_create(struct server_config *config);
struct tunnel_cipher_ctx * tunnel_cipher_create(struct server_env_t *env, const char *init_pkg);
void tunnel_cipher_release(struct server_env_t *env, struct tunnel_cipher_ctx *tc);

#endif // defined(__SSR_CIPHER__)
