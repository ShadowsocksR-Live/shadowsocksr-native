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

struct server_env_t * create_ssr_cipher_env(struct server_config *config);
void init_obfs(struct server_env_t *env, const char *protocol, const char *obfs);

#endif // defined(__SSR_CIPHER__)
