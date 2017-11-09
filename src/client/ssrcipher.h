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
    struct server_env_t *env; // __weak_ptr
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct obfs_t *protocol;
    struct obfs_t *obfs;
};

#define SSR_ERR_MAP(V)                                                         \
  V( 0, ssr_ok,                 "All is OK.")                                  \
  V(-1, ssr_client_decode,      "client decode error.")                        \
  V(-2, ssr_invalid_password,   "invalid password or cipher.")                 \
  V(-3, ssr_client_post_decrypt,"client post decrypt error.")                  \

typedef enum ssr_err {
#define SSR_ERR_GEN(code, name, _) name = code,
    SSR_ERR_MAP(SSR_ERR_GEN)
#undef SSR_ERR_GEN
    ssr_max_errors,
} ssr_err;

const char *ssr_strerror(enum ssr_err err);

struct tunnel_cipher_ctx;
struct buffer_t;

struct server_env_t * ssr_cipher_env_create(struct server_config *config);
void ssr_cipher_env_release(struct server_env_t *env);
struct tunnel_cipher_ctx * tunnel_cipher_create(struct server_env_t *env, const struct buffer_t *init_pkg);
void tunnel_cipher_release(struct tunnel_cipher_ctx *tc);
enum ssr_err tunnel_encrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf);

typedef void(*fn_feedback)(const struct buffer_t *buf, void *ptr);
enum ssr_err tunnel_decrypt(struct tunnel_cipher_ctx *tc, struct buffer_t *buf, fn_feedback feedback, void *ptr);

#endif // defined(__SSR_CIPHER__)
