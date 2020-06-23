#ifndef __TLS_CLI_H__
#define __TLS_CLI_H__ 1

#include <stdbool.h>
#include <uv.h>

#include "ref_count_def.h"

struct tls_cli_ctx;

uv_os_sock_t tls_client_get_tcp_fd(const struct tls_cli_ctx* cli);

bool tls_cli_is_closing(struct tls_cli_ctx* ctx);

REF_COUNT_ADD_REF_DECL(tls_cli_ctx); // tls_cli_ctx_add_ref
REF_COUNT_RELEASE_DECL(tls_cli_ctx); // tls_cli_ctx_release

struct tls_cli_ctx* tls_client_launch(uv_loop_t* loop, const char* domain, const char* ip_addr, int port, uint64_t timeout_msec);

void tls_client_send_data(struct tls_cli_ctx* ctx, const uint8_t* data, size_t size);

typedef void (*tls_cli_on_shutting_down_cb)(struct tls_cli_ctx* ctx, void* p);
void tls_client_shutdown(struct tls_cli_ctx* ctx, tls_cli_on_shutting_down_cb cb, void* p);

typedef void (*tls_cli_tcp_conn_cb)(struct tls_cli_ctx* cli, void* p);
void tls_client_set_tcp_connect_callback(struct tls_cli_ctx* cli, tls_cli_tcp_conn_cb cb, void* p);

typedef void (*tls_cli_on_connection_established_cb)(struct tls_cli_ctx* tls_cli, int status, void* p);
void tls_cli_set_on_connection_established_callback(struct tls_cli_ctx* tls_cli, tls_cli_on_connection_established_cb cb, void* p);

typedef void (*tls_cli_on_write_done_cb)(struct tls_cli_ctx* tls_cli, int status, void* p);
void tls_cli_set_on_write_done_callback(struct tls_cli_ctx* tls_cli, tls_cli_on_write_done_cb cb, void* p);

typedef void (*tls_cli_on_data_received_cb)(struct tls_cli_ctx* tls_cli, int status, const uint8_t* data, size_t size, void* p);
void tls_cli_set_on_data_received_callback(struct tls_cli_ctx* tls_cli, tls_cli_on_data_received_cb cb, void* p);

#endif // __TLS_CLI_H__
