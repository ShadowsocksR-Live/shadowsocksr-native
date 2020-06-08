#ifndef __TLS_CLI_H__
#define __TLS_CLI_H__ 1

#include <uv.h>

struct tunnel_ctx;
struct server_config;
struct tls_cli_ctx;

struct tls_cli_ctx* tls_client_launch(struct tunnel_ctx *tunnel, struct server_config *config);

typedef void (*tls_cli_tcp_conn_cb)(struct tls_cli_ctx *cli, void *p);
void tls_client_set_tcp_connect_callback(struct tls_cli_ctx *cli, tls_cli_tcp_conn_cb cb, void *p);

uv_os_sock_t tls_client_get_tcp_fd(const struct tls_cli_ctx *cli);

void tls_client_shutdown(struct tunnel_ctx *tunnel);

#endif // __TLS_CLI_H__
