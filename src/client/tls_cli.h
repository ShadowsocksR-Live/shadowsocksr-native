#ifndef __TLS_CLI_H__
#define __TLS_CLI_H__ 1

struct tunnel_ctx;
struct server_config;

void tls_client_launch(struct tunnel_ctx *tunnel, struct server_config *config);
void tls_client_shutdown(struct tunnel_ctx *tunnel);

#endif // __TLS_CLI_H__
