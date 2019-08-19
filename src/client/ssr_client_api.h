//
// Created by ssrlive on 4/6/18.
//

#ifndef SHADOWSOCKSR_NATIVE_SSR_CLIENT_API_H
#define SHADOWSOCKSR_NATIVE_SSR_CLIENT_API_H

struct server_config;
struct ssr_client_state;

/* listener.c */
int ssr_run_loop_begin(struct server_config *cf, void(*feedback_state)(struct ssr_client_state *state, void *p), void *p);
void ssr_run_loop_shutdown(struct ssr_client_state *state);
int ssr_get_listen_socket_fd(struct ssr_client_state *state);

void set_app_name(const char *name);
void set_dump_info_callback(void(*callback)(const char *info, void *p), void *p);

#endif //SHADOWSOCKSR_NATIVE_SSR_CLIENT_API_H
