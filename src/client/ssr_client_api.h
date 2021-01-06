//
// Created by ssrlive on 4/6/18.
//

#ifndef SHADOWSOCKSR_NATIVE_SSR_CLIENT_API_H
#define SHADOWSOCKSR_NATIVE_SSR_CLIENT_API_H

#include "ssr_extern_def.h"

#include <stdbool.h>
#include "ssr_qr_code.h"
#include "ssr_cipher_names.h"
#include "exe_file_path.h"
#include "dump_info.h"
#include "ssr_executive.h"
#if !defined(_WIN32)
#include "sockaddr_universal.h"
#endif

struct ssr_client_state;

/* listener.c */
int ssr_run_loop_begin(struct server_config *cf, void(*feedback_state)(struct ssr_client_state *state, void *p), void *p);
void ssr_run_loop_shutdown(struct ssr_client_state *state);
int ssr_get_listen_socket_fd(struct ssr_client_state *state);
int ssr_get_client_error_code(struct ssr_client_state *state);
void state_set_force_quit(struct ssr_client_state *state, bool force_quit, int delay_ms);

#endif //SHADOWSOCKSR_NATIVE_SSR_CLIENT_API_H
