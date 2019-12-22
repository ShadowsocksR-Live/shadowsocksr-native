/*
 * udprelay.h - Define UDP relay's buffers and callbacks
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _UDPRELAY_H
#define _UDPRELAY_H

#include <uv.h>

struct ss_host_port;
struct udp_listener_ctx_t;
struct cipher_env_t;
union sockaddr_universal;
struct buffer_t;

struct udp_listener_ctx_t * udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
#ifdef MODULE_LOCAL
    const union sockaddr_universal *remote_addr,
    const struct ss_host_port *tunnel_addr,
#endif
    int mtu, int timeout, struct cipher_env_t *cipher_env,
    const char *protocol, const char *protocol_param);

void udprelay_shutdown(struct udp_listener_ctx_t *server_ctx);

typedef void (*udp_on_recv_data_callback)(struct udp_listener_ctx_t *udp_ctx, const union sockaddr_universal *src_addr, const struct buffer_t *data);
void udp_relay_set_udp_on_recv_data_callback(struct udp_listener_ctx_t *udp_ctx, udp_on_recv_data_callback callback);
uv_loop_t * udp_relay_context_get_loop(struct udp_listener_ctx_t *udp_ctx);

#endif // _UDPRELAY_H
