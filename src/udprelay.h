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
#include <stdbool.h>

struct ss_host_port;
struct udp_listener_ctx_t;
struct cipher_env_t;
union sockaddr_universal;
struct socks5_address;
struct buffer_t;
struct udp_remote_ctx_t;

typedef void(*udp_remote_data_arrived_callback)(struct udp_remote_ctx_t *remote_ctx, const uint8_t*data, size_t len, void*p);
struct udp_remote_ctx_t * udp_remote_launch_begin(uv_loop_t* loop, uint64_t timeout, const struct socks5_address *dst_addr);
void udp_remote_set_data_arrived_callback(struct udp_remote_ctx_t *ctx, udp_remote_data_arrived_callback callback, void*p);
void udp_remote_send_data(struct udp_remote_ctx_t *remote_ctx, const uint8_t*data, size_t len);
bool udp_remote_is_alive(struct udp_remote_ctx_t *ctx);
typedef void(*udp_remote_dying_callback)(struct udp_remote_ctx_t *ctx, void*p);
void udp_remote_set_dying_callback(struct udp_remote_ctx_t *ctx, udp_remote_dying_callback callback, void*p);
void udp_remote_destroy(struct udp_remote_ctx_t *ctx);

struct udp_listener_ctx_t * udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
    const union sockaddr_universal *remote_addr, struct cipher_env_t *cipher_env);

void udprelay_shutdown(struct udp_listener_ctx_t *server_ctx);

typedef void (*udp_on_recv_data_callback)(struct udp_listener_ctx_t *udp_ctx, const union sockaddr_universal *src_addr, const struct buffer_t *data, void*p);
void udp_relay_set_udp_on_recv_data_callback(struct udp_listener_ctx_t *udp_ctx, udp_on_recv_data_callback callback, void*p);
uv_loop_t * udp_relay_context_get_loop(struct udp_listener_ctx_t *udp_ctx);
void udp_relay_send_data(struct udp_listener_ctx_t* udp_ctx, union sockaddr_universal* addr, const uint8_t* data, size_t len);

#endif // _UDPRELAY_H
