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
struct client_ssrot_udp_listener_ctx;
struct cipher_env_t;
union sockaddr_universal;
struct socks5_address;
struct buffer_t;
struct udp_remote_ctx_t;

int udp_create_listener(const char *host, uint16_t port, uv_loop_t *loop, uv_udp_t *udp);

typedef void(*udp_remote_data_arrived_callback)(struct udp_remote_ctx_t *remote_ctx, const uint8_t*data, size_t len, void*p);
struct udp_remote_ctx_t * udp_remote_launch_begin(uv_loop_t* loop, uint64_t timeout, const struct socks5_address *dst_addr);
void udp_remote_set_data_arrived_callback(struct udp_remote_ctx_t *ctx, udp_remote_data_arrived_callback callback, void*p);
void udp_remote_send_data(struct udp_remote_ctx_t *remote_ctx, const uint8_t*data, size_t len);
bool udp_remote_is_alive(struct udp_remote_ctx_t *ctx);
typedef void(*udp_remote_dying_callback)(struct udp_remote_ctx_t *ctx, void*p);
void udp_remote_set_dying_callback(struct udp_remote_ctx_t *ctx, udp_remote_dying_callback callback, void*p);
void udp_remote_destroy(struct udp_remote_ctx_t *ctx);

struct client_ssrot_udp_listener_ctx *
client_ssrot_udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
    const union sockaddr_universal *remote_addr);

void client_ssrot_udprelay_shutdown(struct client_ssrot_udp_listener_ctx *server_ctx);

typedef void (*udp_on_recv_data_callback)(struct client_ssrot_udp_listener_ctx *udp_ctx, const union sockaddr_universal *src_addr, const struct buffer_t *data, void*p);
void udp_relay_set_udp_on_recv_data_callback(struct client_ssrot_udp_listener_ctx *udp_ctx, udp_on_recv_data_callback callback, void*p);
uv_loop_t * udp_relay_context_get_loop(struct client_ssrot_udp_listener_ctx *udp_ctx);
void udp_relay_send_data(struct client_ssrot_udp_listener_ctx* udp_ctx, union sockaddr_universal* addr, const uint8_t* data, size_t len);

void udp_uv_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void udp_uv_release_buffer(uv_buf_t *buf);

size_t
udprelay_parse_header(const uint8_t *buf, size_t buf_len,
    char *host, char *port, struct sockaddr_storage *storage);
char * get_addr_str(const struct sockaddr *sa, char* buf, size_t buf_len);


struct client_udp_listener_ctx;

struct client_udp_listener_ctx *
client_udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
    const union sockaddr_universal *remote_addr, struct cipher_env_t *cipher_env,
    int mtu, int timeout,
    const char *protocol, const char *protocol_param);
void client_udprelay_shutdown(struct client_udp_listener_ctx *listener_ctx);


struct server_udp_listener_ctx;

struct server_udp_listener_ctx *
server_udprelay_begin(uv_loop_t *loop, const char *server_host, uint16_t server_port,
    struct cipher_env_t *cipher_env,
    int mtu, int timeout,
    const char *protocol, const char *protocol_param);
void server_udprelay_shutdown(struct server_udp_listener_ctx *listener_ctx);

#endif // _UDPRELAY_H
