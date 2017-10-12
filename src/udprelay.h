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
#include <time.h>

#include "encrypt.h"
#include "jconf.h"
#include "obfs/obfs.h"

#ifdef MODULE_REMOTE
#include "resolv.h"
#endif

#include "cache.h"
#include "common.h"

int init_udprelay(uv_loop_t *loop, const char *server_host, const char *server_port,
#ifdef MODULE_LOCAL
    const struct sockaddr *remote_addr, const int remote_addr_len,
    const struct ss_host_port tunnel_addr,
#endif
    int mtu, int timeout, const char *iface, struct cipher_env_t *cipher_env,
    const char *protocol, const char *protocol_param);

void free_udprelay(void);

#endif // _UDPRELAY_H
