/*
 * common.h - Provide global definitions
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
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

#ifndef _COMMON_H
#define _COMMON_H

#if defined(_WIN32)
#define PATH_SEPARATOR '\\'
#else
#define PATH_SEPARATOR '/'
#endif

#define CFG_JSON "config.json"

#if defined(WIN32)
#define DEFAULT_CONF_PATH CFG_JSON
#else
#define DEFAULT_CONF_PATH "/etc/ssr-native/" CFG_JSON
#endif // defined(WIN32)

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#if defined(MODULE_TUNNEL) || defined(MODULE_REDIR)
#define MODULE_LOCAL
#endif

//#include <libcork/ds.h>

#include "encrypt.h"
#include "obfs/obfs.h"

#ifndef __weak_ptr
#define __weak_ptr
#endif

#if defined(_LOCAL_H)
struct server_env_t {
    char *hostname;
    char *host;
    int port;
    int udp_port;
    struct sockaddr_storage *addr; // resolved address
    struct sockaddr_storage *addr_udp; // resolved address
    int addr_len;
    int addr_udp_len;

    char *psw; // raw password
    struct cipher_env_t *cipher;

    // SSR
    char *protocol_name; // for logging use only?
    char *obfs_name; // for logging use only?

    char *protocol_param;
    char *obfs_param;

    void *protocol_global;
    void *obfs_global;

    int enable;
    char *id;
    char *group;
    int udp_over_tcp;
};
#endif // defined(_LOCAL_H)

#ifdef ANDROID
int protect_socket(int fd);
int send_traffic_stat(uint64_t tx, uint64_t rx);

extern int log_tx_rx;
extern uint64_t tx;
extern uint64_t rx;
extern uint64_t last;
extern char *prefix;

#endif

/* ASSERT() is for debug checks, VERIFY() for run-time sanity checks.
* DEBUG_VERIFIES is for expensive debug verifies that we only want to
* enable in debug builds but still want type-checked by the compiler
* in release builds.
*/
#if defined(NDEBUG)
# define ASSERT(exp) (void)(exp)
# define VERIFY(exp)   do { if (!(exp)) { abort(); } } while (0)
# define DEBUG_VERIFIES (0)
#else
#include <assert.h>
# define ASSERT(exp)  assert(exp)
# define VERIFY(exp)   assert(exp)
# define DEBUG_VERIFIES (1)
#endif

#define UNREACHABLE() VERIFY(!"Unreachable code reached.")

#if !defined(CONTAINER_OF)
#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))
#endif // !defined(CONTAINER_OF)

#endif // _COMMON_H
