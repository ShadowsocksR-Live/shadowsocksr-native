/*
 * shadowsocks.h - Header files of library interfaces
 *
 * Copyright (C) 2013 - 2014, Max Lv <max.c.lv@gmail.com>
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
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _SHADOWSOCKS_H
#define _SHADOWSOCKS_H

typedef struct {
    char *server;         // server hostname or ip
    char *method;         // encryption method
    char *passwd;         // password of server
    char *config;         // file path to config
    char *acl;            // file path to acl
    int server_port;      // port number of server
    int local_port;       // port number of local
    int timeout;          // connection timeout
    int fast_open;        // tcp fast open
    int verbose;          // verbose mode
} profile_t;

// create and start a shadowsocks service,
// if success, return the pid.
// if not, return -1
int create_ss_service (profile_t profile, char *log_file);

#endif // _SHADOWSOCKS_H
