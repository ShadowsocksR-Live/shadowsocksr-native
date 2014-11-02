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
    char *remote_host;    // hostname or ip of remote server
    char *local_addr;     // local ip to bind 
    char *method;         // encryption method
    char *password;       // password of remote server
    char *acl;            // file path to acl
    char *log;            // file path to log
    int remote_port;      // port number of remote server
    int local_port;       // port number of local server
    int timeout;          // connection timeout
    int fast_open;        // enable tcp fast open
    int udp_relay;        // enable udp relay
    int verbose;          // verbose mode
} profile_t;

// create and start a shadowsocks service,
// if success, return the tid.
// if not, return -1
int start_ss_service(profile_t profile);

// stop the current shadowsocks service,
// if blocking set true, this call will be blocked until no events left.
// call this function in blocking mode would take quite long time, depends on
// the timeout you set.
void stop_ss_service(int blocking);

#endif // _SHADOWSOCKS_H
