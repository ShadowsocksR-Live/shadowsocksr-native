/*
 * http_simple.h - Define shadowsocks server's buffers and callbacks
 *
 * Copyright (C) 2015 - 2015, Break Wa11 <mmgac001@gmail.com>
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

#ifndef _TLS1_2_TICKET_H
#define _TLS1_2_TICKET_H

void * tls12_ticket_auth_init_data();
obfs * tls12_ticket_auth_new_obfs();
void tls12_ticket_auth_dispose(obfs *self);

int tls12_ticket_auth_client_encode(obfs *self, char **pencryptdata, int datalength, size_t* capacity);
int tls12_ticket_auth_client_decode(obfs *self, char **pencryptdata, int datalength, size_t* capacity, int *needsendback);

#endif // _TLS1_2_TICKET_H
