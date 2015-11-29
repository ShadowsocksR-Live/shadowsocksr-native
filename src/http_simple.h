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

#ifndef _HTTP_SIMPLE_H
#define _HTTP_SIMPLE_H

obfs * http_simple_new_obfs();
void http_simple_dispose(obfs *self);

int http_simple_client_encode(obfs *self, char **pencryptdata, int datalength, ssize_t* capacity);
int http_simple_client_decode(obfs *self, char **pencryptdata, int datalength, ssize_t* capacity, int *needsendback);

#endif // _HTTP_SIMPLE_H
