/*
 * auth.h - Define shadowsocks server's buffers and callbacks
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

#ifndef _AUTH_H
#define _AUTH_H

void * auth_simple_init_data();
obfs * auth_simple_new_obfs();
void auth_simple_dispose(obfs *self);

int auth_simple_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);
int auth_simple_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);


int auth_sha1_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);
int auth_sha1_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);

int auth_sha1_v2_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);
int auth_sha1_v2_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);

int auth_sha1_v4_client_pre_encrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);
int auth_sha1_v4_client_post_decrypt(obfs *self, char **pplaindata, int datalength, size_t* capacity);


#endif // _AUTH_H
