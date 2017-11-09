/*
 * ssrbuffer.h - buffer interface
 *
 * Copyright (C) 2017 - 2017, ssrlive
 *
 * This file is part of the shadowsocksr-native.
 *
 * shadowsocksr-native is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocksr-native is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __SSR_BUFFER_H__
#define __SSR_BUFFER_H__

#include <stdint.h>

struct buffer_t {
    size_t len;
    size_t capacity;
    char   *buffer;
};

struct buffer_t * buffer_alloc(size_t capacity);
struct buffer_t * buffer_clone(struct buffer_t *ptr);
int buffer_realloc(struct buffer_t *ptr, size_t capacity);
void buffer_free(struct buffer_t *ptr);

#endif // __SSR_BUFFER_H__
