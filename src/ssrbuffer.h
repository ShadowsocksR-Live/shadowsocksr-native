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
#include <stddef.h>

#if __MEM_CHECK__
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif // __MEM_CHECK__

struct buffer_t {
    size_t len;
    size_t capacity;
    uint8_t *buffer;
    int ref_count;
};

#define BUFFER_CONSTANT_INSTANCE(ptrName, data, data_len) \
    struct buffer_t obj##ptrName = {(size_t)(data_len), (size_t)(data_len), (uint8_t *)(data)}; \
    struct buffer_t *(ptrName) = & obj##ptrName

struct buffer_t * buffer_create(size_t capacity);
struct buffer_t * buffer_create_from(const uint8_t *data, size_t len);
size_t buffer_get_length(const struct buffer_t *ptr);
const uint8_t * buffer_get_data(const struct buffer_t *ptr, size_t *length);
void buffer_add_ref(struct buffer_t *ptr);
void buffer_release(struct buffer_t *ptr);
int buffer_compare(const struct buffer_t *ptr1, const struct buffer_t *ptr2, size_t size);
void buffer_reset(struct buffer_t *ptr);
struct buffer_t * buffer_clone(const struct buffer_t *ptr);
size_t buffer_realloc(struct buffer_t *ptr, size_t capacity);
void buffer_insert(struct buffer_t *ptr, size_t pos, const uint8_t *data, size_t size);
void buffer_insert2(struct buffer_t *ptr, size_t pos, const struct buffer_t *data);
size_t buffer_store(struct buffer_t *ptr, const uint8_t *data, size_t size);
void buffer_replace(struct buffer_t *dst, const struct buffer_t *src);
size_t buffer_concatenate(struct buffer_t *ptr, const uint8_t *data, size_t size);
size_t buffer_concatenate2(struct buffer_t *dst, const struct buffer_t *src);
void buffer_shortened_to(struct buffer_t *ptr, size_t begin, size_t len);

#endif // __SSR_BUFFER_H__
