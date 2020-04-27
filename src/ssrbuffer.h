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

#if defined(_MSC_VER)
//#define __MEM_CHECK__ 1
#endif

#if __MEM_CHECK__
#if !defined(_CRTDBG_MAP_ALLOC)
#define _CRTDBG_MAP_ALLOC
#endif
#include <stdlib.h>
#include <crtdbg.h>

#define MEM_CHECK_BEGIN() do { _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF ); } while(0)
#define MEM_CHECK_BREAK_ALLOC(x) do { _CrtSetBreakAlloc(x); } while(0)
#define MEM_CHECK_DUMP_LEAKS() do { _CrtDumpMemoryLeaks(); } while(0)

#else

#define MEM_CHECK_BEGIN() do { ; } while(0)
#define MEM_CHECK_BREAK_ALLOC(x) do { (void)x; } while(0)
#define MEM_CHECK_DUMP_LEAKS() do { ; } while(0)

#endif // __MEM_CHECK__

struct buffer_t;

struct buffer_t * buffer_create(size_t capacity);
struct buffer_t * buffer_create_from(const uint8_t *data, size_t len);
size_t buffer_get_length(const struct buffer_t *ptr);
const uint8_t * buffer_get_data(const struct buffer_t *ptr, size_t *length);
size_t buffer_get_capacity(const struct buffer_t *ptr);
void buffer_add_ref(struct buffer_t *ptr);
void buffer_release(struct buffer_t *ptr);
int buffer_compare(const struct buffer_t *ptr1, const struct buffer_t *ptr2, size_t size);
void buffer_reset(struct buffer_t *ptr);
struct buffer_t * buffer_clone(const struct buffer_t *ptr);
uint8_t * buffer_raw_clone(const struct buffer_t *orig, void*(*allocator)(size_t), size_t *len, size_t *capacity);
size_t buffer_realloc(struct buffer_t *ptr, size_t capacity);
void buffer_insert(struct buffer_t *ptr, size_t pos, const uint8_t *data, size_t size);
void buffer_insert2(struct buffer_t *ptr, size_t pos, const struct buffer_t *data);
size_t buffer_store(struct buffer_t *ptr, const uint8_t *data, size_t size);
void buffer_replace(struct buffer_t *dst, const struct buffer_t *src);
size_t buffer_concatenate(struct buffer_t *ptr, const uint8_t *data, size_t size);
size_t buffer_concatenate2(struct buffer_t *dst, const struct buffer_t *src);
void buffer_shortened_to(struct buffer_t *ptr, size_t begin, size_t len);

uint8_t * mem_insert(const uint8_t *src, size_t src_size, size_t pos, const uint8_t *chunk, size_t chunk_size, void*(*allocator)(size_t), size_t *total_size);

#endif // __SSR_BUFFER_H__
