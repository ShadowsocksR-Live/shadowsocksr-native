/*
 * ssrbuffer.c - buffer interface implement.
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "ssrbuffer.h"

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

struct buffer_t {
    size_t len;
    size_t capacity;
    uint8_t *buffer;
    int ref_count;
};

void check_memory_content(struct buffer_t *buf) {
#if __MEM_CHECK__
    static const char data[] = "\xE7\x3C\x73\xA6\x66\x43\x28\x67\xAF\xD3\x5C\xE2\x70\x80\x0D\xD7";
    if (buf && buf->len >= strlen(data)) {
        if (memcmp(buf->buffer, data, strlen(data)) == 0) {
            // _CrtDbgBreak();
        }
    }
#endif // __MEM_CHECK__
    (void)buf;
}

#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

static size_t _memory_size_internal(void *ptr) {
    if (ptr == NULL) {
        return 0;
    }
#if defined(_WIN32) && defined(_MSC_VER)
    return _msize(ptr);
#elif defined(__APPLE__)
    return malloc_size(ptr);
#else
    return malloc_usable_size(ptr); // Linux and __MINGW32__
#endif
}

static void mem_alloc_size_verify(size_t expected_size, void* ptr) {
    size_t allocated_size = _memory_size_internal(ptr);
    const char* fmt = ">>>> memory panic of expected size = %d and allocated size = %d in OS %s <<<<\n";
#if defined(__mips)
    if (allocated_size < expected_size) {
        size_t delta = expected_size - allocated_size;
        printf(fmt, (int)expected_size, (int)allocated_size, "__mips");
        allocated_size += delta; // FIXME: it is a strange bug from malloc_usable_size.
    }
#endif
    if (allocated_size < expected_size) {
        printf(fmt, (int)expected_size, (int)allocated_size, "");
        assert(0);
    }
}

struct buffer_t * buffer_create(size_t capacity) {
    struct buffer_t *ptr = (struct buffer_t *) calloc(1, sizeof(struct buffer_t));
    assert(ptr);
    if (ptr == NULL) {
        return NULL;
    }
    ptr->buffer = (uint8_t *) calloc(capacity, sizeof(uint8_t));
    if (ptr->buffer == NULL) {
        free(ptr);
        return NULL;
    }
    ptr->capacity = capacity;
    ptr->ref_count = 1;
    mem_alloc_size_verify(capacity, ptr->buffer);
    return ptr;
}

void buffer_add_ref(struct buffer_t *ptr) {
    if (ptr) {
        ptr->ref_count++;
    }
}

struct buffer_t * buffer_create_from(const uint8_t *data, size_t len) {
    struct buffer_t *result = buffer_create(max(1, len) * 2);
    buffer_store(result, data, len);
    return result;
}

size_t buffer_get_length(const struct buffer_t *ptr) {
    return ptr ? ptr->len : 0;
}

const uint8_t * buffer_get_data(const struct buffer_t *ptr, size_t *length) {
    if (length) {
        *length = buffer_get_length(ptr);
    }
    return ptr ? ptr->buffer : NULL;
}

size_t buffer_get_capacity(const struct buffer_t *ptr) {
    return ptr->capacity;
}

int buffer_compare(const struct buffer_t *ptr1, const struct buffer_t *ptr2, size_t size) {
    if (ptr1==NULL && ptr2==NULL) {
        return 0;
    }
    if (ptr1 && ptr2==NULL) {
        return -1;
    }
    if (ptr1==NULL && ptr2) {
        return 1;
    }
    {
        size_t size1 = (size==SIZE_MAX) ? ptr1->len : min(size, ptr1->len);
        size_t size2 = (size==SIZE_MAX) ? ptr2->len : min(size, ptr2->len);
        size_t size0 = min(size1, size2);
        int ret = memcmp(ptr1->buffer, ptr2->buffer, size0);
        return (ret != 0) ? ret : ((size1 == size2) ? 0 : ((size0 == size1) ? 1 : -1));
    }
}

void buffer_reset(struct buffer_t *ptr) {
    if (ptr) {
        ptr->len = 0;
        if (ptr->buffer) {
            memset(ptr->buffer, 0, ptr->capacity);
        }
    }
}

struct buffer_t * buffer_clone(const struct buffer_t *ptr) {
    struct buffer_t *result = NULL;
    if (ptr == NULL) {
        return result;
    }
    result = buffer_create( max(ptr->capacity, ptr->len) );
    result->len = ptr->len;
    memmove(result->buffer, ptr->buffer, ptr->len);
    check_memory_content(result);
    return result;
}

uint8_t * buffer_raw_clone(const struct buffer_t *orig, void*(*allocator)(size_t), size_t *len, size_t *capacity) {
    uint8_t *p = NULL;
    if (orig == NULL || allocator == NULL) {
        return NULL;
    }
    p = (uint8_t*) allocator(orig->capacity);
    if (p == NULL) {
        return NULL;
    }
    memset(p, 0, orig->capacity);
    memmove(p, orig->buffer, orig->len);
    if (len) {
        *len = orig->len;
    }
    if (capacity) {
        *capacity = orig->capacity;
    }
    return p;
}

size_t buffer_realloc(struct buffer_t *ptr, size_t capacity) {
    size_t real_capacity = 0;
    if (ptr == NULL) {
        return real_capacity;
    }
    real_capacity = max(capacity, ptr->capacity);
    if (ptr->capacity < real_capacity) {
        void* old_buf = ptr->buffer;
        ptr->buffer = (uint8_t *) realloc(ptr->buffer, real_capacity);
        if (ptr->buffer == NULL) {
            free(old_buf);
            return 0;
        }
        memset(ptr->buffer + ptr->capacity, 0, real_capacity - ptr->capacity);
        ptr->capacity = real_capacity;
        mem_alloc_size_verify(real_capacity, ptr->buffer);
    }
    return real_capacity;
}

size_t buffer_store(struct buffer_t *ptr, const uint8_t *data, size_t size) {
    size_t result = 0;
    if (ptr==NULL) {
        return result;
    }
    result = buffer_realloc(ptr, size);
    if (ptr->buffer && data && size) {
        memmove(ptr->buffer, data, size);
    }
    ptr->len = size;
    check_memory_content(ptr);
    return min(size, result);
}

void buffer_replace(struct buffer_t *dst, const struct buffer_t *src) {
    if (dst) {
        if (src) {
            buffer_store(dst, src->buffer, src->len);
        } else {
            buffer_reset(dst);
        }
    }
    /*
    if (dst==NULL || src==NULL) { return; }
    buffer_store(dst, src->buffer, src->len);
    */
}

void buffer_insert(struct buffer_t *ptr, size_t pos, const uint8_t *data, size_t size) {
    if (ptr==NULL || data==NULL || size==0) {
        return;
    }
    if (pos > ptr->len) {
        pos = ptr->len;
    }
    buffer_realloc(ptr, ptr->len + size);
    memmove(ptr->buffer + pos + size, ptr->buffer + pos, ptr->len - pos);
    memmove(ptr->buffer + pos, data, size);
    ptr->len += size;
}

void buffer_insert2(struct buffer_t *ptr, size_t pos, const struct buffer_t *data) {
    if (ptr==NULL || data==NULL) {
        return;
    }
    buffer_insert(ptr, pos, data->buffer, data->len);
}

size_t buffer_concatenate(struct buffer_t *ptr, const uint8_t *data, size_t size) {
    size_t result = buffer_realloc(ptr, ptr->len + size);
    memmove(ptr->buffer + ptr->len, data, size);
    ptr->len += size;
    check_memory_content(ptr);
    return min(ptr->len, result);
}

size_t buffer_concatenate2(struct buffer_t *dst, const struct buffer_t *src) {
    if (dst==NULL || src==NULL) { return 0; }
    return buffer_concatenate(dst, src->buffer, src->len);
}

void buffer_shortened_to(struct buffer_t *ptr, size_t begin, size_t len) {
    if (ptr && (begin <= ptr->len) && (len <= (ptr->len - begin))) {
        if (begin != 0) {
            memmove(ptr->buffer, ptr->buffer + begin, len);
        }
        ptr->buffer[len] = 0;
        ptr->len = len;
    }
    check_memory_content(ptr);
}

void buffer_release(struct buffer_t *ptr) {
    if (ptr == NULL) {
        return;
    }
    ptr->ref_count--;
    if (ptr->ref_count > 0) {
        return;
    }
    if (ptr->buffer != NULL) {
        mem_alloc_size_verify(ptr->capacity, ptr->buffer);
        free(ptr->buffer);
    }
    free(ptr);
}

uint8_t * mem_insert(const uint8_t *src, size_t src_size, size_t pos, const uint8_t *chunk, size_t chunk_size, void*(*allocator)(size_t), size_t *total_size) {
    uint8_t *result;
    size_t total = 0;
    if (allocator==NULL) {
        return NULL;
    }
    if (src == NULL) {
        src_size = 0;
    }
    if (pos > src_size) {
        pos = src_size;
    }
    if (chunk == NULL) {
        chunk_size = 0;
    }
    total = src_size + chunk_size;
    if (total_size) {
        *total_size = total;
    }
    if (total == 0) {
        return NULL;
    }
    result = (uint8_t *) allocator(total + 1);
    if (result == NULL) {
        return NULL;
    }
    memset(result, 0, (total + 1));

    memmove(result, src, pos);
    memmove(result + pos + chunk_size, src + pos, src_size - pos);
    memmove(result + pos, chunk, chunk_size);

    return result;
}
