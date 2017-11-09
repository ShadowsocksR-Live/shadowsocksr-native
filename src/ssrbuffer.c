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
#include "ssrbuffer.h"

struct buffer_t * buffer_alloc(size_t capacity) {
    struct buffer_t *ptr = calloc(1, sizeof(struct buffer_t));
    ptr->buffer = calloc(capacity, sizeof(char));
    ptr->capacity = capacity;
    return ptr;
}

struct buffer_t * buffer_clone(struct buffer_t *ptr) {
    if (ptr == NULL) {
        return NULL;
    }
    struct buffer_t *result = buffer_alloc(ptr->capacity);
    result->len = ptr->len;
    memcpy(result->buffer, ptr->buffer, ptr->len);
    return result;
}

int buffer_realloc(struct buffer_t *ptr, size_t capacity) {
    if (ptr == NULL) {
        return -1;
    }
    size_t real_capacity = max(capacity, ptr->capacity);
    if (ptr->capacity < real_capacity) {
        ptr->buffer = realloc(ptr->buffer, real_capacity);
        ptr->capacity = real_capacity;
    }
    return (int)real_capacity;
}

void buffer_free(struct buffer_t *ptr) {
    if (ptr == NULL) {
        return;
    }
    ptr->len = 0;
    ptr->capacity = 0;
    if (ptr->buffer != NULL) {
        free(ptr->buffer);
    }
    free(ptr);
}
