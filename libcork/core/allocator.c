/* -*- coding: utf-8 -*-
 * ----------------------------------------------------------------------
 * Copyright © 2011, RedJack, LLC.
 * All rights reserved.
 *
 * Please see the COPYING file in this distribution for license
 * details.
 * ----------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libcork/core/allocator.h"
#include "libcork/core/attributes.h"
#include "libcork/core/error.h"
#include "libcork/core/types.h"


/*-----------------------------------------------------------------------
 * reallocf
 */

#if !CORK_HAVE_REALLOCF
void *
cork_xrealloc(void *ptr, size_t new_size)
{
    void  *result = realloc(ptr, new_size);
    if (result == NULL) {
        free(ptr);
    }
    return result;
}
#endif


/*-----------------------------------------------------------------------
 * Allocating strings
 */

static inline const char *
strndup_internal(const char *str, size_t len)
{
    size_t  allocated_size = len + sizeof(size_t) + 1;
    size_t  *new_str = malloc(allocated_size);
    if (new_str == NULL) {
        return NULL;
    }

    *new_str = allocated_size;
    char  *dest = (char *) (void *) (new_str + 1);
    strncpy(dest, str, len);
    dest[len] = '\0';
    return dest;
}

const char *
cork_xstrndup(const char *str, size_t len)
{
    return strndup_internal(str, len);
}

const char *
cork_xstrdup(const char *str)
{
    return strndup_internal(str, strlen(str));
}


void
cork_strfree(const char *str)
{
    size_t  *base = ((size_t *) str) - 1;
    free(base);
}


/*-----------------------------------------------------------------------
 * Abort on failure
 */

void *
cork_malloc(size_t size)
{
    void  *result = cork_xmalloc(size);
    if (CORK_UNLIKELY(result == NULL)) {
        abort();
    }
    return result;
}

void *
cork_calloc(size_t count, size_t size)
{
    void  *result = cork_xcalloc(count, size);
    if (CORK_UNLIKELY(result == NULL)) {
        abort();
    }
    return result;
}

void *
cork_realloc(void *ptr, size_t new_size)
{
    void  *result = cork_xrealloc(ptr, new_size);
    if (CORK_UNLIKELY(result == NULL)) {
        abort();
    }
    return result;
}

const char *
cork_strdup(const char *src)
{
    const char  *result = cork_xstrdup(src);
    if (CORK_UNLIKELY(result == NULL)) {
        abort();
    }
    return result;
}

const char *
cork_strndup(const char *src, size_t size)
{
    const char  *result = cork_xstrndup(src, size);
    if (CORK_UNLIKELY(result == NULL)) {
        abort();
    }
    return result;
}
