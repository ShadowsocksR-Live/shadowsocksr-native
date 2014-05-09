/* -*- coding: utf-8 -*-
 * ----------------------------------------------------------------------
 * Copyright © 2011-2012, RedJack, LLC.
 * All rights reserved.
 *
 * Please see the COPYING file in this distribution for license
 * details.
 * ----------------------------------------------------------------------
 */

#ifndef LIBCORK_CORE_ALLOCATOR_H
#define LIBCORK_CORE_ALLOCATOR_H

#include <stdlib.h>

#include <libcork/core/api.h>
#include <libcork/core/attributes.h>
#include <libcork/core/error.h>
#include <libcork/core/types.h>


/*-----------------------------------------------------------------------
 * Recoverable
 */

#define cork_xmalloc  malloc
#define cork_xcalloc  calloc
#define cork_xfree    free

#if CORK_HAVE_REALLOCF
#define cork_xrealloc  reallocf
#else
CORK_API void *
cork_xrealloc(void *ptr, size_t new_size) CORK_ATTR_MALLOC;
#endif

/* type-based macros */
#define cork_xnew(type)  ((type *) cork_xmalloc(sizeof(type)))

/* string-related functions */

CORK_API const char *
cork_xstrdup(const char *str);

CORK_API const char *
cork_xstrndup(const char *str, size_t size);

CORK_API void
cork_strfree(const char *str);


/*-----------------------------------------------------------------------
 * Abort on failure
 */

CORK_API void *
cork_malloc(size_t size) CORK_ATTR_MALLOC;

CORK_API void *
cork_calloc(size_t count, size_t size) CORK_ATTR_MALLOC;

CORK_API void *
cork_realloc(void *ptr, size_t new_size) CORK_ATTR_MALLOC;

CORK_API const char *
cork_strdup(const char *src) CORK_ATTR_MALLOC;

CORK_API const char *
cork_strndup(const char *src, size_t size) CORK_ATTR_MALLOC;

#define cork_new(type) \
    cork_malloc(sizeof(type))


#endif /* LIBCORK_CORE_ALLOCATOR_H */
