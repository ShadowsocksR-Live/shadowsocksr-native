/* -*- coding: utf-8 -*-
 * ----------------------------------------------------------------------
 * Copyright © 2012, RedJack, LLC.
 * All rights reserved.
 *
 * Please see the COPYING file in this distribution for license
 * details.
 * ----------------------------------------------------------------------
 */

#ifndef LIBCORK_THREADS_BASICS_H
#define LIBCORK_THREADS_BASICS_H

#include <assert.h>

#include <libcork/core/api.h>
#include <libcork/core/attributes.h>
#include <libcork/threads/atomics.h>


/*-----------------------------------------------------------------------
 * Thread IDs
 */

typedef unsigned int  cork_thread_id;

#define CORK_THREAD_NONE  ((cork_thread_id) 0)

/* Returns a valid ID for any thread — even the main thread and threads that
 * aren't created by libcork. */
CORK_API cork_thread_id
cork_current_thread_get_id(void);


/*-----------------------------------------------------------------------
 * Main functions
 */

struct cork_thread_body {
    int
    (*run)(struct cork_thread_body *self);

    void
    (*free)(struct cork_thread_body *self);
};

#define cork_thread_body_run(tb)  ((tb)->run((tb)))
#define cork_thread_body_free(tb)  ((tb)->free((tb)))


/*-----------------------------------------------------------------------
 * Threads
 */

struct cork_thread;

/* Returns NULL for the main thread, and for any thread not created via
 * cork_thread_new/cork_thread_start. */
CORK_API struct cork_thread *
cork_current_thread_get(void);

CORK_API struct cork_thread *
cork_thread_new(const char *name, struct cork_thread_body *body);

/* Thread must not have been started yet. */
CORK_API void
cork_thread_free(struct cork_thread *thread);

CORK_API const char *
cork_thread_get_name(struct cork_thread *thread);

CORK_API cork_thread_id
cork_thread_get_id(struct cork_thread *thread);

/* Can only be called once per thread.  Thread will automatically be freed when
 * its done. */
CORK_API int
cork_thread_start(struct cork_thread *thread);

/* Can only be called once per thread; must be called after cork_thread_start. */
CORK_API int
cork_thread_join(struct cork_thread *thread);


/*-----------------------------------------------------------------------
 * Executing something once
 */

#if CORK_CONFIG_HAVE_GCC_ASM && (CORK_CONFIG_ARCH_X86 || CORK_CONFIG_ARCH_X64)
#define cork_pause() \
    do { \
        __asm__ __volatile__ ("pause"); \
    } while (0)
#else
#define cork_pause()  do { /* do nothing */ } while (0)
#endif


#define cork_once_barrier(name) \
    static struct { \
        volatile int  barrier; \
        cork_thread_id  initializing_thread; \
    } name##__once;

#define cork_once(name, call) \
    do { \
        if (CORK_LIKELY(name##__once.barrier == 2)) { \
            /* already initialized */ \
        } else { \
            /* Try to claim the ability to perform the initialization */ \
            int  prior_state = cork_int_cas(&name##__once.barrier, 0, 1); \
            if (CORK_LIKELY(prior_state == 0)) { \
                CORK_ATTR_UNUSED int  result; \
                /* we get to initialize */ \
                call; \
                result = cork_int_cas(&name##__once.barrier, 1, 2); \
                assert(result == 1); \
            } else { \
                /* someone else is initializing, spin/wait until done */ \
                while (name##__once.barrier != 2) { cork_pause(); } \
            } \
        } \
    } while (0)

#define cork_once_recursive(name, call) \
    do { \
        if (CORK_LIKELY(name##__once.barrier == 2)) { \
            /* already initialized */ \
        } else { \
            /* Try to claim the ability to perform the initialization */ \
            int  prior_state = cork_int_cas(&name##__once.barrier, 0, 1); \
            if (CORK_LIKELY(prior_state == 0)) { \
                CORK_ATTR_UNUSED int  result; \
                /* we get to initialize */ \
                name##__once.initializing_thread = \
                    cork_current_thread_get_id(); \
                call; \
                result = cork_int_cas(&name##__once.barrier, 1, 2); \
                assert(result == 1); \
            } else { \
                /* someone else is initializing, is it us? */ \
                if (name##__once.initializing_thread == \
                    cork_current_thread_get_id()) { \
                    /* yep, fall through to let our recursion continue */ \
                } else { \
                    /* nope; wait for the initialization to finish */ \
                    while (name##__once.barrier != 2) { cork_pause(); } \
                } \
            } \
        } \
    } while (0)


/*-----------------------------------------------------------------------
 * Thread-local storage
 */

/* Prefer, in order:
 *
 * 1) __thread storage class
 * 2) pthread_key_t
 */

#if CORK_CONFIG_HAVE_THREAD_STORAGE_CLASS
#define cork_tls(TYPE, NAME) \
static __thread TYPE  NAME##__tls; \
\
static TYPE * \
NAME##_get(void) \
{ \
    return &NAME##__tls; \
}

#elif CORK_HAVE_PTHREADS
#include <stdlib.h>
#include <pthread.h>

#include <libcork/core/allocator.h>

#define cork_tls(TYPE, NAME) \
static pthread_key_t  NAME##__tls_key; \
cork_once_barrier(NAME##__tls_barrier); \
\
static void \
NAME##__tls_destroy(void *vself) \
{ \
    free(vself); \
} \
\
static void \
NAME##__create_key(void) \
{ \
    CORK_ATTR_UNUSED int  rc; \
    rc = pthread_key_create(&NAME##__tls_key, &NAME##__tls_destroy); \
    assert(rc == 0); \
} \
\
static TYPE * \
NAME##_get(void) \
{ \
    TYPE  *self; \
    cork_once(NAME##__tls_barrier, NAME##__create_key()); \
    self = pthread_getspecific(NAME##__tls_key); \
    if (CORK_UNLIKELY(self == NULL)) { \
        self = cork_calloc(1, sizeof(TYPE)); \
        pthread_setspecific(NAME##__tls_key, self); \
    } \
    return self; \
}

#else
#error "No thread-local storage implementation!"
#endif


#endif /* LIBCORK_THREADS_BASICS_H */
