/* -*- coding: utf-8 -*-
 * ----------------------------------------------------------------------
 * Copyright © 2012, RedJack, LLC.
 * All rights reserved.
 *
 * Please see the COPYING file in this distribution for license
 * details.
 * ----------------------------------------------------------------------
 */

#ifndef LIBCORK_THREADS_ATOMICS_H
#define LIBCORK_THREADS_ATOMICS_H

#include <libcork/config.h>
#include <libcork/core/types.h>

/*-----------------------------------------------------------------------
 * GCC intrinsics
 */

/* Ideally we can use GCC's intrinsics to define everything */
#if defined(CORK_CONFIG_HAVE_GCC_ATOMICS)

#define cork_int_atomic_add        __sync_add_and_fetch
#define cork_uint_atomic_add       __sync_add_and_fetch
#define cork_size_atomic_add       __sync_add_and_fetch
#define cork_int_atomic_pre_add    __sync_fetch_and_add
#define cork_uint_atomic_pre_add   __sync_fetch_and_add
#define cork_size_atomic_pre_add   __sync_fetch_and_add
#define cork_int_atomic_sub        __sync_sub_and_fetch
#define cork_uint_atomic_sub       __sync_sub_and_fetch
#define cork_size_atomic_sub       __sync_sub_and_fetch
#define cork_int_atomic_pre_sub    __sync_fetch_and_sub
#define cork_uint_atomic_pre_sub   __sync_fetch_and_sub
#define cork_size_atomic_pre_sub   __sync_fetch_and_sub
#define cork_int_cas               __sync_val_compare_and_swap
#define cork_uint_cas              __sync_val_compare_and_swap
#define cork_size_cas              __sync_val_compare_and_swap
#define cork_ptr_cas               __sync_val_compare_and_swap


/*-----------------------------------------------------------------------
 * End of atomic implementations
 */
#elif defined(_WIN32) && defined(_MSC_VER)
#include <Windows.h>
//
// http://www.cnblogs.com/lvdongjie/p/4452256.html
// http://blog.csdn.net/markl22222/article/details/10474175
//
static inline LONG __sync_val_compare_and_swap(LONG volatile * Destination, LONG Comperand, LONG ExChange) {
    return InterlockedCompareExchange(Destination, ExChange, Comperand);
}

static inline void * __sync_ptr_compare_and_swap(void * volatile * Destination, void *Comperand, void *ExChange) {
    return InterlockedCompareExchangePointer(Destination, ExChange, Comperand);
}

#if defined(_MSC_VER) && (_MSC_VER < 1800)
#if !defined(InterlockedAdd)
#define InterlockedAdd InterlockedExchangeAdd
#endif // !defined(InterlockedAdd)
#endif // defined(_MSC_VER) && (_MSC_VER < 1800)

#define cork_int_atomic_add        InterlockedAdd
#define cork_uint_atomic_add       InterlockedAdd
#define cork_size_atomic_add       InterlockedAdd
#define cork_int_atomic_pre_add    InterlockedExchangeAdd
#define cork_uint_atomic_pre_add   InterlockedExchangeAdd
#define cork_size_atomic_pre_add   InterlockedExchangeAdd
#define cork_int_atomic_sub        InterlockedDecrement
#define cork_uint_atomic_sub       InterlockedDecrement
#define cork_size_atomic_sub       InterlockedDecrement
#define cork_int_atomic_pre_sub    InterlockedDecrement_
#define cork_uint_atomic_pre_sub   InterlockedDecrement_
#define cork_size_atomic_pre_sub   InterlockedDecrement_
#define cork_int_cas               __sync_val_compare_and_swap
#define cork_uint_cas              __sync_val_compare_and_swap
#define cork_size_cas              __sync_val_compare_and_swap
#define cork_ptr_cas               __sync_ptr_compare_and_swap

#else
#error "No atomics implementation!"
#endif


#endif /* LIBCORK_THREADS_ATOMICS_H */
