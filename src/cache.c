/*
 * cache.c - Manage the connection cache for UDPRELAY
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
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

/*
 * Original Author:  Oliver Lorenz (ol), olli@olorenz.org, https://olorenz.org
 * License:  This is licensed under the same terms as uthash itself
 */

#include <errno.h>
#include <stdlib.h>

#include "cache.h"
#include "ssrutils.h"
#include "uthash.h"

#ifdef __MINGW32__
#include "win32.h"
#endif

#if !defined(_WIN32)
#include <sys/time.h>
#endif

ev_tstamp _ev_time(void);

/**
 * A cache entry
 */
struct cache_entry {
    char *key;         /**<The key */
    void *data;        /**<Payload */
    ev_tstamp ts;    /**<Timestamp */
    UT_hash_handle hh; /**<Hash Handle for uthash */
};

/**
 * A cache object
 */
struct cache {
    size_t max_entries;              /**<Amount of entries this cache object can hold */
    struct cache_entry *entries;     /**<Head pointer for uthash */
    void (*free_cb) (void *key, void *element); /**<Callback function to free cache entries */
};

/** Creates a new cache object
 *
 *  @param dst
 *  Where the newly allocated cache object will be stored in
 *
 *  @param capacity
 *  The maximum number of elements this cache object can hold
 *
 *  @return EINVAL if dst is NULL, ENOMEM if calloc fails, 0 otherwise
 */
int
cache_create(struct cache **dst, size_t capacity,
             void (*free_cb)(void *key, void *element))
{
    struct cache *newObj = NULL;

    if (!dst) {
        return EINVAL;
    }

    if ((newObj = (struct cache *) calloc(1, sizeof(*newObj))) == NULL) {
        return ENOMEM;
    }

    newObj->max_entries = capacity;
    newObj->entries     = NULL;
    newObj->free_cb     = free_cb;
    *dst             = newObj;
    return 0;
}

/** Frees an allocated cache object
 *
 *  @param cache
 *  The cache object to free
 *
 *  @param keep_data
 *  Whether to free contained data or just delete references to it
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_delete(struct cache *cache, int keep_data)
{
    struct cache_entry *entry, *tmp;

    if (!cache) {
        return EINVAL;
    }

    if (keep_data) {
        HASH_CLEAR(hh, cache->entries);
    } else {
        HASH_ITER(hh, cache->entries, entry, tmp){
            HASH_DEL(cache->entries, entry);
            if (entry->data != NULL) {
                if (cache->free_cb) {
                    cache->free_cb(entry->key, entry->data);
                } else {
                    safe_free(entry->data);
                }
            }
            safe_free(entry->key);
            safe_free(entry);
        }
    }

    safe_free(cache);
    return 0;
}

/** Clear old cache object
 *
 *  @param cache
 *  The cache object to clear
 *
 *  @param age
 *  Clear only objects older than the age (sec)
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_clear(struct cache *cache, ev_tstamp age)
{
    struct cache_entry *entry, *tmp;
    ev_tstamp now;
    if (!cache) {
        return EINVAL;
    }

    now = _ev_time();

    HASH_ITER(hh, cache->entries, entry, tmp){
        if (now - entry->ts > age) {
            HASH_DEL(cache->entries, entry);
            if (entry->data != NULL) {
                if (cache->free_cb) {
                    cache->free_cb(entry->key, entry->data);
                } else {
                    safe_free(entry->data);
                }
            }
            safe_free(entry->key);
            safe_free(entry);
        }
    }

    return 0;
}

/** Removes a cache entry
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key of the entry to remove
 *
 *  @param key_len
 *  The length of key
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_remove(struct cache *cache, char *key, size_t key_len)
{
    struct cache_entry *tmp;

    if (!cache || !key) {
        return EINVAL;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);

    if (tmp) {
        HASH_DEL(cache->entries, tmp);
        if (tmp->data != NULL) {
            if (cache->free_cb) {
                cache->free_cb(tmp->key, tmp->data);
            } else {
                safe_free(tmp->data);
            }
        }
        safe_free(tmp->key);
        safe_free(tmp);
    }

    return 0;
}

/** Checks if a given key is in the cache
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key to look-up
 *
 *  @param key_len
 *  The length of key
 *
 *  @param result
 *  Where to store the result if key is found.
 *
 *  A warning: Even though result is just a pointer,
 *  you have to call this function with a **ptr,
 *  otherwise this will blow up in your face.
 *
 *  @return EINVAL if cache is NULL, 0 otherwise
 */
int
cache_lookup(struct cache *cache, char *key, size_t key_len, void *result)
{
    struct cache_entry *tmp = NULL;
    char **dirty_hack       = result;

    if (!cache || !key || !result) {
        return EINVAL;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);
    if (tmp) {
        HASH_DELETE(hh, cache->entries, tmp);
        tmp->ts = _ev_time();
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        *dirty_hack = tmp->data;
    } else {
        *dirty_hack = result = NULL;
    }

    return 0;
}

int
cache_key_exist(struct cache *cache, char *key, size_t key_len)
{
    struct cache_entry *tmp = NULL;

    if (!cache || !key) {
        return 0;
    }

    HASH_FIND(hh, cache->entries, key, key_len, tmp);
    if (tmp) {
        HASH_DELETE(hh, cache->entries, tmp);
        tmp->ts = _ev_time();
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        return 1;
    } else {
        return 0;
    }

    return 0;
}

/** Inserts a given <key, value> pair into the cache
 *
 *  @param cache
 *  The cache object
 *
 *  @param key
 *  The key that identifies <value>
 *
 *  @param key_len
 *  The length of key
 *
 *  @param data
 *  Data associated with <key>
 *
 *  @return EINVAL if cache is NULL, ENOMEM if calloc fails, 0 otherwise
 */
int
cache_insert(struct cache *cache, char *key, size_t key_len, void *data)
{
    struct cache_entry *entry     = NULL;
    struct cache_entry *tmp_entry = NULL;

    if (!cache) {
        return EINVAL;
    }

    if ((entry = (struct cache_entry *) calloc(1, sizeof(*entry))) == NULL) {
        return ENOMEM;
    }

    entry->key = (char *) calloc(key_len + 1, sizeof(char));
    memcpy(entry->key, key, key_len);
    entry->key[key_len] = 0;

    entry->data = data;
    entry->ts   = _ev_time();
    HASH_ADD_KEYPTR(hh, cache->entries, entry->key, key_len, entry);

    if (HASH_COUNT(cache->entries) >= cache->max_entries) {
        HASH_ITER(hh, cache->entries, entry, tmp_entry){
            HASH_DELETE(hh, cache->entries, entry);
            if (entry->data != NULL) {
                if (cache->free_cb) {
                    cache->free_cb(entry->key, entry->data);
                } else {
                    safe_free(entry->data);
                }
            }
            safe_free(entry->key);
            safe_free(entry);
            break;
        }
    }

    return 0;
}

#if defined(_WIN32)
#include <Windows.h>

ev_tstamp
_ev_time(void)
{
   FILETIME ft;
   ULARGE_INTEGER ui;

   GetSystemTimeAsFileTime(&ft);
   ui.u.LowPart = ft.dwLowDateTime;
   ui.u.HighPart = ft.dwHighDateTime;

   /* msvc cannot convert ulonglong to double... yes, it is that sucky */
   return (LONGLONG)(ui.QuadPart - 116444736000000000) * 1e-7;
}

#else

ev_tstamp
_ev_time(void)
{
#if EV_USE_REALTIME
    if (expect_true(have_realtime))
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return ts.tv_sec + ts.tv_nsec * 1e-9;
    }
#endif

    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}
#endif
