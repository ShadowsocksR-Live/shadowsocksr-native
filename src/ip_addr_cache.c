#include <time.h>
#include <string.h>
#include <assert.h>

#include "ip_addr_cache.h"
#include "cstl_lib.h"
#include "sockaddr_universal.h"

struct ip_addr_cache {
    struct cstl_map *resolved_ips;
    clock_t expire_interval;
};

struct address_timestamp {
    union sockaddr_universal address;
    clock_t timestamp;
};

static int compare_key(const void *left, const void *right) {
    char *l = *(char **)left;
    char *r = *(char **)right;
    return strcmp(l, r);
}

static void destroy_object(void *obj) {
    if (obj) {
        void *str = *((void **)obj);
        if (str) {
            free(str);
        }
    }
}

struct ip_addr_cache * ip_addr_cache_create(size_t expire_interval_seconds) {
    struct ip_addr_cache *addr_cache = NULL;
    if (expire_interval_seconds < IP_CACHE_EXPIRE_INTERVAL_MIN) {
        expire_interval_seconds = IP_CACHE_EXPIRE_INTERVAL_MIN;
    }
    addr_cache = (struct ip_addr_cache *) calloc(1, sizeof(*addr_cache));
    addr_cache->resolved_ips = cstl_map_new(compare_key, destroy_object, destroy_object);
    addr_cache->expire_interval = (clock_t)(expire_interval_seconds * CLOCKS_PER_SEC);

    return addr_cache;
}

void ip_addr_cache_add_address(struct ip_addr_cache *addr_cache, const char *host, const union sockaddr_universal *address) {
    if (cstl_map_exists(addr_cache->resolved_ips, &host) == cstl_false) {
        char *key = strdup(host);
        struct address_timestamp *addr =
            (struct address_timestamp *)calloc(1, sizeof(struct address_timestamp));
        addr->address = *address;
        addr->timestamp = clock();
        cstl_map_insert(addr_cache->resolved_ips, &key, sizeof(char*), &addr, sizeof(struct address_timestamp*));
    } else {
        assert(!"the item have exist!");
    }
}

void ip_addr_cache_remove_address(struct ip_addr_cache* addr_cache, const char* host) {
    if (addr_cache == NULL || host == NULL) {
        return;
    }
    if (cstl_map_exists(addr_cache->resolved_ips, &host) == cstl_true) {
        if (cstl_map_remove(addr_cache->resolved_ips, &host) != CSTL_ERROR_SUCCESS) {
            assert(!"remove the item failed!");
        }
    } else {
        assert(!"the item not exist!");
    }
}

void expire_ip_remove_cb(struct cstl_map *map, const void *key, const void *value, cstl_bool *stop, void *p) {
    struct ip_addr_cache *addr_cache = (struct ip_addr_cache *)p;
    struct address_timestamp **addr = (struct address_timestamp **)value;
    if (addr && *addr) {
        if ((clock() - (*addr)->timestamp) > addr_cache->expire_interval) {
            cstl_map_remove(map, key);
        }
    }
    (void)stop;
}

bool ip_addr_cache_is_address_exist(struct ip_addr_cache *addr_cache, const char *host) {
    if (addr_cache==NULL || host==NULL) {
        return false;
    }
    return cstl_map_find(addr_cache->resolved_ips, &host) != NULL;
}

union sockaddr_universal * ip_addr_cache_retrieve_address(struct ip_addr_cache *addr_cache, const char *host, void*(*allocator)(size_t)) {
    struct address_timestamp **addr = NULL;
    union sockaddr_universal *target = NULL;
    do {
        if (addr_cache==NULL || host==NULL || allocator==NULL) {
            break;
        }
        addr = (struct address_timestamp **) cstl_map_find(addr_cache->resolved_ips, &host);
        if (addr == NULL || *addr == NULL) {
            break;
        }
        if ((clock() - (*addr)->timestamp) > addr_cache->expire_interval) {
            // once a ip expired, clear the full ip cache map.
            cstl_map_traverse(addr_cache->resolved_ips, &expire_ip_remove_cb, addr_cache);
            break;
        }
        target = (union sockaddr_universal *) allocator(sizeof(*target));
        if (target == NULL) {
            break;
        }
        *target = (*addr)->address;
    } while (false);
    return target;
}

void ip_addr_cache_destroy(struct ip_addr_cache *addr_cache) {
    cstl_map_delete(addr_cache->resolved_ips);
    free(addr_cache);
}

