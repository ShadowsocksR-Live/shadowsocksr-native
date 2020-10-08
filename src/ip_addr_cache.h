#if !defined(__IP_ADDR_CACHE_H__)
#define __IP_ADDR_CACHE_H__ 1

#include <stddef.h>
#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define IP_CACHE_EXPIRE_INTERVAL_MIN    (60 * 60)  // 3600 seconds, 1 hour.

struct ip_addr_cache;
union sockaddr_universal;

struct ip_addr_cache * ip_addr_cache_create(size_t expire_interval_seconds);
void ip_addr_cache_add_address(struct ip_addr_cache *addr_cache, const char *host, const union sockaddr_universal *address);
bool ip_addr_cache_is_address_exist(struct ip_addr_cache *addr_cache, const char *host);
void ip_addr_cache_remove_address(struct ip_addr_cache* addr_cache, const char* host);
union sockaddr_universal * ip_addr_cache_retrieve_address(struct ip_addr_cache *addr_cache, const char *host, void*(*allocator)(size_t));
void ip_addr_cache_destroy(struct ip_addr_cache *addr_cache);

#ifdef  __cplusplus
}
#endif

#endif // __IP_ADDR_CACHE_H__

