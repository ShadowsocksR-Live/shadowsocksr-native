/* 
 * Original Author:  Oliver Lorenz (ol), olli@olorenz.org, https://olorenz.org
 * License:  This is licensed under the same terms as uthash itself
 */

#ifndef _CACHE_
#define _CACHE_

struct client_cache;

extern int client_cache_create(struct foo_cache **dst, const size_t capacity,
			    void (*free_cb) (void *element));
extern int client_cache_delete(struct foo_cache *cache, int keep_data);
extern int client_cache_lookup(struct foo_cache *cache, char *key, void *result);
extern int client_cache_insert(struct foo_cache *cache, char *key, void *data);

#endif
