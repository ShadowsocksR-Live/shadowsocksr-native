#include <assert.h>
#include <string.h>
#include "traffic_audit.h"
#include "ssr_executive.h"

static int obj_cmp(const void* left, const void* right) {
    char* l = *(char**)left;
    char* r = *(char**)right;
    return strcmp(l, r);
}

static void obj_destroy(void* obj) {
    if (obj) {
        void* str = *((void**)obj);
        if (str) {
            free(str);
        }
    }
}

struct cstl_map* container_create(void) {
    return obj_map_create(obj_cmp, obj_destroy, obj_destroy);
}

void container_destroy(struct cstl_map* container) {
    obj_map_destroy(container);
}

void container_add_user_tag(struct cstl_map* container, const char* user_tag) {
    char* u;
    struct user_traffic* t;

    assert(container);
    assert(user_tag);

    if (obj_map_exists(container, user_tag)) {
        return;
    };

    u = strdup(user_tag);
    assert(u);

    t = (struct user_traffic*)calloc(1, sizeof(*t));
    assert(t);

    strncpy(t->user_tag, user_tag, sizeof(t->user_tag));

    obj_map_add(container, &u, sizeof(void*), &t, sizeof(void*));
}

void container_remove_user_tag(struct cstl_map* container, const char* user_tag) {
    assert(container);
    assert(user_tag);
    obj_map_remove(container, user_tag);
}
