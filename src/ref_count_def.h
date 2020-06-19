#ifndef __REF_COUNT_H__
#define __REF_COUNT_H__ 1

#include <assert.h>

#define REF_COUNT_MEMBER \
    int ref_count

#define REF_COUNT_ADD_REF_DECL(struct_name) \
int struct_name##_add_ref(struct struct_name* struct_name##_ptr)

#define REF_COUNT_RELEASE_DECL(struct_name) \
int struct_name##_release(struct struct_name* struct_name##_ptr)

#define REF_COUNT_ADD_REF_IMPL(struct_name) \
int struct_name##_add_ref(struct struct_name* struct_name##_ptr) { \
    if (struct_name##_ptr) { \
        return (++struct_name##_ptr->ref_count); \
    } \
    return 0; \
}

#define REF_COUNT_RELEASE_IMPL(struct_name, internal_free_fn) \
int struct_name##_release(struct struct_name* struct_name##_ptr) { \
    int ref__count = 0; \
    if (struct_name##_ptr) { \
        ref__count = (--struct_name##_ptr->ref_count); \
        if (ref__count <= 0) { \
            assert(ref__count == 0); \
            internal_free_fn(struct_name##_ptr); \
        } \
    } \
    return ref__count; \
}

#endif // __REF_COUNT_H__
