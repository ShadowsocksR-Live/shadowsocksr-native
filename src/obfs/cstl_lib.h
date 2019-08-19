/** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **
 *  This file is part of cstl library
 *  Copyright (C) 2011 Avinash Dongre ( dongre.avinash@gmail.com )
 *  Copyright (C) 2018 ssrlive ( ssrlivebox@gmail.com )
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 * 
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 * 
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **/

#ifndef __CSTL_LIB_H__
#define __CSTL_LIB_H__

#include <stdlib.h>

//#include "c_errors.h"
/* ------------------------------------------------------------------------*/
/*                 C O M M O N    E R R O R    C O D E                     */
/* ------------------------------------------------------------------------*/
#define CSTL_ERROR_SUCCESS  0
#define CSTL_ERROR_ERROR    1
#define CSTL_ERROR_MEMORY   2
#define CSTL_ELEMENT_RETURN_ERROR 3
/* ------------------------------------------------------------------------*/
/*         D Y N A M I C    A R R A Y   E R R O R    C O D E S             */
/* ------------------------------------------------------------------------*/
#define CSTL_ARRAY_NOT_INITIALIZED    101
#define CSTL_ARRAY_INDEX_OUT_OF_BOUND 102
#define CSTL_ARRAY_INSERT_FAILED      103

#define CSTL_DEQUE_NOT_INITIALIZED    201
#define CSTL_DEQUE_INDEX_OUT_OF_BOUND 202

#define CSTL_RBTREE_NOT_INITIALIZED   401
#define CSTL_RBTREE_KEY_DUPLICATE     402
#define CSTL_RBTREE_KEY_NOT_FOUND     403

#define CSTL_SET_NOT_INITIALIZED      501
#define CSTL_SET_INVALID_INPUT        502

#define CSTL_MAP_NOT_INITIALIZED      501
#define CSTL_MAP_INVALID_INPUT        502

#define CSTL_SLIST_INSERT_FAILED      601


/* ------------------------------------------------------------------------*/
/*       C O M M O N       D E F I N I T O N S                             */
/* ------------------------------------------------------------------------*/

typedef void (*cstl_destroy)(void*);
typedef int  (*cstl_compare)(const void*, const void*);
typedef void (*cstl_traversal)( void*);

typedef int  cstl_error;
typedef int  cstl_bool;

#define cstl_black           0
#define cstl_red             1
#define cstl_true            1
#define cstl_false           0

/* ------------------------------------------------------------------------*/
/*                            P  A  I   R                                  */
/* ------------------------------------------------------------------------*/

struct cstl_iterator {
    const void * (*next)(struct cstl_iterator *pIterator);
    void (*replace_current_value)(struct cstl_iterator *pIterator, void *new_value, size_t size);
    const void* (*current_key)(struct cstl_iterator *pIterator);
    const void* (*current_value)(struct cstl_iterator *pIterator);
    void* pContainer;
    size_t current_index;
    void* current_element;
};


// #include "c_array.h"
struct cstl_array;

extern struct cstl_array* cstl_array_new ( size_t init_size, cstl_compare fn_c, cstl_destroy fn_d);
extern cstl_error cstl_array_push_back ( struct cstl_array* pArray, void* elem, size_t elem_size);
extern const void * cstl_array_element_at(struct cstl_array* pArray, size_t index);
extern cstl_error cstl_array_insert_at ( struct cstl_array* pArray, size_t index, void* elem, size_t elem_size);
extern size_t cstl_array_size( struct cstl_array* pArray);
extern size_t cstl_array_capacity( struct cstl_array* pArray );
extern cstl_bool  cstl_array_empty( struct cstl_array* pArray);
extern cstl_error cstl_array_reserve( struct cstl_array* pArray, size_t pos);
extern const void * cstl_array_front(struct cstl_array* pArray);
extern const void * cstl_array_back(struct cstl_array* pArray);
extern cstl_error cstl_array_remove_from ( struct cstl_array*, size_t pos);
extern cstl_error cstl_array_delete( struct cstl_array* pArray);

extern struct cstl_iterator* cstl_array_new_iterator(struct cstl_array* pArray);
extern void cstl_array_delete_iterator ( struct cstl_iterator* pItr);


// #include "c_deque.h"
struct cstl_deque;

extern struct cstl_deque* cstl_deque_new( size_t deq_size , cstl_compare fn_c, cstl_destroy fn_d);
extern size_t cstl_deque_count(struct cstl_deque *deque);
extern cstl_error     cstl_deque_push_back (struct cstl_deque* pDeq, void* elem, size_t elem_size);
extern cstl_error     cstl_deque_push_front(struct cstl_deque* pDeq, void* elem, size_t elem_size);

extern const void * cstl_deque_front(struct cstl_deque* pDeq);
extern const void * cstl_deque_back(struct cstl_deque* pDeq);
extern cstl_error     cstl_deque_pop_back  (struct cstl_deque* pDeq);
extern cstl_error     cstl_deque_pop_front (struct cstl_deque* pDeq);
extern cstl_bool      cstl_deque_empty     (struct cstl_deque* pDeq);
extern size_t            cstl_deque_size ( struct cstl_deque* pDeq);
extern cstl_error     cstl_deque_delete ( struct cstl_deque* pDeq);
extern const void *   cstl_deque_element_at(struct cstl_deque* pDeq, size_t index);

extern struct cstl_iterator* cstl_deque_new_iterator(struct cstl_deque* pDeq);
extern void cstl_deque_delete_iterator ( struct cstl_iterator* pItr);


//#include "c_rb.h"

struct cstl_object;

struct cstl_rb_node {
    struct cstl_rb_node *left;
    struct cstl_rb_node *right;
    struct cstl_rb_node *parent;
    int color;
    struct cstl_object* key;
    struct cstl_object* value;
};

struct cstl_rb {
    struct cstl_rb_node* root;
    struct cstl_rb_node sentinel;
    cstl_destroy destruct_k_fn;
    cstl_destroy destruct_v_fn;
    cstl_compare compare_fn;
};

extern struct cstl_rb* cstl_rb_new(cstl_compare fn_c,cstl_destroy fn_ed, cstl_destroy fn_vd );
extern cstl_error cstl_rb_insert(struct cstl_rb* pTree, const void* k, size_t key_size, const void* v, size_t value_size);
extern struct cstl_rb_node* cstl_rb_find(struct cstl_rb* pTree, const void* key);
extern struct cstl_rb_node* cstl_rb_remove(struct cstl_rb* pTree, const void* key);
extern cstl_error  cstl_rb_delete (struct cstl_rb* pTree);
extern cstl_bool   cstl_rb_empty  (struct cstl_rb* pTree);

extern struct cstl_rb_node *cstl_rb_minimum( struct cstl_rb* pTree, struct cstl_rb_node* x );
extern struct cstl_rb_node* cstl_rb_tree_successor(struct cstl_rb* pTree, struct cstl_rb_node* x);


// #include "c_set.h"
struct cstl_set;

extern struct cstl_set* cstl_set_new( cstl_compare fn_c, cstl_destroy fn_d);
extern cstl_error   cstl_set_insert ( struct cstl_set* pSet, void* key, size_t key_size);
extern cstl_bool    cstl_set_exists ( struct cstl_set* pSet, void* key);
extern cstl_error   cstl_set_remove ( struct cstl_set* pSet, void* key);
extern const void * cstl_set_find(struct cstl_set* pSet, const void* key);
extern cstl_error   cstl_set_delete ( struct cstl_set* pSet);

extern struct cstl_iterator* cstl_set_new_iterator(struct cstl_set* pSet);
extern void cstl_set_delete_iterator ( struct cstl_iterator* pItr);


//#include "c_map.h"
struct cstl_map;

extern struct cstl_map* cstl_map_new( cstl_compare fn_c_k, cstl_destroy fn_k_d, cstl_destroy fn_v_d);
extern cstl_error   cstl_map_insert(struct cstl_map* pMap, const void* key, size_t key_size, const void* value, size_t value_size);
extern cstl_bool    cstl_map_exists(struct cstl_map* pMap, const void* key);
extern cstl_error   cstl_map_replace(struct cstl_map* pMap, const void* key, const void* value,  size_t value_size);
extern cstl_error   cstl_map_remove(struct cstl_map* pMap, const void* key);
extern const void * cstl_map_find   ( struct cstl_map* pMap, const void* key);
extern cstl_error   cstl_map_delete ( struct cstl_map* pMap);

extern struct cstl_iterator* cstl_map_new_iterator(struct cstl_map* pMap);
extern void cstl_map_delete_iterator ( struct cstl_iterator* pItr);


//#include "c_slist.h"
struct cstl_list;

extern struct cstl_list * cstl_list_new (cstl_destroy fn_d, cstl_compare fn_c);
extern size_t cstl_list_count(struct cstl_list* pList);
extern void           cstl_list_destroy   (struct cstl_list* pSlist);
extern void           cstl_list_clear   (struct cstl_list* pSlist);
extern cstl_error     cstl_list_insert   (struct cstl_list* pSlist, size_t pos, void* elem, size_t elem_size);
extern cstl_error     cstl_list_push_back(struct cstl_list* pSlist, void* elem, size_t elem_size);
extern void           cstl_list_remove   (struct cstl_list* pSlist, size_t pos);
extern void           cstl_list_for_each (struct cstl_list* pSlist, void (*fn)(const void *elem, void *p), void *p);
extern const void *   cstl_list_find(struct cstl_list* pSlist, void* find_value);
extern const void *   cstl_list_element_at(struct cstl_list* pSlist, size_t pos);
extern size_t  cstl_list_size(struct cstl_list* pSlist);

extern struct cstl_iterator* cstl_list_new_iterator(struct cstl_list* pSlit);
extern void cstl_list_delete_iterator ( struct cstl_iterator* pItr);


// #include "c_algorithms.h"
extern void cstl_for_each(struct cstl_iterator *pIterator, void(*fn)(const void *value, const void *key, void *p), void *p);


/* ------------------------------------------------------------------------*/
/*            H E L P E R       F U N C T I O N S                          */
/* ------------------------------------------------------------------------*/

extern void  cstl_copy(void* destination, void* source, size_t size);
extern void  cstl_get(void* destination, void* source, size_t size);
extern char* cstl_strdup(const char *ptr);

struct cstl_object;

extern struct cstl_object* cstl_object_new(const void* inObject, size_t obj_size);
extern cstl_error cstl_object_get_raw(struct cstl_object *inObject, void**elem);
extern const void * cstl_object_get_data(struct cstl_object *inObject);
extern void  cstl_object_delete(struct cstl_object* inObject);
extern void  cstl_object_replace_raw(struct cstl_object* current_object, const void* elem, size_t elem_size);

#endif // __CSTL_LIB_H__
