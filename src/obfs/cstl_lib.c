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

#include "cstl_lib.h"
#include <string.h>
#include <stdio.h>

// c_algorithms.c
#include <stdlib.h>

void
cstl_for_each(struct cstl_iterator *pIterator, void(*fn)(const void *value, const void *key, void *p), void *p) {
    const void *pElement;
    if (pIterator==NULL || fn==NULL) {
        return;
    }
    while ((pElement = pIterator->next(pIterator)) != NULL) {
        const void *value = pIterator->current_value(pIterator);
        const void *key = pIterator->current_key ? pIterator->current_key(pIterator) : NULL;
        fn(value, key, p);
    }
}


// c_array.c
#include <string.h>
#include <stdio.h>

struct cstl_array {
    size_t capacity; /* Number of maximum elements array can hold without reallocation */
    size_t count;  /* Number of current elements in the array */
    struct cstl_object** pElements; /* actual storage area */
    cstl_compare compare_fn; /* Compare function pointer*/
    cstl_destroy destruct_fn; /* Destructor function pointer*/
};

static struct cstl_array*
cstl_array_check_and_grow(struct cstl_array* pArray) {
    if (pArray->count >= pArray->capacity) {
        size_t size;
        pArray->capacity = 2 * pArray->capacity;
        size = pArray->capacity * sizeof(struct cstl_object*);
        pArray->pElements = (struct cstl_object**) realloc(pArray->pElements, size);
    }
    return pArray;
}

struct cstl_array*
cstl_array_new(size_t array_size, cstl_compare fn_c, cstl_destroy fn_d) {
    struct cstl_array* pArray = (struct cstl_array*)calloc(1, sizeof(struct cstl_array));
    if (!pArray) {
        return (struct cstl_array*)0;
    }
    pArray->capacity = array_size < 8 ? 8 : array_size;
    pArray->pElements = (struct cstl_object**) calloc(pArray->capacity, sizeof(struct cstl_object*));
    if (!pArray->pElements) {
        free(pArray);
        return (struct cstl_array*)0;
    }
    pArray->compare_fn = fn_c;
    pArray->destruct_fn = fn_d;
    pArray->count = 0;

    return pArray;
}

static cstl_error
cstl_array_insert(struct cstl_array* pArray, size_t index, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_object* pObject = cstl_object_new(elem, elem_size);
    if (!pObject) {
        return CSTL_ARRAY_INSERT_FAILED;
    }
    pArray->pElements[index] = pObject;
    pArray->count++;
    return rc;
}

cstl_error
cstl_array_push_back(struct cstl_array* pArray, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;

    if (!pArray) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    cstl_array_check_and_grow(pArray);

    rc = cstl_array_insert(pArray, pArray->count, elem, elem_size);

    return rc;
}

const void *
cstl_array_element_at(struct cstl_array* pArray, size_t index) {
    if (!pArray) {
        return NULL;
    }
    if (index >= pArray->count) {
        return NULL;
    }
    return cstl_object_get_data(pArray->pElements[index]);
}

size_t
cstl_array_size(struct cstl_array* pArray) {
    if (pArray == (struct cstl_array*)0) {
        return 0;
    }
    return pArray->count;
}

size_t
cstl_array_capacity(struct cstl_array* pArray) {
    if (pArray == (struct cstl_array*)0) {
        return 0;
    }
    return pArray->capacity;
}

cstl_bool
cstl_array_empty(struct cstl_array* pArray) {
    if (pArray == (struct cstl_array*)0) {
        return 0;
    }
    return pArray->count == 0 ? cstl_true : cstl_false;
}

cstl_error
cstl_array_reserve(struct cstl_array* pArray, size_t new_size) {
    if (pArray == (struct cstl_array*)0) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    if (new_size <= pArray->capacity) {
        return CSTL_ERROR_SUCCESS;
    }
    cstl_array_check_and_grow(pArray);
    return CSTL_ERROR_SUCCESS;
}

const void *
cstl_array_front(struct cstl_array* pArray) {
    return cstl_array_element_at(pArray, 0);
}

const void *
cstl_array_back(struct cstl_array* pArray) {
    return cstl_array_element_at(pArray, pArray->count - 1);
}

cstl_error
cstl_array_insert_at(struct cstl_array* pArray, size_t index, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    if (!pArray) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    if (index > pArray->capacity) {
        return CSTL_ARRAY_INDEX_OUT_OF_BOUND;
    }
    cstl_array_check_and_grow(pArray);

    memmove(&(pArray->pElements[index + 1]),
            &pArray->pElements[index],
            (pArray->count - index) * sizeof(struct cstl_object*));

    rc = cstl_array_insert(pArray, index, elem, elem_size);

    return rc;
}

cstl_error
cstl_array_remove_from(struct cstl_array* pArray, size_t index) {
    cstl_error   rc = CSTL_ERROR_SUCCESS;

    if (!pArray) {
        return rc;
    }
    if (index >= pArray->count) {
        return CSTL_ARRAY_INDEX_OUT_OF_BOUND;
    }
    if (pArray->destruct_fn) {
        void *elem = (void *) cstl_array_element_at(pArray, index);
        if (elem) {
            pArray->destruct_fn(elem);
        }
    }
    cstl_object_delete(pArray->pElements[index]);

    memmove(&(pArray->pElements[index]),
            &pArray->pElements[index + 1],
            (pArray->count - index) * sizeof(struct cstl_object*));
    pArray->count--;

    return rc;
}

cstl_error
cstl_array_delete(struct cstl_array* pArray) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    size_t i = 0;

    if (pArray == (struct cstl_array*)0) {
        return CSTL_ARRAY_NOT_INITIALIZED;
    }
    if (pArray->destruct_fn) {
        for (i = 0; i < pArray->count; i++) {
            void *elem = (void *) cstl_array_element_at(pArray, i);
            if ( elem ) {
                pArray->destruct_fn(elem);
            }
        }
    }

    for (i = 0; i < pArray->count; i++) {
        cstl_object_delete(pArray->pElements[i]);
    }
    free(pArray->pElements);
    free(pArray);
    return rc;
}

static const void *
cstl_array_get_next(struct cstl_iterator* pIterator) {
    struct cstl_array *pArray = (struct cstl_array*)pIterator->pContainer;
    if (pIterator->current_index >= cstl_array_size(pArray)) {
        return (const void *)0;
    }
    pIterator->current_element = pArray->pElements[pIterator->current_index++];
    return pIterator->current_element;
}

static const void*
cstl_array_get_value(struct cstl_iterator *pIterator) {
    struct cstl_object *element = (struct cstl_object *)pIterator->current_element;
    return cstl_object_get_data(element);
}

static void
cstl_array_replace_value(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_array*  pArray = (struct cstl_array*)pIterator->pContainer;
    struct cstl_object *currentElement = (struct cstl_object *)pIterator->current_element;
    if (pArray->destruct_fn) {
        void *old_element = (void *) cstl_object_get_data(currentElement);
        if (old_element) {
            pArray->destruct_fn(old_element);
        }
    }
    cstl_object_replace_raw(currentElement, elem, elem_size);
}

struct cstl_iterator*
cstl_array_new_iterator(struct cstl_array* pArray) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->next = cstl_array_get_next;
    itr->current_value = cstl_array_get_value;
    itr->replace_current_value = cstl_array_replace_value;
    itr->pContainer = pArray;
    itr->current_index = 0;
    return itr;
}

void
cstl_array_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_deque.c
#include <string.h>

struct cstl_deque {
    struct cstl_object**pElements;
    size_t capacity;
    size_t count;
    size_t head;
    size_t tail;
    cstl_compare compare_fn;
    cstl_destroy destruct_fn;
};

#define cstl_deque_INDEX(x)  ((char *)(pDeq)->pElements + (sizeof(struct cstl_object) * (x)))

static cstl_error
cstl_deque_insert(struct cstl_deque* pDeq, size_t index, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_object* pObject = cstl_object_new(elem, elem_size);
    if (!pObject) {
        return CSTL_ARRAY_INSERT_FAILED;
    }
    pDeq->pElements[index] = pObject;
    pDeq->count++;
    return rc;
}

static struct cstl_deque*
cstl_deque_grow(struct cstl_deque* pDeq) {
    size_t size;
    pDeq->capacity = pDeq->capacity * 2;
    size = pDeq->capacity * sizeof(struct cstl_object*);
    pDeq->pElements = (struct cstl_object**) realloc(pDeq->pElements, size);
    return pDeq;
}

struct cstl_deque*
cstl_deque_new(size_t deq_size, cstl_compare fn_c, cstl_destroy fn_d) {
    struct cstl_deque* pDeq = (struct cstl_deque*)calloc(1, sizeof(struct cstl_deque));
    if (pDeq == (struct cstl_deque*)0) {
        return (struct cstl_deque*)0;
    }
    pDeq->capacity = deq_size < 8 ? 8 : deq_size;
    pDeq->pElements = (struct cstl_object**) calloc(pDeq->capacity, sizeof(struct cstl_object*));

    if (pDeq == (struct cstl_deque*)0) {
        return (struct cstl_deque*)0;
    }
    pDeq->compare_fn = fn_c;
    pDeq->destruct_fn = fn_d;
    pDeq->head = pDeq->capacity / 2;
    pDeq->tail = pDeq->head + 1;
    pDeq->count = 0;

    return pDeq;
}

size_t cstl_deque_count(struct cstl_deque *deque) {
    return deque->count;
}

cstl_error
cstl_deque_push_back(struct cstl_deque* pDeq, void* elem, size_t elem_size) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->tail == pDeq->capacity) {
        pDeq = cstl_deque_grow(pDeq);
    }
    cstl_deque_insert(pDeq, pDeq->tail, elem, elem_size);
    pDeq->tail++;

    return CSTL_ERROR_SUCCESS;
}

cstl_error
cstl_deque_push_front(struct cstl_deque* pDeq, void* elem, size_t elem_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    size_t to = 0;
    size_t from = 0;
    size_t count = 0;

    if (pDeq->head == 0) {
        pDeq = cstl_deque_grow(pDeq);
        to = (pDeq->capacity - pDeq->count) / 2;
        from = pDeq->head + 1;
        count = pDeq->tail - from;
        memmove(&(pDeq->pElements[to]), &(pDeq->pElements[from]), count * sizeof(struct cstl_object*));
        pDeq->head = to - 1;
        pDeq->tail = pDeq->head + count + 1;
    }
    cstl_deque_insert(pDeq, pDeq->head, elem, elem_size);
    pDeq->head--;
    return rc;
}

const void * cstl_deque_front(struct cstl_deque* pDeq) {
    if (pDeq) {
        return cstl_deque_element_at(pDeq, 0);
    }
    return (struct cstl_deque*)0;
}

const void * cstl_deque_back(struct cstl_deque* pDeq) {
    if (pDeq) {
        return cstl_deque_element_at(pDeq, pDeq->count - 1);
    }
    return (struct cstl_deque*)0;
}

cstl_error
cstl_deque_pop_back(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->destruct_fn) {
        void *elem = (void *) cstl_deque_element_at(pDeq, pDeq->count - 1);
        if ( elem ) {
            pDeq->destruct_fn(elem);
        }
    }
    cstl_object_delete(pDeq->pElements[pDeq->tail - 1]);
    pDeq->tail--;
    pDeq->count--;

    return CSTL_ERROR_SUCCESS;
}

cstl_error
cstl_deque_pop_front(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_DEQUE_NOT_INITIALIZED;
    }
    if (pDeq->destruct_fn) {
        void *elem = (void *) cstl_deque_element_at(pDeq, 0);
        if ( elem ) {
            pDeq->destruct_fn(elem);
        }
    }
    cstl_object_delete(pDeq->pElements[pDeq->head + 1]);

    pDeq->head++;
    pDeq->count--;

    return CSTL_ERROR_SUCCESS;
}

cstl_bool
cstl_deque_empty(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return cstl_true;
    }
    return pDeq->count == 0 ? cstl_true : cstl_false;
}

size_t
cstl_deque_size(struct cstl_deque* pDeq) {
    if (pDeq == (struct cstl_deque*)0) {
        return cstl_true;
    }
    return pDeq->count;
}

const void *
cstl_deque_element_at(struct cstl_deque* pDeq, size_t index) {
    if ((pDeq==NULL) || (index >= pDeq->count)) {
        return NULL;
    }
    return cstl_object_get_data(pDeq->pElements[(pDeq->head + 1) + index]);
}

cstl_error
cstl_deque_delete(struct cstl_deque* pDeq) {
    size_t i = 0;

    if (pDeq == (struct cstl_deque*)0) {
        return CSTL_ERROR_SUCCESS;
    }
    if (pDeq->destruct_fn) {
        for (i = 0; i < pDeq->count; ++i) {
            void *elem = (void *) cstl_deque_element_at(pDeq, i);
            if ( elem ) {
                pDeq->destruct_fn(elem);
            }
        }
    }
    for (i = pDeq->head + 1; i < pDeq->tail; i++) {
        cstl_object_delete(pDeq->pElements[i]);
    }
    free(pDeq->pElements);
    free(pDeq);

    return CSTL_ERROR_SUCCESS;
}

static const void *
cstl_deque_get_next(struct cstl_iterator* pIterator) {
    struct cstl_deque *pDeq = (struct cstl_deque*)pIterator->pContainer;
    size_t index = pIterator->current_index;

    if (index <= pDeq->head || index >= pDeq->tail) {
        return (const void *)0;
    }
    pIterator->current_element = pDeq->pElements[pIterator->current_index++];
    return pIterator->current_element;
}

static const void*
cstl_deque_get_value(struct cstl_iterator *pIterator) {
    struct cstl_object *element = (struct cstl_object *)pIterator->current_element;
    return cstl_object_get_data(element);
}

static void
cstl_deque_replace_value(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_deque*  pDeq = (struct cstl_deque*)pIterator->pContainer;
    struct cstl_object *currentElement = (struct cstl_object *)pIterator->current_element;
    if (pDeq->destruct_fn) {
        void *old_element = (void *) cstl_object_get_data(currentElement);
        if (old_element) {
            pDeq->destruct_fn(old_element);
        }
    }
    cstl_object_replace_raw(currentElement, elem, elem_size);
}

struct cstl_iterator*
cstl_deque_new_iterator(struct cstl_deque* pDeq) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->next = cstl_deque_get_next;
    itr->current_value = cstl_deque_get_value;
    itr->replace_current_value = cstl_deque_replace_value;
    itr->current_index = pDeq->head + 1;
    itr->pContainer = pDeq;
    return itr;
}

void
cstl_deque_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_map.c
#include <stdio.h>

struct cstl_map {
    struct cstl_rb* root;
};

struct cstl_map*
cstl_map_new(cstl_compare fn_c_k, cstl_destroy fn_k_d, cstl_destroy fn_v_d) {
    struct cstl_map* pMap = (struct cstl_map*)calloc(1, sizeof(struct cstl_map));
    if (pMap == (struct cstl_map*)0) {
        return (struct cstl_map*)0;
    }
    pMap->root = cstl_rb_new(fn_c_k, fn_k_d, fn_v_d);
    if (pMap->root == (struct cstl_rb*)0) {
        return (struct cstl_map*)0;
    }
    return pMap;
}

cstl_error
cstl_map_insert(struct cstl_map* pMap, const void* key, size_t key_size, const void* value, size_t value_size) {
    if (pMap == (struct cstl_map*)0) {
        return CSTL_MAP_NOT_INITIALIZED;
    }
    return cstl_rb_insert(pMap->root, key, key_size, value, value_size);
}

cstl_bool
cstl_map_exists(struct cstl_map* pMap, const void* key) {
    cstl_bool found = cstl_false;
    struct cstl_rb_node* node;

    if (pMap == (struct cstl_map*)0) {
        return cstl_false;
    }
    node = cstl_rb_find(pMap->root, key);
    if (node != (struct cstl_rb_node*)0) {
        return cstl_true;
    }
    return found;
}

cstl_error
cstl_map_replace(struct cstl_map* pMap, const void* key, const void* value,  size_t value_size) {
    struct cstl_rb_node* node;
    if (pMap == (struct cstl_map*)0) {
        return CSTL_MAP_NOT_INITIALIZED;
    }
    node = cstl_rb_find(pMap->root, key);
    if (node == (struct cstl_rb_node*)0) {
        return CSTL_RBTREE_KEY_NOT_FOUND;
    }

    if (pMap->root->destruct_v_fn) {
        void* old_element = (void *)cstl_object_get_data(node->value);
        if (old_element) {
            pMap->root->destruct_v_fn(old_element);
        }
    }
    cstl_object_replace_raw(node->value, value, value_size);
    return CSTL_ERROR_SUCCESS;
}


cstl_error
cstl_map_remove(struct cstl_map* pMap, const void* key) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* node;
    if (pMap == (struct cstl_map*)0) {
        return CSTL_MAP_NOT_INITIALIZED;
    }
    node = cstl_rb_remove(pMap->root, key);
    if (node != (struct cstl_rb_node*)0) {
        void* removed_node = (void *)0;
        if (pMap->root->destruct_k_fn) {
            removed_node = (void *) cstl_object_get_data(node->key);
            if (removed_node) {
                pMap->root->destruct_k_fn(removed_node);
            }
        }
        cstl_object_delete(node->key);

        if (pMap->root->destruct_v_fn) {
            removed_node = (void *) cstl_object_get_data(node->value);
            if (removed_node) {
                pMap->root->destruct_v_fn(removed_node);
            }
        }
        cstl_object_delete(node->value);

        free(node);
    }
    return rc;
}

const void *
cstl_map_find(struct cstl_map* pMap, const void* key) {
    struct cstl_rb_node* node;

    if (pMap == (struct cstl_map*)0) {
        return (void *)0;
    }
    node = cstl_rb_find(pMap->root, (void *) key);
    if (node == (struct cstl_rb_node*)0) {
        return (void *)0;
    }
    return cstl_object_get_data(node->value);
}

cstl_error
cstl_map_delete(struct cstl_map* x) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    if (x != (struct cstl_map*)0) {
        rc = cstl_rb_delete(x->root);
        free(x);
    }
    return rc;
}

static struct cstl_rb_node *
cstl_map_minimum(struct cstl_map *x) {
    return cstl_rb_minimum(x->root, x->root->root);
}

static const void *
cstl_map_get_next(struct cstl_iterator* pIterator) {
    struct cstl_map *x = (struct cstl_map*)pIterator->pContainer;
    struct cstl_rb_node *ptr = NULL;
    if (!pIterator->current_element) {
        pIterator->current_element = cstl_map_minimum(x);
    } else {
        pIterator->current_element = cstl_rb_tree_successor(x->root, (struct cstl_rb_node*)pIterator->current_element);
    }
    ptr = (struct cstl_rb_node*)pIterator->current_element;
    if (ptr==NULL || ptr->key==NULL) {
        return NULL;
    }
    return ptr;
}

static const void*
cstl_map_get_key(struct cstl_iterator *pIterator) {
    struct cstl_rb_node *current = (struct cstl_rb_node*)pIterator->current_element;
    return cstl_object_get_data(current->key);
}

static const void*
cstl_map_get_value(struct cstl_iterator *pIterator) {
    struct cstl_rb_node* current = (struct cstl_rb_node*)pIterator->current_element;
    return cstl_object_get_data(current->value);
}

static void
cstl_map_replace_value(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_map *pMap = (struct cstl_map*)pIterator->pContainer;
    struct cstl_rb_node* node = (struct cstl_rb_node*)pIterator->current_element;

    if (pMap->root->destruct_v_fn) {
        void *old_element = (void *) cstl_object_get_data(node->value);
        if (old_element) {
            pMap->root->destruct_v_fn(old_element);
        }
    }
    cstl_object_replace_raw(node->value, elem, elem_size);
}

struct cstl_iterator*
cstl_map_new_iterator(struct cstl_map* pMap) {
    struct cstl_iterator *itr = (struct cstl_iterator*)calloc(1, sizeof(struct cstl_iterator));
    itr->next = cstl_map_get_next;
    itr->current_key = cstl_map_get_key;
    itr->current_value = cstl_map_get_value;
    itr->replace_current_value = cstl_map_replace_value;
    itr->pContainer = pMap;
    itr->current_index = 0;
    itr->current_element = (void*)0;
    return itr;
}

void
cstl_map_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_rb.c
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define rb_sentinel &pTree->sentinel

static void debug_verify_properties(struct cstl_rb*);
static void debug_verify_property_1(struct cstl_rb*, struct cstl_rb_node*);
static void debug_verify_property_2(struct cstl_rb*, struct cstl_rb_node*);
static int debug_node_color(struct cstl_rb*, struct cstl_rb_node* n);
static void debug_verify_property_4(struct cstl_rb*, struct cstl_rb_node*);
static void debug_verify_property_5(struct cstl_rb*, struct cstl_rb_node*);
static void debug_verify_property_5_helper(struct cstl_rb*, struct cstl_rb_node*, int, int*);

static void
__left_rotate(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    struct cstl_rb_node* y;
    y = x->right;
    x->right = y->left;
    if (y->left != rb_sentinel) {
        y->left->parent = x;
    }
    if (y != rb_sentinel) {
        y->parent = x->parent;
    }
    if (x->parent) {
        if (x == x->parent->left) {
            x->parent->left = y;
        } else {
            x->parent->right = y;
        }
    } else {
        pTree->root = y;
    }
    y->left = x;
    if (x != rb_sentinel) {
        x->parent = y;
    }
}

static void
__right_rotate(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    struct cstl_rb_node* y = x->left;
    x->left = y->right;
    if (y->right != rb_sentinel) {
        y->right->parent = x;
    }
    if (y != rb_sentinel) {
        y->parent = x->parent;
    }
    if (x->parent) {
        if (x == x->parent->right) {
            x->parent->right = y;
        } else {
            x->parent->left = y;
        }
    } else {
        pTree->root = y;
    }
    y->right = x;
    if (x != rb_sentinel) {
        x->parent = y;
    }
}

struct cstl_rb*
cstl_rb_new(cstl_compare fn_c, cstl_destroy fn_ed, cstl_destroy fn_vd) {
    struct cstl_rb* pTree = (struct cstl_rb*)calloc(1, sizeof(struct cstl_rb));
    if (pTree == (struct cstl_rb*)0) {
        return (struct cstl_rb*)0;
    }
    pTree->compare_fn = fn_c;
    pTree->destruct_k_fn = fn_ed;
    pTree->destruct_v_fn = fn_vd;
    pTree->root = rb_sentinel;
    pTree->sentinel.left = rb_sentinel;
    pTree->sentinel.right = rb_sentinel;
    pTree->sentinel.parent = (struct cstl_rb_node*)0;
    pTree->sentinel.color = cstl_black;

    return pTree;
}

static void
__rb_insert_fixup(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x != pTree->root && x->parent->color == cstl_red) {
        if (x->parent == x->parent->parent->left) {
            struct cstl_rb_node* y = x->parent->parent->right;
            if (y->color == cstl_red) {
                x->parent->color = cstl_black;
                y->color = cstl_black;
                x->parent->parent->color = cstl_red;
                x = x->parent->parent;
            } else {
                if (x == x->parent->right) {
                    x = x->parent;
                    __left_rotate(pTree, x);
                }
                x->parent->color = cstl_black;
                x->parent->parent->color = cstl_red;
                __right_rotate(pTree, x->parent->parent);
            }
        } else {
            struct cstl_rb_node* y = x->parent->parent->left;
            if (y->color == cstl_red) {
                x->parent->color = cstl_black;
                y->color = cstl_black;
                x->parent->parent->color = cstl_red;
                x = x->parent->parent;
            } else {
                if (x == x->parent->left) {
                    x = x->parent;
                    __right_rotate(pTree, x);
                }
                x->parent->color = cstl_black;
                x->parent->parent->color = cstl_red;
                __left_rotate(pTree, x->parent->parent);
            }
        }
    }
    pTree->root->color = cstl_black;
}

struct cstl_rb_node*
cstl_rb_find(struct cstl_rb* pTree, const void* key) {
    struct cstl_rb_node* x = pTree->root;

    while (x != rb_sentinel) {
        const void *cur_key = cstl_object_get_data(x->key);
        int c = pTree->compare_fn(key, cur_key);
        if (c == 0) {
            break;
        } else {
            x = c < 0 ? x->left : x->right;
        }
    }
    if (x == rb_sentinel) {
        return (struct cstl_rb_node*)0;
    }
    return x;
}

cstl_error
cstl_rb_insert(struct cstl_rb* pTree, const void* k, size_t key_size, const void* v, size_t value_size) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* x;
    struct cstl_rb_node* y;
    struct cstl_rb_node* z;

    x = (struct cstl_rb_node*)calloc(1, sizeof(struct cstl_rb_node));
    if (x == (struct cstl_rb_node*)0) {
        return CSTL_ERROR_MEMORY;
    }
    x->left = rb_sentinel;
    x->right = rb_sentinel;
    x->color = cstl_red;

    x->key = cstl_object_new(k, key_size);
    if (v) {
        x->value = cstl_object_new(v, value_size);
    } else {
        x->value = (struct cstl_object*)0;
    }

    y = pTree->root;
    z = (struct cstl_rb_node*)0;

    while (y != rb_sentinel) {
        const void *cur_key = cstl_object_get_data(y->key);
        const void *new_key = cstl_object_get_data(x->key);
        int c = pTree->compare_fn(new_key, cur_key);
        if (c == 0) {
            cstl_object_delete(x->key);
            cstl_object_delete(x->value);
            free(x);
            return CSTL_RBTREE_KEY_DUPLICATE;
        }
        z = y;
        if (c < 0) {
            y = y->left;
        } else {
            y = y->right;
        }
    }
    x->parent = z;
    if (z) {
        const void *cur_key = cstl_object_get_data(z->key);
        const void *new_key = cstl_object_get_data(x->key);
        int c = pTree->compare_fn(new_key, cur_key);
        if (c < 0) {
            z->left = x;
        } else {
            z->right = x;
        }
    } else {
        pTree->root = x;
    }
    __rb_insert_fixup(pTree, x);

    debug_verify_properties(pTree);
    return rc;
}

static void
__rb_remove_fixup(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x != pTree->root && x->color == cstl_black) {
        if (x == x->parent->left) {
            struct cstl_rb_node* w = x->parent->right;
            if (w->color == cstl_red) {
                w->color = cstl_black;
                x->parent->color = cstl_red;
                __left_rotate(pTree, x->parent);
                w = x->parent->right;
            }
            if (w->left->color == cstl_black && w->right->color == cstl_black) {
                w->color = cstl_red;
                x = x->parent;
            } else {
                if (w->right->color == cstl_black) {
                    w->left->color = cstl_black;
                    w->color = cstl_red;
                    __right_rotate(pTree, w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = cstl_black;
                w->right->color = cstl_black;
                __left_rotate(pTree, x->parent);
                x = pTree->root;
            }
        } else {
            struct cstl_rb_node* w = x->parent->left;
            if (w->color == cstl_red) {
                w->color = cstl_black;
                x->parent->color = cstl_red;
                __right_rotate(pTree, x->parent);
                w = x->parent->left;
            }
            if (w->right->color == cstl_black && w->left->color == cstl_black) {
                w->color = cstl_red;
                x = x->parent;
            } else {
                if (w->left->color == cstl_black) {
                    w->right->color = cstl_black;
                    w->color = cstl_red;
                    __left_rotate(pTree, w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = cstl_black;
                w->left->color = cstl_black;
                __right_rotate(pTree, x->parent);
                x = pTree->root;
            }
        }
    }
    x->color = cstl_black;
}

static struct cstl_rb_node*
__remove_c_rb(struct cstl_rb* pTree, struct cstl_rb_node* z) {
    struct cstl_rb_node* x = (struct cstl_rb_node*)0;
    struct cstl_rb_node* y = (struct cstl_rb_node*)0;

    if (z->left == rb_sentinel || z->right == rb_sentinel) {
        y = z;
    } else {
        y = z->right;
        while (y->left != rb_sentinel) {
            y = y->left;
        }
    }
    if (y->left != rb_sentinel) {
        x = y->left;
    } else {
        x = y->right;
    }
    x->parent = y->parent;
    if (y->parent) {
        if (y == y->parent->left) {
            y->parent->left = x;
        } else {
            y->parent->right = x;
        }
    } else {
        pTree->root = x;
    }
    if (y != z) {
        struct cstl_object* tmp;
        tmp = z->key;
        z->key = y->key;
        y->key = tmp;

        tmp = z->value;
        z->value = y->value;
        y->value = tmp;
    }
    if (y->color == cstl_black) {
        __rb_remove_fixup(pTree, x);
    }
    debug_verify_properties(pTree);
    return y;
}

struct cstl_rb_node*
cstl_rb_remove(struct cstl_rb* pTree, const void* key) {
    struct cstl_rb_node* z = (struct cstl_rb_node*)0;

    z = pTree->root;
    while (z != rb_sentinel) {
        const void *cur_key = cstl_object_get_data(z->key);
        int c = pTree->compare_fn(key, cur_key);
        if (c == 0) {
            break;
        } else {
            z = (c < 0) ? z->left : z->right;
        }
    }
    if (z == rb_sentinel) {
        return (struct cstl_rb_node*)0;
    }
    return __remove_c_rb(pTree, z);
}

static void
__delete_c_rb_node(struct cstl_rb* pTree, struct cstl_rb_node* x) {

    if (pTree->destruct_k_fn) {
        void *key = (void *) cstl_object_get_data(x->key);
        pTree->destruct_k_fn(key);
    }
    cstl_object_delete(x->key);

    if (x->value) {
        if (pTree->destruct_v_fn) {
            void *value = (void *) cstl_object_get_data(x->value);
            pTree->destruct_v_fn(value);
        }
        cstl_object_delete(x->value);
    }
}

cstl_error
cstl_rb_delete(struct cstl_rb* pTree) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* z = pTree->root;

    while (z != rb_sentinel) {
        if (z->left != rb_sentinel) {
            z = z->left;
        } else if (z->right != rb_sentinel) {
            z = z->right;
        } else {
            __delete_c_rb_node(pTree, z);
            if (z->parent) {
                z = z->parent;
                if (z->left != rb_sentinel) {
                    free(z->left);
                    z->left = rb_sentinel;
                } else if (z->right != rb_sentinel) {
                    free(z->right);
                    z->right = rb_sentinel;
                }
            } else {
                free(z);
                z = rb_sentinel;
            }
        }
    }
    free(pTree);
    return rc;
}

struct cstl_rb_node *
cstl_rb_minimum(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x->left != rb_sentinel) {
        x = x->left;
    }
    return x;
}

struct cstl_rb_node *
cstl_rb_maximum(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    while (x->right != rb_sentinel) {
        x = x->right;
    }
    return x;
}

cstl_bool
cstl_rb_empty(struct cstl_rb* pTree) {
    if (pTree->root != rb_sentinel) {
        return cstl_true;
    }
    return cstl_false;
}

struct cstl_rb_node*
cstl_rb_tree_successor(struct cstl_rb* pTree, struct cstl_rb_node* x) {
    struct cstl_rb_node *y = (struct cstl_rb_node*)0;
    if (x->right != rb_sentinel) {
        return cstl_rb_minimum(pTree, x->right);
    }
    if (x == cstl_rb_maximum(pTree, pTree->root)) {
        return (struct cstl_rb_node*)0;
    }
    y = x->parent;
    while (y != rb_sentinel && x == y->right) {
        x = y;
        y = y->parent;
    }
    return y;
}

/*
struct cstl_rb_node *
cstl_rb_get_next(struct cstl_rb* pTree, struct cstl_rb_node**current, struct cstl_rb_node**pre) {
    struct cstl_rb_node* prev_current;
    while ((*current) != rb_sentinel) {
        if ((*current)->left == rb_sentinel) {
            prev_current = (*current);
            (*current) = (*current)->right;
            return prev_current->raw_data.key;
        } else {
            (*pre) = (*current)->left;
            while ((*pre)->right != rb_sentinel && (*pre)->right != (*current))
                (*pre) = (*pre)->right;
            if ((*pre)->right == rb_sentinel) {
                (*pre)->right = (*current);
                (*current) = (*current)->left;
            } else {
                (*pre)->right = rb_sentinel;
                prev_current = (*current);
                (*current) = (*current)->right;
                return prev_current->raw_data.key;
            }
        }
    }
    return (struct cstl_rb_node*)0;
} */

void debug_verify_properties(struct cstl_rb* t) {
    debug_verify_property_1(t, t->root);
    debug_verify_property_2(t, t->root);
    debug_verify_property_4(t, t->root);
    debug_verify_property_5(t, t->root);
}

void debug_verify_property_1(struct cstl_rb* pTree, struct cstl_rb_node* n) {
    assert(debug_node_color(pTree, n) == cstl_red || debug_node_color(pTree, n) == cstl_black);
    if (n == rb_sentinel) { return; }
    debug_verify_property_1(pTree, n->left);
    debug_verify_property_1(pTree, n->right);
}

void debug_verify_property_2(struct cstl_rb* pTree, struct cstl_rb_node* root) {
    assert(debug_node_color(pTree, root) == cstl_black);
}

int debug_node_color(struct cstl_rb* pTree, struct cstl_rb_node* n) {
    return n == rb_sentinel ? cstl_black : n->color;
}

void debug_verify_property_4(struct cstl_rb* pTree, struct cstl_rb_node* n) {
    if (debug_node_color(pTree, n) == cstl_red) {
        assert(debug_node_color(pTree, n->left) == cstl_black);
        assert(debug_node_color(pTree, n->right) == cstl_black);
        assert(debug_node_color(pTree, n->parent) == cstl_black);
    }
    if (n == rb_sentinel) { return; }
    debug_verify_property_4(pTree, n->left);
    debug_verify_property_4(pTree, n->right);
}

void debug_verify_property_5(struct cstl_rb* pTree, struct cstl_rb_node* root) {
    int black_count_path = -1;
    debug_verify_property_5_helper(pTree, root, 0, &black_count_path);
}

void debug_verify_property_5_helper(struct cstl_rb* pTree, struct cstl_rb_node* n, int black_count, int* path_black_count) {
    if (debug_node_color(pTree, n) == cstl_black) {
        black_count++;
    }
    if (n == rb_sentinel) {
        if (*path_black_count == -1) {
            *path_black_count = black_count;
        } else {
            assert(black_count == *path_black_count);
        }
        return;
    }
    debug_verify_property_5_helper(pTree, n->left, black_count, path_black_count);
    debug_verify_property_5_helper(pTree, n->right, black_count, path_black_count);
}


// c_set.c
#include <stdio.h>

struct cstl_set {
    struct cstl_rb* root;
};

struct cstl_set*
cstl_set_new(cstl_compare fn_c, cstl_destroy fn_d) {
    struct cstl_set* pSet = (struct cstl_set*)calloc(1, sizeof(struct cstl_set));
    if (pSet == (struct cstl_set*)0) {
        return (struct cstl_set*)0;
    }
    pSet->root = cstl_rb_new(fn_c, fn_d, (void*)0);
    if (pSet->root == (struct cstl_rb*)0) {
        return (struct cstl_set*)0;
    }
    return pSet;
}

cstl_error
cstl_set_insert(struct cstl_set* pSet, void* key, size_t key_size) {
    if (pSet == (struct cstl_set*)0) {
        return CSTL_SET_NOT_INITIALIZED;
    }
    return cstl_rb_insert(pSet->root, key, key_size, (void*)0, 0);
}

cstl_bool
cstl_set_exists(struct cstl_set* pSet, void* key) {
    cstl_bool found = cstl_false;
    struct cstl_rb_node* node;

    if (pSet == (struct cstl_set*)0) {
        return cstl_false;
    }
    node = cstl_rb_find(pSet->root, key);
    if (node != (struct cstl_rb_node*)0) {
        return cstl_true;
    }
    return found;
}

cstl_error
cstl_set_remove(struct cstl_set* pSet, void* key) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    struct cstl_rb_node* node;
    if (pSet == (struct cstl_set*)0) {
        return CSTL_SET_NOT_INITIALIZED;
    }
    node = cstl_rb_remove(pSet->root, key);
    if (node != (struct cstl_rb_node*)0) {
        if (pSet->root->destruct_k_fn) {
            void *key = (void *) cstl_object_get_data(node->key);
            if (key) {
                pSet->root->destruct_k_fn(key);
            }
        }
        cstl_object_delete(node->key);

        free(node);
    }
    return rc;
}

const void * cstl_set_find(struct cstl_set* pSet, const void* key) {
    struct cstl_rb_node* node;

    if (pSet == (struct cstl_set*)0) {
        return NULL;
    }
    node = cstl_rb_find(pSet->root, key);
    if (node == (struct cstl_rb_node*)0) {
        return NULL;
    }
    return cstl_object_get_data(node->key);
}

cstl_error
cstl_set_delete(struct cstl_set* x) {
    cstl_error rc = CSTL_ERROR_SUCCESS;
    if (x != (struct cstl_set*)0) {
        rc = cstl_rb_delete(x->root);
        free(x);
    }
    return rc;
}

static struct cstl_rb_node *
cstl_set_minimum(struct cstl_set *x) {
    return cstl_rb_minimum(x->root, x->root->root);
}

static const void *
cstl_set_get_next(struct cstl_iterator* pIterator) {
    struct cstl_set *x = (struct cstl_set*)pIterator->pContainer;
    struct cstl_rb_node *ptr = NULL;
    if (!pIterator->current_element) {
        pIterator->current_element = cstl_set_minimum(x);
    } else {
        pIterator->current_element = cstl_rb_tree_successor(x->root, (struct cstl_rb_node*)pIterator->current_element);
    }
    ptr = (struct cstl_rb_node*)pIterator->current_element;
    if (ptr==NULL || ptr->key==NULL) {
        return NULL;
    }
    return ptr;
}

static const void*
cstl_set_get_key(struct cstl_iterator* pIterator) {
    struct cstl_rb_node *current = (struct cstl_rb_node*)pIterator->current_element;
    return cstl_object_get_data(current->key);
}

static const void*
cstl_set_get_value(struct cstl_iterator *pIterator) {
    return cstl_set_get_key(pIterator);
}

struct cstl_iterator*
cstl_set_new_iterator(struct cstl_set* pSet) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->next = cstl_set_get_next;
    itr->current_key = cstl_set_get_key;
    itr->current_value = cstl_set_get_value;
    itr->pContainer = pSet;
    itr->current_index = 0;
    itr->current_element = (void*)0;
    return itr;
}

void
cstl_set_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_list.c

struct cstl_list_node {
    struct cstl_object* elem;
    struct cstl_list_node *next;
};

struct cstl_list {
    struct cstl_list_node* head;
    cstl_destroy destruct_fn;
    cstl_compare compare_key_fn;
    size_t size;
};

struct cstl_list*
cstl_list_new(cstl_destroy fn_d, cstl_compare fn_c) {
    struct cstl_list* pList = (struct cstl_list*)calloc(1, sizeof(struct cstl_list));
    pList->head = (struct cstl_list_node*)0;
    pList->destruct_fn = fn_d;
    pList->compare_key_fn = fn_c;
    pList->size = 0;
    return pList;
}

size_t cstl_list_count(struct cstl_list* pList) {
    return pList->size;
}

void
cstl_list_destroy(struct cstl_list* pList) {
    cstl_list_clear(pList);
    free(pList);
}

void cstl_list_clear(struct cstl_list* pList) {
    while (pList->size != 0) {
        cstl_list_remove(pList, 0);
    }
}

cstl_error
cstl_list_push_back(struct cstl_list* pList, void* elem, size_t elem_size) {
    return cstl_list_insert(pList, pList->size, elem, elem_size);
}

static void
__cstl_slist_remove(struct cstl_list* pList, struct cstl_list_node* pSlistNode) {
    if (pList->destruct_fn) {
        void *elem = (void *)cstl_object_get_data(pSlistNode->elem);
        if (elem) {
            pList->destruct_fn(elem);
        }
    }
    cstl_object_delete(pSlistNode->elem);

    free(pSlistNode);
}

void
cstl_list_remove(struct cstl_list* pList, size_t pos) {
    size_t i = 0;

    struct cstl_list_node* current = pList->head;
    struct cstl_list_node* previous = (struct cstl_list_node*)0;

    if (pos >= pList->size) { return; }

    if (pos == 0) {
        pList->head = current->next;
        __cstl_slist_remove(pList, current);
        pList->size--;
        return;
    }
    for (i = 0; i < pos; ++i) {
        previous = current;
        current = current->next;
    }
    previous->next = current->next;
    __cstl_slist_remove(pList, current);

    pList->size--;
}

cstl_error
cstl_list_insert(struct cstl_list* pList, size_t pos, void* elem, size_t elem_size) {
    size_t i = 0;
    struct cstl_list_node* current = pList->head;
    struct cstl_list_node* new_node = (struct cstl_list_node*)0;
    struct cstl_list_node* previous = (struct cstl_list_node*)0;

    if (pos > pList->size) {
        pos = pList->size;
    }

    new_node = (struct cstl_list_node*)calloc(1, sizeof(struct cstl_list_node));
    new_node->next = (struct cstl_list_node*)0;
    new_node->elem = cstl_object_new(elem, elem_size);
    if (!new_node->elem) {
        free(new_node);
        return CSTL_SLIST_INSERT_FAILED;
    }

    if (pos == 0) {
        new_node->next = pList->head;
        pList->head = new_node;
        pList->size++;
        return CSTL_ERROR_SUCCESS;
    }

    for (i = 0; i < pos; ++i) {
        previous = current;
        current = current->next;
    }

    previous->next = new_node;
    new_node->next = current;
    pList->size++;

    return CSTL_ERROR_SUCCESS;
}

void
cstl_list_for_each(struct cstl_list* pList, void(*fn)(const void *elem, void *p), void *p) {
    struct cstl_list_node* current = pList->head;
    if (fn == NULL) {
        return;
    }
    while (current != (struct cstl_list_node*)0) {
        fn(cstl_object_get_data(current->elem), p);
        current = current->next;
    }
}

const void *
cstl_list_find(struct cstl_list* pList, void* find_value) {
    struct cstl_list_node* current = pList->head;
    while (current != (struct cstl_list_node*)0) {
        const void *tmp = cstl_object_get_data(current->elem);
        if (pList->compare_key_fn(find_value, tmp) == 0) {
            return tmp;
        }
        current = current->next;
    }
    return NULL;
}

const void * cstl_list_element_at(struct cstl_list* pList, size_t pos) {
    struct cstl_list_node* current = NULL;
    size_t index = 0;
    if (pList==NULL || pList->size==0) {
        return NULL;
    }
    if (pos >= pList->size) {
        pos = (pList->size - 1);
    }
    current = pList->head;
    for (index=0; index<pos; ++index) {
        current = current->next;
    }
    return current ? cstl_object_get_data(current->elem) : NULL;
}

size_t cstl_list_size(struct cstl_list* pList) {
    return pList ? pList->size : 0;
}

static const void *
cstl_list_get_next(struct cstl_iterator* pIterator) {
    struct cstl_list *pList = (struct cstl_list*)pIterator->pContainer;
    if (!pIterator->current_element) {
        pIterator->current_element = (struct cstl_list_node*)pList->head;
    } else {
        pIterator->current_element = ((struct cstl_list_node*)pIterator->current_element)->next;
    }
    return pIterator->current_element;
}

static const void*
cstl_list_get_value(struct cstl_iterator *pIterator) {
    struct cstl_object *pObj = ((struct cstl_list_node*)pIterator->current_element)->elem;
    return cstl_object_get_data(pObj);
}

static void
cstl_list_replace_value(struct cstl_iterator *pIterator, void* elem, size_t elem_size) {
    struct cstl_list*  pList = (struct cstl_list*)pIterator->pContainer;
    struct cstl_object *pObj = ((struct cstl_list_node*)pIterator->current_element)->elem;

    if (pList->destruct_fn) {
        void *old_element = (void *) cstl_object_get_data(pObj);
        if (old_element) {
            pList->destruct_fn(old_element);
        }
    }
    cstl_object_replace_raw(pObj, elem, elem_size);
}

struct cstl_iterator*
cstl_list_new_iterator(struct cstl_list* pList) {
    struct cstl_iterator *itr = (struct cstl_iterator*) calloc(1, sizeof(struct cstl_iterator));
    itr->next = cstl_list_get_next;
    itr->current_value = cstl_list_get_value;
    itr->replace_current_value = cstl_list_replace_value;
    itr->pContainer = pList;
    itr->current_element = (void*)0;
    itr->current_index = 0;
    return itr;
}

void
cstl_list_delete_iterator(struct cstl_iterator* pItr) {
    free(pItr);
}


// c_util.c
#include <string.h>
#include <stdlib.h>

void
cstl_copy(void* destination, void* source, size_t size) {
    memcpy((char*)destination, source, size);
}

void
cstl_get(void* destination, void* source, size_t size) {
    memcpy(destination, (char*)source, size);
}

char * cstl_strdup(const char *ptr) {
#ifdef WIN32
    return _strdup(ptr);
#else
    return strdup(ptr);
#endif
}

struct cstl_object {
    void* raw_data;
    size_t size;
};

struct cstl_object*
cstl_object_new(const void* inObject, size_t obj_size) {
    struct cstl_object* tmp = (struct cstl_object*)calloc(1, sizeof(struct cstl_object));
    if (!tmp) {
        return (struct cstl_object*)0;
    }
    tmp->size = obj_size;
    tmp->raw_data = (void*)calloc(obj_size, sizeof(char));
    if (!tmp->raw_data) {
        free(tmp);
        return (struct cstl_object*)0;
    }
    memcpy(tmp->raw_data, inObject, obj_size);
    return tmp;
}

const void * cstl_object_get_data(struct cstl_object *inObject) {
    return inObject->raw_data;
}

void
cstl_object_replace_raw(struct cstl_object* current_object, const void* elem, size_t elem_size) {
    free(current_object->raw_data);
    current_object->raw_data = (void*)calloc(elem_size, sizeof(char));
    memcpy(current_object->raw_data, elem, elem_size);
}

void
cstl_object_delete(struct cstl_object* inObject) {
    if (inObject) {
        free(inObject->raw_data);
        free(inObject);
    }
}
