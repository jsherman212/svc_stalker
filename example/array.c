#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"

static const int STARTING_CAPACITY = 1;

int array_bsearch(struct array *a, const void *key,
        int (*compar)(const void *, const void *), void **result){
    if(!a){
        *result = NULL;
        return ARRAY_NULL;
    }

    if(array_empty(a)){
        *result = NULL;
        return ARRAY_KEY_NOT_FOUND;
    }

    *result = bsearch(key, a->items, a->len, sizeof(void *), compar);

    if(!(*result))
        return ARRAY_KEY_NOT_FOUND;

    return ARRAY_OK;
}

int array_clear(struct array *a){
    free(a->items);
    a->items = NULL;

    a->len = 0;
    a->capacity = STARTING_CAPACITY;

    return ARRAY_OK;
}

int array_destroy(struct array **a){
    array_clear(*a);

    free(*a);
    *a = NULL;

    return ARRAY_OK;
}

int array_empty(struct array *a){
    return !a || a->len == 0;
}

int array_insert(struct array *a, void *elem){
    if(!a)
        return ARRAY_NULL;

    if(!a->items)
        a->items = malloc(a->capacity * sizeof(void *));

    if(a->len >= a->capacity - 1){
        a->capacity *= 2;

        void **items_rea = realloc(a->items, a->capacity * sizeof(void *));
        a->items = items_rea;
    }

    a->items[a->len++] = elem;

    return ARRAY_OK;
}

int array_qsort(struct array *a, int (*compar)(const void *, const void *)){
    if(!a)
        return ARRAY_NULL;

    qsort(a->items, a->len, sizeof(void *), compar);

    return ARRAY_OK;
}

static int _array_remove(struct array *a, int idx){
    if(idx < 0 || idx >= a->len)
        return ARRAY_OOB;

    if(idx == a->len - 1){
        a->len--;
        return ARRAY_OK;
    }

    void **start = a->items + idx;
    size_t bytes = ((a->items + a->len) - (start + 1)) * sizeof(void *);

    memmove(start, start + 1, bytes);

    a->len--;

    return ARRAY_OK;
}

int array_remove(struct array *a, int idx){
    if(!a)
        return ARRAY_NULL;

    if(array_empty(a))
        return ARRAY_OK;

    return _array_remove(a, idx);
}

int array_remove_elem(struct array *a, void *elem){
    if(!a)
        return ARRAY_NULL;

    if(array_empty(a))
        return ARRAY_OK;

    int elemidx = 0;

    while(a->items[elemidx] != elem && elemidx < a->len)
        elemidx++;

    return _array_remove(a, elemidx);
}

int array_safe_get(struct array *a, int idx, void **itemout){
    if(!a)
        return ARRAY_NULL;

    if(idx < 0 || idx >= a->len)
        return ARRAY_OOB;

    *itemout = a->items[idx];

    return ARRAY_OK;
}

int array_shrink_to_fit(struct array *a){
    if(!a)
        return ARRAY_NULL;

    void **items_rea = realloc(a->items, a->len * sizeof(void *));

    a->items = items_rea;
    a->capacity = a->len;

    return ARRAY_OK;
}

struct array *array_new(void){
    struct array *a = malloc(sizeof(struct array));

    a->items = NULL;
    a->len = 0;
    a->capacity = STARTING_CAPACITY;

    return a;
}
