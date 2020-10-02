#ifndef _ARRAY_H_
#define _ARRAY_H_

struct array {
    /* the items that make up the array */
    void **items;

    /* how many items the array currently holds */
    unsigned long len;

    /* The amount of memory allocated for this array.
     * Doubles every time a->len >= a->capacity - 1.
     */
    unsigned long capacity;
};

enum {
    ARRAY_OK = 0, ARRAY_NULL, ARRAY_OOB, ARRAY_KEY_NOT_FOUND
};

int array_bsearch(struct array *, const void *,
        int (*)(const void *, const void *), void **);
int array_clear(struct array *);
int array_destroy(struct array **);
int array_empty(struct array *);
int array_insert(struct array *, void *);
int array_qsort(struct array *, int (*)(const void *, const void *));
int array_remove(struct array *, int);
int array_remove_elem(struct array *, void *);
int array_safe_get(struct array *, int, void **);
int array_shrink_to_fit(struct array *);

struct array *array_new(void);

#endif
