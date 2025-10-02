// void_store.c
#include "void_store.h"
#include <stdlib.h>
#include <string.h>

struct void_store
{
    size_t  n_elements;   /**< Number of managed slots */
    size_t  n_max;        /**< Max manageable slots */
    size_t  tot_size;     /**< Total size */
    void**  elements;     /**< Pointer array of length 'size' */
    size_t* element_size; /**< Size array of length 'size' */
};

/*
 * Initialize a store with 'len' slots, using calloc so that:
 * - el[] entries start as NULL
 * - el_size[] entries start as 0
 *
 * On allocation failure, any successful allocation is released and
 * a zero-initialized (invalid) store is returned (size = 0, pointers = NULL).
 */
int void_store_init(size_t len, void_store_t** st)
{
    if(len <= 0) return -1;

    void_store_t* store = calloc(1, sizeof(void_store_t));

    if(!store) return -1;

    store->n_elements = 0;
    store->n_max      = len;

    /* Zero-initialized arrays */
    store->elements     = (void**)calloc(len, sizeof(void*));
    store->element_size = (size_t*)calloc(len, sizeof(size_t));

    /* If either allocation failed, clean up and return an invalid store */
    if(!store->elements || !store->element_size)
    {
        void_store_close(store);
        return -1;
    }

    /* assign the store */
    *st = store;
    return 0;
}

/*
 * Release internal arrays owned by the store and reset fields.
 * Does not free elements pointed to by el[i]; that remains caller-owned.
 */
void void_store_close(void_store_t* st)
{
    if(!st) return;

    free(st->elements);
    free(st->element_size);
    free(st);
}

int void_store_add(void_store_t* st, void* elem, size_t elem_size)
{
    if(!st || (st->n_elements <= st->n_max)) return -1;

    /* set element ptr */
    st->elements[st->n_elements]      = elem;
    /* sel element size */
    st->element_size[st->n_elements]  = elem_size;
    /* add size to tot */
    st->tot_size                     += elem_size;
    /* increase elements counter */
    st->n_elements++;

    return 0;
}

size_t void_store_size(const void_store_t* st)
{
    if(!st || !st->elements || !st->element_size) return 0;

    size_t total = 0;
    for(size_t i = 0; i < st->n_elements; ++i)
    {
        const void*  p = st->elements[i];
        const size_t n = st->element_size[i];

        if(!p || n <= 0) return 0;

        total += n;
    }

    return total;
}

size_t void_store_memcpy(void* dst, size_t dst_len, const void_store_t* st)
{
    if(!dst || !st || !st->elements || dst_len == 0) return 0;

    if(void_store_size(st) == 0) return 0;

    /* Copy elements in order;
    caller guarantees no overlap with dst. */
    unsigned char* out = (unsigned char*)dst;
    size_t         off = 0;

    for(size_t i = 0; i < st->n_elements; ++i)
    {
        const void*  p = st->elements ? st->elements[i] : NULL;
        const size_t n = st->element_size ? st->element_size[i] : 0;

        if(!p || n <= 0) return 0;

        /* Capacity already checked globally, but keep a defensive guard. */
        if(n > dst_len - off) return 0;

        memcpy(
            out + off, p,
            n); /* Undefined if regions overlap: caller must avoid overlap. */
        off += n;
    }

    return off;
}
