// void_store.c
#include "void_store.h"
#include <stdio.h>
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
        free(store);
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
void void_store_close(void_store_t** st)
{
    if(!st || !*st) return;
    void_store_t* store = *st;
    free(store->elements);
    free(store->element_size);
    free(store);
    *st = NULL;  // avoid dangling pointer
}

int void_store_add(void_store_t* st, void* elem, size_t elem_size)
{
    if(!st || (st->n_elements >= st->n_max)) return -1;

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

void* void_store_get(const void_store_t* st, size_t idx)
{
    return st->elements[idx];
}

void* void_store_malloc_buf(void_store_t* st)
{
    if(!st)
    {
        fprintf(stderr, "[void_store_malloc_buf] invalid input\n");
        return NULL;
    }

    size_t len = void_store_size(st);
    if(!len)
    {
        fprintf(stderr, "[void_store_malloc_buf] empty store\n");
        return NULL;
    }

    void* buf = malloc(len);

    if(!buf)
    {
        fprintf(stderr, "[void_store_malloc_buf] malloc failed\n");
        return NULL;
    }

    if(void_store_memcpy(buf, len, st) != len)
    {
        fprintf(stderr, "[void_store_malloc_buf] memcpy failed\n");
        free(buf);
        return NULL;
    }

    return buf;
}

size_t void_store_size(const void_store_t* st)
{
    return st ? st->tot_size : 0;
}

size_t void_store_memcpy(void* dst, size_t dst_len, const void_store_t* st)
{
    if(!dst || !st || !st->elements || !st->element_size) return 0;
    size_t need = void_store_size(st);
    if(need == 0 || need > dst_len) return 0;
    unsigned char* out = (unsigned char*)dst;
    size_t         off = 0;
    for(size_t i = 0; i < st->n_elements; ++i)
    {
        const void* p = st->elements[i];
        size_t      n = st->element_size[i];
        if(!p || n == 0) return 0;
        memcpy(out + off, p, n);
        off += n;
    }

    return off == need ? off : 0;
}
