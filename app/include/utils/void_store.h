/**
 * @file auth_interface.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef VOID_STORE_H
#define VOID_STORE_H

/**
 * @file void_store.h
 * @brief Minimal generic store of pointers paired with their element sizes.
 *
 * This interface manages two parallel arrays: one holding generic element
 * pointers and one holding the corresponding element sizes in bytes.
 * The container itself does not own or free the elements; it only manages
 * the arrays that track them.
 */

#include <stddef.h>  // size_t

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @struct void_store
 * @brief Container for generic pointers and their sizes.
 *
 * - size: number of slots managed by this store.
 * - el: array of void* element slots of length 'size'.
 * - el_size: array of size_t element sizes of length 'size'.
 *
 * The store does not allocate or free the pointed-to elements; ownership stays
 * with the caller. All fields are public for simple, C-style access patterns.
 */

typedef struct void_store void_store_t;

/**
 * @brief Initialize a store with 'len' slots.
 *
 * Allocates the internal arrays 'el' and 'el_size' with 'len' entries each and
 * returns the store by value, zero-initialized on creation. On allocation
 * failure, the returned store will have one or both arrays set to NULL; caller
 * should check for NULL before use.
 *
 * @param len Number of slots to allocate.
 * @param st Pointer to the store to open; ignored if NULL.
 * @return Initialized store (by value). Arrays may be NULL on allocation failure.
 */
int void_store_init(size_t len, void_store_t** st);

/**
 * @brief Release internal arrays owned by the store.
 *
 * Frees 'el' and 'el_size' if non-NULL and resets fields to safe defaults.
 * This function does not free elements referenced by 'el[i]'; freeing those
 * remains the caller's responsibility.
 *
 * @param st Pointer to the store to close; ignored if NULL.
 */
void void_store_close(void_store_t* st);

/**
 * @brief Append an element pointer and its size to the end of the store.
 *
 * Grows the internal arrays by one slot, assigns the provided pointer and size,
 * and returns the index of the inserted element via out_index when non-NULL.
 *
 * The store does not take ownership of elem; the caller is responsible for its lifetime.
 *
 * @param st          Store to mutate (must not be NULL).
 * @param elem        Pointer to element payload (may be non-NULL to be recorded).
 * @param elem_size   Size in bytes of elem; may be 0 if elem is NULL.
 * @return 0 on success; -1 on allocation/overflow error.
 */
int void_store_add(void_store_t* st, void* elem, size_t elem_size);

/**
 * @brief Compute total byte length of all non-NULL elements.
 *
 * Sums st->el_size[i] where st->el[i] != NULL with overflow checks.
 * On success writes returns the sum; otherwise -1.
 */
size_t void_store_size(const void_store_t* st);

/**
 * @brief Serialize the entire store into dst (contiguously).
 *
 * Precondition: dst points to a buffer of at least dst_len bytes and
 * does not overlap any st->el[i] region; on success returns the number
 * of bytes written, otherwise -1.
 */
size_t void_store_memcpy(void* dst, size_t dst_len, const void_store_t* st);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // VOID_STORE_H
