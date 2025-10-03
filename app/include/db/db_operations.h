/**
 * @file db_operations.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef DB_OPERATIONS_H
#define DB_OPERATIONS_H

#include "db_internal.h"
#include "void_store.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    DB_OPERATION_PUT_RESERVE = 0
} DB_operation_type_t;

typedef struct
{
    DB_operation_type_t type;
    MDB_dbi             dbi;   /* db in which operate */
    void_store_t*       key_store;
    void_store_t*       val_store;
    unsigned            flags; /* MDB_NOOVERWRITE | MDB_APPEND */
    // MDB_val key;
    // MDB_val val;
    // DB_key_t key;
    // DB_val_t val;

    /* filled by the reserve pass */
    void*  dst;     /* reserved pointer returned by mdb_put */
    size_t dst_len; /* reserved length (for asserts / safety) */
} DB_operation_t;

int exec_ops(DB_operation_t* ops, uint8_t* n_ops);

#ifdef __cplusplus
}
#endif

#endif /* DB_OPERATIONS_H */
