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
    DB_OPERATION_NONE = 0,
    DB_OPERATION_PUT,
    DB_OPERATION_GET,
    DB_OPERATION_MAX,
} DB_operation_type_t;

struct DB_operation
{
    DB_operation_type_t type;
    MDB_dbi             dbi;   /* db in which operate */
    void_store_t*       key_store;
    void_store_t*       val_store;
    unsigned            flags; /* MDB_NOOVERWRITE | MDB_APPEND */

    struct DB_operation* prev;
    struct DB_operation* next;

    /* emergency variables */
    void*  dst;
    size_t dst_len;
};

typedef struct DB_operation DB_operation_t;

int  ops_prepare_op(DB_operation_t* op, DB_operation_type_t type, MDB_dbi dbi,
                    unsigned flags);
int  ops_link(DB_operation_t* ops, uint8_t n_ops);
int  ops_exec(DB_operation_t* ops, uint8_t* n_ops);
void ops_free(DB_operation_t** ops, uint8_t* n_ops);

#ifdef __cplusplus
}
#endif

#endif /* DB_OPERATIONS_H */
