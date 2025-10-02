/**
 * @file db.h
 * @brief 
 * Generic, type-aware batch that reuses
 * dbi_desc_t encoders and optional reservers
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef DB_OPERATIONS_H
#define DB_OPERATIONS_H

#pragma once
#include <stddef.h>
#include "db.h"
#include "kv_core.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef int (*val_measure_fn)(const void* obj, size_t* out_len);
/* write_fn must write exactly dst_len bytes derived from measure_fn */
typedef int (*val_write_fn)(void* dst, size_t dst_len, const void* obj);

typedef struct
{
    const void* key_obj; /* typed key object for key_enc() */
    const void*
           val_obj; /* typed value object for val_meas/val_write or val_enc */
    DBI_ID dbi_id;  /* DBI enum */
    unsigned
        flags; /* caller flags (NO_OVERWRITE, APPEND, DUPSORT pairing, etc.) */

    /* internal after reserve pass */
    MDB_val k;       /* encoded key */
    void*   dst;     /* reserved destination */
    size_t  dst_len; /* reserved size */
} db_op_t;

typedef struct
{
    db_op_t* ops;
    size_t   count;
    size_t   cap;
} db_ops_batch;

/* Lifecycle */
void db_ops_init(db_ops_batch* b);
void db_ops_reset(db_ops_batch* b);
void db_ops_free(db_ops_batch* b);

/* Add a generic op (typed key/value follow dbi-desc encoders and writers). */
int db_ops_add(db_ops_batch* b, DBI_ID id, const void* key_obj,
               const void* val_obj, unsigned flags);

/* Execute all ops atomically with reserve-then-write; retries on MAP_FULL. */
int db_ops_execute(DB* db, db_ops_batch* b);

#ifdef __cplusplus
}
#endif

#endif /* DB_OPERATIONS_H */
