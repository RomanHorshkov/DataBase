/* db_operations.c */
// #include <stdlib.h>
// #include <string.h>
// #include "codec.h"
#include "db_operations.h"

#include "utils_interface.h"

// /* Extend the registry with optional value measure/write hooks (non-breaking default NULL) */
// typedef struct
// {
//     const char*  name;
//     db_encode_fn key_enc;
//     db_decode_fn key_dec;
//     db_print_fn  key_prn;
//     db_encode_fn val_enc; /* existing single-shot encoder */
//     db_decode_fn val_dec;
//     db_print_fn  val_prn;
//     db_cmp_fn    cmp;
//     unsigned     open_flags;
//     unsigned     put_flags;
//     MDB_dbi      dbi;

//     /* NEW (optional): if set, batch can use MDB_RESERVE + write */
//     val_measure_fn val_meas;
//     val_write_fn   val_write;
// } dbi_desc_ext_t;

// /* Reserve+write with fallback to single-encoder for DBIs lacking measure/write. */
// static int db_ops_execute_once(DB* db, db_ops_batch* b)
// {
//     MDB_txn* txn = NULL;
//     int      rc  = mdb_txn_begin(db->env, NULL, 0, &txn);
//     if(rc) return rc;

//     /* Pass 1: encode keys and reserve values where supported. */
//     for(size_t i = 0; i < b->count; ++i)
//     {
//         db_op_t*        op = &b->ops[i];
//         dbi_desc_ext_t* d  = (dbi_desc_ext_t*)&db->dbis[op->dbi_id];

//         /* Encode key */
//         if(d->key_enc(op->key_obj, &op->k))
//         {
//             rc = EINVAL;
//             goto abort;
//         }

//         /* Prefer reserve path if measure/write available */
//         if(d->val_meas && d->val_write)
//         {
//             size_t vlen = 0;
//             rc          = d->val_meas(op->val_obj, &vlen);
//             if(rc) goto abort;

//             MDB_val  v = {.mv_size = vlen, .mv_data = NULL};
//             unsigned put_flags =
//                 op->flags | db->dbis[op->dbi_id].put_flags | MDB_RESERVE;
//             rc = mdb_put(txn, d->dbi, &op->k, &v, put_flags);
//             if(rc) goto abort;
//             op->dst     = v.mv_data;
//             op->dst_len = v.mv_size;
//         }
//         else
//         {
//             /* Fallback: encode value now and put without reserve */
//             MDB_val v;
//             if(d->val_enc(op->val_obj, &v))
//             {
//                 rc = EINVAL;
//                 goto abort;
//             }
//             unsigned put_flags = op->flags | db->dbis[op->dbi_id].put_flags;
//             rc                 = mdb_put(txn, d->dbi, &op->k, &v, put_flags);
//             if(rc) goto abort;
//         }
//     }

//     /* Pass 2: write into reserved areas (only those using reserve path). */
//     for(size_t i = 0; i < b->count; ++i)
//     {
//         db_op_t* op = &b->ops[i];
//         if(!op->dst) continue; /* fallback ops already written */
//         dbi_desc_ext_t* d = (dbi_desc_ext_t*)&db->dbis[op->dbi_id];
//         rc                = d->val_write(op->dst, op->dst_len, op->val_obj);
//         if(rc) goto abort;
//     }

//     rc = mdb_txn_commit(txn);
//     return rc;

// abort:
//     mdb_txn_abort(txn);
//     return rc;
// }

// int db_ops_execute(DB* db, db_ops_batch* b)
// {
// retry:
//     int rc = db_ops_execute_once(db, b);
//     if(rc == MDB_MAP_FULL)
//     {
//         int gr = db_env_mapsize_expand(db);
//         if(gr != 0) return db_map_mdb_err(gr);
//         goto retry;
//     }
//     return db_map_mdb_err(rc);
// }
static int op_write_reserved(MDB_txn* txn, DB_operation_t* operations,
                             uint8_t* n_ops)
{
    int ret = -1;
    for(size_t i = 0; i < *n_ops; i++)
    {
        /* get the single operation */
        DB_operation_t* op = &operations[i];

        switch(op->op_type)
        {
            case DB_OPERATION_PUT_RESERVE:

                /* must be set by reserve pass */
                if(!op->dst || op->dst_len <= 0) return -EFAULT;

                /* write all the data */
                ret = void_store_memcpy(op->dst, op->dst_len, op->val_store);
                if(ret != 0)
                {
                    return ret;
                }
                break;

            default:
                ret = -1;
                break;
        }
    }

    return ret;
}

static int op_reserve(MDB_txn* txn, DB_operation_t* operation)
{
    /* Create afresh keys to not corrupt original data */
    /* copy the same key */
    MDB_val k = {.mv_size = void_store_size(operation->key_store),
                 .mv_data = NULL};
    void_store_memcpy(k.mv_data, k.mv_size, operation->key_store);

    /* copy just data size  */
    MDB_val v = {.mv_size = void_store_size(operation->val_store),
                 .mv_data = NULL};

    int ret = mdb_put(txn, operation->dbi, &k, &v, MDB_RESERVE);

    if(ret != MDB_SUCCESS)
    {
        return ret;
    }

    /* remember where to write later */
    operation->dst     = v.mv_data;
    operation->dst_len = v.mv_size;

    return ret;
}

int exec_ops(DB_operation_t* ops, uint8_t* n_ops)
{
    if(!ops || *n_ops <= 0) return -EINVAL;

    /* Initialize the transaction */
    MDB_txn* txn = NULL;

    int ret = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(ret != MDB_SUCCESS) return ret;

    for(size_t i = 0; i < *n_ops; i++)
    {
        /* get the single operation */
        DB_operation_t* op = &ops[i];

        switch(op->op_type)
        {
            case DB_OPERATION_PUT_RESERVE:
                ret = op_reserve(txn, op);
                if(ret != MDB_SUCCESS) goto fail;
                break;

            default:
                break;
        }
    }

    op_write_reserved(txn, ops, n_ops);

fail:
    mdb_txn_abort(txn);
    return -1;
}
