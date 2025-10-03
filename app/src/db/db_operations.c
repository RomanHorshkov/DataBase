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

static void free_ops(DB_operation_t** ops, uint8_t* n_ops);

static int op_write_reserved(DB_operation_t* operations, uint8_t* n_ops);

static int op_reserve(MDB_txn* txn, DB_operation_t* op);

static int exec_op(MDB_txn* txn, DB_operation_t* op);

int exec_ops(DB_operation_t* ops, uint8_t* n_ops)
{
    if(!ops || *n_ops == 0)
    {
        fprintf(stderr, "[dp_operations] exec_ops invalid input");
        return -EINVAL;
    }

    /* Initialize the transaction */
    MDB_txn* txn = NULL;

retry:
    int ret = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(ret != MDB_SUCCESS) goto fail;

    for(size_t i = 0; i < *n_ops; i++)
    {
        /* exec single operation */
        ret = exec_op(txn, &ops[i]);

        if(ret != MDB_SUCCESS)
        {
            if(ret == MDB_MAP_FULL)
            {
                mdb_txn_abort(txn);
                ret = db_env_mapsize_expand();
                if(ret != 0) goto fail;
                goto retry;
            }

            goto fail;
        }
    }

    ret = op_write_reserved(ops, n_ops);
    if(ret == 0) goto fail;

    /* Commit the transaction */
    ret = mdb_txn_commit(txn);
    if(ret == MDB_MAP_FULL)
    {
        /* txn aborted by commit */
        ret = db_env_mapsize_expand();
        if(ret != 0)
        {
            fprintf(stderr,
                    "[dp_operations] exec_ops failed \
                    expanding mapsize %d\n",
                    ret);
            goto fail;
        }
        goto retry;
    }

    /* free operations */
    free_ops(&ops, n_ops);

    return ret;
fail:
    mdb_txn_abort(txn);
    free_ops(&ops, n_ops);
    return ret;
}

static void free_ops(DB_operation_t** ops, uint8_t* n_ops)
{
    if(!ops || !*ops || !n_ops) return;
    DB_operation_t* arr = *ops;
    for(size_t i = 0; i < *n_ops; i++)
    {
        void_store_close(&arr[i].key_store);
        void_store_close(&arr[i].val_store);
    }
    free(arr);
    *ops = NULL;
}

static int op_write_reserved(DB_operation_t* operations, uint8_t* n_ops)
{
    int ret = -1;
    for(size_t i = 0; i < *n_ops; i++)
    {
        /* get the single operation */
        DB_operation_t* op = &operations[i];
        if(op->type != DB_OPERATION_PUT_RESERVE) continue;

        /* must be set by reserve pass */
        if(!op->dst || op->dst_len <= 0) return -EFAULT;

        size_t wrote = void_store_memcpy(op->dst, op->dst_len, op->val_store);
        if(wrote != op->dst_len) return -EFAULT;
    }

    return ret;
}

static int op_reserve(MDB_txn* txn, DB_operation_t* op)
{
    size_t klen = void_store_size(op->key_store);
    size_t vlen = void_store_size(op->val_store);
    if(klen == 0 || vlen == 0) return -EINVAL;

    /* Create key buffer */
    void* kbuf = malloc(klen);
    if(!kbuf) return -ENOMEM;
    if(void_store_memcpy(kbuf, klen, op->key_store) != klen)
    {
        free(kbuf);
        return -EFAULT;
    }

    // MDB_val k = { .mv_size = klen, .mv_data = void_store_get(op->key_store, 0) };
    MDB_val k = {.mv_size = klen, .mv_data = kbuf};
    MDB_val v = {.mv_size = vlen, .mv_data = NULL};

    /* Reserve value bytes; on success v.mv_data points to LMDB-owned space */
    int ret = mdb_put(txn, op->dbi, &k, &v, op->flags | MDB_RESERVE);
    free(kbuf);
    if(ret != MDB_SUCCESS)
    {
        fprintf(stderr, "[dp_operations] op_reserve %d\n", ret);
        return ret;
    }

    /* remember where to write later */
    op->dst     = v.mv_data;
    op->dst_len = v.mv_size;

    return ret;
}

static int exec_op(MDB_txn* txn, DB_operation_t* op)
{
    switch(op->type)
    {
        case DB_OPERATION_PUT_RESERVE:
            return op_reserve(txn, op);

        default:
            return -1;
    }
}
