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

static int op_put(MDB_txn* txn, DB_operation_t* op);

static int op_get(MDB_txn* txn, DB_operation_t* op);

static int exec_op(MDB_txn* txn, DB_operation_t* op);

void ops_free(DB_operation_t** ops, uint8_t* n_ops);

int ops_prepare_op(DB_operation_t* op, DB_operation_type_t type, MDB_dbi dbi,
                   unsigned flags)
{
    if(!op || type <= DB_OPERATION_NONE || type >= DB_OPERATION_MAX)
    {
        return -EIO;
    }

    op->type  = type;
    op->dbi   = dbi;
    op->flags = flags;

    /* linking */
    op->prev = NULL;
    op->next = NULL;

    return 0;
}

int ops_link(DB_operation_t* ops, uint8_t n_ops)
{
    if(!ops) return -EIO;

    /* Nothing to link */
    if(n_ops <= 1) return 0;

    /* Use size_t for indexing but compare with n_ops after cast */
    for(size_t i = 0; i < (size_t)n_ops; ++i)
    {
        DB_operation_t* op = &ops[i];

        if(i == 0)
        {
            op->prev = NULL;
            op->next = &ops[i + 1];
        }
        else if(i == (size_t)n_ops - 1)
        {
            op->prev = &ops[i - 1];
            op->next = NULL;
        }
        else
        {
            op->prev = &ops[i - 1];
            op->next = &ops[i + 1];
        }
    }

    return 0;
}
int ops_exec(DB_operation_t* ops, uint8_t* n_ops)
{
    if(!ops || *n_ops == 0)
    {
        fprintf(stderr, "[dp_operations] ops_exec invalid input");
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

    /* Commit the transaction */
    ret = mdb_txn_commit(txn);
    if(ret == MDB_MAP_FULL)
    {
        /* txn aborted by commit */
        ret = db_env_mapsize_expand();
        if(ret != 0)
        {
            fprintf(stderr,
                    "[dp_operations] ops_exec failed \
                    expanding mapsize %d\n",
                    ret);
            goto fail;
        }
        goto retry;
    }

    return ret;
fail:
    mdb_txn_abort(txn);
    ops_free(&ops, n_ops);
    return ret;
}

static int op_get(MDB_txn* txn, DB_operation_t* op)
{
    MDB_val k    = {0};
    MDB_val v    = {0};
    void*   kbuf = NULL;
    int     ret;

    /* If a key store exists, build key buffer from it */
    if(op->key_store)
    {
        kbuf = void_store_malloc_buf(op->key_store);
        if(!kbuf)
        {
            fprintf(stderr, "[op_get] void_store_malloc_buf failed\n");
            return -ENOMEM;
        }
        k.mv_size = void_store_size(op->key_store);
        k.mv_data = kbuf;
    }
    else
    {
        /* No key_store: try to use previous op's dst as key (runtime dependency) */
        if(!op->prev || !op->prev->dst || op->prev->dst_len == 0)
        {
            fprintf(stderr, "[op_get] missing prev result for key\n");
            return -EINVAL;
        }
        k.mv_size = op->prev->dst_len;
        k.mv_data = op->prev->dst; /* do NOT free this pointer here */
        kbuf      = NULL;          /* mark didn't allocate */
    }

    ret = mdb_get(txn, op->dbi, &k, &v);

    /* free key buffer if allocated one */
    if(kbuf) free(kbuf);

    if(ret != MDB_SUCCESS)
    {
        if(ret != MDB_NOTFOUND) /* optional: special-case NOTFOUND handling */
            fprintf(stderr, "[dp_operations] op_get mdb_get %d\n", ret);
        return ret;
    }

    /* copy value out to a new buffer owned by op->dst */
    void* buf = malloc(v.mv_size);
    if(!buf)
    {
        fprintf(stderr, "[dp_operations] op_get malloc failed\n");
        return -ENOMEM;
    }
    memcpy(buf, v.mv_data, v.mv_size);

    /* save result in op (caller/ops_free will free) */
    op->dst     = buf;
    op->dst_len = v.mv_size;
    return MDB_SUCCESS;
}

static int op_put(MDB_txn* txn, DB_operation_t* op)
{
    /* allocate the key */
    void* kbuf = void_store_malloc_buf(op->key_store);
    if(!kbuf)
    {
        fprintf(stderr, "[op_put] void_store_malloc_buf failed\n");
        return -ENOMEM;
    }

    size_t vlen = void_store_size(op->val_store);
    if(vlen == 0)
    {
        free(kbuf);
        return -EINVAL;
    }

    MDB_val k = {.mv_size = void_store_size(op->key_store), .mv_data = kbuf};
    MDB_val v = {.mv_size = vlen, .mv_data = NULL};

    int rc = mdb_put(txn, op->dbi, &k, &v, op->flags | MDB_RESERVE);
    if(rc != MDB_SUCCESS)
    {
        free(kbuf);
        fprintf(stderr, "[db_operations] op_put reserve %d\n", rc);
        return rc;
    }

    size_t wrote = void_store_memcpy(v.mv_data, v.mv_size, op->val_store);
    if(wrote != v.mv_size)
    {
        // App encoding bug; value didn't match promised size
        free(kbuf);
        return -EFAULT;
    }

    free(kbuf);
    return MDB_SUCCESS;
}

static int exec_op(MDB_txn* txn, DB_operation_t* op)
{
    switch(op->type)
    {
        case DB_OPERATION_PUT:
            return op_put(txn, op);

        case DB_OPERATION_GET:
            return op_get(txn, op);
        default:
            return -1;
    }
}

void ops_free(DB_operation_t** ops, uint8_t* n_ops)
{
    if(!ops || !*ops || !n_ops) return;
    DB_operation_t* arr = *ops;
    for(size_t i = 0; i < *n_ops; i++)
    {
        /* close void stores (tolerant to NULL) */
        void_store_close(&arr[i].key_store);
        void_store_close(&arr[i].val_store);

        /* free any result buffers allocated by op_get */
        if(arr[i].dst)
        {
            free(arr[i].dst);
            arr[i].dst     = NULL;
            arr[i].dst_len = 0;
        }
    }
    free(arr);
    *ops = NULL;
}
