/* db_operations.c */
#include <stdlib.h>
#include <string.h>
#include "codec.h"
#include "db_operations.h"

/* Extend the registry with optional value measure/write hooks (non-breaking default NULL) */
typedef struct
{
    const char*  name;
    db_encode_fn key_enc;
    db_decode_fn key_dec;
    db_print_fn  key_prn;
    db_encode_fn val_enc; /* existing single-shot encoder */
    db_decode_fn val_dec;
    db_print_fn  val_prn;
    db_cmp_fn    cmp;
    unsigned     open_flags;
    unsigned     put_flags;
    MDB_dbi      dbi;

    /* NEW (optional): if set, batch can use MDB_RESERVE + write */
    val_measure_fn val_meas;
    val_write_fn   val_write;
} dbi_desc_ext_t;

/* Assume db->dbis is compatible with dbi_desc_ext_t in this TU. */

/* Basic vector mgmt */
void db_ops_init(db_ops_batch* b)
{
    b->ops   = NULL;
    b->count = 0;
    b->cap   = 0;
}
void db_ops_reset(db_ops_batch* b)
{
    b->count = 0;
}
void db_ops_free(db_ops_batch* b)
{
    free(b->ops);
    b->ops   = NULL;
    b->count = b->cap = 0;
}

static int db_ops_grow(db_ops_batch* b, size_t want)
{
    if(b->cap >= want) return 0;
    size_t ncap = b->cap ? b->cap * 2 : 8;
    while(ncap < want)
        ncap *= 2;
    void* p = realloc(b->ops, ncap * sizeof(db_op_t));
    if(!p) return -ENOMEM;
    b->ops = (db_op_t*)p;
    b->cap = ncap;
    return 0;
}

int db_ops_add(db_ops_batch* b, DBI_ID id, const void* key_obj,
               const void* val_obj, unsigned flags)
{
    if(!b || !key_obj || !val_obj) return -EINVAL;
    int rc = db_ops_grow(b, b->count + 1);
    if(rc) return rc;
    db_op_t* op   = &b->ops[b->count++];
    op->dbi_id    = id;
    op->key_obj   = key_obj;
    op->val_obj   = val_obj;
    op->flags     = flags;
    op->k.mv_data = NULL;
    op->k.mv_size = 0;
    op->dst       = NULL;
    op->dst_len   = 0;
    return 0;
}

/* Reserve+write with fallback to single-encoder for DBIs lacking measure/write. */
static int db_ops_execute_once(DB* db, db_ops_batch* b)
{
    MDB_txn* txn = NULL;
    int      rc  = mdb_txn_begin(db->env, NULL, 0, &txn);
    if(rc) return rc;

    /* Pass 1: encode keys and reserve values where supported. */
    for(size_t i = 0; i < b->count; ++i)
    {
        db_op_t*        op = &b->ops[i];
        dbi_desc_ext_t* d  = (dbi_desc_ext_t*)&db->dbis[op->dbi_id];

        /* Encode key */
        if(d->key_enc(op->key_obj, &op->k))
        {
            rc = EINVAL;
            goto abort;
        }

        /* Prefer reserve path if measure/write available */
        if(d->val_meas && d->val_write)
        {
            size_t vlen = 0;
            rc          = d->val_meas(op->val_obj, &vlen);
            if(rc) goto abort;

            MDB_val  v = {.mv_size = vlen, .mv_data = NULL};
            unsigned put_flags =
                op->flags | db->dbis[op->dbi_id].put_flags | MDB_RESERVE;
            rc = mdb_put(txn, d->dbi, &op->k, &v, put_flags);
            if(rc) goto abort;
            op->dst     = v.mv_data;
            op->dst_len = v.mv_size;
        }
        else
        {
            /* Fallback: encode value now and put without reserve */
            MDB_val v;
            if(d->val_enc(op->val_obj, &v))
            {
                rc = EINVAL;
                goto abort;
            }
            unsigned put_flags = op->flags | db->dbis[op->dbi_id].put_flags;
            rc                 = mdb_put(txn, d->dbi, &op->k, &v, put_flags);
            if(rc) goto abort;
        }
    }

    /* Pass 2: write into reserved areas (only those using reserve path). */
    for(size_t i = 0; i < b->count; ++i)
    {
        db_op_t* op = &b->ops[i];
        if(!op->dst) continue; /* fallback ops already written */
        dbi_desc_ext_t* d = (dbi_desc_ext_t*)&db->dbis[op->dbi_id];
        rc                = d->val_write(op->dst, op->dst_len, op->val_obj);
        if(rc) goto abort;
    }

    rc = mdb_txn_commit(txn);
    return rc;

abort:
    mdb_txn_abort(txn);
    return rc;
}

int db_ops_execute(DB* db, db_ops_batch* b)
{
retry:
    int rc = db_ops_execute_once(db, b);
    if(rc == MDB_MAP_FULL)
    {
        int gr = db_env_mapsize_expand(db);
        if(gr != 0) return db_map_mdb_err(gr);
        goto retry;
    }
    return db_map_mdb_err(rc);
}
