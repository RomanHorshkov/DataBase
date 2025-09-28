#include "kv_core.h"
#include <string.h>
#include "codec.h"
int kv_put(DBI_ID id, const void* key_obj, const void* val_obj, unsigned flags)
{
    MDB_val     k, v;
    dbi_desc_t* d = &db->dbis[id];
    if(d->key_enc(key_obj, &k)) return -EINVAL;
    if(d->val_enc(val_obj, &v)) return -EINVAL;
    MDB_txn* txn;
    int      rc = mdb_txn_begin(db->env, NULL, 0, &txn);
    if(rc) return db_map_mdb_err(rc);
    rc = mdb_put(txn, d->dbi, &k, &v, flags);
    if(rc)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }
    rc = mdb_txn_commit(txn);
    return db_map_mdb_err(rc);
}

int kv_get(DBI_ID id, const void* key_obj, void* out_val_obj)
{
    MDB_val     k, v;
    dbi_desc_t* d = &db->dbis[id];
    if(d->key_enc(key_obj, &k)) return -EINVAL;
    MDB_txn* txn;
    int      rc = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);
    if(rc) return db_map_mdb_err(rc);
    rc = mdb_get(txn, d->dbi, &k, &v);
    if(rc)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }
    rc = d->val_dec ? d->val_dec(&v, out_val_obj) : 0;
    mdb_txn_abort(txn);
    return rc;
}

int kv_del(DBI_ID id, const void* key_obj)
{
    MDB_val     k;
    dbi_desc_t* d = &db->dbis[id];
    if(d->key_enc(key_obj, &k)) return -EINVAL;
    MDB_txn* txn;
    int      rc = mdb_txn_begin(db->env, NULL, 0, &txn);
    if(rc) return db_map_mdb_err(rc);
    rc = mdb_del(txn, d->dbi, &k, NULL);
    if(rc)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }
    rc = mdb_txn_commit(txn);
    return db_map_mdb_err(rc);
}

int kv_del_kv(DBI_ID id, const void* key_obj, const void* val_obj)
{
    MDB_val     k, v;
    dbi_desc_t* d = &db->dbis[id];
    if(d->key_enc(key_obj, &k) || d->val_enc(val_obj, &v)) return -EINVAL;
    MDB_txn* txn;
    int      rc = mdb_txn_begin(db->env, NULL, 0, &txn);
    if(rc) return db_map_mdb_err(rc);
    rc = mdb_del(txn, d->dbi, &k, &v);
    if(rc)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }
    rc = mdb_txn_commit(txn);
    return db_map_mdb_err(rc);
}

int kv_scan(DBI_ID id, const void* start_key_obj, const void* end_key_obj,
            scan_cb cb, void* ud)
{
    dbi_desc_t* d = &db->dbis[id];
    MDB_val     k, v, kstart, kend;
    int         have_s = start_key_obj != NULL;
    int         have_e = end_key_obj != NULL;
    if(have_s && d->key_enc(start_key_obj, &kstart)) return -EINVAL;
    if(have_e && d->key_enc(end_key_obj, &kend)) return -EINVAL;
    MDB_txn* txn;
    int      rc = mdb_txn_begin(db->env, NULL, MDB_RDONLY, &txn);
    if(rc) return db_map_mdb_err(rc);
    MDB_cursor* cur;
    rc = mdb_cursor_open(txn, d->dbi, &cur);
    if(rc)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }
    MDB_cursor_op op   = have_s ? MDB_SET_RANGE : MDB_FIRST;
    MDB_val       seek = have_s ? kstart : k;
    rc                 = mdb_cursor_get(cur, &seek, &v, op);
    while(rc == MDB_SUCCESS)
    {
        k = seek;
        if(have_e)
        {
            int cmp = mdb_cmp(txn, d->dbi, &k, &kend);
            if(cmp > 0) break;
        }
        if(cb(&k, &v, ud) != 0) break;
        rc = mdb_cursor_get(cur, &seek, &v, MDB_NEXT);
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    return 0;
}

/* dump */
struct dump_ctx
{
    dbi_desc_t* d;
    FILE*       out;
};
static int dump_cb(const MDB_val* k, const MDB_val* v, void* ud)
{
    struct dump_ctx* c = (struct dump_ctx*)ud;
    if(c->d->key_prn)
        c->d->key_prn(k, c->out);
    else
        fprintf(c->out, "<k %zuB>", k->mv_size);
    fputs(" → ", c->out);
    if(c->d->val_prn)
        c->d->val_prn(v, c->out);
    else
        fprintf(c->out, "<v %zuB>", v->mv_size);
    fputc('\n', c->out);
    return 0;
}
int kv_dump(DBI_ID id, FILE* out)
{
    struct dump_ctx c = {.d = &db->dbis[id], .out = out};
    return kv_scan(id, NULL, NULL, dump_cb, &c);
}
int kv_dump_all(FILE* out)
{
    for(int i = 0; i < DBI_COUNT; i++)
    {
        fprintf(out, "# %s", db->dbis[i].name);
        kv_dump((DBI_ID)i, out);
    }
    return 0;
}
