/**
 * @file db_data.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db_acl.h"
#include "db_int.h"
#include "fsutil.h"
#include "sha256.h"
#include "uuid.h"

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */

static int      db_user_get_role(const uint8_t id[DB_ID_SIZE],
                                 user_role_t  *out_role);
static uint64_t now_secs(void);

static inline void write_data_meta(void *dst, const Sha256 *digest,
                                   const char *mime, uint64_t size,
                                   uint64_t      created_at,
                                   const uint8_t owner[DB_ID_SIZE])
{
    DataMeta *m = (DataMeta *)dst;
    memset(m, 0, sizeof *m);
    m->ver = DB_VER;
    memcpy(m->sha, digest->b, 32);
    snprintf(m->mime, sizeof m->mime, "%s",
             (mime && *mime) ? mime : "application/octet-stream");
    m->size       = size;
    m->created_at = created_at;
    memcpy(m->owner, owner, DB_ID_SIZE);
}

static inline int db_data_get_and_check_mem(const MDB_val *v, DataMeta *out)
{
    if(!v || v->mv_size != sizeof(DataMeta)) return -EINVAL;
    if(out) memcpy(out, v->mv_data, sizeof *out);
    return 0;
}

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

int db_data_get_meta(uint8_t data_id[DB_ID_SIZE], DataMeta *out_meta)
{
    if(!out_meta) return -EINVAL;
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = data_id};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_data_id2meta, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }

    mrc = db_data_get_and_check_mem(&v, out_meta);

    mdb_txn_abort(txn);
    return mrc;
}

int db_data_get_path(uint8_t data_id[DB_ID_SIZE], char *out_path,
                     unsigned long out_sz)
{
    if(!out_path || out_sz == 0 || !data_id) return -EINVAL;

    DataMeta meta;
    int      rc = db_data_get_meta(data_id, &meta);
    if(rc != 0) return rc; /* already -ENOENT / -EIO / -EINVAL */

    char   hex[65];
    Sha256 d;
    memcpy(d.b, meta.sha, 32);
    crypt_sha256_hex(&d, hex);

    if(path_sha256(out_path, out_sz, DB->root, hex) < 0) return -EIO;
    return 0;
}

int db_data_add_from_fd(uint8_t owner[DB_ID_SIZE], int src_fd, const char *mime,
                        uint8_t out_data_id[DB_ID_SIZE])
{
    if(!owner || src_fd < 0) return -EINVAL;

    user_role_t owner_role;
    memset(&owner_role, 0, sizeof(user_role_t));

    /* Permission check: owner must exist and be a publisher */
    {
        int prc = db_user_get_role(owner, &owner_role);
        if(prc != 0) return db_map_mdb_err(prc);
        if(owner_role != USER_ROLE_PUBLISHER) return -EPERM;
    }

    /* One-pass ingest: stream → temp → fsync → atomic publish; compute digest+size */
    Sha256 digest;
    size_t total = 0;
    if(crypt_store_sha256_object_from_fd(DB->root, src_fd, &digest, &total) !=
       0)
        return -EIO;

    /* Upsert sha2data and data_meta in a single transaction */
    uint8_t  data_id[DB_ID_SIZE] = {0};
    unsigned db_sha2id_put_flags = MDB_NOOVERWRITE | MDB_RESERVE;
    unsigned db_dataid_put_flags = MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND;

retry_chunk:
    MDB_txn *txn = NULL;

    int mrc = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    /* sha -> id, make sure unique exists */
    MDB_val shak = {.mv_size = 32, .mv_data = (void *)digest.b};
    MDB_val shav = {.mv_size = DB_ID_SIZE, .mv_data = NULL};

    mrc = mdb_put(txn, DB->db_data_sha2id, &shak, &shav, db_sha2id_put_flags);
    if(mrc == MDB_MAP_FULL)
    {
        mdb_txn_abort(txn);
        int grc = db_env_mapsize_expand();       /* grow */
        if(grc != 0) return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;                        /* retry whole chunk */
    }
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }
    /* generate new id, write it into reserved sha->id slot */
    uuid_v7(data_id);

    MDB_val datak = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};
    MDB_val datav = {.mv_size = sizeof(DataMeta), .mv_data = NULL};

    mrc =
        mdb_put(txn, DB->db_data_id2meta, &datak, &datav, db_dataid_put_flags);
    if(mrc == MDB_MAP_FULL)
    {
        mdb_txn_abort(txn);
        int grc = db_env_mapsize_expand();       /* grow */
        if(grc != 0) return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;                        /* retry whole chunk */
    }
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }

    /* write new id into reserved sha->id slot */
    memcpy(shav.mv_data, data_id, DB_ID_SIZE);

    /* fill DataMeta in-place (no stack buffer) */
    write_data_meta(datav.mv_data, &digest, mime, (uint64_t)total, now_secs(),
                    owner);

    mrc = acl_grant_owner(txn, owner, data_id);

    if(mrc == MDB_MAP_FULL)
    {
        mdb_txn_abort(txn);
        int grc = db_env_mapsize_expand();       /* grow */
        if(grc != 0) return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;                        /* retry whole chunk */
    }
    if(mrc != 0)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }

    mrc = mdb_txn_commit(txn);
    if(mrc == MDB_MAP_FULL)
    {
        int grc = db_env_mapsize_expand();
        if(grc != 0) return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;
    }
    if(mrc != MDB_SUCCESS)
    {
        /* txn is already aborted/freed on commit error */
        return db_map_mdb_err(mrc);
    }
    if(out_data_id) memcpy(out_data_id, data_id, DB_ID_SIZE);
    return 0;
}

int db_data_delete(const uint8_t owner[DB_ID_SIZE],
                   const uint8_t data_id[DB_ID_SIZE])
{
    if(!owner || !data_id) return -EINVAL;

    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS) return -EIO;

    /* must be owner */
    {
        int rc = acl_has_owner(txn, owner, data_id);
        if(rc != 0)
        {
            mdb_txn_abort(txn);
            return rc;
        }
    }

    /* fetch meta (for blob path) */
    DataMeta meta = {0};
    {
        MDB_val k  = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};
        MDB_val v  = {0};
        int     rc = mdb_get(txn, DB->db_data_id2meta, &k, &v);
        if(rc == MDB_NOTFOUND)
        {
            mdb_txn_abort(txn);
            return -ENOENT;
        }
        if(rc != MDB_SUCCESS || v.mv_size != sizeof(DataMeta))
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
        memcpy(&meta, v.mv_data, sizeof meta);
    }

    /* nuke all ACLs for this data */
    {
        int rc = acl_data_destroy(txn, data_id);
        if(rc != 0)
        {
            mdb_txn_abort(txn);
            return rc;
        }
    }

    /* drop lookups */
    {
        MDB_val sk = {.mv_size = 32, .mv_data = meta.sha};
        (void)mdb_del(txn, DB->db_data_sha2id, &sk, NULL);

        MDB_val mk = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};
        (void)mdb_del(txn, DB->db_data_id2meta, &mk, NULL);
    }

    int mrc = mdb_txn_commit(txn);
    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    /* best-effort unlink (DB is source of truth) */
    {
        char   path[4096], hex[65];
        Sha256 d;
        memcpy(d.b, meta.sha, 32);
        crypt_sha256_hex(&d, hex);
        if(path_sha256(path, sizeof path, DB->root, hex) == 0)
            (void)unlink(path);
    }

    return 0;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static int db_user_get_role(const uint8_t id[DB_ID_SIZE], user_role_t *out_role)
{
    if(!id || !out_role) return -EINVAL;

    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = (void *)id};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_user_id2data, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc == MDB_NOTFOUND ? MDB_NOTFOUND : mrc);
    }

    uint8_t role = 0;
    if(db_user_get_and_check_mem(&v, NULL, &role, NULL, NULL, NULL) != 0)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    *out_role = (user_role_t)role;
    mdb_txn_abort(txn);
    return 0;
}

static uint64_t now_secs(void)
{
    return (uint64_t)time(NULL);
}