/**
 * @file db_data.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db_int.h"
#include "db_acl.h"
#include "uuid.h"
#include "fsutil.h"
#include "sha256.h"

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

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

int db_data_get_meta(uint8_t data_id[DB_ID_SIZE], DataMeta *out_meta)
{
    if(!out_meta)
        return -EINVAL;
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = data_id};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_data_meta, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }
    if(v.mv_size != sizeof(DataMeta))
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    memcpy(out_meta, v.mv_data, sizeof *out_meta);
    mdb_txn_abort(txn);
    return 0;
}

int db_data_get_path(uint8_t data_id[DB_ID_SIZE], char *out_path,
                     unsigned long out_sz)
{
    if(!out_path || out_sz == 0 || !data_id)
        return -EINVAL;

    DataMeta meta;
    int      rc = db_data_get_meta(data_id, &meta);
    if(rc != 0)
        return rc; /* already -ENOENT / -EIO / -EINVAL */

    char   hex[65];
    Sha256 d;
    memcpy(d.b, meta.sha, 32);
    crypt_sha256_hex(&d, hex);

    if(path_sha256(out_path, out_sz, DB->root, hex) < 0)
        return -EIO;
    return 0;
}

int db_data_add_from_fd(uint8_t owner[DB_ID_SIZE], int src_fd, const char *mime,
                        uint8_t out_data_id[DB_ID_SIZE])
{
    if(!owner || src_fd < 0)
        return -EINVAL;

    user_role_t owner_role;
    memset(&owner_role, 0, sizeof(user_role_t));

    /* Permission check: owner must exist and be a publisher */
    {
        int prc = db_user_get_role(owner, &owner_role);
        if(prc != 0)
            return db_map_mdb_err(prc);
        if(owner_role != USER_ROLE_PUBLISHER)
            return -EPERM;
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
    if(mrc != MDB_SUCCESS)
        return db_map_mdb_err(mrc);

    /* sha -> data, make sure unique exists */
    MDB_val shak = {.mv_size = 32, .mv_data = (void *)digest.b};
    MDB_val shav = {.mv_size = sizeof(DataMeta), .mv_data = NULL};

    mrc = mdb_put(txn, DB->db_sha2data, &shak, &shav, db_sha2id_put_flags);
    if(mrc == MDB_MAP_FULL)
    {
        mdb_txn_abort(txn);
        int grc = db_env_mapsize_expand(); /* grow */
        if(grc != 0)
            return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;               /* retry whole chunk */
    }
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }
    /* new object generate id, write it into reserved sha->id slot */
    uuid_v7(data_id);
    memcpy(shav.mv_data, data_id, DB_ID_SIZE);

    MDB_val datak = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};
    MDB_val datav = {.mv_size = sizeof(DataMeta), .mv_data = NULL};

    mrc = mdb_put(txn, DB->db_data_meta, &datak, &datav, db_dataid_put_flags);
    if(mrc == MDB_MAP_FULL)
    {
        mdb_txn_abort(txn);
        int grc = db_env_mapsize_expand(); /* grow */
        if(grc != 0)
            return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;               /* retry whole chunk */
    }
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }

    /* fill DataMeta in-place (no stack buffer) */
    DataMeta *mp = (DataMeta *)datav.mv_data;
    memset(mp, 0, sizeof *mp);
    mp->ver = DB_VER;
    memcpy(mp->sha, digest.b, 32);
    snprintf(mp->mime, sizeof mp->mime, "%s",
             (mime && *mime) ? mime : "application/octet-stream");
    mp->size       = (uint64_t)total;
    mp->created_at = now_secs();
    memcpy(mp->owner, owner, DB_ID_SIZE);

    if(acl_grant_txn(txn, owner, ACL_RTYPE_OWNER, data_id) != 0)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    mrc = mdb_txn_commit(txn);
    if(mrc == MDB_MAP_FULL)
    {
        int grc = db_env_mapsize_expand();
        if(grc != 0)
            return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;
    }
    if(mrc != MDB_SUCCESS)
    {
        /* txn is already aborted/freed on commit error */
        return db_map_mdb_err(mrc);
    }
    if(out_data_id)
        memcpy(out_data_id, data_id, DB_ID_SIZE);
    return 0;
}

int db_data_delete(const uint8_t owner[DB_ID_SIZE],
                   const uint8_t data_id[DB_ID_SIZE])
{
    if(!owner || !data_id)
        return -EINVAL;

retry_chunk:
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

    /* Owner check: owner must have presence in 'O' */
    {
        int rc = acl_check_present_txn(txn, owner, ACL_RTYPE_OWNER, data_id);
        if(rc == -ENOENT)
        {
            mdb_txn_abort(txn);
            return -EPERM;
        }
        if(rc != 0)
        {
            mdb_txn_abort(txn);
            return rc;
        }
    }

    /* Ensure data exists & get meta for blob path */
    DataMeta meta = {0};
    {
        MDB_val k  = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};
        MDB_val v  = {0};
        int     rc = mdb_get(txn, DB->db_data_meta, &k, &v);
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

    /* For each rtype, repeatedly position on (data|rtype), delete one dup at a time,
    i.e. dereference the relationships between users and this data */
    const char rtypes[3] = {ACL_RTYPE_OWNER, ACL_RTYPE_SHARE, ACL_RTYPE_USER};
    for(size_t i = 0; i < 3; ++i)
    {
        char    rt = rtypes[i];
        uint8_t rkey[17];
        acl_rev_key(rkey, data_id, rt);

        MDB_cursor *cur = NULL;
        if(mdb_cursor_open(txn, DB->db_acl_by_res, &cur) != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }

        MDB_val k = {.mv_size = sizeof rkey, .mv_data = rkey};
        MDB_val v = {0};

        for(;;)
        {
            int rc = mdb_cursor_get(cur, &k, &v, MDB_SET_KEY);
            if(rc == MDB_NOTFOUND)
                break; /* no more dupset for this rtype */
            if(rc != MDB_SUCCESS)
            {
                mdb_cursor_close(cur);
                mdb_txn_abort(txn);
                return -EIO;
            }

            if(v.mv_size == DB_ID_SIZE)
            {
                uint8_t principal[DB_ID_SIZE];
                memcpy(principal, v.mv_data, DB_ID_SIZE);
                uint8_t fkey[33];
                acl_fwd_key(fkey, principal, rt, data_id);
                MDB_val fk = {.mv_size = sizeof fkey, .mv_data = fkey};

                /* delete forward pair */
                (void)mdb_del(txn, DB->db_acl_fwd, &fk, NULL);

                /* delete this exact reverse dup */
                (void)mdb_del(txn, DB->db_acl_by_res, &k, &v);
            }
            /* loop repositions with MDB_SET_KEY until dupset exhausted */
        }

        mdb_cursor_close(cur);
    }

    /* Delete sha->data mapping */
    {
        MDB_val sk = {.mv_size = 32, .mv_data = meta.sha};
        (void)mdb_del(txn, DB->db_sha2data, &sk, NULL);
    }

    /* Delete data_meta entry */
    {
        MDB_val mk = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};
        (void)mdb_del(txn, DB->db_data_meta, &mk, NULL);
    }

    int mrc = mdb_txn_commit(txn);
    if(mrc == MDB_MAP_FULL)
    {
        int grc = db_env_mapsize_expand();
        if(grc != 0)
            return db_map_mdb_err(grc); /* stop if grow failed */
        goto retry_chunk;
    }
    if(mrc != MDB_SUCCESS)
    {
        /* txn is already aborted/freed on commit error */
        return db_map_mdb_err(mrc);
    }

    /* Remove the blob (best-effort) */
    {
        char   path[4096];
        Sha256 d;
        memcpy(d.b, meta.sha, 32);
        char hex[65];
        crypt_sha256_hex(&d, hex);
        if(path_sha256(path, sizeof path, DB->root, hex) == 0)
            unlink(path); /* ignore errors; DB is source of truth */
    }

    return 0;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static int db_user_get_role(const uint8_t id[DB_ID_SIZE], user_role_t *out_role)
{
    if(!out_role)
        return -EINVAL;
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = (void *)id};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_user, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return mrc;
    }
    if(v.mv_size != sizeof(UserPacked))
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    memcpy(out_role, &((UserPacked *)v.mv_data)->role, sizeof(user_role_t));
    mdb_txn_abort(txn);
    return 0;
}

static uint64_t now_secs(void)
{
    return (uint64_t)time(NULL);
}