/**
 * @file db_env.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db_int.h"
#include "fsutil.h"

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */

/* Logical names of LMDB sub-databases */
#define DB_USER          "user"          /* key=id(16), val=UserPacked */
#define DB_USER_EMAIL2ID "user_email2id" /* key=email , val=id(16) */
#define DB_DATA_META     "data_meta"     /* key=data_id(16) , val=DataMeta */
#define DB_SHA2DATA      "sha2data"      /* key=sha(32) , val=data_id(16) */

/* Presence-only ACL DBs */
#define DB_ACL_FWD \
    "acl_fwd" /* key=principal(16)|rtype(1)|data(16), val=uint8_t sentinel */
#define DB_ACL_BY_RES \
    "acl_by_res" /* key=data(16)|rtype(1),              val=principal(16) */

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */

/* Global DB handle */
struct DB *DB = NULL;

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */
static int db_data_ensure_layout(const char *root);
static int db_env_setup_and_open(const char *root_dir, size_t mapsize_bytes);
static int db_env_mapsize_set(uint64_t mapsize_bytes);

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

/** Initialize the environment, create sub-databases. */
int db_open(const char *root_dir, size_t mapsize_bytes)
{
    if(!root_dir || mapsize_bytes == 0)
        return -EINVAL;

    int erc = db_data_ensure_layout(root_dir);
    if(erc != 0)
        return erc; /* already -EIO */

    DB = calloc(1, sizeof(struct DB));
    if(!DB)
        return -ENOMEM;

    snprintf(DB->root, sizeof DB->root, "%s", root_dir);

    if(mdb_env_create(&DB->env) != MDB_SUCCESS)
    {
        free(DB);
        DB = NULL;
        return -EIO;
    }
    char metadir[2048];
    snprintf(metadir, sizeof metadir, "%s/meta", root_dir);
    if(db_env_setup_and_open(metadir, mapsize_bytes) != MDB_SUCCESS)
        goto fail_env;

    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        goto fail_env;

    if(mdb_dbi_open(txn, DB_USER, MDB_CREATE, &DB->db_user) != MDB_SUCCESS)
        goto fail;
    if(mdb_dbi_open(txn, DB_USER_EMAIL2ID, MDB_CREATE, &DB->db_user_email2id) !=
       MDB_SUCCESS)
        goto fail;
    if(mdb_dbi_open(txn, DB_DATA_META, MDB_CREATE, &DB->db_data_meta) !=
       MDB_SUCCESS)
        goto fail;
    if(mdb_dbi_open(txn, DB_SHA2DATA, MDB_CREATE, &DB->db_sha2data) !=
       MDB_SUCCESS)
        goto fail;

    /* ACLs: forward (presence sentinel) + reverse (dupsort, dupfixed) */
    if(mdb_dbi_open(txn, DB_ACL_FWD, MDB_CREATE, &DB->db_acl_fwd) !=
       MDB_SUCCESS)
        goto fail;
    if(mdb_dbi_open(txn, DB_ACL_BY_RES, MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED,
                    &DB->db_acl_by_res) != MDB_SUCCESS)
        goto fail;

    if(mdb_txn_commit(txn) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        goto fail_env;
    }
    return 0;

fail:
    mdb_txn_abort(txn);
fail_env:
    mdb_env_close(DB->env);
    free(DB);
    DB = NULL;
    return -EIO;
}

void db_close(void)
{
    if(!DB)
        return;
    mdb_env_close(DB->env);
    free(DB);
    DB = NULL;
}

int db_env_mapsize_expand(void)
{
    if(!DB || !DB->env)
        return -EIO;
    uint64_t desired = DB->map_size_bytes * 2;
    if(desired > DB->map_size_bytes_max)
        return MDB_MAP_FULL;
    return db_env_mapsize_set(desired);
}

int db_env_metrics(uint64_t *used, uint64_t *mapsize, uint32_t *psize)
{
    if(!DB || !DB->env)
        return -EINVAL;
    MDB_envinfo info;
    MDB_stat    st;
    int         rc;
    rc = mdb_env_info(DB->env, &info);
    if(rc != MDB_SUCCESS)
        return -EIO;
    rc = mdb_env_stat(DB->env, &st);
    if(rc != MDB_SUCCESS)
        return -EIO;
    if(mapsize)
        *mapsize = (uint64_t)info.me_mapsize;
    if(psize)
        *psize = (uint32_t)st.ms_psize;
    if(used)
        *used = ((uint64_t)info.me_last_pgno + 1ull) * (uint64_t)st.ms_psize;
    return 0;
}

int db_map_mdb_err(int mdb_rc)
{
    switch(mdb_rc)
    {
        case MDB_SUCCESS:
            return 0;
            break;

        case MDB_NOTFOUND:
            return -ENOENT;
            break;

        case MDB_KEYEXIST:
            return -EEXIST;
            break;

        case MDB_MAP_FULL:
            return -ENOMEM;
            break;

        default:
            return -mdb_rc;
            break;
    }
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static int db_data_ensure_layout(const char *root)
{
    char p[2048];

    snprintf(p, sizeof p, "%s", root);
    if(mkdir_p(p, 0770) != 0 && errno != EEXIST)
        return -EIO;

    snprintf(p, sizeof p, "%s/objects/sha256", root);
    if(mkdir_p(p, 0770) != 0 && errno != EEXIST)
        return -EIO;

    snprintf(p, sizeof p, "%s/meta", root);
    if(mkdir_p(p, 0770) != 0 && errno != EEXIST)
        return -EIO;

    return 0;
}

static int db_env_setup_and_open(const char *metadir, size_t mapsize_bytes)
{
    if(!DB || !DB->env)
        return -EIO;

    DB->map_size_bytes = mapsize_bytes;

    const char *mx         = getenv("LMDB_MAPSIZE_MAX_MB");
    DB->map_size_bytes_max = mx ? (uint64_t)strtoull(mx, NULL, 10) << 20
                                : (uint64_t)mapsize_bytes * 8;

    int mrc = mdb_env_set_maxdbs(DB->env, 16);
    if(mrc != MDB_SUCCESS)
        return mrc;

    mrc = db_env_mapsize_set(DB->map_size_bytes);
    if(mrc != MDB_SUCCESS)
        return mrc;

    mrc = mdb_env_open(DB->env, metadir, 0, 0770);
    if(mrc != MDB_SUCCESS)
        return mrc;

    return 0;
}

static int db_env_mapsize_set(uint64_t mapsize_bytes)
{
    int mrc = mdb_env_set_mapsize(DB->env, (size_t)mapsize_bytes);
    if(mrc == MDB_SUCCESS)
    {
        DB->map_size_bytes = mapsize_bytes;
        return 0;
    }
    return mrc;
}