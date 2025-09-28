/**
 * @file db.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db.h"
#include <sodium.h>
#include "kv_core.h"
#include "uuid.h"

#include "fsutil.h"

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */

/* User role bits */
#define ROLE_VIEWER    (1u << 0) /* can just view and share */
#define ROLE_PUBLISHER (1u << 1) /* can upload new data */

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */

/* Global DB handle */
DB* db = NULL;

/* Registry from schemas.def (enum is already defined in the header) */
#define DBI_EXPAND_DESC(id, name, kenc, kdec, kpr, venc, vdec, vpr, cmp, \
                        flags)                                           \
    [DBI_##id] =                                                         \
        (dbi_desc_t){name, kenc, kdec, kpr, venc, vdec, vpr, cmp, flags, 0},
static dbi_desc_t REGISTRY[DBI_COUNT] = {
#define _(id, name, kenc, kdec, kpr, venc, vdec, vpr, cmp, flags) \
    DBI_EXPAND_DESC(id, name, kenc, kdec, kpr, venc, vdec, vpr, cmp, flags)
#include "../include/schemas.def"
#undef _
};
#undef DBI_EXPAND_DESC

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */

static int user_create_tx(Tx* tx, const char* email, uint8_t elen,
                          const char* pw, uuid16_t* out_id);

static int ensure_user_tx(Tx* tx, const char* email, uint8_t elen,
                          uuid16_t* uid);

/**
 * @brief The db_data_ensure_layout function is a static utility that ensures
 * the directory structure for a database is properly set up under the
 * specified root path. It creates the necessary directories
 * (root, root/objects/sha256, and root/meta) with appropriate permissions,
 * returning -EIO if any directory creation fails for reasons other than the
 * directory already existing.
 */
static int db_data_ensure_layout(const char* root);

static int db_env_setup_and_open(const char* root_dir, size_t mapsize_bytes);

static int db_env_mapsize_set(uint64_t mapsize_bytes);

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

/** Initialize the environment, create sub-databases. */
int db_open(const char* root_dir, size_t mapsize_bytes)
{
    if(!root_dir || mapsize_bytes == 0) return -EINVAL;

    int ret = db_data_ensure_layout(root_dir);
    if(ret != 0) return ret;

    db = calloc(1, sizeof(DB));
    if(!db)
    {
        fprintf(stderr, "%s:%d db open failed\n", __FILE__, __LINE__);
        return -ENOMEM;
    }

    snprintf(db->root, sizeof db->root, "%s", root_dir);

    if(mdb_env_create(&db->env) != MDB_SUCCESS)
    {
        fprintf(stderr, "%s:%d db open failed\n", __FILE__, __LINE__);
        free(db);
        db = NULL;
        return -EIO;
    }

    char metadir[2048];
    snprintf(metadir, sizeof metadir, "%s/meta", root_dir);
    if(db_env_setup_and_open(metadir, mapsize_bytes) != MDB_SUCCESS)
    {
        fprintf(stderr, "%s:%d db open db_env_setup_and_open\n", __FILE__,
                __LINE__);
        goto fail_env;
    }

    MDB_txn* txn = NULL;
    if(mdb_txn_begin(db->env, NULL, 0, &txn) != MDB_SUCCESS) goto fail_env;

    for(int i = 0; i < DBI_COUNT; i++)
    {
        db->dbis[i] = REGISTRY[i];
        fprintf(stderr, "%s:%d db open dbi name %s\n", __FILE__, __LINE__,
                db->dbis[i].name);
        ret = mdb_dbi_open(txn, db->dbis[i].name,
                           db->dbis[i].flags | MDB_CREATE, &db->dbis[i].dbi);
        if(ret != MDB_SUCCESS)
        {
            fprintf(stderr, "%s:%d db open mdb_dbi_open %s error %d\n",
                    __FILE__, __LINE__, db->dbis[i].name, ret);
            goto fail;
        }
        if(db->dbis[i].cmp)
            mdb_set_compare(txn, db->dbis[i].dbi, db->dbis[i].cmp);
    }

    // if(mdb_dbi_open(txn, DB_ACL_REL, MDB_CREATE | MDB_DUPSORT | MDB_DUPFIXED,
    //                 &DB->db_acl_rel) != MDB_SUCCESS)
    //     goto fail;

    ret = mdb_txn_commit(txn);
    if(ret != MDB_SUCCESS)
    {
        fprintf(stderr, "%s:%d db_open mdb_txn_commit failed\n", __FILE__,
                __LINE__);
        goto fail_env;
    }
    return 0;

fail:
    mdb_txn_abort(txn);
    return db_map_mdb_err(ret);
fail_env:
    mdb_env_close(db->env);
    free(db);
    db = NULL;
    return db_map_mdb_err(ret);
}

void db_close(void)
{
    if(!db || !db->env) return;
    for(int i = 0; i < DBI_COUNT; i++)
        if(db->dbis[i].dbi) mdb_dbi_close(db->env, db->dbis[i].dbi);
    mdb_env_close(db->env);
    db->env = NULL;
    free(db);
    db = NULL;
}

#define DB_USER_ID2META_BUILD_VAL(ver_, role_, email_len_, email_) \
    (id2data_val_t)                                                \
    {                                                              \
        .ver = (ver_), .role = (role_), .email_len = (email_len_), \
        .email = email_                                            \
    }

#define DB_USER_EMAIL2ID_BUILD_VAL(user_id_) ((email2id_val_t){.v = (user_id_)})

int db_user_register_new(const char* email, uint8_t elen, const char* password,
                         uuid16_t* new_id)
{
    /* USER_ID2DATA */
    /* generate user key - ID */
    id2data_key_t usr_key = {0};
    int           ret     = uuid_gen(&usr_key.k);
    if(ret != 0) return db_map_mdb_err(ret);

    /* generate user val - Meta */
    id2data_val_t usr_val =
        DB_USER_ID2META_BUILD_VAL(0, ROLE_VIEWER, elen, email);

    /* derived from kv_put, put data in the DB */
    ret = user_id2data_put(&usr_key, &usr_val, NO_OVERWRITE | APPEND);
    if(ret != 0) return db_map_mdb_err(ret);

    /* USER_EMAIL2ID */
    /* generate email key - email */
    email2id_key_t email_key = {0};
    email_key.ptr            = email;
    email_key.len            = elen;

    /* generate email val - ID */
    email2id_val_t email_val = DB_USER_EMAIL2ID_BUILD_VAL(usr_key.k);

    ret = user_email2id_put(&email_key, &email_val, NO_OVERWRITE);
    if(ret != 0) return db_map_mdb_err(ret);

    if(new_id) *new_id = usr_key.k;

    return ret;
}

int db_env_mapsize_expand(void)
{
    if(!db || !db->env) return -EIO;
    uint64_t desired = db->map_size_bytes * 2;
    if(desired > db->map_size_bytes_max) return MDB_MAP_FULL;
    return db_env_mapsize_set(desired);
}

int db_env_metrics(uint64_t* used, uint64_t* mapsize, uint32_t* psize)
{
    if(!db || !db->env) return -EINVAL;
    MDB_envinfo info;
    MDB_stat    st;
    int         rc;
    rc = mdb_env_info(db->env, &info);
    if(rc != MDB_SUCCESS) return -EIO;
    rc = mdb_env_stat(db->env, &st);
    if(rc != MDB_SUCCESS) return -EIO;
    if(mapsize) *mapsize = (uint64_t)info.me_mapsize;
    if(psize) *psize = (uint32_t)st.ms_psize;
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

int tx_begin(int rdonly, Tx* out)
{
    if(!out) return -EINVAL;
    out->txn = NULL;
    int rc   = mdb_txn_begin(db->env, NULL, rdonly ? MDB_RDONLY : 0, &out->txn);
    return db_map_mdb_err(rc);
}

int tx_commit(Tx* t)
{
    if(!t || !t->txn) return -EINVAL;
    int rc = mdb_txn_commit(t->txn);
    t->txn = NULL;
    return db_map_mdb_err(rc);
}

void tx_abort(Tx* t)
{
    if(t && t->txn)
    {
        mdb_txn_abort(t->txn);
        t->txn = NULL;
    }
}

MDB_dbi db_get_dbi(DBI_ID dbi_id)
{
    return db->dbis[dbi_id].dbi;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static int user_create_tx(Tx* tx, const char* email, uint8_t elen,
                          const char* password, uuid16_t* out_id)
{
    /* Check not exists */
    MDB_val k_email = {.mv_size = elen, .mv_data = (void*)email};
    MDB_val v_id;
    int mrc = mdb_get(tx->txn, db_get_dbi(DBI_USER_EMAIL2ID), &k_email, &v_id);
    if(mrc == MDB_SUCCESS) return -EEXIST; /* already present */

    uuid16_t uid;
    if(uuid_gen(&uid) != 0) return -EIO;

    /* Hash password */
    // char hash[crypto_pwhash_STRBYTES];
    // if(crypto_pwhash_str(hash, password, strlen(password),
    //                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
    //                      crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    //     return -EIO;

    id2data_val_t rec;
    memset(&rec, 0, sizeof rec);
    rec.ver       = 1;
    rec.role      = ROLE_VIEWER;
    rec.email_len = elen;
    memcpy(rec.email, email, elen);

    // rec.pw_tag = 1;
    // strncpy(rec.pw_hash, hash, sizeof rec.pw_hash - 1);

    /* Put email→id and user */
    MDB_val v_uid = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid.b};

    mrc = mdb_put(tx->txn, db_dbi(DBI_USER_EMAIL2ID), &k_email, &v_uid,
                  MDB_NOOVERWRITE);

    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    MDB_val k_uid = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid.b};
    MDB_val v_user;

    if(enc_user_rec(&rec, &v_user) != 0) return -EINVAL;

    mrc = mdb_put(tx->txn, db_dbi(DBI_USER_ID2DATA), &k_uid, &v_user,
                  MDB_NOOVERWRITE);

    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    if(out_id) *out_id = uid;
    return 0;
}

static int ensure_user_tx(Tx* tx, const char* email, uint8_t elen,
                          uuid16_t* uid)
{
    MDB_val k   = {.mv_size = elen, .mv_data = (void*)email}, v;
    int     mrc = mdb_get(tx->txn, db_dbi(DBI_USER_EMAIL2ID), &k, &v);
    if(mrc == MDB_SUCCESS)
    {
        if(v.mv_size != DB_ID_SIZE) return -EIO;
        memcpy(uid->b, v.mv_data, DB_ID_SIZE);
        return 0;
    }
    /* create with temp password */
    const char* temp_pw = "!#TEMP#";
    int         rc      = user_create_tx(tx, email, elen, temp_pw, uid);
    return rc;
}

static int db_data_ensure_layout(const char* root)
{
    char p[2048];

    snprintf(p, sizeof p, "%s", root);
    if(mkdir_p(p, 0770) != 0 && errno != EEXIST) return -EIO;

    snprintf(p, sizeof p, "%s/objects/sha256", root);
    if(mkdir_p(p, 0770) != 0 && errno != EEXIST) return -EIO;

    snprintf(p, sizeof p, "%s/meta", root);
    if(mkdir_p(p, 0770) != 0 && errno != EEXIST) return -EIO;

    return 0;
}

static int db_env_setup_and_open(const char* metadir, size_t mapsize_bytes)
{
    if(!db || !db->env) return -EIO;

    db->map_size_bytes = mapsize_bytes;

    const char* mx         = getenv("LMDB_MAPSIZE_MAX_MB");
    db->map_size_bytes_max = mx ? (uint64_t)strtoull(mx, NULL, 10) << 20
                                : (uint64_t)mapsize_bytes * 8;

    int mrc = mdb_env_set_maxdbs(db->env, 16);
    if(mrc != MDB_SUCCESS) return mrc;

    mrc = db_env_mapsize_set(db->map_size_bytes);
    if(mrc != MDB_SUCCESS) return mrc;

    mrc = mdb_env_open(db->env, metadir, 0, 0770);
    if(mrc != MDB_SUCCESS) return mrc;

    return 0;
}

static int db_env_mapsize_set(uint64_t mapsize_bytes)
{
    int mrc = mdb_env_set_mapsize(db->env, (size_t)mapsize_bytes);
    if(mrc == MDB_SUCCESS)
    {
        db->map_size_bytes = mapsize_bytes;
        return 0;
    }
    return mrc;
}
