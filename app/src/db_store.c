/* ========================================================================= */
/*                               db_store.c                                  */
/* ========================================================================= */
/* LMDB-backed database store implementation.                                */
/* Presence-only ACL with forward (principal|rtype|data) and reverse          */
/* (data|rtype -> principal duplist) indexes.                                */
/* ========================================================================= */

#include "db_store.h"
#include "fsutil.h"
#include "sha256.h"
#include "uuid.h"

#include <lmdb.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

/* ========================================================================== */
/*                                   Types                                    */
/* ========================================================================== */

/* -------------------------- ACL namespaces -------------------------------- */
/* Presence-only ACL rtype namespaces */
#define ACL_RTYPE_OWNER     'O' /* owner */
#define ACL_RTYPE_SHARE     'S' /* share/reshare */
#define ACL_RTYPE_USER      'U' /* view */

/* --------------------------- User roles ----------------------------------- */
#define USER_ROLE_NONE      0u
#define USER_ROLE_VIEWER    (1u << 0)
#define USER_ROLE_PUBLISHER (1u << 1)

typedef uint16_t user_role_t;

/* ----------------------- Packed DB records -------------------------------- */

typedef struct __attribute__((packed))
{
    /* 16 bytes user id */
    uint8_t     id[DB_ID_SIZE];

    /* zero-terminated email */
    char        email[EMAIL_MAX_LEN];

    /* role uint16_t */
    user_role_t role;
} UserPacked;

typedef struct __attribute__((packed))
{
    uint8_t  ver;               /* version for future evolution */
    uint8_t  sha[32];           /* SHA-256 of stored object */
    char     mime[32];          /* MIME type */
    uint64_t size;              /* total bytes */
    uint64_t created_at;        /* epoch seconds */
    uint8_t  owner[DB_ID_SIZE]; /* uploader id */
} DataMeta;

/* ========================================================================== */
/*                                  Globals                                   */
/* ========================================================================== */

/* Handle for the whole store.  All LMDB databases live under <root>/meta,   */
/* while content-addressed objects live under <root>/objects/sha256/.. .     */
struct DB
{
    char     root[1024]; /* Root directory */
    MDB_env *env;        /* LMDB environment */

    MDB_dbi  db_user;          /* User DBI */
    MDB_dbi  db_user_email2id; /* Email -> ID DBI */
    MDB_dbi  db_data_meta;     /* Data meta DBI */
    MDB_dbi  db_sha2data;      /* SHA -> data_id DBI */

    /* Presence-only ACLs */
    MDB_dbi
        db_acl_fwd; /* key=principal(16)|rtype(1)|data(16), val=uint8_t(1) */
    MDB_dbi
        db_acl_by_res; /* key=data(16)|rtype(1),                val=principal(16) (dupsort, dupfixed) */
};

/* Private global */
static struct DB *DB = NULL; /* Global DB handle */

/* Logical names of LMDB sub-databases */
#define DB_USER "user" /* key=id(16)                 , val=UserPacked */
#define DB_USER_EMAIL2ID \
    "user_email2id" /* key=email                  , val=id(16)     */
#define DB_DATA_META \
    "data_meta"                /* key=data_id(16)            , val=DataMeta   */
#define DB_SHA2DATA "sha2data" /* key=sha(32)                , val=data_id(16)*/

/* Presence-only ACL DBs */
#define DB_ACL_FWD \
    "acl_fwd" /* key=principal(16)|rtype(1)|data(16), val=uint8_t sentinel */
#define DB_ACL_BY_RES \
    "acl_by_res" /* key=data(16)|rtype(1),              val=principal(16) */

/* ========================================================================== */
/*                                Local Helpers                               */
/* ========================================================================== */

/** Convert LMDB error codes to -errno style. */
static int map_mdb_err(int mdb_rc)
{
    if(mdb_rc == MDB_SUCCESS)
        return 0;
    if(mdb_rc == MDB_NOTFOUND)
        return -ENOENT;
    return -EIO;
}

/** Create the necessary directory structure under 'root'. */
static int ensure_layout(const char *root)
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

/** Return current time in seconds since the epoch. */
static uint64_t now_secs(void)
{
    return (uint64_t)time(NULL);
}

/* ----------------------------- ACL keys ---------------------------------- */

/* 33 bytes: principal(16) | rtype(1) | resource(16) */
static inline void acl_fwd_key(uint8_t       out[33],
                               const uint8_t principal[DB_ID_SIZE], char rtype,
                               const uint8_t resource[DB_ID_SIZE])
{
    memcpy(out, principal, DB_ID_SIZE);
    out[16] = (uint8_t)rtype;
    memcpy(out + 17, resource, DB_ID_SIZE);
}

/* 17 bytes: resource(16) | rtype(1)  (reverse key) */
static inline void acl_rev_key(uint8_t       out[17],
                               const uint8_t resource[DB_ID_SIZE], char rtype)
{
    memcpy(out, resource, DB_ID_SIZE);
    out[16] = (uint8_t)rtype;
}

/* ---------------------- Presence-only ACL ops ---------------------------- */

/** Grant presence in both forward and reverse ACL DBs (same txn). */
static int acl_grant_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE],
                         char rtype, const uint8_t resource[DB_ID_SIZE])
{
    uint8_t fkey[33];
    acl_fwd_key(fkey, principal, rtype, resource);
    MDB_val fk  = {.mv_size = sizeof fkey, .mv_data = fkey};
    uint8_t one = 1;
    MDB_val fv  = {.mv_size = 1, .mv_data = &one};
    if(mdb_put(txn, DB->db_acl_fwd, &fk, &fv, 0) != MDB_SUCCESS)
        return -EIO;

    uint8_t rkey[17];
    acl_rev_key(rkey, resource, rtype);
    MDB_val rk = {.mv_size = sizeof rkey, .mv_data = rkey};
    MDB_val rv = {.mv_size = DB_ID_SIZE, .mv_data = (void *)principal};
    if(mdb_put(txn, DB->db_acl_by_res, &rk, &rv, 0) != MDB_SUCCESS)
        return -EIO;

    return 0;
}

/** Revoke presence from both DBs (same txn). */
// static int acl_revoke_txn(MDB_txn* txn,
//                           const uint8_t principal[DB_ID_SIZE],
//                           char rtype,
//                           const uint8_t resource[DB_ID_SIZE])
// {
//     uint8_t fkey[33];  acl_fwd_key(fkey, principal, rtype, resource);
//     MDB_val fk = { .mv_size = sizeof fkey, .mv_data = fkey };
//     int rc = mdb_del(txn, DB->db_acl_fwd, &fk, NULL);
//     if (rc != MDB_SUCCESS && rc != MDB_NOTFOUND) return -EIO;

//     uint8_t rkey[17];  acl_rev_key(rkey, resource, rtype);
//     MDB_val rk = { .mv_size = sizeof rkey, .mv_data = rkey };
//     MDB_val rv = { .mv_size = DB_ID_SIZE,  .mv_data = (void*)principal };
//     rc = mdb_del(txn, DB->db_acl_by_res, &rk, &rv); /* exact dup removal */
//     if (rc != MDB_SUCCESS && rc != MDB_NOTFOUND) return -EIO;

//     return 0;
// }

/** Check forward presence (returns 0 if present, -ENOENT if absent). */
static int acl_check_present_txn(MDB_txn      *txn,
                                 const uint8_t principal[DB_ID_SIZE],
                                 char rtype, const uint8_t resource[DB_ID_SIZE])
{
    uint8_t fkey[33];
    acl_fwd_key(fkey, principal, rtype, resource);
    MDB_val fk = {.mv_size = sizeof fkey, .mv_data = fkey};
    MDB_val vv = {0};
    int     rc = mdb_get(txn, DB->db_acl_fwd, &fk, &vv);
    if(rc == MDB_SUCCESS)
        return 0;
    if(rc == MDB_NOTFOUND)
        return -ENOENT;
    return -EIO;
}

/** Effective access if present in any of {O,S,U}. */
static int acl_has_any_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE],
                           const uint8_t resource[DB_ID_SIZE])
{
    int rc;
    rc = acl_check_present_txn(txn, principal, ACL_RTYPE_OWNER, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    rc = acl_check_present_txn(txn, principal, ACL_RTYPE_SHARE, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    rc = acl_check_present_txn(txn, principal, ACL_RTYPE_USER, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    return -ENOENT;
}

/* --------------------------- Meta helpers -------------------------------- */

/** Read a DataMeta for a given data id. */
static int db_get_data_meta(uint8_t data_id[DB_ID_SIZE], DataMeta *out_meta)
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
        return map_mdb_err(mrc);
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

/** Look up a user's role by id. */
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
        return map_mdb_err(mrc);
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

/** Set a user's role in the DB. */
static int db_user_set_role(uint8_t userId[DB_ID_SIZE], user_role_t role)
{
    if(role != USER_ROLE_VIEWER && role != USER_ROLE_PUBLISHER &&
       role != USER_ROLE_NONE)
        return -EINVAL;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = (void *)userId};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_user, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return map_mdb_err(mrc);
    }
    if(v.mv_size != sizeof(UserPacked))
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    UserPacked up;
    memcpy(&up, v.mv_data, sizeof up);
    up.role    = role;
    MDB_val nv = {.mv_size = sizeof up, .mv_data = (void *)&up};
    if(mdb_put(txn, DB->db_user, &k, &nv, 0) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    if(mdb_txn_commit(txn) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    return 0;
}

/* ========================================================================== */
/*                                Public API                                  */
/* ========================================================================== */

/** Initialize the environment, create sub-databases. */
int db_open(const char *root_dir, uint64_t mapsize_bytes)
{
    if(!root_dir || mapsize_bytes == 0)
        return -EINVAL;

    int erc = ensure_layout(root_dir);
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

    mdb_env_set_maxdbs(DB->env, 32);
    mdb_env_set_mapsize(DB->env, (size_t)mapsize_bytes);

    char metadir[2048];
    snprintf(metadir, sizeof metadir, "%s/meta", root_dir);
    if(mdb_env_open(DB->env, metadir, 0, 0770) != MDB_SUCCESS)
    {
        mdb_env_close(DB->env);
        free(DB);
        DB = NULL;
        return -EIO;
    }

    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
    {
        mdb_env_close(DB->env);
        free(DB);
        DB = NULL;
        return -EIO;
    }

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

/** Close the environment and free the global handle. */
void db_close(void)
{
    if(!DB)
        return;
    mdb_env_close(DB->env);
    free(DB);
    DB = NULL;
}

/** Insert a user if not already present. If present, copy id into out_id. */
int db_add_user(const char email[EMAIL_MAX_LEN], uint8_t out_id[DB_ID_SIZE])
{
    if(!email || email[0] == '\0')
        return -EINVAL;

    /* Lookup first (RO) */
    uint8_t existing[DB_ID_SIZE] = {0};
    int     frc                  = db_user_find_by_email(email, existing);

    if(frc == 0)
    {
        if(out_id)
            memcpy(out_id, existing, DB_ID_SIZE);
        return -EEXIST;
    }
    else if(frc != -ENOENT)
    {
        return -EIO;
    }

    /* Generate unique id */
    uint8_t id[DB_ID_SIZE];
    do
    {
        uuid_v7(id);
    } while(db_user_find_by_id(id, NULL) == 0);

    /* Prepare packed user */
    UserPacked up = {0};
    up.role       = USER_ROLE_NONE;
    memcpy(up.id, id, DB_ID_SIZE);
    snprintf(up.email, sizeof up.email, "%.*s", EMAIL_MAX_LEN - 1, email);

    /* Insert in a RW transaction */
    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

    /* id -> user */
    MDB_val k_id = {.mv_size = DB_ID_SIZE, .mv_data = (void *)id};
    MDB_val v_up = {.mv_size = sizeof(UserPacked), .mv_data = (void *)&up};
    int     mrc  = mdb_put(txn, DB->db_user, &k_id, &v_up, MDB_NOOVERWRITE);
    if(mrc == MDB_KEYEXIST)
    {
        mdb_txn_abort(txn);
        if(out_id)
            memcpy(out_id, id, DB_ID_SIZE);
        return -EEXIST;
    }
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    /* email -> id */
    MDB_val k_email = {.mv_size = strlen(email), .mv_data = (void *)email};
    MDB_val v_id    = {.mv_size = DB_ID_SIZE, .mv_data = (void *)id};
    mrc = mdb_put(txn, DB->db_user_email2id, &k_email, &v_id, MDB_NOOVERWRITE);
    if(mrc == MDB_KEYEXIST)
    {
        mdb_txn_abort(txn);
        if(out_id)
            memcpy(out_id, id, DB_ID_SIZE);
        return -EEXIST;
    }
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    if(mdb_txn_commit(txn) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    if(out_id)
        memcpy(out_id, id, DB_ID_SIZE);
    return 0;
}

/** Look up a user by id and optionally return email. */
int db_user_find_by_id(const uint8_t id[DB_ID_SIZE], char out[EMAIL_MAX_LEN])
{
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = (void *)id};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_user, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return map_mdb_err(mrc);
    }
    if(v.mv_size != sizeof(UserPacked))
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    if(out)
        memcpy(out, ((UserPacked *)v.mv_data)->email, EMAIL_MAX_LEN);
    mdb_txn_abort(txn);
    return 0;
}

/** Look up a user id by email. */
int db_user_find_by_email(const char email[EMAIL_MAX_LEN],
                          uint8_t    out_id[DB_ID_SIZE])
{
    if(!email || email[0] == '\0')
        return -EINVAL;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = strlen(email), .mv_data = (void *)email};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_user_email2id, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return map_mdb_err(mrc);
    }
    if(v.mv_size != DB_ID_SIZE)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    if(out_id)
        memcpy(out_id, v.mv_data, DB_ID_SIZE);
    mdb_txn_abort(txn);
    return 0;
}

/** Share data with a user identified by email (grants presence in 'U'). */
int db_user_share_data_with_user_email(uint8_t    owner[DB_ID_SIZE],
                                       uint8_t    data_id[DB_ID_SIZE],
                                       const char email[EMAIL_MAX_LEN])
{
    if(!owner || !data_id || !email || email[0] == '\0')
        return -EINVAL;

    uint8_t target_user_id[DB_ID_SIZE] = {0};

    /* Resolve recipient */
    {
        int frc = db_user_find_by_email(email, target_user_id);
        if(frc != 0)
            return frc; /* -ENOENT / -EIO / -EINVAL */
    }

    /* Role check stays (coarse global permissions) */
    {
        user_role_t owner_role = 0;
        int         prc        = db_user_get_role(owner, &owner_role);
        if(prc == -ENOENT)
            return -ENOENT;
        if(prc != 0)
            return -EIO;
        if(owner_role != USER_ROLE_PUBLISHER && owner_role != USER_ROLE_VIEWER)
            return -EPERM;
    }

    /* One RW transaction for existence check + ACL checks + grant */
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

    /* Ensure data exists */
    {
        MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = data_id};
        MDB_val v   = {0};
        int     mrc = mdb_get(txn, DB->db_data_meta, &k, &v);
        if(mrc == MDB_NOTFOUND)
        {
            mdb_txn_abort(txn);
            return -ENOENT;
        }
        if(mrc != MDB_SUCCESS || v.mv_size != sizeof(DataMeta))
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
    }

    /* Sharer must have any of O/S/U on this data */
    if(acl_has_any_txn(txn, owner, data_id) != 0)
    {
        mdb_txn_abort(txn);
        return -EPERM;
    }

    /* Presence in 'U' (view) namespace for recipient */
    if(acl_grant_txn(txn, target_user_id, ACL_RTYPE_USER, data_id) != 0)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    if(mdb_txn_commit(txn) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    return 0;
}

/** Ingest a blob, deduplicate by SHA-256, grant owner presence. */
int db_upload_data_from_fd(uint8_t owner[DB_ID_SIZE], int src_fd,
                           const char *mime, uint8_t out_data_id[DB_ID_SIZE])
{
    if(!owner || src_fd < 0)
        return -EINVAL;

    user_role_t owner_role;

    /* Permission check: owner must exist and be a publisher */
    {
        int prc = db_user_get_role(owner, &owner_role);
        if(prc == -ENOENT)
            return -ENOENT;
        if(prc != 0)
            return -EIO;
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
    uint8_t  data_id[DB_ID_SIZE];
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val sk  = {.mv_size = 32, .mv_data = (void *)digest.b};
    MDB_val sv  = {0};
    int     mrc = mdb_get(txn, DB->db_sha2data, &sk, &sv);

    /* Dedup hit: reuse existing id, grant owner presence, and return -EEXIST */
    if(mrc == MDB_SUCCESS && sv.mv_size == DB_ID_SIZE)
    {
        memcpy(data_id, sv.mv_data, DB_ID_SIZE);
        if(acl_grant_txn(txn, owner, ACL_RTYPE_OWNER, data_id) != 0)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
        if(mdb_txn_commit(txn) != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
        if(out_data_id)
            memcpy(out_data_id, data_id, DB_ID_SIZE);
        return -EEXIST;
    }
    /* New object: assign id and write meta + sha2data */
    else if(mrc == MDB_NOTFOUND)
    {
        uuid_v7(data_id);

        DataMeta mp;
        memset(&mp, 0, sizeof mp);
        mp.ver = 1;
        memcpy(mp.sha, digest.b, 32);
        snprintf(mp.mime, sizeof mp.mime, "%s",
                 (mime && *mime) ? mime : "application/octet-stream");
        mp.size       = (uint64_t)total;
        mp.created_at = now_secs();
        memcpy(mp.owner, owner, DB_ID_SIZE);

        MDB_val mk  = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};
        MDB_val mv  = {.mv_size = sizeof(DataMeta), .mv_data = (void *)&mp};
        MDB_val siv = {.mv_size = DB_ID_SIZE, .mv_data = (void *)data_id};

        if(mdb_put(txn, DB->db_data_meta, &mk, &mv, 0) != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
        if(mdb_put(txn, DB->db_sha2data, &sk, &siv, 0) != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
        if(acl_grant_txn(txn, owner, ACL_RTYPE_OWNER, data_id) != 0)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }

        if(mdb_txn_commit(txn) != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
        if(out_data_id)
            memcpy(out_data_id, data_id, DB_ID_SIZE);
        return 0;
    }
    else
    {
        /* Unexpected LMDB error */
        mdb_txn_abort(txn);
        return -EIO;
    }
}

/** Given a data id, resolve the absolute filesystem path of its blob. */
int db_resolve_data_path(uint8_t data_id[DB_ID_SIZE], char *out_path,
                         unsigned long out_sz)
{
    if(!out_path || out_sz == 0 || !data_id)
        return -EINVAL;

    DataMeta meta;
    int      rc = db_get_data_meta(data_id, &meta);
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

int db_user_set_role_viewer(uint8_t userId[DB_ID_SIZE])
{
    return db_user_set_role(userId, USER_ROLE_VIEWER);
}
int db_user_set_role_publisher(uint8_t userId[DB_ID_SIZE])
{
    return db_user_set_role(userId, USER_ROLE_PUBLISHER);
}

/** List all users. */
int db_user_list_all(uint8_t *out_ids, size_t *inout_count_max)
{
    if(!inout_count_max)
        return -EINVAL;
    size_t   cap = out_ids ? *inout_count_max : 0, n = 0;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;
    MDB_cursor *cur;
    if(mdb_cursor_open(txn, DB->db_user, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k = {0}, v = {0};
    for(int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST); rc == MDB_SUCCESS;
        rc     = mdb_cursor_get(cur, &k, &v, MDB_NEXT))
    {
        if(v.mv_size != sizeof(UserPacked))
            continue;
        const UserPacked *up = (const UserPacked *)v.mv_data;
        if(n < cap && out_ids)
            memcpy(out_ids + n * DB_ID_SIZE, up->id, DB_ID_SIZE);
        n++;
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

/** List all publishers. */
int db_user_list_publishers(uint8_t *out_ids, size_t *inout_count_max)
{
    if(!inout_count_max)
        return -EINVAL;
    size_t   cap = out_ids ? *inout_count_max : 0, n = 0;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;
    MDB_cursor *cur;
    if(mdb_cursor_open(txn, DB->db_user, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k = {0}, v = {0};
    for(int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST); rc == MDB_SUCCESS;
        rc     = mdb_cursor_get(cur, &k, &v, MDB_NEXT))
    {
        if(v.mv_size != sizeof(UserPacked))
            continue;
        const UserPacked *up = (const UserPacked *)v.mv_data;
        if(up->role == USER_ROLE_PUBLISHER)
        {
            if(n < cap && out_ids)
                memcpy(out_ids + n * DB_ID_SIZE, up->id, DB_ID_SIZE);
            n++;
        }
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

/** List all viewers. */
int db_user_list_viewers(uint8_t *out_ids, size_t *inout_count_max)
{
    if(!inout_count_max)
        return -EINVAL;
    size_t   cap = out_ids ? *inout_count_max : 0, n = 0;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;
    MDB_cursor *cur;
    if(mdb_cursor_open(txn, DB->db_user, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k = {0}, v = {0};
    for(int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST); rc == MDB_SUCCESS;
        rc     = mdb_cursor_get(cur, &k, &v, MDB_NEXT))
    {
        if(v.mv_size != sizeof(UserPacked))
            continue;
        const UserPacked *up = (const UserPacked *)v.mv_data;
        if(up->role == USER_ROLE_VIEWER)
        {
            if(n < cap && out_ids)
                memcpy(out_ids + n * DB_ID_SIZE, up->id, DB_ID_SIZE);
            n++;
        }
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

/* ----------------------------- Owner delete ------------------------------ */

/**
 * @brief Delete a data object and everything it touches (ACL forward+reverse, meta, mapping, blob).
 *        Only the owner (rtype 'O') can delete.
 * @return 0 on success, -EPERM if not owner, -ENOENT if missing, -EIO on error.
 */
int db_owner_delete_data(const uint8_t actor[DB_ID_SIZE],
                         const uint8_t data_id[DB_ID_SIZE])
{
    if(!actor || !data_id)
        return -EINVAL;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

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

    /* Owner check: actor must have presence in 'O' */
    {
        int rc = acl_check_present_txn(txn, actor, ACL_RTYPE_OWNER, data_id);
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
                /* delete forward pair */
                uint8_t fkey[33];
                acl_fwd_key(fkey, principal, rt, data_id);
                MDB_val fk = {.mv_size = sizeof fkey, .mv_data = fkey};
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

    /* Commit DB first, then unlink blob on disk. */
    if(mdb_txn_commit(txn) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
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