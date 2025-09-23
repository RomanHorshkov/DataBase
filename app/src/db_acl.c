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

_Static_assert(DB_ID_SIZE == 16, "ACL code assumes 16-byte IDs");

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
/* ACL rtype namespaces */
#define ACL_RTYPE_OWNER 'O' /* owner */
#define ACL_RTYPE_SHARE 'S' /* share/reshare */
#define ACL_RTYPE_VIEW  'V' /* view */

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

static void acl_fwd_key(uint8_t out[33], const uint8_t principal[DB_ID_SIZE],
                        char rel, const uint8_t resource[DB_ID_SIZE]);

/* resource(16) | rel(1) => 17 bytes (dupset key for principals) */
static void acl_rev_key(uint8_t out[17], const uint8_t resource[DB_ID_SIZE],
                        char rel);

static inline void fwd_key(uint8_t out[33], const uint8_t principal[DB_ID_SIZE],
                           uint8_t rel, const uint8_t resource[DB_ID_SIZE])
{
    acl_fwd_key(out, principal, (char)rel, resource);
}

static inline void rev_key(uint8_t out[17], const uint8_t resource[DB_ID_SIZE],
                           uint8_t rel)
{
    acl_rev_key(out, resource, (char)rel);
}

static int put_forward(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                       uint8_t rel, const uint8_t resource[DB_ID_SIZE]);

static int put_reverse(MDB_txn* txn, const uint8_t resource[DB_ID_SIZE],
                       uint8_t rel, const uint8_t principal[DB_ID_SIZE]);

static void del_forward(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                        uint8_t rel, const uint8_t resource[DB_ID_SIZE]);

static void del_reverse(MDB_txn* txn, const uint8_t resource[DB_ID_SIZE],
                        uint8_t rel, const uint8_t principal[DB_ID_SIZE]);

static int has_forward(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                       uint8_t rel, const uint8_t resource[DB_ID_SIZE]);

/* --------------------------- Public grant/revoke --------------------------- */

int acl_grant_owner(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                    const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    /* Write both sides; both idempotent. */
    int rc = put_forward(txn, principal, ACL_RTYPE_OWNER, resource);
    if(rc) return rc;
    return put_reverse(txn, resource, ACL_RTYPE_OWNER, principal);
}

int acl_grant_share(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                    const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    /* Also reflect in forward so we can list by user quickly. */
    int rc = put_forward(txn, principal, ACL_RTYPE_SHARE, resource);
    if(rc) return rc;
    return put_reverse(txn, resource, ACL_RTYPE_SHARE, principal);
}

int acl_grant_view(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                   const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    int rc = put_forward(txn, principal, ACL_RTYPE_VIEW, resource);
    if(rc) return rc;
    return put_reverse(txn, resource, ACL_RTYPE_VIEW, principal);
}

int acl_revoke_owner(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                     const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    del_forward(txn, principal, ACL_RTYPE_OWNER, resource);
    del_reverse(txn, resource, ACL_RTYPE_OWNER, principal);
    return 0;
}

int acl_revoke_share(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                     const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    del_forward(txn, principal, ACL_RTYPE_SHARE, resource);
    del_reverse(txn, resource, ACL_RTYPE_SHARE, principal);
    return 0;
}

int acl_revoke_view(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                    const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    del_forward(txn, principal, ACL_RTYPE_VIEW, resource);
    del_reverse(txn, resource, ACL_RTYPE_VIEW, principal);
    return 0;
}

/* ----------------------------- Presence checks ---------------------------- */

int acl_has_owner(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                  const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    return has_forward(txn, principal, ACL_RTYPE_OWNER, resource);
}

int acl_has_share(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                  const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    return has_forward(txn, principal, ACL_RTYPE_SHARE, resource);
}

int acl_has_view(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                 const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    return has_forward(txn, principal, ACL_RTYPE_VIEW, resource);
}

int acl_has_any(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !principal || !resource) return -EINVAL;
    int rc = has_forward(txn, principal, ACL_RTYPE_OWNER, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    rc = has_forward(txn, principal, ACL_RTYPE_SHARE, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    rc = has_forward(txn, principal, ACL_RTYPE_VIEW, resource);
    return rc;
}

/* Callback invoked for each hit.
 * Return 0 to continue, non-zero to stop early.
 * `rel` is one of ACL_RTYPE_OWNER/ACL_RTYPE_SHARE/ACL_RTYPE_VIEW (exposed only here as a tag). */
typedef int (*acl_iter_cb)(const uint8_t resource[DB_ID_SIZE], uint8_t rel,
                           void* user);

/* Iterate all resources accessible by `principal`.
 * If you need to filter (owner/share/view), add three booleans and skip others. */
int acl_list_data_for_user(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                           acl_iter_cb cb, void* user)
{
    if(!txn || !principal || !cb) return -EINVAL;

    MDB_cursor* cur = NULL;
    if(mdb_cursor_open(txn, DB->db_acl_fwd, &cur) != MDB_SUCCESS) return -EIO;

    /* Start from the smallest key with this principal:
       principal | 0x00 | 0x00..0x00 */
    uint8_t start[33];
    memset(start, 0, sizeof start);
    memcpy(start, principal, DB_ID_SIZE);

    MDB_val k = {.mv_size = sizeof start, .mv_data = start};
    MDB_val v = {0};

    int rc = mdb_cursor_get(cur, &k, &v, MDB_SET_RANGE);
    while(rc == MDB_SUCCESS)
    {
        /* Stop when principal prefix changes (first 16 bytes). */
        uint8_t* key = (uint8_t*)k.mv_data;
        if(memcmp(key, principal, DB_ID_SIZE) != 0) break;

        uint8_t        rel      = key[16];
        const uint8_t* resource = key + 17;

        int cr = cb(resource, rel, user);
        if(cr)
        {
            mdb_cursor_close(cur);
            return 0;
        }

        rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
    }

    mdb_cursor_close(cur);
    if(rc == MDB_NOTFOUND) return 0;
    return (rc == MDB_SUCCESS) ? 0 : -EIO;
}

int acl_data_destroy(MDB_txn* txn, const uint8_t resource[DB_ID_SIZE])
{
    if(!txn || !resource) return -EINVAL;

    const char rels[3] = {'O', 'S', 'V'};

    for(size_t i = 0; i < 3; ++i)
    {
        char rel = rels[i];

        uint8_t rkey[17];
        acl_rev_key(rkey, resource, rel);

        MDB_cursor* cur = NULL;
        if(mdb_cursor_open(txn, DB->db_acl_rel, &cur) != MDB_SUCCESS)
            return -EIO;

        MDB_val k = {.mv_size = sizeof rkey, .mv_data = rkey};
        MDB_val v = {0};

        for(;;)
        {
            int rc = mdb_cursor_get(cur, &k, &v, MDB_SET_KEY);
            if(rc == MDB_NOTFOUND) break;
            if(rc != MDB_SUCCESS)
            {
                mdb_cursor_close(cur);
                return -EIO;
            }

            if(v.mv_size == DB_ID_SIZE)
            {
                /* delete forward: principal|rel|resource -> 1 */
                uint8_t fkey[33];
                acl_fwd_key(fkey, (const uint8_t*)v.mv_data, rel, resource);
                MDB_val fk = {.mv_size = sizeof fkey, .mv_data = fkey};
                (void)mdb_del(txn, DB->db_acl_fwd, &fk, NULL);

                /* delete this exact reverse dup (current cursor item) */
                if(mdb_cursor_del(cur, 0) != MDB_SUCCESS)
                {
                    mdb_cursor_close(cur);
                    return -EIO;
                }

                /* loop re-seeks to the same rkey until dupset is empty */
            }
        }

        mdb_cursor_close(cur);

        /* clean any empty residue key (harmless if already gone) */
        MDB_val rk = {.mv_size = sizeof rkey, .mv_data = rkey};
        (void)mdb_del(txn, DB->db_acl_rel, &rk, NULL);
    }
    return 0;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static void acl_fwd_key(uint8_t out[33], const uint8_t principal[DB_ID_SIZE],
                        char rel, const uint8_t resource[DB_ID_SIZE])
{
    memcpy(out, principal, DB_ID_SIZE);
    out[16] = (uint8_t)rel;
    memcpy(out + 17, resource, DB_ID_SIZE);
}

/* resource(16) | rel(1) => 17 bytes (dupset key for principals) */
static void acl_rev_key(uint8_t out[17], const uint8_t resource[DB_ID_SIZE],
                        char rel)
{
    memcpy(out, resource, DB_ID_SIZE);
    out[16] = (uint8_t)rel;
}

static int put_forward(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                       uint8_t rel, const uint8_t resource[DB_ID_SIZE])
{
    uint8_t k[33];
    fwd_key(k, principal, rel, resource);
    uint8_t one = 1;
    MDB_val fk  = {.mv_size = sizeof k, .mv_data = k};
    MDB_val fv  = {.mv_size = 1, .mv_data = &one};
    int     mrc = mdb_put(txn, DB->db_acl_fwd, &fk, &fv, MDB_NOOVERWRITE);
    if(mrc != MDB_SUCCESS && mrc != MDB_KEYEXIST) return db_map_mdb_err(mrc);
    return 0;
}

static int put_reverse(MDB_txn* txn, const uint8_t resource[DB_ID_SIZE],
                       uint8_t rel, const uint8_t principal[DB_ID_SIZE])
{
    uint8_t k[17];
    rev_key(k, resource, rel);
    MDB_val rk  = {.mv_size = sizeof k, .mv_data = k};
    MDB_val rv  = {.mv_size = DB_ID_SIZE, .mv_data = (void*)principal};
    int     mrc = mdb_put(txn, DB->db_acl_rel, &rk, &rv, MDB_NODUPDATA);
    if(mrc != MDB_SUCCESS && mrc != MDB_KEYEXIST) return db_map_mdb_err(mrc);
    return 0;
}

static void del_forward(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                        uint8_t rel, const uint8_t resource[DB_ID_SIZE])
{
    uint8_t k[33];
    fwd_key(k, principal, rel, resource);
    MDB_val fk = {.mv_size = sizeof k, .mv_data = k};
    (void)mdb_del(txn, DB->db_acl_fwd, &fk, NULL);
}

static void del_reverse(MDB_txn* txn, const uint8_t resource[DB_ID_SIZE],
                        uint8_t rel, const uint8_t principal[DB_ID_SIZE])
{
    uint8_t k[17];
    rev_key(k, resource, rel);
    MDB_val rk = {.mv_size = sizeof k, .mv_data = k};
    MDB_val rv = {.mv_size = DB_ID_SIZE, .mv_data = (void*)principal};
    (void)mdb_del(txn, DB->db_acl_rel, &rk, &rv);
}

static int has_forward(MDB_txn* txn, const uint8_t principal[DB_ID_SIZE],
                       uint8_t rel, const uint8_t resource[DB_ID_SIZE])
{
    uint8_t k[33];
    fwd_key(k, principal, rel, resource);
    MDB_val fk = {.mv_size = sizeof k, .mv_data = k};
    MDB_val vv = {0};
    int     rc = mdb_get(txn, DB->db_acl_fwd, &fk, &vv);
    if(rc == MDB_SUCCESS) return 0;
    if(rc == MDB_NOTFOUND) return -ENOENT;
    return -EIO;
}