/**
 * @file db_users.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db_int.h"
#include "uuid.h"
#include "db_acl.h"

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

static int db_user_set_role(uint8_t userId[DB_ID_SIZE], user_role_t role);

/* qsort comparator for 16-byte ids */
static int cmp_id16(const void *a, const void *b)
{
    return memcmp(a, b, DB_ID_SIZE);
}

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

/** Look up a user by id and optionally return email. */
int db_user_find_by_id(const uint8_t id[DB_ID_SIZE], char out[DB_EMAIL_MAX_LEN])
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
        return db_map_mdb_err(mrc);
    }
    if(v.mv_size != sizeof(UserPacked))
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    if(out)
        memcpy(out, ((UserPacked *)v.mv_data)->email, DB_EMAIL_MAX_LEN);
    mdb_txn_abort(txn);
    return 0;
}

int db_user_find_by_ids(size_t n_users, const uint8_t ids_flat[])
{
    if(n_users == 0 || !ids_flat)
        return -EINVAL;

    MDB_txn *txn = NULL;
    int      mrc = mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn);
    if(mrc != MDB_SUCCESS)
        return db_map_mdb_err(mrc);

    /* Try fast path: sort local copy */
    uint8_t *ids_sorted = (uint8_t *)malloc(n_users * DB_ID_SIZE);
    if(ids_sorted)
    {
        memcpy(ids_sorted, ids_flat, n_users * DB_ID_SIZE);
        qsort(ids_sorted, n_users, DB_ID_SIZE, cmp_id16);

        /* de-dup in place */
        size_t uniq = 0;
        for(size_t i = 0; i < n_users; ++i)
        {
            if(uniq == 0 ||
               memcmp(ids_sorted + (uniq - 1) * DB_ID_SIZE,
                      ids_sorted + i * DB_ID_SIZE, DB_ID_SIZE) != 0)
            {
                if(uniq != i)
                    memcpy(ids_sorted + uniq * DB_ID_SIZE,
                           ids_sorted + i * DB_ID_SIZE, DB_ID_SIZE);
                ++uniq;
            }
        }

        MDB_cursor *cur = NULL;
        if(mdb_cursor_open(txn, DB->db_user, &cur) != MDB_SUCCESS)
        {
            free(ids_sorted);
            mdb_txn_abort(txn);
            return -EIO;
        }

        MDB_val k = {0}, v = {0};
        int     rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
        if(rc == MDB_NOTFOUND)
        {
            mdb_cursor_close(cur);
            free(ids_sorted);
            mdb_txn_abort(txn);
            return db_map_mdb_err(rc);
        }
        if(rc != MDB_SUCCESS)
        {
            mdb_cursor_close(cur);
            free(ids_sorted);
            mdb_txn_abort(txn);
            return db_map_mdb_err(rc);
        }

        for(size_t i = 0; i < uniq; ++i)
        {
            const uint8_t *want = ids_sorted + i * DB_ID_SIZE;

            /* advance until current key >= want */
            for(;;)
            {
                int cmp = (k.mv_size == DB_ID_SIZE)
                              ? memcmp(k.mv_data, want, DB_ID_SIZE)
                              : (k.mv_size < DB_ID_SIZE ? -1 : 1);
                if(cmp >= 0)
                    break;

                rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
                if(rc != MDB_SUCCESS)
                {
                    mdb_cursor_close(cur);
                    free(ids_sorted);
                    mdb_txn_abort(txn);
                    return db_map_mdb_err(rc);
                }
            }

            if(k.mv_size != DB_ID_SIZE ||
               memcmp(k.mv_data, want, DB_ID_SIZE) != 0)
            {
                mdb_cursor_close(cur);
                free(ids_sorted);
                mdb_txn_abort(txn);
                return db_map_mdb_err(MDB_NOTFOUND);
            }
            if(v.mv_size != sizeof(UserPacked))
            {
                mdb_cursor_close(cur);
                free(ids_sorted);
                mdb_txn_abort(txn);
                return -EIO;
            }

            /* prefetch for next iteration (optional) */
            if(i + 1 < uniq)
            {
                rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
                if(rc != MDB_SUCCESS && rc != MDB_NOTFOUND)
                {
                    mdb_cursor_close(cur);
                    free(ids_sorted);
                    mdb_txn_abort(txn);
                    return -EIO;
                }
            }
        }

        mdb_cursor_close(cur);
        free(ids_sorted);
        mdb_txn_abort(txn); /* read-only: abort, don’t commit */
        return 0;
    }

    /* Fallback: individual lookups */
    for(size_t i = 0; i < n_users; ++i)
    {
        const uint8_t *id = &ids_flat[i * DB_ID_SIZE];
        MDB_val        k  = {.mv_size = DB_ID_SIZE, .mv_data = (void *)id};
        MDB_val        v  = {0};
        mrc               = mdb_get(txn, DB->db_user, &k, &v);
        if(mrc != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return db_map_mdb_err(mrc);
        }
        if(v.mv_size != sizeof(UserPacked))
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
    }
    mdb_txn_abort(txn); /* read-only: abort */
    return 0;
}

/** Look up a user id by email. */
int db_user_find_by_email(const char email[DB_EMAIL_MAX_LEN],
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
        return db_map_mdb_err(mrc);
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

int db_add_user(const char email[DB_EMAIL_MAX_LEN], uint8_t out_id[DB_ID_SIZE])
{
    if(!email ||
       email[0] == '\0' /* || strnlen(email, DB_EMAIL_MAX_LEN - 1) == 0 */)
        return -EINVAL;

    /* normalize length once (stored without '\0') */
    const size_t elen = strnlen(email, DB_EMAIL_MAX_LEN - 1);
    if(elen == 0)
        return -EINVAL;

    unsigned db_email_put_flags = MDB_NOOVERWRITE | MDB_RESERVE;
    unsigned db_user_put_flags  = MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND;
retry_chunk:
    /* Insert in db_email2id, if not already exists insert in the main */
    MDB_txn *txn = NULL;

    int mrc = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(mrc != MDB_SUCCESS)
        return db_map_mdb_err(mrc);

    /* email->id; if exists stop */
    MDB_val k_email2id = {.mv_size = elen, .mv_data = (void *)email};
    MDB_val v_email2id = {.mv_size = DB_ID_SIZE, .mv_data = NULL};

    mrc = mdb_put(txn, DB->db_user_email2id, &k_email2id, &v_email2id,
                  db_email_put_flags);
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
    /* id -> user */
    MDB_val k_id = {.mv_size = DB_ID_SIZE, .mv_data = NULL};
    MDB_val v_up = {.mv_size = sizeof(UserPacked), .mv_data = NULL};
    /* Only use MDB_APPEND if keys are monotonic (e.g., UUIDv7). */

    /* Generate unique id */
    uint8_t id[DB_ID_SIZE];
    while(1)
    {
        uuid_v7(id);
        k_id.mv_data = id;
        mrc = mdb_put(txn, DB->db_user, &k_id, &v_up, db_user_put_flags);
        if(mrc == MDB_KEYEXIST)
        {
            /* ultra-rare: regenerate and retry */
            continue;
        }
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
        break;
    }

    /* Fill the reserved page memory directly — no temp buffer */
    uint8_t *w = (uint8_t *)v_up.mv_data;

    /* id[16] */
    memcpy(w, id, DB_ID_SIZE);
    w += DB_ID_SIZE;

    /* email[128] zero-terminated + padded */
    memcpy(w, email, elen);
    memset(w + elen, 0, DB_EMAIL_MAX_LEN - elen); /* pad with zeros */
    w += DB_EMAIL_MAX_LEN;

    /* role (2 bytes); use memcpy to avoid alignment/endianness pitfalls */
    user_role_t role = USER_ROLE_NONE;
    memcpy(w, &role, sizeof role);

    /* finalize email->id by writing the freshly created id */
    memcpy(v_email2id.mv_data, id, DB_ID_SIZE);

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
    if(out_id)
        memcpy(out_id, id, DB_ID_SIZE);
    return 0;
}

int db_add_users(size_t     n_users,
                 const char email_flat[n_users * DB_EMAIL_MAX_LEN])
{
    if(!email_flat)
        return -EINVAL;

    const unsigned email_put_flags =
        MDB_NOOVERWRITE | MDB_RESERVE; /* not append */
    const unsigned user_put_flags =
        MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND; /* append ok */

retry_chunk:
    MDB_txn *txn = NULL;
    int      mrc = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(mrc != MDB_SUCCESS)
        return db_map_mdb_err(mrc);

    for(size_t i = 0; i < n_users; ++i)
    {
        const char *ei   = &email_flat[i * DB_EMAIL_MAX_LEN];
        size_t      elen = strnlen(ei, DB_EMAIL_MAX_LEN - 1);
        if(elen == 0)
        {
            mdb_txn_abort(txn);
            return -EINVAL;
        }

        /* email -> id (reserve slot if new; skip if exists) */
        MDB_val k_e = {.mv_size = elen, .mv_data = (void *)ei};
        MDB_val v_e = {.mv_size = DB_ID_SIZE, .mv_data = NULL};

        mrc = mdb_put(txn, DB->db_user_email2id, &k_e, &v_e, email_put_flags);
        if(mrc == MDB_KEYEXIST)
        {
            continue; /* duplicate: skip this email */
        }
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

        /* generate strictly increasing UUIDv7 key */
        uint8_t id[DB_ID_SIZE];
        uuid_v7(id);

        MDB_val k_u = {.mv_size = DB_ID_SIZE, .mv_data = id};
        MDB_val v_u = {.mv_size = sizeof(UserPacked), .mv_data = NULL};

        mrc = mdb_put(txn, DB->db_user, &k_u, &v_u, user_put_flags);
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

        /* fill user record */
        uint8_t *w = (uint8_t *)v_u.mv_data;
        memcpy(w, id, DB_ID_SIZE);
        w += DB_ID_SIZE;
        memcpy(w, ei, elen);
        memset(w + elen, 0, DB_EMAIL_MAX_LEN - elen);
        w                += DB_EMAIL_MAX_LEN;
        user_role_t role  = USER_ROLE_NONE;
        memcpy(w, &role, sizeof role);

        /* finalize email->id */
        memcpy(v_e.mv_data, id, DB_ID_SIZE);
    }

    mrc = mdb_txn_commit(txn);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        if(mrc == MDB_MAP_FULL)
        {
            int grc = db_env_mapsize_expand(); /* grow */
            if(grc != 0)
                return db_map_mdb_err(grc); /* hit max? bubble up */
            goto retry_chunk;               /* 3) retry whole chunk */
        }

        return db_map_mdb_err(mrc);
    }
    return 0;
}

/** List all users. */
int db_user_list_all(uint8_t *out_ids, size_t *inout_count_max)
{
    if(!inout_count_max)
        return -EINVAL;
    size_t cap = out_ids ? *inout_count_max : 0, n = 0;

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
    size_t cap = out_ids ? *inout_count_max : 0, n = 0;

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
    size_t cap = out_ids ? *inout_count_max : 0, n = 0;

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

/** Share data with a user identified by email (grants presence in 'U'). */
int db_user_share_data_with_user_email(uint8_t    owner[DB_ID_SIZE],
                                       uint8_t    data_id[DB_ID_SIZE],
                                       const char email[DB_EMAIL_MAX_LEN])
{
    if(!owner || !data_id || !email || email[0] == '\0')
        return -EINVAL;

    uint8_t target_user_id[DB_ID_SIZE] = {0};

retry_chunk:
    /* Resolve recipient */
    {
        int frc = db_user_find_by_email(email, target_user_id);
        if(frc != 0)
            return frc; /* -ENOENT / -EIO / -EINVAL */
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

    int mrc = mdb_txn_commit(txn);
    if(mrc == MDB_MAP_FULL)
    {
        int grc = db_env_mapsize_expand();
        if(grc != 0)
            return db_map_mdb_err(grc);
        goto retry_chunk;
    }
    if(mrc != MDB_SUCCESS)
    {
        /* txn is already aborted/freed on commit error */
        return db_map_mdb_err(mrc);
    }
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

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static int db_user_set_role(uint8_t userId[DB_ID_SIZE], user_role_t role)
{
    if(role != USER_ROLE_VIEWER && role != USER_ROLE_PUBLISHER &&
       role != USER_ROLE_NONE)
        return -EINVAL;
retry_chunk:
    MDB_txn    *txn;
    MDB_cursor *cur;
    MDB_val     k    = {.mv_size = DB_ID_SIZE, .mv_data = userId};
    MDB_val     oldv = {0};
    MDB_val     newv = {.mv_size = sizeof(UserPacked), .mv_data = NULL};
    int         rc   = -1;

    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

    if(mdb_cursor_open(txn, DB->db_user, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    rc = mdb_cursor_get(cur, &k, &oldv, MDB_SET_KEY);
    if(rc != MDB_SUCCESS || oldv.mv_size != sizeof(UserPacked))
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }

    /* Check previous user role */
    if(((const UserPacked *)oldv.mv_data)->role == role)
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn);
        return 0;
    }

    rc = mdb_cursor_put(cur, &k, &newv, MDB_CURRENT | MDB_RESERVE);
    if(rc != MDB_SUCCESS)
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }

    /* copy old record into LMDB slot */
    memcpy(newv.mv_data, oldv.mv_data, sizeof(UserPacked));

    /* patch just the role field (unaligned-safe) */
    memcpy((uint8_t *)newv.mv_data + offsetof(UserPacked, role), &role,
           sizeof(role));

    mdb_cursor_close(cur);

    int mrc = mdb_txn_commit(txn);
    if(mrc == MDB_MAP_FULL)
    {
        int grc = db_env_mapsize_expand();
        if(grc != 0)
            return db_map_mdb_err(grc);
        goto retry_chunk;
    }
    if(mrc != MDB_SUCCESS)
    {
        /* txn is already aborted/freed on commit error */
        return db_map_mdb_err(mrc);
    }
    return 0;
}