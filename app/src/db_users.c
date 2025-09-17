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

    /* Insert in db_email2id, if not already exists insert in the main */
    MDB_txn *txn = NULL;

    int mrc = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(mrc != MDB_SUCCESS)
        return db_map_mdb_err(mrc);

    /* email->id; if exists stop */
    MDB_val k_email2id = {.mv_size = elen, .mv_data = (void *)email};
    MDB_val v_email2id = {.mv_size = DB_ID_SIZE, .mv_data = NULL};

    unsigned db_email_put_flags = MDB_NOOVERWRITE | MDB_RESERVE;
    mrc = mdb_put(txn, DB->db_user_email2id, &k_email2id, &v_email2id,
                  db_email_put_flags);

    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }

    /* id -> user */
    MDB_val k_id = {.mv_size = DB_ID_SIZE, .mv_data = NULL};
    MDB_val v_up = {.mv_size = sizeof(UserPacked), .mv_data = NULL};
    /* Only use MDB_APPEND if keys are monotonic (e.g., UUIDv7). */
    unsigned db_user_put_flags = MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND;

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

    if(mdb_txn_commit(txn) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    if(out_id)
        memcpy(out_id, id, DB_ID_SIZE);
    return 0;
}
int db_add_users(size_t n_users, const char email_flat[])
{
    if(!email_flat)
        return -EINVAL;

    MDB_txn *txn = NULL;
    int      mrc = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(mrc != MDB_SUCCESS)
        return db_map_mdb_err(mrc);

    const unsigned email_put_flags =
        MDB_NOOVERWRITE | MDB_RESERVE; /* not append */
    const unsigned user_put_flags =
        MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND; /* append ok */

    uint8_t last_id[DB_ID_SIZE] = {0}; /* monotonic guard */
    int     have_last           = 0;

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
            continue; /* duplicate email: skip */
        if(mrc != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return db_map_mdb_err(mrc);
        }

        /* generate strictly increasing UUIDv7 key */
        uint8_t id[DB_ID_SIZE];
        for(;;)
        {
            uuid_v7(id);
            if(!have_last || memcmp(id, last_id, DB_ID_SIZE) > 0)
                break;
            /* extremely rare same/retro key → regenerate; or add a bump() here if you have one */
        }

        MDB_val k_u = {.mv_size = DB_ID_SIZE, .mv_data = id};
        MDB_val v_u = {.mv_size = sizeof(UserPacked), .mv_data = NULL};

        mrc = mdb_put(txn, DB->db_user, &k_u, &v_u, user_put_flags);
        if(mrc == MDB_KEYEXIST)
        {             /* unbelievably rare */
            continue; /* regenerate on next loop */
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

        memcpy(last_id, id, DB_ID_SIZE);
        have_last = 1;
    }

    mrc = mdb_txn_commit(txn);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
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

    /* Resolve recipient */
    {
        int frc = db_user_find_by_email(email, target_user_id);
        if(frc != 0)
            return frc; /* -ENOENT / -EIO / -EINVAL */
    }

    /* Role check stays (coarse global permissions) */
    // {
    //     user_role_t owner_role = 0;
    //     int         prc        = db_user_get_role(owner, &owner_role);
    //     if(prc == -ENOENT)
    //         return -ENOENT;
    //     if(prc != 0)
    //         return -EIO;
    //     if(owner_role != USER_ROLE_PUBLISHER && owner_role != USER_ROLE_VIEWER)
    //         return -EPERM;
    // }

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

    if(mdb_txn_commit(txn) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    return 0;
}