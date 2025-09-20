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

#include "ctype.h"

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

static void write_user_mem(uint8_t *dst, const char *email, uint8_t email_len,
                           user_role_t role);

static int sanitize_email(char email[DB_EMAIL_MAX_LEN], uint8_t *length);

/* qsort comparator for 16-byte ids */
static inline int cmp_id16(const void *a, const void *b)
{
    return memcmp(a, b, DB_ID_SIZE);
}

static inline int is_local_allowed(unsigned char c)
{
    /* RFC 5322 (unquoted) pragmatic subset */
    if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
       (c >= '0' && c <= '9'))
        return 1;
    switch(c)
    {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '/':
        case '=':
        case '?':
        case '^':
        case '_':
        case '`':
        case '{':
        case '|':
        case '}':
        case '~':
        case '.':
            return 1;
        default:
            return 0;
    }
}

static inline int is_domain_allowed(unsigned char c)
{
    if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
       (c >= '0' && c <= '9') || c == '-' || c == '.')
        return 1;
    return 0;
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
    if(k.mv_size != DB_ID_SIZE)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }
    if(out)
    {
        if(db_user_get_and_check_mem(&v, NULL, NULL, NULL, out, NULL) != 0)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
    }

    mdb_txn_abort(txn);
    return 0;
}

int db_user_find_by_ids(size_t        n_users,
                        const uint8_t ids_flat[n_users * DB_ID_SIZE])
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
        if(k.mv_size != DB_ID_SIZE)
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

int db_add_user(char email[DB_EMAIL_MAX_LEN], uint8_t out_id[DB_ID_SIZE])
{
    if(!email ||
       email[0] == '\0' /* || strnlen(email, DB_EMAIL_MAX_LEN - 1) == 0 */)
        return -EINVAL;

    uint8_t elen = 0;
    if(sanitize_email(email, &elen) != 0)
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
    MDB_val v_up = {.mv_size = (size_t)(3 + elen), .mv_data = NULL};
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
            /* grow */
            int grc = db_env_mapsize_expand();
            /* stop if grow failed */
            if(grc != 0)
                return db_map_mdb_err(grc);

            /* retry whole chunk if grow success */
            goto retry_chunk;
        }
        if(mrc != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return db_map_mdb_err(mrc);
        }
        break;
    }

    /* Fill the reserved page memory directly — no temp buffer */
    uint8_t    *w    = (uint8_t *)v_up.mv_data;
    user_role_t role = USER_ROLE_NONE;
    write_user_mem(w, email, elen, role);

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

int db_add_users(size_t n_users, char email_flat[n_users * DB_EMAIL_MAX_LEN])
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
        char   *ei   = &email_flat[i * DB_EMAIL_MAX_LEN];
        uint8_t elen = 0;
        if(sanitize_email(ei, &elen) != 0)
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
        MDB_val v_u = {.mv_size = (size_t)(3 + elen), .mv_data = NULL};

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
        uint8_t    *w    = (uint8_t *)v_u.mv_data;
        user_role_t role = USER_ROLE_NONE;
        write_user_mem(w, ei, elen, role);

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

int db_user_list_all(uint8_t *out_ids, size_t *inout_count_max)
{
    if(!inout_count_max || !out_ids)
        return -EINVAL;
    size_t n = 0;

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
        if(k.mv_size != DB_ID_SIZE)
            continue;
        if(n < *inout_count_max && out_ids)
            memcpy(out_ids + n * DB_ID_SIZE, k.mv_data, DB_ID_SIZE);
        n++;
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

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
        if(k.mv_size != DB_ID_SIZE)
            continue;

        uint8_t user_role = 0;
        db_user_get_and_check_mem(&v, NULL, &user_role, NULL, NULL, NULL);
        /* Check if publisher */
        if(user_role == USER_ROLE_PUBLISHER)
        {
            if(n < cap && out_ids)
                memcpy(out_ids + n * DB_ID_SIZE, k.mv_data, DB_ID_SIZE);
            n++;
        }
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

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
        if(k.mv_size != DB_ID_SIZE)
            continue;

        uint8_t user_role = 0;
        db_user_get_and_check_mem(&v, NULL, &user_role, NULL, NULL, NULL);
        /* Check if publisher */
        if(user_role == USER_ROLE_VIEWER)
        {
            if(n < cap && out_ids)
                memcpy(out_ids + n * DB_ID_SIZE, k.mv_data, DB_ID_SIZE);
            n++;
        }
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

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

int db_user_get_and_check_mem(const MDB_val *v, uint8_t *out_ver,
                              uint8_t *out_role, uint8_t *out_email_len,
                              char     out_email[DB_EMAIL_MAX_LEN],
                              uint8_t *out_size)
{
    if(!v || v->mv_size < 3)
        return -EINVAL;

    const uint8_t *p    = (const uint8_t *)v->mv_data;
    const uint8_t  ver  = p[0];
    const uint8_t  role = p[1];
    const uint8_t  el   = p[2];

    if((size_t)3 + el > v->mv_size)
        return -EINVAL;  // value too short
    if(out_ver)
        *out_ver = ver;
    if(out_role)
        *out_role = role;
    if(out_email_len)
        *out_email_len = el;

    if(out_email)
    {
        if(el >= DB_EMAIL_MAX_LEN)
            return -ENOSPC;
        memcpy(out_email, p + 3, el);
        out_email[el] = '\0';
    }
    if(out_size)
    {
        *out_size = 3 + el;
    }

    return 0;
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

retry_chunk:;
    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_cursor *cur = NULL;
    if(mdb_cursor_open(txn, DB->db_user, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k    = {.mv_size = DB_ID_SIZE, .mv_data = userId};
    MDB_val oldv = {0};
    int     rc   = mdb_cursor_get(cur, &k, &oldv, MDB_SET_KEY);
    if(rc != MDB_SUCCESS)
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }

    uint8_t ver = 0, old_role = 0, el = 0, sz = 0;
    char    email_buf[DB_EMAIL_MAX_LEN];
    rc = db_user_get_and_check_mem(&oldv, &ver, &old_role, &el, email_buf, &sz);
    if(rc != 0)
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }

    /* no-op if same role */
    if(old_role == role)
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn); /* read-only change avoided */
        return 0;
    }

    /* reserve space exactly equal to current record size */
    MDB_val newv = {.mv_size = sz, .mv_data = NULL};
    rc           = mdb_cursor_put(cur, &k, &newv, MDB_CURRENT | MDB_RESERVE);
    if(rc != MDB_SUCCESS)
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }

    /* rewrite record in-place */
    write_user_mem((uint8_t *)newv.mv_data, email_buf, el, role);

    mdb_cursor_close(cur);
    int mrc = mdb_txn_commit(txn);
    if(mrc == MDB_MAP_FULL)
    {
        int grc = db_env_mapsize_expand();
        if(grc != 0)
            return db_map_mdb_err(grc);
        goto retry_chunk;
    }
    return db_map_mdb_err(mrc);
}

static void write_user_mem(uint8_t *dst, const char *email, uint8_t email_len,
                           user_role_t role)
{
    dst[0] = DB_VER;
    dst[1] = (uint8_t)role;
    dst[2] = email_len;
    memcpy(dst + 3, email, email_len);
}

int sanitize_email(char email[DB_EMAIL_MAX_LEN], uint8_t *out_len)
{
    if(!email || !out_len)
        return -ENOENT;

    /* Require a NUL within the buffer */
    size_t len = strnlen(email, DB_EMAIL_MAX_LEN);
    if(len == 0 || len >= DB_EMAIL_MAX_LEN)
        return -ENOENT;

    /* No leading/trailing spaces; no control chars/DEL/space anywhere */
    if(isspace((unsigned char)email[0]) ||
       isspace((unsigned char)email[len - 1]))
        return -ENOENT;
    for(size_t k = 0; k < len; ++k)
    {
        unsigned char c = (unsigned char)email[k];
        if(c <= 0x20 || c == 0x7F)
            return -ENOENT; /* forbid space & controls */
    }

    /* Exactly one '@' and split */
    char *at = memchr(email, '@', len);
    if(!at)
        return -ENOENT;
    if(memchr(at + 1, '@', (size_t)(email + len - (at + 1))))
        return -ENOENT;

    size_t local_len  = (size_t)(at - email);
    size_t domain_len = len - local_len - 1;
    if(local_len == 0 || domain_len == 0)
        return -ENOENT;
    if(local_len > 64)
        return -ENOENT;

    /* Local-part: dot-atom, no leading/trailing dot, no ".." */
    {
        const unsigned char *p = (const unsigned char *)email;
        if(p[0] == '.' || p[local_len - 1] == '.')
            return -ENOENT;
        int prev_dot = 0;
        for(size_t k = 0; k < local_len; ++k)
        {
            unsigned char c = p[k];
            if(!is_local_allowed(c))
                return -ENOENT;
            if(c == '.')
            {
                if(prev_dot)
                    return -ENOENT;
                prev_dot = 1;
            }
            else
            {
                prev_dot = 0;
            }
        }
    }

    /* Domain: labels [A-Za-z0-9-], no leading/trailing '-', at least one dot,
       TLD length >= 2; lowercase domain in place */
    {
        unsigned char *p = (unsigned char *)(at + 1);
        if(p[0] == '.' || p[domain_len - 1] == '.')
            return -ENOENT;

        size_t label_len = 0;
        int    have_dot  = 0;
        for(size_t k = 0; k < domain_len; ++k)
        {
            unsigned char c = p[k];
            if(!is_domain_allowed(c))
                return -ENOENT;

            /* lowercase in-place (domain only) */
            if(c >= 'A' && c <= 'Z')
            {
                c    = (unsigned char)(c - 'A' + 'a');
                p[k] = c;
            }

            if(c == '.')
            {
                have_dot = 1;
                if(label_len == 0)
                    return -ENOENT; /* empty label */
                if(p[k - 1] == '-')
                    return -ENOENT; /* ends with '-' */
                if(label_len > 63)
                    return -ENOENT;
                label_len = 0;
            }
            else
            {
                if(label_len == 0 && c == '-')
                    return -ENOENT; /* starts with '-' */
                label_len++;
            }
        }
        if(label_len == 0 || label_len > 63)
            return -ENOENT;
        if(!have_dot)
            return -ENOENT;
        if(label_len < 2)
            return -ENOENT; /* TLD >= 2 */
    }

    if(len > 255)
        return -ENOENT; /* fits uint8_t design */

    *out_len = (uint8_t)len;
    // if(len + 1 < DB_EMAIL_MAX_LEN)
    // {
    //     memset(email + len + 1, 0, DB_EMAIL_MAX_LEN - (len + 1));
    // }
    return 0;
}