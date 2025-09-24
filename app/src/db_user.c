/**
 * @file db_users.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db_acl.h"
#include "db_internal.h"
#include "utils_interface.h"

#include "ctype.h"

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */

/**
 * DB USER 
 */

/* user_id2data user data structure to store in db */
typedef struct __attribute__((packed))
{
    uint8_t     ver;       /* 1 byte version for future evolution */
    user_role_t role;      /* 1 byte role */
    uint8_t     email_len; /* 1 byte email length */
    char       *email;     /* variable-length not-terminated email */
} DB_user_id2data_packed;

/* user_email2id id data structure to store in db */
typedef struct __attribute__((packed))
{
    uint8_t id[DB_UUID_SIZE]
} db_user_mail2id_packed_t;

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */

static size_t db_user_id2data_data_size(const void *p)
{
    return 3u + ((DB_user_id2data_packed *)p)->email_len;
}

static void db_user_id2data_data_write(void *dst, void *src)
{
    DB_user_id2data_packed *c = (DB_user_id2data_packed *)src;
    uint8_t                *w = (uint8_t *)dst;
    w[0]                      = c->ver;
    w[1]                      = (uint8_t)c->role;
    w[2]                      = c->email_len;
    memcpy(w + 3, c->email, c->email_len);
    /* no trailing NUL stored; reader knows length from byte 2 */
}

static size_t db_user_mail2id_data_size(const void *p)
{
    (void)p;
    return DB_UUID_SIZE;
}

static void db_user_mail2id_write(void *dst, void *p)
{
    // (uint8_t *)dst = *(uint8_t *)p;
    memcpy(dst, p, DB_UUID_SIZE);
}

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
#define DB_ENC_USER_ID2DATA(ver, role, email_len, email)                        \
    (DB_val_t)                                                                  \
    {                                                                           \
        .ctx  = &(DB_user_id2data_packed){(ver), (role), (email_len), (email)}, \
        .size = db_user_id2data_data_size, .write = db_user_id2data_data_write  \
    }

#define DB_ENC_USER_MAIL2ID(user_id)                                      \
    (DB_val_t)                                                            \
    {                                                                     \
        .ctx  = &(db_user_mail2id_packed_t){(user_id)},                   \
        .size = db_user_mail2id_data_size, .write = db_user_mail2id_write \
    }

static int db_user_set_role(uint8_t userId[DB_UUID_SIZE], user_role_t role);

static void write_user_mem(uint8_t *dst, const char *email, uint8_t email_len,
                           user_role_t role);

/* qsort comparator for 16-byte ids */
static inline int cmp_id16(const void *a, const void *b)
{
    return memcmp(a, b, DB_UUID_SIZE);
}


static int db_put_reserve(MDB_txn *txn, const DB_operation_t *operations,
                          uint8_t n_operations, uint8_t *failed_op)
{
    if(!txn || !operations || n_operations <= 0) return -EINVAL;

    /* getting data loop */
    for(uint8_t i = 0; i < n_operations; ++i)
    {
        DB_operation_t *operation = &operations[i];

        /* Check operation params */
        if(!operation->val.ctx || !operation->val.size || !operation->val.write)
            return -EINVAL;

        MDB_val k = {.mv_size = operation->key.data_len,
                     .mv_data = (void *)operation->key.data_ptr};
        MDB_val v = {.mv_size = operation->val.size(operation->val.ctx),
                     .mv_data = NULL};

        int rc = mdb_put(txn, operation->dbi, &k, &v,
                         MDB_RESERVE | operation->flags);
        if(rc != MDB_SUCCESS)
        {
            printf("Nok mdb_put\n");
            if(failed_op) *failed_op = i;
            return rc;
        }

        /* remember where to write later */
        operation->dst     = v.mv_data;
        operation->dst_len = v.mv_size;
    }

    return MDB_SUCCESS;
}

static int db_put_write_reserved(DB_operation_t *operations,
                                 uint8_t         n_operations)
{
    if(!operations || n_operations <= 0) return -EINVAL;

    for(size_t i = 0; i < n_operations; ++i)
    {
        /* must be set by reserve pass */
        if(!operations[i].dst) return -EFAULT;

        operations[i].val.write(operations[i].dst, operations[i].val.ctx);
    }
    return MDB_SUCCESS;
}

static int db_register_new(MDB_txn *txn, uint8_t email_len, const char *email,
                           const uint8_t *user_id
                           /*, const void *pwrec, size_t pwrec_sz*/)
{
    if(!txn || !email || !user_id /* || !pwrec*/) return -EINVAL;

    int N_OPERATIONS = 2;

    /* build the operations to be executed on the whole db
    for adding a new user:
    insert new user email and verify not exists.
    insert new user data
    TO DO: insert new user pwd
    */
    DB_operation_t ops[N_OPERATIONS];

    printf("ok here_1\n");
    ops[0].dbi = DB->db_user_id2data;
    ops[0].key = DB_KEY_GEN_ID16(user_id);
    ops[0].val = DB_ENC_USER_ID2DATA(DB_VER, USER_ROLE_NONE, email_len, email);
    ops[0].flags = MDB_NOOVERWRITE | MDB_APPEND;

    printf("ok here_2\n");
    /* 2) email -> id */
    ops[1].dbi   = DB->db_user_mail2id;
    ops[1].key   = DB_KEY_GEN_MAIL(email, email_len);
    ops[1].val   = DB_ENC_USER_MAIL2ID(user_id);
    ops[1].flags = MDB_NOOVERWRITE;
    printf("ok here_3\n");

    // /* 3) id -> password */
    // ops[2].dbi   = DB->db_user_id2pw;
    // ops[2].key   = DB_KEY_ID16(user_id);
    // ops[2].val   = DB_ENC_SPAN(pwrec, pwrec_sz);
    // ops[2].flags = MDB_NOOVERWRITE;

    size_t failed = (size_t)-1;
    int rc = db_put_reserve(txn, ops, N_OPERATIONS, &failed);
    if(rc != MDB_SUCCESS)
    {
        printf("Nok db_put_reserve\n");
        return rc;
    }
    printf("ok db_put_reserve\n");

    return db_put_write_reserved(ops, N_OPERATIONS);
}

int auth_register_new(const char *email_in, /* const char *pwd_in, */
                      uint8_t *out_user_id)
{
    if(!email_in || email_in[0] == '\0') return -EINVAL;

    uint8_t elen = 0;
    if(sanitize_email(email_in, DB_EMAIL_MAX_LEN, &elen) != 0) return -EINVAL;
    printf("ok sanitize\n");

    uint8_t user_id[DB_UUID_SIZE];
    uuid_v7(user_id);

    // uint8_t pwrec[PWREC_SIZE];
    // if(password_hash(pwd_in, pwrec) != 0) return -EIO;

retry:
    MDB_txn *txn = NULL;
    int      rc  = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(rc != MDB_SUCCESS) return db_map_mdb_err(rc);
    printf("ok mdb_txn_begin\n");

    rc =
        db_register_new(txn, elen, email_in, user_id /*, pwrec, sizeof pwrec*/);
    if(rc != MDB_SUCCESS)
    {
        printf("Nok db_register_new\n");
        mdb_txn_abort(txn);
        if(rc == MDB_MAP_FULL)
        {
            int gr = db_env_mapsize_expand();
            if(gr != 0) return db_map_mdb_err(gr);
            goto retry;
        }

        return db_map_mdb_err(rc);
    }
        printf("ok db_register_new\n");

    rc = mdb_txn_commit(txn);
    if(rc == MDB_MAP_FULL)
    {
        printf("Nok mdb_txn_commit\n");
        int gr = db_env_mapsize_expand();
        if(gr != 0) return db_map_mdb_err(gr);
        goto retry;
    }
    if(rc != MDB_SUCCESS) return db_map_mdb_err(rc);
    printf("ok mdb_txn_commit\n");
    if(out_user_id) memcpy(out_user_id, user_id, DB_UUID_SIZE);
    return 0;
}

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

/** Look up a user by id and optionally return email. */
int db_user_find_by_id(const uint8_t id[DB_UUID_SIZE],
                       char          out[DB_EMAIL_MAX_LEN])
{
    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = DB_UUID_SIZE, .mv_data = (void *)id};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_user_id2data, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }
    if(k.mv_size != DB_UUID_SIZE)
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
                        const uint8_t ids_flat[n_users * DB_UUID_SIZE])
{
    if(n_users == 0 || !ids_flat) return -EINVAL;

    MDB_txn *txn = NULL;
    int      mrc = mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn);
    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    /* Try fast path: sort local copy */
    uint8_t *ids_sorted = (uint8_t *)malloc(n_users * DB_UUID_SIZE);
    if(ids_sorted)
    {
        memcpy(ids_sorted, ids_flat, n_users * DB_UUID_SIZE);
        qsort(ids_sorted, n_users, DB_UUID_SIZE, cmp_id16);

        /* de-dup in place */
        size_t uniq = 0;
        for(size_t i = 0; i < n_users; ++i)
        {
            if(uniq == 0 ||
               memcmp(ids_sorted + (uniq - 1) * DB_UUID_SIZE,
                      ids_sorted + i * DB_UUID_SIZE, DB_UUID_SIZE) != 0)
            {
                if(uniq != i)
                    memcpy(ids_sorted + uniq * DB_UUID_SIZE,
                           ids_sorted + i * DB_UUID_SIZE, DB_UUID_SIZE);
                ++uniq;
            }
        }

        MDB_cursor *cur = NULL;
        if(mdb_cursor_open(txn, DB->db_user_id2data, &cur) != MDB_SUCCESS)
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
            const uint8_t *want = ids_sorted + i * DB_UUID_SIZE;

            /* advance until current key >= want */
            for(;;)
            {
                int cmp = (k.mv_size == DB_UUID_SIZE)
                              ? memcmp(k.mv_data, want, DB_UUID_SIZE)
                              : (k.mv_size < DB_UUID_SIZE ? -1 : 1);
                if(cmp >= 0) break;

                rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT);
                if(rc != MDB_SUCCESS)
                {
                    mdb_cursor_close(cur);
                    free(ids_sorted);
                    mdb_txn_abort(txn);
                    return db_map_mdb_err(rc);
                }
            }

            if(k.mv_size != DB_UUID_SIZE ||
               memcmp(k.mv_data, want, DB_UUID_SIZE) != 0)
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
        const uint8_t *id = &ids_flat[i * DB_UUID_SIZE];
        MDB_val        k  = {.mv_size = DB_UUID_SIZE, .mv_data = (void *)id};
        MDB_val        v  = {0};
        mrc               = mdb_get(txn, DB->db_user_id2data, &k, &v);
        if(mrc != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            return db_map_mdb_err(mrc);
        }
        if(k.mv_size != DB_UUID_SIZE)
        {
            mdb_txn_abort(txn);
            return -EIO;
        }
    }
    mdb_txn_abort(txn); /* read-only: abort */
    return 0;
}

int db_user_find_by_email(const char email[DB_EMAIL_MAX_LEN],
                          uint8_t    out_id[DB_UUID_SIZE])
{
    if(!email || email[0] == '\0') return -EINVAL;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = strlen(email), .mv_data = (void *)email};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_user_mail2id, &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }
    if(v.mv_size != DB_UUID_SIZE)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    if(out_id) memcpy(out_id, v.mv_data, DB_UUID_SIZE);
    mdb_txn_abort(txn);
    return 0;
}

int db_add_user(char email[DB_EMAIL_MAX_LEN], uint8_t out_id[DB_UUID_SIZE])
{
    if(!email ||
       email[0] == '\0' /* || strnlen(email, DB_EMAIL_MAX_LEN - 1) == 0 */)
        return -EINVAL;

    uint8_t elen = 0;
    if(sanitize_email(email, DB_EMAIL_MAX_LEN, &elen) != 0) return -EINVAL;

    unsigned db_email_put_flags = MDB_NOOVERWRITE | MDB_RESERVE;
    unsigned db_user_put_flags  = MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND;
retry_chunk:
    /* Insert in db_email2id, if not already exists insert in the main */
    MDB_txn *txn = NULL;

    int mrc = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    /* email->id; if exists stop */
    MDB_val k_email2id = {.mv_size = elen, .mv_data = (void *)email};
    MDB_val v_email2id = {.mv_size = DB_UUID_SIZE, .mv_data = NULL};

    mrc = mdb_put(txn, DB->db_user_mail2id, &k_email2id, &v_email2id,
                  db_email_put_flags);
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
    /* id -> user */
    MDB_val k_id = {.mv_size = DB_UUID_SIZE, .mv_data = NULL};
    MDB_val v_up = {.mv_size = (size_t)(3 + elen), .mv_data = NULL};
    /* Only use MDB_APPEND if keys are monotonic (e.g., UUIDv7). */

    /* Generate unique id */
    uint8_t id[DB_UUID_SIZE];
    while(1)
    {
        uuid_v7(id);
        k_id.mv_data = id;
        mrc =
            mdb_put(txn, DB->db_user_id2data, &k_id, &v_up, db_user_put_flags);
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
            if(grc != 0) return db_map_mdb_err(grc);

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
    memcpy(v_email2id.mv_data, id, DB_UUID_SIZE);

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
    if(out_id) memcpy(out_id, id, DB_UUID_SIZE);
    return 0;
}

int db_add_users(size_t n_users, char email_flat[n_users * DB_EMAIL_MAX_LEN])
{
    if(!email_flat) return -EINVAL;

    const unsigned email_put_flags =
        MDB_NOOVERWRITE | MDB_RESERVE; /* not append */
    const unsigned user_put_flags =
        MDB_NOOVERWRITE | MDB_RESERVE | MDB_APPEND; /* append ok */

retry_chunk:
    MDB_txn *txn = NULL;
    int      mrc = mdb_txn_begin(DB->env, NULL, 0, &txn);
    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    for(size_t i = 0; i < n_users; ++i)
    {
        char   *ei   = &email_flat[i * DB_EMAIL_MAX_LEN];
        uint8_t elen = 0;
        if(sanitize_email(ei, DB_EMAIL_MAX_LEN, &elen) != 0)
        {
            mdb_txn_abort(txn);
            return -EINVAL;
        }

        /* email -> id (reserve slot if new; skip if exists) */
        MDB_val k_e = {.mv_size = elen, .mv_data = (void *)ei};
        MDB_val v_e = {.mv_size = DB_UUID_SIZE, .mv_data = NULL};

        mrc = mdb_put(txn, DB->db_user_mail2id, &k_e, &v_e, email_put_flags);
        if(mrc == MDB_KEYEXIST)
        {
            continue; /* duplicate: skip this email */
        }
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

        /* generate strictly increasing UUIDv7 key */
        uint8_t id[DB_UUID_SIZE];
        uuid_v7(id);

        MDB_val k_u = {.mv_size = DB_UUID_SIZE, .mv_data = id};
        MDB_val v_u = {.mv_size = (size_t)(3 + elen), .mv_data = NULL};

        mrc = mdb_put(txn, DB->db_user_id2data, &k_u, &v_u, user_put_flags);
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

        /* fill user record */
        uint8_t    *w    = (uint8_t *)v_u.mv_data;
        user_role_t role = USER_ROLE_NONE;
        write_user_mem(w, ei, elen, role);

        /* finalize email->id */
        memcpy(v_e.mv_data, id, DB_UUID_SIZE);
    }

    mrc = mdb_txn_commit(txn);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        if(mrc == MDB_MAP_FULL)
        {
            int grc = db_env_mapsize_expand();       /* grow */
            if(grc != 0) return db_map_mdb_err(grc); /* hit max? bubble up */
            goto retry_chunk;                        /* 3) retry whole chunk */
        }

        return db_map_mdb_err(mrc);
    }
    return 0;
}

int db_user_list_all(uint8_t *out_ids, size_t *inout_count_max)
{
    if(!inout_count_max || !out_ids) return -EINVAL;
    size_t n = 0;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;
    MDB_cursor *cur;
    if(mdb_cursor_open(txn, DB->db_user_id2data, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k = {0}, v = {0};
    for(int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST); rc == MDB_SUCCESS;
        rc     = mdb_cursor_get(cur, &k, &v, MDB_NEXT))
    {
        if(k.mv_size != DB_UUID_SIZE) continue;
        if(n < *inout_count_max && out_ids)
            memcpy(out_ids + n * DB_UUID_SIZE, k.mv_data, DB_UUID_SIZE);
        n++;
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

int db_user_list_publishers(uint8_t *out_ids, size_t *inout_count_max)
{
    if(!inout_count_max) return -EINVAL;
    size_t cap = out_ids ? *inout_count_max : 0, n = 0;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;
    MDB_cursor *cur;
    if(mdb_cursor_open(txn, DB->db_user_id2data, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k = {0}, v = {0};
    for(int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST); rc == MDB_SUCCESS;
        rc     = mdb_cursor_get(cur, &k, &v, MDB_NEXT))
    {
        if(k.mv_size != DB_UUID_SIZE) continue;

        uint8_t user_role = 0;
        db_user_get_and_check_mem(&v, NULL, &user_role, NULL, NULL, NULL);
        /* Check if publisher */
        if(user_role == USER_ROLE_PUBLISHER)
        {
            if(n < cap && out_ids)
                memcpy(out_ids + n * DB_UUID_SIZE, k.mv_data, DB_UUID_SIZE);
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
    if(!inout_count_max) return -EINVAL;
    size_t cap = out_ids ? *inout_count_max : 0, n = 0;

    MDB_txn *txn;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;
    MDB_cursor *cur;
    if(mdb_cursor_open(txn, DB->db_user_id2data, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k = {0}, v = {0};
    for(int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST); rc == MDB_SUCCESS;
        rc     = mdb_cursor_get(cur, &k, &v, MDB_NEXT))
    {
        if(k.mv_size != DB_UUID_SIZE) continue;

        uint8_t user_role = 0;
        db_user_get_and_check_mem(&v, NULL, &user_role, NULL, NULL, NULL);
        /* Check if publisher */
        if(user_role == USER_ROLE_VIEWER)
        {
            if(n < cap && out_ids)
                memcpy(out_ids + n * DB_UUID_SIZE, k.mv_data, DB_UUID_SIZE);
            n++;
        }
    }
    mdb_cursor_close(cur);
    mdb_txn_abort(txn);
    *inout_count_max = n;
    return 0;
}

int db_user_share_data_with_user_email(const uint8_t owner[DB_UUID_SIZE],
                                       const uint8_t data_id[DB_UUID_SIZE],
                                       const char    email[DB_EMAIL_MAX_LEN])
{
    if(!owner || !data_id || !email || email[0] == '\0') return -EINVAL;

    uint8_t target[DB_UUID_SIZE] = {0};

    /* Resolve recipient once (outside txn ok; id is stable). */
    {
        int rc = db_user_find_by_email(email, target);
        if(rc != 0) return rc; /* -ENOENT / -EIO / -EINVAL */
    }

    /* No-op if trying to share to self */
    if(memcmp(owner, target, DB_UUID_SIZE) == 0) return 0;

retry_txn:
    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS) return -EIO;

    /* Ensure data exists */
    {
        MDB_val k  = {.mv_size = DB_UUID_SIZE, .mv_data = (void *)data_id};
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
    }

    /* Policy (MVP): only OWNERS can share; recipients get VIEW; no re-share. */
    {
        int rc = acl_has_owner(txn, owner, data_id);
        if(rc != 0)
        {
            mdb_txn_abort(txn);
            return -EPERM;
        } /* not an owner */
    }

    /* If recipient already has any access, we’re done (idempotent). */
    {
        int rc = acl_has_any(txn, target, data_id);
        if(rc == 0)
        {
            mdb_txn_abort(txn);
            return 0;
        }
        if(rc != -ENOENT)
        {
            mdb_txn_abort(txn);
            return rc;
        }
    }

    /* Grant VIEW to recipient (writes forward+reverse; idempotent). */
    {
        int rc = acl_grant_view(txn, target, data_id);
        if(rc != 0)
        {
            mdb_txn_abort(txn);
            return rc;
        }
    }

    int mrc = mdb_txn_commit(txn);
    if(mrc == MDB_MAP_FULL)
    {
        int grc = db_env_mapsize_expand();
        if(grc != 0) return db_map_mdb_err(grc);
        goto retry_txn;
    }
    if(mrc != MDB_SUCCESS) return db_map_mdb_err(mrc);

    return 0;
}

int db_user_set_role_viewer(uint8_t userId[DB_UUID_SIZE])
{
    return db_user_set_role(userId, USER_ROLE_VIEWER);
}
int db_user_set_role_publisher(uint8_t userId[DB_UUID_SIZE])
{
    return db_user_set_role(userId, USER_ROLE_PUBLISHER);
}

int db_user_get_and_check_mem(const MDB_val *v, uint8_t *out_ver,
                              uint8_t *out_role, uint8_t *out_email_len,
                              char     out_email[DB_EMAIL_MAX_LEN],
                              uint8_t *out_size)
{
    if(!v || v->mv_size < 3) return -EINVAL;

    const uint8_t *p    = (const uint8_t *)v->mv_data;
    const uint8_t  ver  = p[0];
    const uint8_t  role = p[1];
    const uint8_t  el   = p[2];

    if((size_t)3 + el != v->mv_size) return -EINVAL;  // value too short/longS
    if(out_ver) *out_ver = ver;
    if(out_role) *out_role = role;
    if(out_email_len) *out_email_len = el;

    if(out_email)
    {
        if(el >= DB_EMAIL_MAX_LEN) return -ENOSPC;
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
static int db_user_set_role(uint8_t userId[DB_UUID_SIZE], user_role_t role)
{
    if(role != USER_ROLE_VIEWER && role != USER_ROLE_PUBLISHER &&
       role != USER_ROLE_NONE)
        return -EINVAL;

retry_chunk:;
    MDB_txn *txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS) return -EIO;

    MDB_cursor *cur = NULL;
    if(mdb_cursor_open(txn, DB->db_user_id2data, &cur) != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return -EIO;
    }

    MDB_val k    = {.mv_size = DB_UUID_SIZE, .mv_data = userId};
    MDB_val oldv = {0};
    int     rc   = mdb_cursor_get(cur, &k, &oldv, MDB_SET_KEY);
    if(rc != MDB_SUCCESS)
    {
        mdb_cursor_close(cur);
        mdb_txn_abort(txn);
        return db_map_mdb_err(rc);
    }

    uint8_t ver = 0, old_role = 0, el = 0, sz = 0;
    char    email_buf[DB_EMAIL_MAX_LEN] = {0};
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
        if(grc != 0) return db_map_mdb_err(grc);
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
