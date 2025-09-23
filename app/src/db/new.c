/**
 * @file db_env.c
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "db_intern.h"

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
#define DB_KEY_SPAN(p, n)                \
    (DB_key_t)                           \
    {                                    \
        .data_ptr = (p), .data_len = (n) \
    }
#define DB_KEY_MAIL(email, n) DB_KEY_SPAN((email), (n))
#define DB_KEY_ID16(id)       DB_KEY_SPAN((id), DB_ID_SIZE)

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */

typedef size_t (*DB_size_fn)(const void *ctx);
typedef void (*DB_write_fn)(void *dst, const void *ctx);

/* value encoder: knows how big the value is, and how to write it into a buffer */
typedef struct
{
    const void *ctx;
    DB_size_fn  size;
    DB_write_fn write;
} DB_encoder_t;

/* key descriptor: “just bytes” */
typedef struct
{
    const void *data_ptr;
    uint8_t     data_len;
} DB_key_t;

typedef struct
{
    MDB_dbi      dbi;
    DB_key_t     key;
    DB_encoder_t val;
    unsigned     flags; /* extras: e.g. MDB_NOOVERWRITE | MDB_APPEND */
} DB_spec_t;

/* one RESERVE-put */
static inline int db_put_reserve(MDB_txn *txn, const DB_spec_t *op)
{
}

static size_t enc_user_size(const void *p)
{
    return 3u + ((user_data_packed_t *)p)->email_len;
}

static void enc_user_write(void *dst, void *p)
{
    user_data_packed_t *c = (user_data_packed_t *)p;
    uint8_t            *w = (uint8_t *)dst;
    w[0]                  = c->ver;
    w[1]                  = (uint8_t)c->role;
    w[2]                  = c->email_len;
    memcpy(w + 3, c->email, c->email_len);
    /* no trailing NUL stored; reader knows length from byte 2 */
}

#define DB_ENC_USER(ver, role, email, elen)                                 \
    (DB_encoder)                                                            \
    {                                                                       \
        .ctx  = &(user_data_packed_t){(ver), (role), (email_len), (email)}, \
        .size = enc_user_size, .write = enc_user_write                      \
    }

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */

static int db_put_reserve(MDB_txn *txn, const DB_spec_t *operations,
                          uint8_t n_operations,
                          size_t *failed_index /* optional */)
{
    if(!txn || !operations || n_operations <= 0) return -EINVAL;

    /* getting data loop */
    for(uint8_t i = 0; i < n_operations; ++i)
    {
        DB_spec_t *operation = &operations[i];

        /* Check operation params */
        if(!operation->val.ctx || !operation->val.size || !operation->val.write)
            return -EINVAL;

        MDB_val k = {.mv_size = operation->key.data_len,
                     .mv_data = (void *)operation->key.data_ptr};
        MDB_val v = {.mv_size = operation->val.size(operation->val.ctx),
                     .mv_data = NULL};

        int rc = mdb_put(txn, operation->dbi, &k, &v,
                         MDB_RESERVE || operation->flags);
        if(rc != MDB_SUCCESS)
        {
            if(failed_index) *failed_index = i;
            return rc;
        }
    }

    /* setting data loop */
    for(uint8_t i = 0; i < n_operations; ++i)
    {
        DB_spec_t *operation = &operations[i];

        operation->val.write(v.mv_data, operation->val.ctx); /* fill in place */
        return MDB_SUCCESS;
    }
    return MDB_SUCCESS;
}

int db_register_new(MDB_txn *txn, uint8_t email_len, const char *email,
                    const uint8_t user_id[DB_ID_SIZE], const void *pwrec,
                    size_t pwrec_sz)
{
    if(!txn || !email || !user_id || !pwrec) return -EINVAL;

    /* build the three ops */
    DB_spec_t ops[3];

    ops[0].dbi   = DB->db_user_id2data;
    ops[0].key   = DB_KEY_ID16(user_id);
    ops[0].val   = DB_ENC_USER(DB_VER, USER_ROLE_NONE, email_len, email);
    ops[0].flags = MDB_NOOVERWRITE | MDB_APPEND;

    /* 2) email -> id */
    ops[1].dbi   = DB->db_user_mail2id;
    ops[1].key   = DB_KEY_MAIL(email_len, email);
    ops[1].val   = DB_ENC_SPAN(user_id, DB_ID_SIZE);
    ops[1].flags = MDB_NOOVERWRITE;

    /* 3) id -> password (opaque fixed record) */
    ops[2].dbi   = DB->db_user_id2pw;
    ops[2].key   = DB_KEY_ID16(user_id);
    ops[2].val   = DB_ENC_SPAN(pwrec, pwrec_sz);
    ops[2].flags = MDB_NOOVERWRITE;

    size_t failed = (size_t)-1;
    int    rc     = db_apply_puts(txn, ops, 3, &failed);
    if(rc == MDB_KEYEXIST && failed == 1) return -EEXIST; /* email taken */
    return rc;
}

int auth_register_new(const char *email_in, const char *pwd_in,
                      uint8_t out_user_id[DB_ID_SIZE])
{
    if(!email_in || email_in[0] == '\0') return -EINVAL;

    uint8_t elen = 0;
    if(sanitize_email(email_in, &elen) != 0) return -EINVAL;

    uint8_t user_id[DB_ID_SIZE];
    uuid_v7(user_id);

    uint8_t pwrec[PWREC_SIZE];
    if(password_hash(pwd_in, pwrec) != 0) return -EIO;

    for(;;)
    {
        MDB_txn *txn = NULL;
        int      rc  = mdb_txn_begin(DB->env, NULL, 0, &txn);
        if(rc != MDB_SUCCESS) return db_map_mdb_err(rc);

        rc = db_register_new(txn, email_in, elen, user_id, pwrec, sizeof pwrec);
        if(rc != MDB_SUCCESS)
        {
            mdb_txn_abort(txn);
            if(rc == MDB_MAP_FULL)
            {
                int gr = db_env_mapsize_expand();
                if(gr == 0) continue;
                return db_map_mdb_err(gr);
            }
            if(rc == -EEXIST)
            {
                return rc;
            }
            return db_map_mdb_err(rc);
        }
        rc = mdb_txn_commit(txn);
        if(rc == MDB_MAP_FULL)
        {
            int gr = db_env_mapsize_expand();
            if(gr == 0) continue;
            return db_map_mdb_err(gr);
        }
        if(rc != MDB_SUCCESS) return db_map_mdb_err(rc);
        if(out_user_id) memcpy(out_user_id, user_id, DB_ID_SIZE);
        return 0;
    }
}

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */
