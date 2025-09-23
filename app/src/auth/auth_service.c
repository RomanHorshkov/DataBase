/**
 * @file auth_service.c
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "auth_intern.h"
#include "password.h"
// #include "sha256.h"       /* your SHA-256 for token hashing */
// #include "db_intern.h"       /* DB, DB->db_* */
// #include "db_interface.h" /* db_user_find_by_email, db_add_user, ... */
// #include "auth_service.h"

#define AUTH_VER         1
#define SESSION_TTL_SECS (7ull * 24ull * 3600ull) /* 7 days */

/* Optional pepper for session token hashing (hex string in env). */
static unsigned char G_PEPPER[32];
static int           G_HAVE_PEPPER = 0;

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */
static int hash_password_store(char        out[crypto_pwhash_STRBYTES],
                               const char* pw);

static int verify_password(const char* stored, const char* pw);

static void token_hash(const unsigned char raw[AUTH_SESSION_TOKEN_RAW_LEN],
                       unsigned char       out32[32]);

static int token_b64_from_raw(
    const unsigned char raw[AUTH_SESSION_TOKEN_RAW_LEN],
    char                out[AUTH_SESSION_TOKEN_B64_LEN]);

static int token_raw_from_b64(
    const char* b64, unsigned char out_raw[AUTH_SESSION_TOKEN_RAW_LEN]);

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

int auth_register_local(const char* email, const char* password)
{
    if(!email || !*email || !password || !*password) return -EINVAL;

    /* create user (or fail if exists) */
    uint8_t user_id[DB_ID_SIZE] = {0};
    int     ret                 = db_add_user(email, user_id);

    if(ret != 0)
    {
        /* EEXIST included */
        goto fail;
    }

    /* 1) id -> user */
    enc_user_ctx uctx = {
        .ver = DB_VER, .role = USER_ROLE_NONE, .elen = elen, .email = email};

    /* hash password */
    UserPwdHash rec;
    memset(&rec, 0, sizeof rec);
    rec.ver = AUTH_VER;
    rc      = hash_password_store(rec.pwhash, password);
    if(rc != 0) return rc;

    /* Step 3: persist user_id -> pw_hash in one RW txn */
    MDB_txn* txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS) return -EIO;

    MDB_val k   = {.mv_size = DB_ID_SIZE, .mv_data = uid};
    MDB_val v   = {.mv_size = sizeof rec, .mv_data = &rec};
    int     mrc = mdb_put(txn, DB->db_user_pwd, &k, &v, MDB_NOOVERWRITE);
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }
    if(mdb_txn_commit(txn) != MDB_SUCCESS) return -EIO;

    if(out_user_id) memcpy(out_user_id, uid, DB_ID_SIZE);
    return 0;

fail:
    return ret;
}

int auth_login_password(const char* email, const char* password,
                        char out_session_token_b64[AUTH_SESSION_TOKEN_B64_LEN])
{
    if(!email || !*email || !password || !*password) return -EINVAL;

    /* Lookup user_id and password hash */
    uint8_t uid[DB_ID_SIZE] = {0};
    int     rc              = db_user_find_by_email(email, uid);
    if(rc != 0) return -EPERM; /* don’t leak which part failed */

    MDB_txn* txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    UserPwdHash rec;
    MDB_val     k   = {.mv_size = DB_ID_SIZE, .mv_data = uid};
    MDB_val     v   = {0};
    int         mrc = mdb_get(txn, DB->db_user_pwd, &k, &v);
    if(mrc != MDB_SUCCESS || v.mv_size != sizeof rec)
    {
        mdb_txn_abort(txn);
        return -EPERM;
    }
    memcpy(&rec, v.mv_data, sizeof rec);
    mdb_txn_abort(txn);

    rc = verify_password(rec.pwhash, password);
    if(rc != 0) return -EPERM;

    /* Create session */
    unsigned char raw[AUTH_SESSION_TOKEN_RAW_LEN];
    randombytes_buf(raw, sizeof raw);

    unsigned char h[32];
    token_hash(raw, h);

    SessionRec s = {0};
    s.ver        = AUTH_VER;
    memcpy(s.user_id, uid, DB_ID_SIZE);
    s.created_at = now_secs();
    s.expires_at = s.created_at + SESSION_TTL_SECS;

retry_put:
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS) return -EIO;
    MDB_val sk = {.mv_size = sizeof h, .mv_data = h};
    MDB_val sv = {.mv_size = sizeof s, .mv_data = &s};
    mrc        = mdb_put(txn, DB->db_session, &sk, &sv, MDB_NOOVERWRITE);
    if(mrc == MDB_MAP_FULL)
    {
        mdb_txn_abort(txn);
        rc = db_env_mapsize_expand();
        if(rc != 0) return rc;
        goto retry_put;
    }
    if(mrc != MDB_SUCCESS)
    {
        mdb_txn_abort(txn);
        return db_map_mdb_err(mrc);
    }
    if(mdb_txn_commit(txn) != MDB_SUCCESS) return -EIO;

    /* Return token (base64url, no padding) */
    return token_b64_from_raw(raw, out_session_token_b64);
}

int auth_session_resolve(const char* session_token_b64,
                         uint8_t     out_user_id[DB_ID_SIZE])
{
    if(!session_token_b64 || !*session_token_b64 || !out_user_id)
        return -EINVAL;

    unsigned char raw[AUTH_SESSION_TOKEN_RAW_LEN];
    int           rc = token_raw_from_b64(session_token_b64, raw);
    if(rc != 0) return rc;

    unsigned char h[32];
    token_hash(raw, h);

    MDB_txn* txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, MDB_RDONLY, &txn) != MDB_SUCCESS)
        return -EIO;

    MDB_val k   = {.mv_size = sizeof h, .mv_data = h};
    MDB_val v   = {0};
    int     mrc = mdb_get(txn, DB->db_session, &k, &v);
    if(mrc != MDB_SUCCESS || v.mv_size != sizeof(SessionRec))
    {
        mdb_txn_abort(txn);
        return -ENOENT;
    }

    SessionRec s;
    memcpy(&s, v.mv_data, sizeof s);
    mdb_txn_abort(txn);

    if(s.expires_at < now_secs()) return -ENOENT; /* expired */

    memcpy(out_user_id, s.user_id, DB_ID_SIZE);
    return 0;
}

int auth_logout(const char* session_token_b64)
{
    if(!session_token_b64 || !*session_token_b64) return -EINVAL;

    unsigned char raw[AUTH_SESSION_TOKEN_RAW_LEN], h[32];
    int           rc = token_raw_from_b64(session_token_b64, raw);
    if(rc != 0) return rc;
    token_hash(raw, h);

    MDB_txn* txn = NULL;
    if(mdb_txn_begin(DB->env, NULL, 0, &txn) != MDB_SUCCESS) return -EIO;

    MDB_val k = {.mv_size = sizeof h, .mv_data = h};
    (void)mdb_del(txn, DB->db_session, &k, NULL);
    if(mdb_txn_commit(txn) != MDB_SUCCESS) return -EIO;
    return 0;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static int hash_password_store(char out[crypto_pwhash_STRBYTES], const char* pw)
{
    if(!pw) return -EINVAL;
    if(crypto_pwhash_str(out, pw, strlen(pw),
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        return -EIO;
    }
    return 0;
}

static int verify_password(const char* stored, const char* pw)
{
    if(!stored || !pw) return -EINVAL;
    int rc = crypto_pwhash_str_verify(stored, pw, strlen(pw));
    if(rc == 0) return 0;
    if(rc == -1) return -EPERM; /* wrong password */
    return -EIO;
}

/* ---- token helpers ---- */

static void token_hash(const unsigned char raw[AUTH_SESSION_TOKEN_RAW_LEN],
                       unsigned char       out32[32])
{
    /* H = SHA256( [pepper?] || raw ) */
    Sha256Ctx ctx;
    crypt_sha256_init(&ctx);
    if(G_HAVE_PEPPER) crypt_sha256_update(&ctx, G_PEPPER, 32);
    crypt_sha256_update(&ctx, raw, AUTH_SESSION_TOKEN_RAW_LEN);
    crypt_sha256_final(&ctx, out32);
}

static int token_b64_from_raw(
    const unsigned char raw[AUTH_SESSION_TOKEN_RAW_LEN],
    char                out[AUTH_SESSION_TOKEN_B64_LEN])
{
    /* base64url, no padding */
    size_t out_len = sodium_base64_ENCODED_LEN(
        AUTH_SESSION_TOKEN_RAW_LEN, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if(out_len >= AUTH_SESSION_TOKEN_B64_LEN) return -EINVAL;
    sodium_bin2base64(out, out_len, raw, AUTH_SESSION_TOKEN_RAW_LEN,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return 0;
}

static int token_raw_from_b64(const char*   b64,
                              unsigned char out_raw[AUTH_SESSION_TOKEN_RAW_LEN])
{
    if(!b64) return -EINVAL;
    size_t bin_len = 0;
    if(sodium_base642bin(out_raw, AUTH_SESSION_TOKEN_RAW_LEN, b64, strlen(b64),
                         NULL, &bin_len, NULL,
                         sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
        return -EINVAL;
    return (bin_len == AUTH_SESSION_TOKEN_RAW_LEN) ? 0 : -EINVAL;
}
