
#include "auth.h"
#include <sodium.h>
#include <string.h>
#include "uuid.h"

int auth_crypto_init(void)
{
    if(sodium_init() < 0) return -EIO;
    return 0;
}

/* helper: make email key */
static inline email_key_t ek(const char* email, u8 elen)
{
    email_key_t k = {.ptr = email, .len = elen};
    return k;
}

static int user_create_tx(DB* db, Tx* tx, const char* email, u8 elen,
                          const char* pw, uuid16_t* out_id)
{
    /* Check not exists */
    MDB_val k_email = {.mv_size = elen, .mv_data = (void*)email};
    MDB_val v_id;
    int     mrc = mdb_get(tx->txn, db_dbi(db, DBI_EMAIL2ID), &k_email, &v_id);
    if(mrc == MDB_SUCCESS) return -EEXIST; /* already present */

    uuid16_t uid;
    if(uuid_gen(&uid) != 0) return -EIO;

    /* Hash password */
    char hash[crypto_pwhash_STRBYTES];
    if(crypto_pwhash_str(hash, pw, strlen(pw),
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
        return -EIO;

    user_rec_t rec;
    memset(&rec, 0, sizeof rec);
    rec.ver       = 1;
    rec.role      = ROLE_VIEWER;
    rec.email_len = elen;
    memcpy(rec.email, email, elen);
    rec.pw_tag = 1;
    strncpy(rec.pw_hash, hash, sizeof rec.pw_hash - 1);

    /* Put email→id and user */
    MDB_val v_uid = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid.b};
    mrc           = mdb_put(tx->txn, db_dbi(db, DBI_EMAIL2ID), &k_email, &v_uid,
                            MDB_NOOVERWRITE);
    if(mrc != MDB_SUCCESS) return map_mdb_err(mrc);

    MDB_val k_uid = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid.b};
    MDB_val v_user;
    if(enc_user_rec(&rec, &v_user) != 0) return -EINVAL;
    mrc = mdb_put(tx->txn, db_dbi(db, DBI_USER), &k_uid, &v_user,
                  MDB_NOOVERWRITE);
    if(mrc != MDB_SUCCESS) return map_mdb_err(mrc);

    if(out_id) *out_id = uid;
    return 0;
}

int auth_register(DB* db, const char* email, u8 elen, const char* password,
                  uuid16_t* new_id)
{
    if(!db || !email || !password || elen == 0) return -EINVAL;
    Tx  tx;
    int rc = tx_begin(db, 0, &tx);
    if(rc) return rc;
    rc = user_create_tx(db, &tx, email, elen, password, new_id);
    if(rc == 0)
    {
        rc = tx_commit(&tx);
        if(rc) return rc;
        return 0;
    }
    tx_abort(&tx);
    return rc;
}

int auth_login(DB* db, const char* email, u8 elen, const char* pw,
               uuid16_t* out_id)
{
    if(!db || !email || !pw) return -EINVAL;
    Tx  tx;
    int rc = tx_begin(db, 1, &tx);
    if(rc) return rc;
    MDB_val k   = {.mv_size = elen, .mv_data = (void*)email}, v;
    int     mrc = mdb_get(tx.txn, db_dbi(db, DBI_EMAIL2ID), &k, &v);
    if(mrc != MDB_SUCCESS)
    {
        tx_abort(&tx);
        return -ENOENT;
    }
    if(v.mv_size != DB_ID_SIZE)
    {
        tx_abort(&tx);
        return -EIO;
    }
    uuid16_t uid;
    memcpy(uid.b, v.mv_data, DB_ID_SIZE);
    MDB_val ku = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid.b}, vu;
    mrc        = mdb_get(tx.txn, db_dbi(db, DBI_USER), &ku, &vu);
    if(mrc != MDB_SUCCESS)
    {
        tx_abort(&tx);
        return -ENOENT;
    }
    user_rec_t rec;
    if(dec_user_rec(&vu, &rec) != 0)
    {
        tx_abort(&tx);
        return -EIO;
    }
    tx_abort(&tx);
    if(rec.pw_tag != 1) return -EIO;
    if(crypto_pwhash_str_verify(rec.pw_hash, pw, strlen(pw)) != 0)
        return -EPERM;
    if(out_id) *out_id = uid;
    return 0;
}

int auth_set_password(DB* db, const uuid16_t* uid, const char* pw)
{
    if(!db || !uid || !pw) return -EINVAL;
    Tx  tx;
    int rc = tx_begin(db, 0, &tx);
    if(rc) return rc;
    MDB_val ku  = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid->b}, vu;
    int     mrc = mdb_get(tx.txn, db_dbi(db, DBI_USER), &ku, &vu);
    if(mrc != MDB_SUCCESS)
    {
        tx_abort(&tx);
        return -ENOENT;
    }
    user_rec_t rec;
    if(dec_user_rec(&vu, &rec) != 0)
    {
        tx_abort(&tx);
        return -EIO;
    }
    char hash[crypto_pwhash_STRBYTES];
    if(crypto_pwhash_str(hash, pw, strlen(pw),
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        tx_abort(&tx);
        return -EIO;
    }
    strncpy(rec.pw_hash, hash, sizeof rec.pw_hash - 1);
    rec.pw_tag = 1;
    MDB_val vnew;
    enc_user_rec(&rec, &vnew);
    mrc = mdb_put(tx.txn, db_dbi(db, DBI_USER), &ku, &vnew, 0);
    if(mrc != MDB_SUCCESS)
    {
        tx_abort(&tx);
        return map_mdb_err(mrc);
    }
    return tx_commit(&tx);
}

/* Ensure user by email inside caller's write Tx: returns 0 and fills uid; creates if missing. */
static int ensure_user_tx(DB* db, Tx* tx, const char* email, u8 elen,
                          uuid16_t* uid)
{
    MDB_val k   = {.mv_size = elen, .mv_data = (void*)email}, v;
    int     mrc = mdb_get(tx->txn, db_dbi(db, DBI_EMAIL2ID), &k, &v);
    if(mrc == MDB_SUCCESS)
    {
        if(v.mv_size != DB_ID_SIZE) return -EIO;
        memcpy(uid->b, v.mv_data, DB_ID_SIZE);
        return 0;
    }
    /* create with temp password */
    const char* temp_pw = "!#TEMP#";
    int         rc      = user_create_tx(db, tx, email, elen, temp_pw, uid);
    return rc;
}

int auth_share_with_user(DB* db, const uuid16_t* resource_id, u8 rtype,
                         const char* email, u8 elen, uuid16_t* out_user_id)
{
    if(!db || !resource_id || !email || elen == 0) return -EINVAL;
    Tx  tx;
    int rc = tx_begin(db, 0, &tx);
    if(rc) return rc;
    uuid16_t uid;
    rc = ensure_user_tx(db, &tx, email, elen, &uid);
    if(rc && rc != -EEXIST && rc != 0)
    {
        tx_abort(&tx);
        return rc;
    }
    /* grant ACL in both directions */
    rc = acl_grant_tx(db, &tx, &uid, rtype, resource_id);
    if(rc)
    {
        tx_abort(&tx);
        return rc;
    }
    rc = tx_commit(&tx);
    if(rc) return rc;
    if(out_user_id) *out_user_id = uid;
    return 0;
}
