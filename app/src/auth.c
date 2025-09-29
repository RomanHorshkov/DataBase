#include "auth.h"
#include "uuid.h"
int auth_crypto_init(void)
{
    if(sodium_init() < 0) return -EIO;
    return 0;
}

int auth_register(const char* email, uint8_t elen, const char* password,
                  uuid16_t* new_id)
{
    if(!email || !password || elen <= 0) return -EINVAL;

    return db_user_register_new(email, elen, password, new_id);
}

// int auth_login(const char* email, uint8_t elen, const char* pw, uuid16_t* out_id)
// {
//     if(!db || !email || !pw) return -EINVAL;

//     Tx  tx;
//     int rc = tx_begin(1, &tx);
//     if(rc) return rc;

//     MDB_val k   = {.mv_size = elen, .mv_data = (void*)email}, v;
//     int     mrc = mdb_get(tx.txn, db_get_dbi(DBI_EMAIL2ID), &k, &v);

//     if(mrc != MDB_SUCCESS)
//     {
//         tx_abort(&tx);
//         return -ENOENT;
//     }
//     if(v.mv_size != DB_ID_SIZE)
//     {
//         tx_abort(&tx);
//         return -EIO;
//     }

//     uuid16_t uid;
//     memcpy(uid.b, v.mv_data, DB_ID_SIZE);
//     MDB_val ku = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid.b}, vu;
//     mrc        = mdb_get(tx.txn, db_get_dbi(DBI_USER), &ku, &vu);
//     if(mrc != MDB_SUCCESS)
//     {
//         tx_abort(&tx);
//         return -ENOENT;
//     }
//     id2data_val_t rec;
//     if(dec_user_rec(&vu, &rec) != 0)
//     {
//         tx_abort(&tx);
//         return -EIO;
//     }
//     tx_abort(&tx);
//     if(rec.pw_tag != 1) return -EIO;
//     if(crypto_pwhash_str_verify(rec.pw_hash, pw, strlen(pw)) != 0)
//         return -EPERM;
//     if(out_id) *out_id = uid;
//     return 0;
// }

// int auth_set_password(const uuid16_t* uid, const char* pw)
// {
//     if(!db || !uid || !pw) return -EINVAL;
//     Tx  tx;
//     int rc = tx_begin(0, &tx);
//     if(rc) return rc;
//     MDB_val ku  = {.mv_size = DB_ID_SIZE, .mv_data = (void*)uid->b}, vu;
//     int     mrc = mdb_get(tx.txn, db_get_dbi(DBI_USER), &ku, &vu);
//     if(mrc != MDB_SUCCESS)
//     {
//         tx_abort(&tx);
//         return -ENOENT;
//     }
//     id2data_val_t rec;
//     if(dec_user_rec(&vu, &rec) != 0)
//     {
//         tx_abort(&tx);
//         return -EIO;
//     }
//     char hash[crypto_pwhash_STRBYTES];
//     if(crypto_pwhash_str(hash, pw, strlen(pw),
//                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
//                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
//     {
//         tx_abort(&tx);
//         return -EIO;
//     }
//     strncpy(rec.pw_hash, hash, sizeof rec.pw_hash - 1);
//     rec.pw_tag = 1;
//     MDB_val vnew;
//     enc_user_rec(&rec, &vnew);
//     mrc = mdb_put(tx.txn, db_get_dbi(DBI_USER), &ku, &vnew, 0);
//     if(mrc != MDB_SUCCESS)
//     {
//         tx_abort(&tx);
//         return db_map_mdb_err(mrc);
//     }
//     return tx_commit(&tx);
// }

// int auth_share_with_user(const uuid16_t* resource_id, uint8_t rtype,
//                          const char* email, uint8_t elen, uuid16_t* out_user_id)
// {
//     if(!db || !resource_id || !email || elen == 0) return -EINVAL;
//     Tx  tx;
//     int rc = tx_begin(0, &tx);
//     if(rc) return rc;
//     uuid16_t uid;
//     rc = ensure_user_tx(&tx, email, elen, &uid);
//     if(rc && rc != -EEXIST && rc != 0)
//     {
//         tx_abort(&tx);
//         return rc;
//     }
//     /* grant ACL in both directions */
//     rc = acl_grant_tx(&tx, &uid, rtype, resource_id);
//     if(rc)
//     {
//         tx_abort(&tx);
//         return rc;
//     }
//     rc = tx_commit(&tx);
//     if(rc) return rc;
//     if(out_user_id) *out_user_id = uid;
//     return 0;
// }
