
// #include "acl.h"

// int acl_grant_tx(DB* db, Tx* tx, const uuid16_t* principal, uint8_t rtype,
//                  const uuid16_t* resource)
// {
//     acl_fwd_key_t fk;
//     fk.principal = *principal;
//     fk.rtype     = rtype;
//     fk.resource  = *resource;
//     MDB_val kf;
//     enc_acl_fwd_k(&fk, &kf);
//     MDB_val v1;
//     enc_u8_one(NULL, &v1);
//     int mrc = mdb_put(tx->txn, db_dbi(db, DBI_ACL_FWD), &kf, &v1, 0);
//     if(mrc != MDB_SUCCESS && mrc != MDB_KEYEXIST) return db_map_mdb_err(mrc);
//     acl_rev_key_t rk;
//     rk.resource  = *resource;
//     rk.rtype     = rtype;
//     rk.principal = *principal;
//     MDB_val kr;
//     enc_acl_rev_k(&rk, &kr);
//     mrc = mdb_put(tx->txn, db_dbi(db, DBI_ACL_REV), &kr, &v1, 0);
//     if(mrc != MDB_SUCCESS && mrc != MDB_KEYEXIST) return db_map_mdb_err(mrc);
//     return 0;
// }
