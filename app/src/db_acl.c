#include "db_int.h"
#include "db_acl.h"

void acl_fwd_key(uint8_t out[33], const uint8_t principal[DB_ID_SIZE],
                 char rtype, const uint8_t resource[DB_ID_SIZE])
{
    memcpy(out, principal, DB_ID_SIZE);
    out[16] = (uint8_t)rtype;
    memcpy(out + 17, resource, DB_ID_SIZE);
}

void acl_rev_key(uint8_t out[17], const uint8_t resource[DB_ID_SIZE],
                 char rtype)
{
    memcpy(out, resource, DB_ID_SIZE);
    out[16] = (uint8_t)rtype;
}

/** Grant presence in both forward and reverse ACL DBs (same txn). */
int acl_grant_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE], char rtype,
                  const uint8_t resource[DB_ID_SIZE])
{
    uint8_t fkey[33];
    acl_fwd_key(fkey, principal, rtype, resource);
    MDB_val fk  = {.mv_size = sizeof fkey, .mv_data = fkey};
    uint8_t one = 1;
    MDB_val fv  = {.mv_size = 1, .mv_data = &one};
    if(mdb_put(txn, DB->db_acl_fwd, &fk, &fv, 0) != MDB_SUCCESS)
        return -EIO;

    uint8_t rkey[17];
    acl_rev_key(rkey, resource, rtype);
    MDB_val rk = {.mv_size = sizeof rkey, .mv_data = rkey};
    MDB_val rv = {.mv_size = DB_ID_SIZE, .mv_data = (void *)principal};
    /* Do not allow duplicates on this db */
    return db_map_mdb_err(
        mdb_put(txn, DB->db_acl_by_res, &rk, &rv, MDB_NODUPDATA));

    return 0;
}

/** Check forward presence (returns 0 if present, -ENOENT if absent). */
int acl_check_present_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE],
                          char rtype, const uint8_t resource[DB_ID_SIZE])
{
    uint8_t fkey[33];
    acl_fwd_key(fkey, principal, rtype, resource);
    MDB_val fk = {.mv_size = sizeof fkey, .mv_data = fkey};
    MDB_val vv = {0};
    int     rc = mdb_get(txn, DB->db_acl_fwd, &fk, &vv);
    if(rc == MDB_SUCCESS)
        return 0;
    if(rc == MDB_NOTFOUND)
        return -ENOENT;
    return -EIO;
}

/** Effective access if present in any of {O,S,U}. */
int acl_has_any_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE],
                    const uint8_t resource[DB_ID_SIZE])
{
    int rc;
    rc = acl_check_present_txn(txn, principal, ACL_RTYPE_OWNER, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    rc = acl_check_present_txn(txn, principal, ACL_RTYPE_SHARE, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    rc = acl_check_present_txn(txn, principal, ACL_RTYPE_USER, resource);
    if(rc == 0)
        return 0;
    else if(rc != -ENOENT)
        return rc;
    return -ENOENT;
}