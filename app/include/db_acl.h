#ifndef DB_ACL_H
#define DB_ACL_H

#include "db_int.h"


/** 
 * @brief Generate a forward ACL key.
 * 33 bytes: principal(16) | rtype(1) | resource(16)
 * @param out Output buffer [33 bytes].
 * @param principal Principal ID [16 bytes].
 * @param rtype Relationship type (one of 'O', 'S', 'U').
 * @param resource Resource ID [16 bytes].
 * @return void
 * 
 */
void acl_fwd_key(uint8_t out[33], const uint8_t principal[DB_ID_SIZE],
                 char rtype, const uint8_t resource[DB_ID_SIZE]);

/**
 * @brief Generate a reverse ACL key.
 * 17 bytes: resource(16) | rtype(1)
 * @param out Output buffer [17 bytes].
 * @param resource Resource ID [16 bytes].
 * @param rtype Relationship type (one of 'O', 'S', 'U').
 * @return void
 */
void acl_rev_key(uint8_t out[17], const uint8_t resource[DB_ID_SIZE],
                 char rtype);
/** Grant presence in both forward and reverse ACL DBs (same txn). */
int acl_grant_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE], char rtype, const uint8_t resource[DB_ID_SIZE]);

/** Check forward presence (returns 0 if present, -ENOENT if absent). */
int acl_check_present_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE], char rtype, const uint8_t resource[DB_ID_SIZE]);

/** Effective access if present in any of {O,S,U}. */
int acl_has_any_txn(MDB_txn *txn, const uint8_t principal[DB_ID_SIZE], const uint8_t resource[DB_ID_SIZE]);

#endif /* DB_ACL_H */