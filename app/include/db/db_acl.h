#ifndef DB_ACL_H
#define DB_ACL_H

#include <stdint.h>
#include "db_intern.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Public relation tags (only exposed in callbacks). */
typedef enum
{
    ACL_REL_OWNER = 'O',
    ACL_REL_SHARE = 'S',
    ACL_REL_VIEW  = 'V'
} acl_rel_t;

/* ----------------------------- Grants / Revokes ----------------------------
 */

int acl_grant_owner(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                    uint8_t resource[DB_ID_SIZE]);

int acl_grant_share(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                    uint8_t resource[DB_ID_SIZE]);

int acl_grant_view(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                   uint8_t resource[DB_ID_SIZE]);

int acl_revoke_owner(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                     uint8_t resource[DB_ID_SIZE]);

int acl_revoke_share(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                     uint8_t resource[DB_ID_SIZE]);

int acl_revoke_view(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                    uint8_t resource[DB_ID_SIZE]);

/* ------------------------------- Checks ----------------------------------- */

int acl_has_owner(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                  uint8_t resource[DB_ID_SIZE]);

int acl_has_share(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                  uint8_t resource[DB_ID_SIZE]);

int acl_has_view(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                 uint8_t resource[DB_ID_SIZE]);

int acl_has_any(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                uint8_t resource[DB_ID_SIZE]);

/* ---------------------------- Listing (forward) ----------------------------
 */

/* Callback for acl_list_data_for_user.
 * Return 0 to continue, non-zero to stop early.
 * 'rel' is one of ACL_REL_* (O/S/V). */
typedef int (*acl_iter_cb)(uint8_t resource[DB_ID_SIZE], uint8_t rel,
                           void *user);

int acl_list_data_for_user(MDB_txn *txn, uint8_t principal[DB_ID_SIZE],
                           acl_iter_cb cb, void *user);

int acl_data_destroy(MDB_txn *txn, uint8_t resource[DB_ID_SIZE]);

#endif /* DB_ACL_H */
