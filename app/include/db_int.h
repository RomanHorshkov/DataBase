/**
 * @file db_int.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef DB_INTERNAL_H
#define DB_INTERNAL_H

#include <errno.h>
#include <lmdb.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>  // unlink

#include "db_interface.h"

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

/* -------------------------- ACL namespaces -------------------------------- */
/* Presence-only ACL rtype namespaces */
#define ACL_RTYPE_OWNER     'O' /* owner */
#define ACL_RTYPE_SHARE     'S' /* share/reshare */
#define ACL_RTYPE_USER      'U' /* view */

/* --------------------------- User roles ----------------------------------- */
#define USER_ROLE_NONE      0u
#define USER_ROLE_VIEWER    (1u << 0)
#define USER_ROLE_PUBLISHER (1u << 1)

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
*/

/* Handle for the whole store.  All LMDB databases live under <root>/meta,   */
/* while content-addressed objects live under <root>/objects/sha256/.. .     */
struct DB
{
    char     root[1024]; /* Root directory */
    MDB_env *env;        /* LMDB environment */

    MDB_dbi db_user;          /* User DBI */
    MDB_dbi db_user_email2id; /* Email -> ID DBI */
    MDB_dbi db_data_meta;     /* Data meta DBI */
    MDB_dbi db_sha2data;      /* SHA -> data_id DBI */

    /* Presence-only ACLs */
    MDB_dbi
        db_acl_fwd; /* key=principal(16)|rtype(1)|data(16), val=uint8_t(1) */
    MDB_dbi
        db_acl_by_res; /* key=data(16)|rtype(1), val=principal(16) (dupsort, dupfixed) */

    /* Stats and health */
    size_t map_size_bytes;
    size_t map_size_bytes_max;
};

extern struct DB *DB; /* defined in db_env.c */

typedef uint16_t user_role_t;

typedef struct __attribute__((packed))
{
    uint8_t     id[DB_ID_SIZE];          /* bytes user id */
    char        email[DB_EMAIL_MAX_LEN]; /* bytes + zero-terminated email */
    user_role_t role;                    /* 2 bytes role */
} UserPacked;

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
*/
int db_map_mdb_err(int mdb_rc);
int db_env_mapsize_expand(void);

#ifdef __cplusplus
}
#endif

#endif /* DB_INTERNAL_H */