/**
 * @file db_internal.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef DB_INTERNAL_H
#define DB_INTERNAL_H

#include <lmdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>  // unlink

#include "db_interface.h"
#include "db_operations.h"

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
*/

/* Handle for the whole store.  All LMDB databases live under <root>/meta,   */
/* while content-addressed objects live under <root>/objects/sha256/.. .     */
struct DB
{
    char     root[1024]; /* Root directory */
    MDB_env* env;        /* LMDB environment */

    /* USER DBIs */
    MDB_dbi db_user_id2meta; /* ID -> META */
    MDB_dbi db_user_mail2id; /* Email -> ID */
    MDB_dbi db_user_id2pwd;  /* ID -> pwd hash */

    /* DATA DBIs */
    MDB_dbi db_data_id2meta; /* Data meta DBI */
    MDB_dbi db_data_sha2id;  /* SHA -> data_id DBI */

    /* ACL DBIs */
    MDB_dbi
        db_acl_fwd; /* key=principal(16)|rtype(1)|data(16), val=uint8_t(1) */
    MDB_dbi
        db_acl_rel; /* key=data(16)|rtype(1), val=principal(16) (dupsort, dupfixed) */

    /* Stats and health */
    size_t map_size_bytes;
    size_t map_size_bytes_max;
};

/* DATABASE */
extern struct DB* DB; /* defined in db_env.c */

/* user role type */
typedef uint8_t user_role_t;

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

/* USER ROLES */
#define USER_ROLE_NONE      0u
#define USER_ROLE_VIEWER    (1u << 0)
#define USER_ROLE_PUBLISHER (1u << 1)

/* PUBLIC */

int db_map_mdb_err(int mdb_rc);
int db_env_mapsize_expand(void);

// int db_user_get_and_check_mem(const MDB_val* v, uint8_t* ver, uint8_t* role,
//                               uint8_t* email_len, char *email,
//                               uint8_t* out_size);

#ifdef __cplusplus
}
#endif

#endif /* DB_INTERNAL_H */
