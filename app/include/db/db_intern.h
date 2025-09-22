/**
 * @file db_intern.h
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
// #include <stddef.h> // in interface
// #include <stdint.h> // in interface
#include <stdio.h>
#include <stdlib.h>
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

/* --------------------------- User roles ----------------------------------- */
#define USER_ROLE_NONE      0u
#define USER_ROLE_VIEWER    (1u << 0)
#define USER_ROLE_PUBLISHER (1u << 1)

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
 */

struct DB
{
    /* Root directory */
    char root[1024];

    /* LMDB environment */
    MDB_env *env;

    /* User DBIs */
    MDB_dbi db_user_id2data;
    MDB_dbi db_user_mail2id;
    MDB_dbi db_user_pwd;

    /* Data DBIs */
    MDB_dbi db_data_id2meta;
    MDB_dbi db_data_sha2id;

    /* ACL DBIs */
    MDB_dbi db_acl_fwd;
    MDB_dbi db_acl_rel;

    /* Session DBIs */
    MDB_dbi db_session_access;
    MDB_dbi db_session_refresh;
    MDB_dbi db_session_revoked;

    /* Stats and health */
    size_t map_size_bytes;
    size_t map_size_bytes_max;
};

extern struct DB *DB; /* defined in db_env.c */

typedef uint8_t user_role_t;

typedef struct __attribute__((packed))
{
    uint8_t     ver;              /* 1 byte version for future evolution */
    user_role_t role;             /* 1 byte role */
    uint8_t     email_len;        /* 1 byte email length */
    char email[DB_EMAIL_MAX_LEN]; /* variable-length zero-terminated email */
} UserPacked;

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
 */
int db_map_mdb_err(int mdb_rc);
int db_env_mapsize_expand(void);

int db_user_get_and_check_mem(const MDB_val *v, uint8_t *ver, uint8_t *role,
                              uint8_t *email_len, char email[DB_EMAIL_MAX_LEN],
                              uint8_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* DB_INTERNAL_H */
