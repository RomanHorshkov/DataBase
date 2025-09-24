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

#include <errno.h>
#include <lmdb.h>
#include <stddef.h>
#include <stdint.h>
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
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
*/

/* DATABASE */
extern struct DB *DB; /* defined in db_env.c */

/* Handle for the whole store.  All LMDB databases live under <root>/meta,   */
/* while content-addressed objects live under <root>/objects/sha256/.. .     */
struct DB
{
    char     root[1024]; /* Root directory */
    MDB_env *env;        /* LMDB environment */

    MDB_dbi db_user_id2data; /* User DBI */
    MDB_dbi db_user_mail2id; /* Email -> ID DBI */
    MDB_dbi db_data_id2meta; /* Data meta DBI */
    MDB_dbi db_data_sha2id;  /* SHA -> data_id DBI */

    MDB_dbi
        db_acl_fwd; /* key=principal(16)|rtype(1)|data(16), val=uint8_t(1) */
    MDB_dbi
        db_acl_rel; /* key=data(16)|rtype(1), val=principal(16) (dupsort, dupfixed) */

    /* Stats and health */
    size_t map_size_bytes;
    size_t map_size_bytes_max;
};

/* UNISHING STRUCTURES */
/* user role type */
typedef uint8_t user_role_t;

/* value of key-val pairs to put in the dbis */
typedef size_t (*DB_data_size_fn)(const void *ctx);
typedef void (*DB_data_write_fn)(void *dst, const void *ctx);

typedef struct
{
    const void      *ctx;   /* db data to insert at value */
    DB_data_size_fn  size;  /* db's specific size func */
    DB_data_write_fn write; /* db's specific write memory func */
} DB_val_t;

/* key descriptor: “just bytes” */
typedef struct
{
    const void *data_ptr;
    size_t     data_len;
} DB_key_t;

typedef struct
{
    MDB_dbi  dbi;
    DB_key_t key;
    DB_val_t val;
    unsigned flags; /* extras: MDB_NOOVERWRITE | MDB_APPEND */

    /* filled by the prepare/reserve pass */
    void   *dst;        /* reserved pointer returned by mdb_put */
    size_t  dst_len;    /* reserved length (for asserts / safety) */
} DB_operation_t;

/* USER SPECIFIC */

/* DATABASE */
// extern struct DB_user_id2data_packed *DB_user_id2data_packed; /* defined in db_user.c */

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

/* creates a DB_key */
#define DB_KEY_GEN(p, n)                 \
    (DB_key_t)                           \
    {                                    \
        .data_ptr = (p), .data_len = (n) \
    }

#define DB_KEY_GEN_ID16(id)       DB_KEY_GEN((id), DB_UUID_SIZE)
#define DB_KEY_GEN_MAIL(email, n) DB_KEY_GEN((email), (n))

/* USER SPECIFIC */
/* --------------------------- User roles ----------------------------------- */
#define USER_ROLE_NONE            0u
#define USER_ROLE_VIEWER          (1u << 0)
#define USER_ROLE_PUBLISHER       (1u << 1)

/* PUBLIC */
int db_map_mdb_err(int mdb_rc);
int db_env_mapsize_expand(void);

int db_user_get_and_check_mem(const MDB_val *v, uint8_t *ver, uint8_t *role,
                              uint8_t *email_len, char email[DB_EMAIL_MAX_LEN],
                              uint8_t *out_size);

#ifdef __cplusplus
}
#endif

#endif /* DB_INTERNAL_H */
