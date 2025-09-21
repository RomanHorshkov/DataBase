/**
 * @file auth_intern.h
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef AUTH_INTERN_H
#define AUTH_INTERN_H

#include <errno.h>
// #include <lmdb.h>
// #include <stddef.h>
// #include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <time.h>
// #include <unistd.h>  // unlink

#include <sodium.h>

#include "db_interface.h"
#include "auth_interface.h"

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */


/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
 */

/* Records */
typedef struct __attribute__((packed))
{
    /* record version */
    uint8_t ver;

    /* libsodium hash string (NUL-terminated) */
    char pwhash[crypto_pwhash_STRBYTES];
} UserPwdHash;

typedef struct __attribute__((packed))
{
    uint8_t  ver;                 /* record version */
    uint8_t  user_id[DB_ID_SIZE]; /* user id */
    uint64_t created_at;          /* epoch secs */
    uint64_t expires_at;          /* epoch secs */
} SessionRec;

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
 */

#ifdef __cplusplus
}
#endif

#endif /* AUTH_INTERN_H */
