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
#include <string.h>
// #include <lmdb.h>
// #include <stddef.h>
// #include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <time.h>
// #include <unistd.h>  // unlink

#include <sodium.h>

#include "auth_interface.h"
#include "db_interface.h"
#include "utils.h"

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

#define SESSION_ID_LEN 32  // 256-bit random, Base64url-encoded length ~43

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
 */

/* Records */

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

/* Session functions */
int session_issue(const uint8_t user_id[16], char access_token[64],
                  char refresh_token[64], uint64_t now_sec);

int session_validate_access(const char* token, uint8_t out_user_id[16],
                            uint64_t now_sec);

int session_rotate_refresh(const char* refresh_token, char new_access[64],
                           char new_refresh[64], uint64_t now_sec);

int session_revoke_all(const uint8_t user_id[16], uint64_t now_sec);

int session_revoke_token(const char* any_token);

/* sodium functions */

/* Constant-time compare: 1 equal, 0 different. */
int ct_memeq(const void* a, const void* b, size_t n);

/* Wipe sensitive memory. */
void secure_wipe(void* p, size_t n);

/* Base64url (no padding). out_len must contain capacity on input; set to written. */
int b64url_encode(const uint8_t* in, size_t n, char* out, size_t* out_len);
int b64url_decode(const char* in, uint8_t* out, size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* AUTH_INTERN_H */
