// auth/session.h
#pragma once
#include <stdint.h>
#include <stddef.h>


/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

#define SESSION_ID_LEN 32  // 256-bit random, Base64url-encoded length ~43


/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
 */

// create short-lived access + long-lived refresh (rotation).
int session_issue(const uint8_t user_id[16], char access_token[64],
                char refresh_token[64], uint64_t now_sec);

// validate -> loads from LMDB, checks expiry, updates last_seen.
int session_validate_access(const char* token, uint8_t out_user_id[16],
                          uint64_t now_sec);

// rotate refresh -> returns new pair, invalidates old refresh (reuse-detection).
int session_rotate_refresh(const char* refresh_token, char new_access[64],
                         char new_refresh[64], uint64_t now_sec);

// revoke (logout everywhere / single device).
int session_revoke_all(const uint8_t user_id[16], uint64_t now_sec);
int session_revoke_token(const char* any_token);
