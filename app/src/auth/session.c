/**
 * @file session.h
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "auth_intern.h"

#include "sha256.h" /* for crypt_rand_bytes */

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */

/* Policy */
#ifndef ACCESS_TTL_SEC
#    define ACCESS_TTL_SEC (15 * 60)
#endif

#ifndef REFRESH_TTL_SEC
#    define REFRESH_TTL_SEC (30ull * 24 * 60 * 60)
#endif

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */

/* Access token record (value of session_access) */
typedef struct __attribute__((packed))
{
    uint8_t  user_id[16];
    uint64_t exp;       /* absolute seconds */
    uint64_t created;   /* absolute seconds */
    uint64_t last_seen; /* absolute seconds */
    uint32_t flags;     /* reserved */
} AccessRec;

/* Refresh token record (value of session_refresh) */
typedef struct __attribute__((packed))
{
    uint8_t  user_id[16];
    uint64_t exp;     /* absolute seconds */
    uint64_t created; /* absolute seconds */
    uint8_t  rotated; /* 1 if used/rotated */
} RefreshRec;

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */

static int make_token(char out_str[SESSION_STR_MAX]);

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

/* TODO: Wire these to your LMDB environment/DBIs (db_session_access, db_session_refresh, db_user2sess). */

int session_issue(const uint8_t user_id[16], char access_token[SESSION_STR_MAX],
                  char refresh_token[SESSION_STR_MAX], uint64_t now_sec)
{
    if(!user_id || !access_token || !refresh_token)
    {
        errno = EINVAL;
        return -1;
    }
    if(make_token(access_token) != 0) return -1;
    if(make_token(refresh_token) != 0) return -1;

    /* NEXT: open RW txn; put:
       - access:<token> -> { user_id, exp=now+ACCESS_TTL_SEC, created=now, last_seen=now }
       - refresh:<token> -> { user_id, exp=now+REFRESH_TTL_SEC, created=now, parent=<random id> }
       - user2sess: key=user_id|access_token -> presence
       Commit txn.
    */
    (void)now_sec;
    return 0;
}

int session_validate_access(const char* token, uint8_t out_user_id[16],
                            uint64_t now_sec)
{
    if(!token || !out_user_id)
    {
        errno = EINVAL;
        return -1;
    }
    /* NEXT: open RO txn; get access:<token>; if not found -> EPERM
            check exp >= now_sec; if expired -> EPERM
            close RO; open RW txn; update last_seen; commit. */
    (void)now_sec;
    errno = ENOSYS; /* not wired yet */
    return -1;
}

int session_rotate_refresh(const char* refresh_token,
                           char        new_access[SESSION_STR_MAX],
                           char new_refresh[SESSION_STR_MAX], uint64_t now_sec)
{
    if(!refresh_token || !new_access || !new_refresh)
    {
        errno = EINVAL;
        return -1;
    }
    /* NEXT: find refresh:<tok>, check exp; delete old; issue new pair; commit atomically. */
    (void)now_sec;
    errno = ENOSYS;
    return -1;
}

int session_revoke_all(const uint8_t user_id[16], uint64_t now_sec)
{
    if(!user_id)
    {
        errno = EINVAL;
        return -1;
    }
    /* NEXT: cursor scan db_user2sess by prefix user_id, delete access entries and reverse links; optionally delete refresh. */
    (void)now_sec;
    errno = ENOSYS;
    return -1;
}

int session_revoke_token(const char* any_token)
{
    if(!any_token)
    {
        errno = EINVAL;
        return -1;
    }
    /* NEXT: try delete in access db; if not there, try refresh db. */
    errno = ENOSYS;
    return -1;
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

/* Generate opaque token = 32 random bytes -> base64url(no padding). */
static int make_token(char out_str[SESSION_STR_MAX])
{
    uint8_t raw[SESSION_RAW_LEN];
    if(crypt_rand_bytes(raw, sizeof raw) != 0) return -1;
    size_t out_len = SESSION_STR_MAX;
    if(b64url_encode(raw, sizeof raw, out_str, &out_len) != 0) return -1;
    return 0;
}
