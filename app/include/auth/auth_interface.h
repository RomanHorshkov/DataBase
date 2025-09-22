/**
 * @file auth_service.h
 * @brief Minimal authentication facade for HTTP layer.
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */
#ifndef AUTH_SERVICE_H
#define AUTH_SERVICE_H

#include <stdint.h>       /* uint8_t */
#include "db_interface.h" /* DB_ID_SIZE */

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

/* Lengths for textual session tokens (return base64url) */
#define AUTH_SESSION_TOKEN_RAW_LEN 32 /* 256-bit */

/* plenty (libsodium macro available too) */
#define AUTH_SESSION_TOKEN_B64_LEN 64

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
 */

/* Initialize crypto (libsodium) once. Call at process start (or inside
 * db_open). */
int auth_crypto_init(void);

/* Register local account (email must not exist). Also persists Argon2id hash.
 */
int auth_register_local(const char *email, const char *password,
                        uint8_t out_user_id[DB_ID_SIZE]);

/* Verify password and issue a session (Set-Cookie uses returned token). */
int auth_login_password(const char *email, const char *password,
                        char out_session_token_b64[AUTH_SESSION_TOKEN_B64_LEN]);

/* Resolve a presented session token -> user_id (checks expiry). */
int auth_session_resolve(const char *session_token_b64,
                         uint8_t     out_user_id[DB_ID_SIZE]);

/* Invalidate a session token (logout) */
int auth_logout(const char *session_token_b64);

#ifdef __cplusplus
}
#endif

#endif /* AUTH_SERVICE_H */
