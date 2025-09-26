#pragma once
#include "db.h"

/* Role bits */
#define ROLE_VIEWER    (1u << 0)
#define ROLE_PUBLISHER (1u << 1)

/* Initialize crypto (libsodium). returns 0 on success */
int auth_crypto_init(void);

/* Register: create user if email not in map. Fills new_id if created. */
int auth_register(DB* db, const char* email, u8 elen, const char* password,
                  uuid16_t* new_id);

/* Login: verify password → returns 0 if ok; -ENOENT if user missing; -EPERM if bad pw */
int auth_login(DB* db, const char* email, u8 elen, const char* password,
               uuid16_t* out_id);

/* Change password (must exist) */
int auth_set_password(DB* db, const uuid16_t* uid, const char* password);

/* Share with user (transactional): ensure user exists for email, grant ACL. */
/* rtype is a small resource type code you define (e.g., 1=image) */
int auth_share_with_user(DB* db, const uuid16_t* resource_id, u8 rtype,
                         const char* email, u8 elen, uuid16_t* out_user_id);
