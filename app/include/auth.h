
#pragma once
#include "db.h"

/* Initialize crypto (libsodium). returns 0 on success */
int auth_crypto_init(void);

/* Register: create user if email not in map. Fills new_id if created. */
int auth_register(const char* email, uint8_t elen, const char* password,
                  uuid16_t* new_id);

// /* Login: verify password → returns 0 if ok; -ENOENT if user missing; -EPERM if bad pw */
// int auth_login(const char* email, uint8_t elen, const char* password,
//                uuid16_t* out_id);

// /* Change password (must exist) */
// int auth_set_password(const uuid16_t* uid, const char* password);

// /* Share with user (transactional): ensure user exists for email, grant ACL. */
// /* rtype is a small resource type code you define (e.g., 1=image) */
// int auth_share_with_user(const uuid16_t* resource_id, uint8_t rtype,
//                          const char* email, uint8_t elen,
//                          uuid16_t* out_user_id);
