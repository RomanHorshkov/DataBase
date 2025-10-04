

#include "db_internal.h"

/* USER ROLES */
#define USER_ROLE_NONE      0u
#define USER_ROLE_VIEWER    (1u << 0)
#define USER_ROLE_PUBLISHER (1u << 1)

int db_user_register_new(uint8_t* email_len, char* email, uint8_t* user_id,
                         char* pwd_hash);
