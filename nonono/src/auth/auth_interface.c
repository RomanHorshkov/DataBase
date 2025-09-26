/**
 * @file auth_interface.c
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "auth_interface.h"
#include "db_interface.h"

int auth_register_new(const char *email_in, /* const char *pwd_in, */
                      uint8_t    *out_user_id)
{
    if(!email_in || email_in[0] == '\0') return -EINVAL;

    uint8_t elen = 0;
    if(sanitize_email(email_in, DB_EMAIL_MAX_LEN, &elen) != 0) return -EINVAL;
    printf("ok sanitize\n");

    uint8_t user_id[DB_UUID_SIZE];
    uuid_v7(user_id);

    // uint8_t pwrec[PWREC_SIZE];
    // if(password_hash(pwd_in, pwrec) != 0) return -EIO;

    /* Register the new user on the DB */
    int rc =
        db_user_register_new(elen, email_in, user_id /*, pwrec, sizeof pwrec*/);

    if(rc != 0)
    {
        return rc;
    }

    if(out_user_id) memcpy(out_user_id, user_id, DB_UUID_SIZE);

    return rc;
}
