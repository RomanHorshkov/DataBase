/**
 * @file auth_interface.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef AUTH_INTERFACE_H
#define AUTH_INTERFACE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

int auth_register_new(const char *email_in, /* const char *pwd_in, */
                      uint8_t    *out_user_id);

#ifdef __cplusplus
}
#endif

#endif /* AUTH_INTERFACE_H */
