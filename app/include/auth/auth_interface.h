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

#ifdef __cplusplus
extern "C"
{
#endif

int auth_register_new(char* email_in /* const char *pwd_in, */);

#ifdef __cplusplus
}
#endif

#endif /* AUTH_INTERFACE_H */
