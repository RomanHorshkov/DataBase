/**
 * @file password.h
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef AUTHENTICATION_PASSWORD_H
#define AUTHENTICATION_PASSWORD_H

#include <stddef.h>
#include <stdint.h>

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

#define PASSWORD_BLOB_MAX 128  // enough for sodium's encoded string

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
 */

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
 */

// hash -> opaque, self-describing blob (algorithm + params + salt + hash).
int password_hash(const char* password, char out_blob[PASSWORD_BLOB_MAX]);

// verify -> 0 ok, -EPERM mismatch, <0 other errors. Can set *needs_rehash=1.
int password_verify(const char* password, const char* blob, int* needs_rehash);

// pick policy (interactive vs sensitive); you’ll compile with one of these.
int password_set_policy_interactive(void);  // mem ~64MB, opslimit ~3
int password_set_policy_sensitive(void);    // mem ~256MB, opslimit ~5

#endif /* AUTHENTICATION_PASSWORD_H */
