
/**
 * @file utils_interface.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef UTILS_INTERFACE_H
#define UTILS_INTERFACE_H

#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include "sha256.h"
#include "uuid.h"

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
*/
/* None */

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
*/
/**
 * @brief
 * @param
 * @return
 */
int sanitize_email(char *email, uint8_t email_max_len, uint8_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* UTILS_INTERFACE_H */
