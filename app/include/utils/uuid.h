/**
 * @file uuid.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef UUID_H
#define UUID_H

#include <stdint.h>

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
 * @brief Generate a random v7 UUID.
 * @param val Output buffer [16 bytes].
 * @return 0 on success, -EINVAL if invalid args.
 */
int uuid_gen(uint8_t* val);

#ifdef __cplusplus
}
#endif

#endif  // UUID_H
