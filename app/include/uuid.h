#pragma once
#include "kv_core.h"

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
int uuid_gen(uint8_t *val);

/**
 * @brief Convert a UUID to a hex string.
 * @param id Input user IDs.
 * @param out33 Output hex string (must be 33 bytes).
 */
void uuid_to_hex(uint8_t *id, char *out33);
