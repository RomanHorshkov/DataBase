#ifndef UUID_H
#define UUID_H
#include <stdint.h>

#define UUID_BYTES_SIZE 16

/**
 * @brief Generate a random v4 UUID.
 * @param val Output buffer [16 bytes].
 * @return 0 on success, -EINVAL if invalid args.
 */
int uuid_v4(uint8_t val[UUID_BYTES_SIZE]);

/**
 * @brief Generate a random v7 UUID.
 * @param val Output buffer [16 bytes].
 * @return 0 on success, -EINVAL if invalid args.
 */
int uuid_v7(uint8_t val[UUID_BYTES_SIZE]);

/**
 * @brief Convert a UUID to a hex string.
 * @param id Input user IDs.
 * @param out33 Output hex string (must be 33 bytes).
 */
void uuid_to_hex(uint8_t id[UUID_BYTES_SIZE], char out33[33]);

#endif  // UUID_H