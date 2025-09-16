#ifndef UUID_H
#define UUID_H
#include <stdint.h>

#define DB_ID_SIZE 16

// Random v4 UUID-like 128-bit id (not textual; binary only)
int  id128_rand(uint8_t val[DB_ID_SIZE]);

// Hex helpers
void id128_to_hex(uint8_t id[DB_ID_SIZE], char out33[33]);
int  id128_equal(uint8_t id_a[DB_ID_SIZE], uint8_t id_b[DB_ID_SIZE]);

#endif  // UUID_H