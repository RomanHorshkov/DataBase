/**
 * @file db_sodium.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef DB_SODIUM_H
#define DB_SODIUM_H

#include <sodium.h>

int init_sodium(void);

int sodium_hash_password(const char* pwd, char out[crypto_pwhash_STRBYTES]);

int sodium_verify_password(const char* pwd, const char* stored);

// int sodium_maybe_rehash(char* stored);

#endif /* DB_SODIUM_H */
