#include "db_sodium.h"
#include <string.h>

int init_sodium(void)
{
    if(sodium_init() < 0) return -1;  // libsodium not available
    return 0;
}

int sodium_hash_password(const char* pwd, char out[crypto_pwhash_STRBYTES])
{
    if(crypto_pwhash_str(out, pwd, strnlen(pwd, 128U),
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        return -1;  // out of memory
    }
    return 0;
}

int sodium_verify_password(const char* pwd, const char* stored)
{
    return crypto_pwhash_str_verify(stored, pwd, strlen(pwd)) == 0 ? 0 : -1;
}

// int sodium_maybe_rehash(char* stored)
// {
//     if(crypto_pwhash_str_needs_rehash(stored,
//                                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
//                                       crypto_pwhash_MEMLIMIT_INTERACTIVE) == 1)
//     {
// char newhash[crypto_pwhash_STRBYTES];
//         if(sodium_hash_password(/* same pwd just verified */, newhash) == 0)
//         {
//             // replace stored with newhash atomically in DB
//             return 1;  // rehashed
//         }
//     }
//     return 0;          // not needed or failed to rehash
// }
