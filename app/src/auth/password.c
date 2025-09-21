/**
 * @file password.h
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "password.h"
#include <errno.h>
#include <sodium.h>
#include <string.h>

static unsigned long long g_opslimit = crypto_pwhash_opslimit_interactive();
static size_t             g_memlimit = crypto_pwhash_memlimit_interactive();

static int ensure_sodium(void) {
    static int done = 0;
    if (!done) {
        if (sodium_init() < 0) return -EIO;
        done = 1;
    }
    return 0;
}

int pw_set_policy_interactive(void) {
    int rc = ensure_sodium(); if (rc) return rc;
    g_opslimit = crypto_pwhash_opslimit_interactive();
    g_memlimit = crypto_pwhash_memlimit_interactive();
    return 0;
}

int pw_set_policy_sensitive(void) {
    int rc = ensure_sodium(); if (rc) return rc;
    g_opslimit = crypto_pwhash_opslimit_sensitive();
    g_memlimit = crypto_pwhash_memlimit_sensitive();
    return 0;
}

int pw_hash(const char* password, char out_blob[PASSWORD_BLOB_MAX]) {
    if (!password || !out_blob) return -EINVAL;
    int rc = ensure_sodium(); if (rc) return rc;
    /* Argon2id v1.3, self-describing string; NO padding hassle. */
    if (crypto_pwhash_str_alg(out_blob, password, strlen(password),
                              g_opslimit, g_memlimit,
                              crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -EIO;
    return 0;
}

int pw_verify(const char* password, const char* blob, int* needs_rehash) {
    if (!password || !blob) return -EINVAL;
    int rc = ensure_sodium(); if (rc) return rc;

    if (crypto_pwhash_str_verify(blob, password, strlen(password)) != 0)
        return -EPERM;

    if (needs_rehash) {
        *needs_rehash = crypto_pwhash_str_needs_rehash(
            blob, g_opslimit, g_memlimit);
    }
    return 0;
}
