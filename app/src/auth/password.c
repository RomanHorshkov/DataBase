/**
 * @file password.h
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "auth_intern.h"

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */

typedef struct __attribute__((packed))
{
    /* version */
    uint8_t ver;

    /* absolute seconds */
    uint64_t created;

    /* absolute seconds */
    uint64_t last_change;

    /* libsodium hash string (NUL-terminated) */
    char pwhash[crypto_pwhash_argon2id_STRBYTES];
} UserPwd_t;

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

// static size_t g_opslimit = crypto_pwhash_opslimit_interactive();
// static size_t g_memlimit = crypto_pwhash_memlimit_interactive();

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

int password_hash(const char* password,
                  char        out_blob[crypto_pwhash_argon2id_STRBYTES])
{
    if(!password || !out_blob) return -EINVAL;
    int rc = ensure_sodium();
    if(rc) return rc;
    if(crypto_pwhash_str_alg(out_blob, password, strlen(password), g_opslimit,
                             g_memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0)
        return -EIO;
    return 0;
}

int password_verify(const char* password, const char* blob, int* needs_rehash)
{
    if(!password || !blob) return -EINVAL;
    int rc = ensure_sodium();
    if(rc) return rc;

    if(crypto_pwhash_str_verify(blob, password, strlen(password)) != 0)
        return -EPERM;

    if(needs_rehash)
    {
        *needs_rehash =
            crypto_pwhash_str_needs_rehash(blob, g_opslimit, g_memlimit);
    }
    return 0;
}

static int ensure_sodium(void)
{
    static int done = 0;
    if(!done)
    {
        if(sodium_init() < 0) return -EIO;
        done = 1;
    }
    return 0;
}

int pw_set_policy_interactive(void)
{
    int rc = ensure_sodium();
    if(rc) return rc;
    g_opslimit = crypto_pwhash_opslimit_interactive();
    g_memlimit = crypto_pwhash_memlimit_interactive();
    return 0;
}

int pw_set_policy_sensitive(void)
{
    int rc = ensure_sodium();
    if(rc) return rc;
    g_opslimit = crypto_pwhash_opslimit_sensitive();
    g_memlimit = crypto_pwhash_memlimit_sensitive();
    return 0;
}

int ct_memeq(const void* a, const void* b, size_t n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    unsigned char        d = 0;
    for(size_t i = 0; i < n; ++i)
        d |= (unsigned char)(x[i] ^ y[i]);
    return d == 0;
}

void secure_wipe(void* p, size_t n)
{
    sodium_memzero(p, n);
}

int b64url_encode(const uint8_t* in, size_t n, char* out, size_t* out_len)
{
    if(!out_len)
    {
        errno = EINVAL;
        return -1;
    }
    size_t need =
        sodium_base64_ENCODED_LEN(n, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if(!out || *out_len < need)
    {
        *out_len = need;
        errno    = ENOSPC;
        return -1;
    }
    sodium_bin2base64(out, need, in, n,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    *out_len = need - 1; /* exclude trailing NUL from “written count” */
    return 0;
}

int b64url_decode(const char* in, uint8_t* out, size_t* out_len)
{
    if(!in || !out || !out_len)
    {
        errno = EINVAL;
        return -1;
    }
    size_t outn = *out_len;
    if(sodium_base642bin(out, outn, in, strlen(in), NULL, out_len, NULL,
                         sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
    {
        errno = EINVAL;
        return -1;
    }
    return 0;
}
