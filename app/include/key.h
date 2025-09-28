#include <stdint.h>

#define DB_ID_SIZE    16
#define DB_EMAIL_SIZE 255
#define SHA256_SIZE   32

typedef struct
{
    uint8_t b[DB_ID_SIZE];
} uuid16_t;

typedef struct
{
    uint8_t b[SHA256_SIZE];
} sha256_t;

/**
 * DBIs keys and values 
 * 
*/

/* ID2DATA */
typedef struct /*  __attribute__((packed)) */
{
    uuid16_t k;
} id2data_key_t;

typedef struct
{
    /* 1 byte version for future evolution */
    uint8_t ver;

    /* 1 byte role */
    uint8_t role;

    /* 1 byte email length without '\0' */
    uint8_t email_len;

    /* variable-length email without '\0' */
    char email[DB_EMAIL_SIZE];

    // /* password */
    // uint8_t pw_tag;

    // char    pw_hash[128];

} id2data_val_t;

/* EMAIL2ID */
typedef struct
{
    /* ptr to variable len string with no \0 */
    const char* ptr;
    /* length without \0 */
    uint8_t len;

} email2id_key_t;

typedef struct /*  __attribute__((packed)) */
{
    uuid16_t v;
} email2id_val_t;

/* ACL_FWD */
typedef struct
{
    /* user id of the resource's owner */
    uuid16_t principal;

    /* possession type */
    uint8_t rtype;

    /* resource id possessed */
    uuid16_t resource;

} acl_fwd_key_t;

/* ACL_REV */
typedef struct
{
    /* resource id possessed */
    uuid16_t resource;

    /* possession type */
    uint8_t rtype;

    /* user id */
    uuid16_t principal;

} acl_rev_key_t;
