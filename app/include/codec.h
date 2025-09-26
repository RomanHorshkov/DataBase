
#pragma once
#include <string.h>
#include "kv_core.h"

/* ===== commonly shared enc/dec/prn ===== */
int enc_fixed(const void* p, size_t sz, MDB_val* out);
int dec_fixed(const MDB_val* in, void* p, size_t sz);

/* uuid16 */
int enc_uuid(const void* obj, MDB_val* out);
int dec_uuid(const MDB_val* in, void* obj);
int pr_uuid(const MDB_val* in, FILE* out);

/* sha256 */
int enc_sha256(const void* obj, MDB_val* out);
int dec_sha256(const MDB_val* in, void* obj);
int pr_sha256(const MDB_val* in, FILE* out);

/* small u8 value=1 (presence flag) */
int enc_u8_one(const void* obj, MDB_val* out);
int pr_u8_one(const MDB_val* in, FILE* out);

/* email key: store as raw bytes (no NUL). We encode from (ptr,len) pair. */
typedef struct
{
    const char* ptr;
    u8          len;
} email_key_t;
int enc_email(const void* obj, MDB_val* out);
int pr_email(const MDB_val* in, FILE* out);

/* ===== domain records ===== */
struct user_rec
{
    u8   ver;
    u8   role;
    u8   email_len;
    char email[255];
    u8   pw_tag;
    char pw_hash[128];
};
int enc_user_rec(const void* obj, MDB_val* out);
int dec_user_rec(const MDB_val* in, void* obj);
int pr_user_rec(const MDB_val* in, FILE* out);

struct data_meta_rec
{
    u8   ver;
    u64  size;
    u32  mime_len;
    char mime[64];
    u64  created_at_unix;
};
int enc_data_meta(const void* obj, MDB_val* out);
int dec_data_meta(const MDB_val* in, void* obj);
int pr_data_meta(const MDB_val* in, FILE* out);

/* ACL keys */
typedef struct
{
    uuid16_t principal;
    u8       rtype;
    uuid16_t resource;
} acl_fwd_k_t;
typedef struct
{
    uuid16_t resource;
    u8       rtype;
    uuid16_t principal;
} acl_rev_k_t;
int enc_acl_fwd_k(const void* obj, MDB_val* out);
int enc_acl_rev_k(const void* obj, MDB_val* out);
int pr_acl_fwd_k(const MDB_val* in, FILE* out);
int pr_acl_rev_k(const MDB_val* in, FILE* out);
