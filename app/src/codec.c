#include "codec.h"
#include <stdio.h>

int enc_fixed(const void* p, size_t sz, MDB_val* out)
{
    out->mv_data = (void*)p;
    out->mv_size = sz;
    return 0;
}
int dec_fixed(const MDB_val* in, void* p, size_t sz)
{
    if(in->mv_size != sz) return -EINVAL;
    memcpy(p, in->mv_data, sz);
    return 0;
}

/* uuid16 */
int enc_uuid(const void* obj, MDB_val* out)
{
    return enc_fixed(obj, DB_ID_SIZE, out);
}
int dec_uuid(const MDB_val* in, void* obj)
{
    return dec_fixed(in, obj, DB_ID_SIZE);
}
int pr_uuid(const MDB_val* in, FILE* out)
{
    if(in->mv_size != DB_ID_SIZE) return -EINVAL;
    const u8* b = (const u8*)in->mv_data;
    for(size_t i = 0; i < DB_ID_SIZE; i++)
        fprintf(out, "%02x", b[i]);
    return 0;
}

/* sha256 */
int enc_sha256(const void* obj, MDB_val* out)
{
    return enc_fixed(obj, SHA256_SIZE, out);
}
int dec_sha256(const MDB_val* in, void* obj)
{
    return dec_fixed(in, obj, SHA256_SIZE);
}
int pr_sha256(const MDB_val* in, FILE* out)
{
    if(in->mv_size != SHA256_SIZE) return -EINVAL;
    const u8* b = (const u8*)in->mv_data;
    for(size_t i = 0; i < SHA256_SIZE; i++)
        fprintf(out, "%02x", b[i]);
    return 0;
}

/* presence value */
int enc_u8_one(const void* obj, MDB_val* out)
{
    static const u8 one = 1;
    (void)obj;
    out->mv_data = (void*)&one;
    out->mv_size = 1;
    return 0;
}
int pr_u8_one(const MDB_val* in, FILE* out)
{
    if(in->mv_size != 1) return -EINVAL;
    fprintf(out, "1");
    return 0;
}

/* email key */
int enc_email(const void* obj, MDB_val* out)
{
    const email_key_t* k = (const email_key_t*)obj;
    out->mv_data         = (void*)k->ptr;
    out->mv_size         = k->len;
    return 0;
}
int pr_email(const MDB_val* in, FILE* out)
{
    fwrite(in->mv_data, 1, in->mv_size, out);
    return 0;
}

/* user_rec packing: [ver|role|elen|email..|pw_tag|pw_hash_str..\0] */
int enc_user_rec(const void* obj, MDB_val* out)
{
    const user_rec_t* u = (const user_rec_t*)obj;
    if(u->email_len > 255) return -EINVAL;
    size_t hlen = strnlen(u->pw_hash, sizeof u->pw_hash);
    if(hlen >= sizeof u->pw_hash) return -EINVAL;
    static _Thread_local unsigned char buf[3 + 255 + 1 + 128];
    unsigned char*                     p = buf;
    *p++                                 = u->ver;
    *p++                                 = u->role;
    *p++                                 = u->email_len;
    memcpy(p, u->email, u->email_len);
    p    += u->email_len;
    *p++  = u->pw_tag;
    memcpy(p, u->pw_hash, hlen + 1);
    p            += hlen + 1;
    out->mv_data  = buf;
    out->mv_size  = (size_t)(p - buf);
    return 0;
}

int dec_user_rec(const MDB_val* in, void* obj)
{
    const unsigned char* p = (const unsigned char*)in->mv_data;
    const unsigned char* e = p + in->mv_size;
    if(e - p < 4) return -EINVAL;
    user_rec_t* u = (user_rec_t*)obj;
    u->ver        = *p++;
    u->role       = *p++;
    u->email_len  = *p++;
    if((size_t)(e - p) < u->email_len + 1) return -EINVAL;
    memcpy(u->email, p, u->email_len);
    p          += u->email_len;
    u->pw_tag   = *p++;
    size_t rem  = (size_t)(e - p);
    if(rem >= sizeof u->pw_hash) return -EINVAL;
    memcpy(u->pw_hash, p, rem);
    u->pw_hash[rem ? rem - 1 : 0] = '\0';
    return 0;
}

int pr_user_rec(const MDB_val* in, FILE* out)
{
    user_rec_t u;
    if(dec_user_rec(in, &u) != 0) return -EINVAL;
    fprintf(out, "{ver:%u role:%u email:'", u.ver, u.role);
    fwrite(u.email, 1, u.email_len, out);
    fprintf(out, "' tag:%u}", u.pw_tag);
    return 0;
}

/* data_meta: [ver|size(8)|mime_len(4)|mime..|created(8)] */
int enc_data_meta(const void* obj, MDB_val* out)
{
    const data_meta_rec_t* m = (const data_meta_rec_t*)obj;
    if(m->mime_len > sizeof m->mime) return -EINVAL;
    static _Thread_local unsigned char buf[1 + 8 + 4 + 64 + 8];
    unsigned char*                     p = buf;
    *p++                                 = m->ver;
    memcpy(p, &m->size, 8);
    p += 8;
    memcpy(p, &m->mime_len, 4);
    p += 4;
    memcpy(p, m->mime, m->mime_len);
    p += m->mime_len;
    memcpy(p, &m->created_at_unix, 8);
    p            += 8;
    out->mv_data  = buf;
    out->mv_size  = (size_t)(p - buf);
    return 0;
}
int dec_data_meta(const MDB_val* in, void* obj)
{
    const unsigned char* p = (const unsigned char*)in->mv_data;
    const unsigned char* e = p + in->mv_size;
    if(e - p < 1 + 8 + 4 + 8) return -EINVAL;
    data_meta_rec_t* m = (data_meta_rec_t*)obj;
    m->ver             = *p++;
    memcpy(&m->size, p, 8);
    p += 8;
    memcpy(&m->mime_len, p, 4);
    p += 4;
    if((size_t)(e - p) < m->mime_len + 8 || m->mime_len > sizeof m->mime)
        return -EINVAL;
    memcpy(m->mime, p, m->mime_len);
    p += m->mime_len;
    memcpy(&m->created_at_unix, p, 8);
    return 0;
}
int pr_data_meta(const MDB_val* in, FILE* out)
{
    data_meta_rec_t m;
    if(dec_data_meta(in, &m) != 0) return -EINVAL;
    fprintf(out, "{ver:%u size:%llu mime:'%.*s' t:%llu}", m.ver,
            (unsigned long long)m.size, (int)m.mime_len, m.mime,
            (unsigned long long)m.created_at_unix);
    return 0;
}

/* ACL keys binary pack */
int enc_acl_fwd_k(const void* obj, MDB_val* out)
{
    const acl_fwd_k_t*                 k = (const acl_fwd_k_t*)obj;
    static _Thread_local unsigned char buf[DB_ID_SIZE + 1 + DB_ID_SIZE];
    unsigned char*                     p = buf;
    memcpy(p, k->principal.b, DB_ID_SIZE);
    p    += DB_ID_SIZE;
    *p++  = k->rtype;
    memcpy(p, k->resource.b, DB_ID_SIZE);
    p            += DB_ID_SIZE;
    out->mv_data  = buf;
    out->mv_size  = (size_t)(p - buf);
    return 0;
}
int enc_acl_rev_k(const void* obj, MDB_val* out)
{
    const acl_rev_k_t*                 k = (const acl_rev_k_t*)obj;
    static _Thread_local unsigned char buf[DB_ID_SIZE + 1 + DB_ID_SIZE];
    unsigned char*                     p = buf;
    memcpy(p, k->resource.b, DB_ID_SIZE);
    p    += DB_ID_SIZE;
    *p++  = k->rtype;
    memcpy(p, k->principal.b, DB_ID_SIZE);
    p            += DB_ID_SIZE;
    out->mv_data  = buf;
    out->mv_size  = (size_t)(p - buf);
    return 0;
}

static int pr_acl_common(const MDB_val* in, FILE* out, int is_fwd)
{
    if(in->mv_size != DB_ID_SIZE + 1 + DB_ID_SIZE) return -EINVAL;
    const u8* p = (const u8*)in->mv_data;
    const u8* a = p;
    const u8* b = p + DB_ID_SIZE + 1;
    for(size_t i = 0; i < DB_ID_SIZE; i++)
        fprintf(out, "%02x", a[i]);
    fprintf(out, is_fwd ? "|rtype:%u|" : "|rtype:%u|", p[DB_ID_SIZE]);
    for(size_t i = 0; i < DB_ID_SIZE; i++)
        fprintf(out, "%02x", b[i]);
    return 0;
}
int pr_acl_fwd_k(const MDB_val* in, FILE* out)
{
    return pr_acl_common(in, out, 1);
}
int pr_acl_rev_k(const MDB_val* in, FILE* out)
{
    return pr_acl_common(in, out, 0);
}
