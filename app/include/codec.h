
#pragma once

#include "lmdb.h"
#include "stddef.h"
#include "stdint.h"
#include "stdio.h"

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

/* small uint8_t value=1 (presence flag) */
int enc_u8_one(const void* obj, MDB_val* out);
int pr_u8_one(const MDB_val* in, FILE* out);

/* user_id2data */
int enc_user_rec(const void* obj, MDB_val* out);
int dec_user_rec(const MDB_val* in, void* obj);
int pr_user_rec(const MDB_val* in, FILE* out);

/* user_email2id */
int enc_email(const void* obj, MDB_val* out);
int pr_email(const MDB_val* in, FILE* out);

/* ===== domain records ===== */

// int enc_data_meta(const void* obj, MDB_val* out);
// int dec_data_meta(const MDB_val* in, void* obj);
// int pr_data_meta(const MDB_val* in, FILE* out);

// int enc_acl_fwd_k(const void* obj, MDB_val* out);
// int enc_acl_rev_k(const void* obj, MDB_val* out);
// int pr_acl_fwd_k(const MDB_val* in, FILE* out);
// int pr_acl_rev_k(const MDB_val* in, FILE* out);
