#pragma once
#include <errno.h>
#include <lmdb.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* ===== Basic types ===== */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define DB_ID_SIZE  16
#define SHA256_SIZE 32

typedef struct
{
    u8 b[DB_ID_SIZE];
} uuid16_t;

typedef struct
{
    u8 b[SHA256_SIZE];
} sha256_t;

/* Forward decl. of schema-specific structs */
typedef struct user_rec      user_rec_t;
typedef struct data_meta_rec data_meta_rec_t;

typedef int (*kv_encode_fn)(const void* obj, MDB_val* out);
typedef int (*kv_decode_fn)(const MDB_val* in, void* obj);
typedef int (*kv_print_fn)(const MDB_val* in, FILE* out);
typedef int (*kv_cmp_fn)(const MDB_val* a, const MDB_val* b);

/* DBI registry entry */
typedef struct
{
    const char*  name;
    kv_encode_fn key_enc;
    kv_decode_fn key_dec;
    kv_print_fn  key_prn;
    kv_encode_fn val_enc;
    kv_decode_fn val_dec;
    kv_print_fn  val_prn;
    kv_cmp_fn    cmp;
    unsigned     flags;
    MDB_dbi      dbi;
} dbi_desc_t;

/* Expands from schemas.def */
#define DBI_EXPAND_ENUM(id, name, ...) DBI_##id,
#define DBI_EXPAND_DESC(id, name, kenc, kdec, kpr, venc, vdec, vpr, cmp, \
                        flags)                                           \
    [DBI_##id] = {name, kenc, kdec, kpr, venc, vdec, vpr, cmp, flags, 0},

/* Public DB handle */
typedef struct
{
    char       root[1024];
    MDB_env*   env;
    dbi_desc_t dbis[
#define _(id, name, ...) DBI_EXPAND_ENUM(id, name)
#include "schemas.def"
#undef _
        0 /* dummy to allow past-the-end index calc; replaced below */
    ];
} DB;

/* Proper enum & DBI_COUNT */
typedef enum
{
#define _(id, name, ...) DBI_EXPAND_ENUM(id, name)
#include "schemas.def"
#undef _
    DBI_COUNT
} DBI_ID;

/* Re-declare dbis array size now that DBI_COUNT is known */
#undef DB
typedef struct
{
    char       root[1024];
    MDB_env*   env;
    dbi_desc_t dbis[DBI_COUNT];
} DB;

/* ===== Core lifecycle ===== */
int  db_open(DB* db, const char* root, size_t mapsize);
void db_close(DB* db);

/* ===== Generic ops (single-shot transactions) ===== */
int kv_put(DB* db, DBI_ID id, const void* key_obj, const void* val_obj,
           unsigned flags);
int kv_get(DB* db, DBI_ID id, const void* key_obj, void* out_val_obj);
int kv_del(DB* db, DBI_ID id, const void* key_obj);
int kv_del_kv(DB* db, DBI_ID id, const void* key_obj, const void* val_obj);

typedef int (*scan_cb)(const MDB_val* k, const MDB_val* v, void* ud);
int kv_scan(DB* db, DBI_ID id, const void* start_key_obj,
            const void* end_key_obj, scan_cb cb, void* ud);

int kv_dump(DB* db, DBI_ID id, FILE* out);
int kv_dump_all(DB* db, FILE* out);
int map_mdb_err(int mrc);
