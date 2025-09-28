#pragma once

#include <db.h>

/* ===== Generic ops (single-shot transactions) ===== */
int kv_put(DBI_ID id, const void* key_obj, const void* val_obj, unsigned flags);
int kv_get(DBI_ID id, const void* key_obj, void* out_val_obj);
int kv_del(DBI_ID id, const void* key_obj);
int kv_del_kv(DBI_ID id, const void* key_obj, const void* val_obj);

typedef int (*scan_cb)(const MDB_val* k, const MDB_val* v, void* ud);
int kv_scan(DBI_ID id, const void* start_key_obj, const void* end_key_obj,
            scan_cb cb, void* ud);

int kv_dump(DBI_ID id, FILE* out);
int kv_dump_all(FILE* out);
