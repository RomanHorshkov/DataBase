# LMDB Presence Store

Content-addressed blob store with **presence-only ACLs** built on top of [LMDB](https://symas.com/lmdb/).
Implements users, roles, metadata, and access control with predictable performance and a clean embedded design in C.

---

## ✨ Features

* **Embedded database**: no separate server; links directly against `liblmdb`.
* **Content-addressed storage**: deduplicates blobs by SHA-256 hash.
* **Presence-only ACL**: lightweight model — access is just *present or not present* in an ACL index.
* **Forward + reverse indexes**:

  * Forward: “principal has type T on resource”
  * Reverse: “all principals of type T on resource” (fast cascades).
* **User management**: random 128-bit IDs, email lookup, roles (Viewer/Publisher).
* **Cascade delete**: owner deletion removes data, metadata, and all ACL entries.
* **Test suite included**: custom runner with `--list`, `--filter`, `--repeat`, etc.

---

## 📂 Project Layout

```
include/
  cryptography/sha256.h    # hashing API
  db_store.h               # DB public API
  fsutil.h                 # filesystem helpers
  uuid.h                   # ID helpers

src/
  cryptography/sha256.c    # OpenSSL-based SHA-256 + object ingest
  db_store.c               # LMDB-backed DB implementation
  fsutil.c                 # mkdir -p, atomic writes, path helpers
  uuid.c                   # random ID128 utilities
  main.c                   # demo entry point
  tests/tests.c            # custom test runner

Makefile
README.md
```

---

## 🗄️ Database Model

All state lives under a **root directory**:

```
<root>/
 ├── meta/                  # LMDB environment (sub-databases)
 └── objects/sha256/        # Content-addressed blob store
      └── xx/yy/<sha256…>   # Two-level sharding by SHA-256 prefix
```

### LMDB Sub-databases

| Name            | Key              | Value         | Purpose                              |                                                   |                                             |
| --------------- | ---------------- | ------------- | ------------------------------------ | ------------------------------------------------- | ------------------------------------------- |
| `user`          | `id[16]`         | `UserPacked`  | User records (id, email, role)       |                                                   |                                             |
| `user_email2id` | `email` (bytes)  | `id[16]`      | Lookup user ID by email              |                                                   |                                             |
| `data_meta`     | `data_id[16]`    | `DataMeta`    | Metadata for each stored object      |                                                   |                                             |
| `sha2data`      | `sha[32]`        | `data_id[16]` | Deduplication map (hash → object id) |                                                   |                                             |
| `acl_fwd`       | \`principal\[16] | rtype(1)      | data\[16]\`                          | `uint8_t` sentinel                                | Forward ACL: “does P have relation R on D?” |
| `acl_by_res`    | \`data\[16]      | rtype(1)\`    | `principal[16]`                      | Reverse ACL: “who has relation R on D?” (dupsort) |                                             |

---

### Metadata Records

#### `UserPacked`

```c
typedef struct __attribute__((packed)) {
    uint8_t    id[16];             // 128-bit random user ID
    char       email[EMAIL_MAX_LEN]; // zero-terminated email
    uint16_t   role;               // USER_ROLE_NONE / VIEWER / PUBLISHER
} UserPacked;
```

#### `DataMeta`

```c
typedef struct __attribute__((packed)) {
    uint8_t   ver;                 // schema version
    uint8_t   sha[32];             // SHA-256 digest
    char      mime[32];            // MIME type (e.g. application/dicom)
    uint64_t  size;                // size in bytes
    uint64_t  created_at;          // epoch seconds
    uint8_t   owner[16];           // uploader's user ID
} DataMeta;
```

---

## 🔑 Access Control (Presence-only ACL)

* **Relation types (`rtype`)**

  * `O` → Owner (full control, can delete)
  * `S` → Share (can reshare)
  * `U` → User (view only)

* **Forward index (`acl_fwd`)**
  Key = `principal | rtype | resource` → Value = sentinel

  > “Does principal P have relation R on data D?”

* **Reverse index (`acl_by_res`)**
  Key = `resource | rtype` → Value = principals (dupsort)

  > “Who are all principals with relation R on data D?”

* **Presence semantics**

  ```
  has_any(P, D) = P has any of {O, S, U} on D
  ```

  Grants and revokes always update both indexes in the same transaction.

---

## 👥 User Roles

* **Viewer**: can view (`U`) and reshare (`S`) data shared with them.
* **Publisher**: viewer rights + can upload new data + delete own data.
* **None**: registered but no rights.

---

## 🚀 Build & Run

### Install dependencies

```bash
sudo apt-get install -y build-essential liblmdb-dev libssl-dev pkg-config
```

### Build binaries

```bash
make                        # demo → build/bin/db_lmdb_demo
make build/bin/db_tests     # test runner
```

### Run demo

```bash
./build/bin/db_lmdb_demo
```

---

## 🧪 Tests

The test runner has its own CLI:

```
Usage: db_tests [--list] [--filter SUBSTR] [--stop] [--repeat N] [--help]
```

### Examples

```bash
make test RUNARGS="--list"            # list all test names
make test RUNARGS="--filter upload"   # run only tests containing "upload"
make test RUNARGS="--repeat 3 --stop" # run suite 3x, stop on first failure
make test RUNARGS="--help"            # show usage
```

### Convenience shortcuts

```bash
make test-list
make test-help
make test-filter F=upload
make test-repeat N=5
```

---

## 🛠️ Public API (Highlights)

From `db_store.h`:

### Users

* `db_add_user(email, out_id)`
* `db_user_find_by_id(id, out_email)`
* `db_user_find_by_email(email, out_id)`
* `db_user_set_role_viewer(id)`
* `db_user_set_role_publisher(id)`
* `db_user_list_all(ids, &count)`
* `db_user_list_viewers(ids, &count)`
* `db_user_list_publishers(ids, &count)`

### Data

* `db_upload_data_from_fd(owner_id, fd, mime, out_data_id)`
* `db_resolve_data_path(data_id, out_path, out_sz)`
* `db_owner_delete_data(owner_id, data_id)`

### Sharing

* `db_user_share_data_with_user_email(owner_id, data_id, target_email)`

---

## ⚡ Notes

* LMDB environments live under `<root>/meta/`.
* Blob objects are written to `<root>/objects/sha256/` using two-level sharding.
* Deduplication is automatic: uploading identical content returns `-EEXIST` and grants owner presence.
* Deletes cascade: all ACL entries, metadata, and the blob are removed.

---

## 📜 License

MIT (or your choice).
