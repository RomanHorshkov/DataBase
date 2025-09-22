# LMDB Presence Store

A compact, embedded datastore for content‑addressed blobs with presence‑only access control lists (ACLs). It stores users, roles, object metadata, and forward/reverse ACL indexes on top of LMDB, providing predictable performance and simple operational characteristics.

## What It Does

* **Embedded key–value database**
  Links directly against LMDB; no daemon, no network round‑trips.

* **Content‑addressed storage (SHA‑256)**
  Blobs are deduplicated by digest and kept under a deterministic filesystem path.

* **Presence‑only ACL model**
  Authorization is expressed by presence/absence of a relation in compact indexes. Supported relations:

  * `O` Owner
  * `S` Share (may re‑share)
  * `U` User (viewer)

* **Users and roles**
  Users have stable 128‑bit IDs and a role:

  * `Viewer` — can view data shared with them (and be granted `U`/`S`)
  * `Publisher` — may upload and manage owned data in addition to viewing
  * `None` — registered, no default privileges

* **Deterministic metadata**
  Each object has a compact metadata record: version, SHA‑256, MIME type, size, creation time, and owner ID.

* **Atomic ingest and delete**
  Uploads stream to a temporary file, fsync, publish atomically, then index in a single transaction. Deletes cascade through ACLs, metadata, and the blob.

* **Fast lookups**

  * Email → user ID
  * User ID → user record
  * Data ID → metadata
  * ACL presence (`O`/`S`/`U`) via forward or reverse indexes

* **Batch‑friendly**
  Supports batch user insertion and efficient set membership checks using cursor merge‑walks.

### LMDB Sub‑databases

* `user` — key: `user_id(16)` → value: packed user record (version, role, email)
* `user_email2id` — key: email bytes → value: `user_id(16)`
* `data_meta` — key: `data_id(16)` → value: packed metadata
* `sha2data` — key: `sha256(32)` → value: `data_id(16)` (deduplication)
* `acl_fwd` — key: `principal(16) | rtype(1) | resource(16)` → value: sentinel
* `acl_by_res` — key: `resource(16) | rtype(1)` → value: `principal(16)` (dupsort)

Keys are chosen for lexicographic friendliness with UUIDv7, enabling efficient `MDB_APPEND` inserts and high page utilization.

## Capabilities

* Create/open/close environment with bounded map size and on‑disk layout bootstrap.
* Add users with validation and canonicalization of emails; idempotent by email.
* Lookup users by ID or email; list all, or list by role.
* Upload data (publishers only), with content deduplication and automatic owner ACL grant.
* Resolve filesystem paths from data IDs to on‑disk objects.
* Share data by granting presence in `U` (and optionally `S`) with forward and reverse indexes updated atomically.
* Delete data (owners only), removing ACL entries, metadata, sha‑index, and the blob.

## Error Semantics

Public APIs return negative errno values:

* `-EINVAL` — invalid input
* `-ENOENT` — missing user/data or absent ACL presence
* `-EPERM` — insufficient privileges
* `-EEXIST` — deduplication hit (already present)
* `-EIO` — storage/database error
* `-ENOMEM` — out of map space (or allocation failure)

LMDB statuses are consistently mapped to errno‑style codes.

## Performance Characteristics

* O(1) lookups by key (email→id, id→record).
* Near‑sequential inserts for UUIDv7 keys (`MDB_APPEND`) minimize page splits.
* Single‑pass ingest (stream → temp → fsync → publish) limits copies.
* Presence checks are direct key probes; reverse scans use dup‑sorted ranges.

Actual throughput and footprint depend on page size, email length distribution, and environment options. The design targets microsecond‑level lookups and small per‑record overhead.

## Build and Test

### Prerequisites

* `liblmdb-dev`
* `libssl-dev` (for SHA‑256 and streaming ingest)
* `build-essential`, `pkg-config`

### Build

```bash
make                # builds demo: build/bin/db_lmdb_demo
make build/bin/db_tests
```

### Run Tests

```bash
make test
make test RUNARGS="--list"        # list tests
make test RUNARGS="--filter upload"
```

## Configuration

* **Root directory**: passed to `db_open`; layout is created if missing.
* **Map size**: configured at `db_open`; expandable up to a maximum (`LMDB_MAPSIZE_MAX_MB` or default multiple).
* **Durability**: default LMDB durability settings; tune at environment open if needed.

## Reliability and Integrity

* Multi‑index updates (metadata and ACL pairs) occur in a single write transaction.
* Ingest writes to a temporary file and atomically renames on success; the database never references a partial blob.
* Blob removal is best‑effort after metadata/ACL deletion; the database is the source of truth.

## Limitations

* Single‑writer semantics from LMDB; readers are concurrent, writers are serialized by the environment.
* ACL model is intentionally minimal (presence only). Fine‑grained policies or time‑bound grants are out of scope.
* Metadata schema is fixed‑size and compact; extensibility relies on the `ver` field for forward‑compatible evolution.

## Roadmap (Indicative)

* Optional role‑based policy hooks on share/reshare.
* Audit events around grant/revoke operations.
* Tooling for orphaned blob GC and environment compaction.
* Optional encryption at rest for blobs and/or metadata.

## License

Specify license terms here.
