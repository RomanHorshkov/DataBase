#ifndef DB_STORE_H
#define DB_STORE_H

#include <stdint.h>
#include <stddef.h>
#include "uuid.h"

#define EMAIL_MAX_LEN 128 /**< Maximum length for email strings */

/* ========================================================================= */
/*                               db_store.h                                  */
/* ========================================================================= */
/* LMDB-backed database store API header (presence-only ACL O/S/U).          */
/* ========================================================================= */

/**
 * @brief Open the LMDB environment and initialize sub-databases.
 * @param root_dir Root directory for the database.
 * @param mapsize_bytes LMDB map size in bytes.
 * @return 0 on success, -EIO on error.
 */
int  db_open(const char* root_dir, uint64_t mapsize_bytes);

/**
 * @brief Close the environment and free the global handle.
 */
void db_close(void);

/* ------------------------------ Users ----------------------------------- */

/**
 * @brief Insert a user if not already present. If present, copy id into out_id.
 * @param email User email.
 * @param out_id Output user ID.
 * @return 0 on insertion, -EEXIST if already existed, -EINVAL bad input, -EIO DB error.
 */
int  db_add_user(const char email[EMAIL_MAX_LEN], uint8_t out_id[DB_ID_SIZE]);

/**
 * @brief Look up a user by id and optionally return email.
 * @param id User ID.
 * @param out_email Output email.
 * @return 0 on success, -ENOENT if not found, -EIO on DB error.
 */
int  db_user_find_by_id(const uint8_t id[DB_ID_SIZE], char out_email[EMAIL_MAX_LEN]);

/**
 * @brief Look up a user id by email.
 * @param email User email.
 * @param out_id Output user ID.
 * @return 0 on success, -ENOENT if not found, -EIO on DB error.
 */
int  db_user_find_by_email(const char email[EMAIL_MAX_LEN], uint8_t out_id[DB_ID_SIZE]);

/**
 * @brief Share data with a user identified by email (grants 'U' presence).
 * @param owner Sharer user ID (must have O/S/U on this data).
 * @param data_id Data ID to share.
 * @param email Recipient email.
 * @return 0 on success, -ENOENT if user or data missing, -EIO on DB error, -EPERM on ACL.
 */
int  db_user_share_data_with_user_email(uint8_t    owner[DB_ID_SIZE],
                                        uint8_t    data_id[DB_ID_SIZE],
                                        const char email[EMAIL_MAX_LEN]);

/**
 * @brief Update a user's role in the DB to viewer.
 * @param userId User ID.
 * @return 0 on success, -ENOENT if user missing, -EINVAL if bad role, -EIO on DB error.
 */
int  db_user_set_role_viewer(uint8_t userId[DB_ID_SIZE]);

/**
 * @brief Update a user's role in the DB to publisher.
 * @param userId User ID.
 * @return 0 on success, -ENOENT if user missing, -EINVAL if bad role, -EIO on DB error.
 */
int  db_user_set_role_publisher(uint8_t userId[DB_ID_SIZE]);

/**
 * @brief List all users.
 * @param out_ids Output user IDs (optional; can be NULL to just count).
 * @param inout_count_max Input capacity; output total count.
 * @return 0 on success, -EINVAL bad args, -EIO on error.
 */
int  db_user_list_all(uint8_t* out_ids, size_t* inout_count_max);

/**
 * @brief List all publishers.
 * @param out_ids Output user IDs.
 * @param inout_count_max Input capacity; output total count.
 * @return 0 on success, -EINVAL bad args, -EIO on error.
 */
int  db_user_list_publishers(uint8_t* out_ids, size_t* inout_count_max);

/**
 * @brief List all viewers.
 * @param out_ids Output user IDs.
 * @param inout_count_max Input capacity; output total count.
 * @return 0 on success, -EINVAL bad args, -EIO on error.
 */
int  db_user_list_viewers(uint8_t* out_ids, size_t* inout_count_max);

/* --------------------------- Blobs & data ------------------------------- */

/**
 * @brief Ingest a blob from 'src_fd', computing SHA-256 while streaming it.
 *        Deduplicates by content; grants 'O' presence to the uploader.
 * @param owner Uploader ID.
 * @param src_fd Source file descriptor.
 * @param mime MIME type.
 * @param out_data_id Output data ID.
 * @return 0 on success, -EEXIST if content existed (id returned), -EPERM if not publisher,
 *         -ENOENT if owner not found, -EINVAL bad args, -EIO on error.
 */
int  db_upload_data_from_fd(uint8_t owner[DB_ID_SIZE],
                            int src_fd, const char* mime,
                            uint8_t out_data_id[DB_ID_SIZE]);

/**
 * @brief Given a data id, resolve the absolute filesystem path of its blob.
 * @param img_id Data ID.
 * @param out_path Output path.
 * @param out_sz Output buffer size.
 * @return 0 on success, -ENOENT if meta missing, -EINVAL bad args, -EIO on path error.
 */
int  db_resolve_data_path(uint8_t img_id[DB_ID_SIZE], char* out_path, unsigned long out_sz);

/**
 * @brief Owner-only delete that removes: forward ACLs, reverse ACLs, sha->data,
 *        data_meta, and the blob on disk (best-effort) in a single RW txn.
 * @param actor Acting user (must have 'O' on data).
 * @param data_id Data to delete.
 * @return 0 on success, -EPERM if actor not owner, -ENOENT if missing, -EIO otherwise.
 */
int  db_owner_delete_data(const uint8_t actor[DB_ID_SIZE], const uint8_t data_id[DB_ID_SIZE]);

/* ACL helpers and operations (reserved for future use) */
/*
 * int db_revoke_data_from_user_email(uint8_t owner[DB_ID_SIZE], uint8_t data_id[DB_ID_SIZE], const char email[EMAIL_MAX_LEN]);
 * int db_revoke_data_from_user_id(uint8_t owner[DB_ID_SIZE], uint8_t data_id[DB_ID_SIZE], const uint8_t user_id[DB_ID_SIZE]);
 */

int  db_env_metrics(uint64_t* used_bytes, uint64_t* mapsize_bytes, uint32_t* page_size);

#endif /* DB_STORE_H */
