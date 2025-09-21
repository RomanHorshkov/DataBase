/**
 * @file db_interface.h
 * @brief 
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#ifndef DB_INTERFACE_H
#define DB_INTERFACE_H

#ifdef __cplusplus
extern "C"
{
#endif

/****************************************************************************
 * PUBLIC DEFINES
 ****************************************************************************
 */

/* ----------------------- Packed DB records -------------------------------- */
#define DB_ID_SIZE       16  /* UUID bytes sizes 128 bits */
#define DB_EMAIL_MAX_LEN 128 /* Maximum length for email strings */
#define DB_VER           0

/****************************************************************************
 * PUBLIC STRUCTURED VARIABLES
 ****************************************************************************
*/

typedef struct __attribute__((packed))
{
    uint8_t  ver;               /* version for future evolution */
    uint8_t  sha[32];           /* SHA-256 of stored object */
    char     mime[32];          /* MIME type */
    uint64_t size;              /* total bytes */
    uint64_t created_at;        /* epoch seconds */
    uint8_t  owner[DB_ID_SIZE]; /* uploader id */
} DataMeta;

/****************************************************************************
 * PUBLIC FUNCTIONS DECLARATIONS
 ****************************************************************************
*/

/**
 * @brief Open the LMDB environment and initialize sub-databases.
 * @param root_dir Root directory for the database.
 * @param mapsize_bytes LMDB map size in bytes.
 * @return 0 on success, -EIO on error.
 */
int db_open(const char* root_dir, size_t mapsize_bytes);

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
int db_add_user(char email[DB_EMAIL_MAX_LEN], uint8_t out_id[DB_ID_SIZE]);

/**
 * @brief Insert a batch of users. If any present, fail.
 * @param n_users User emails amount.
 * @param email_flat User emails flat array
 * @return 0 on insertion, -EEXIST if already existed, -EINVAL bad input, -EIO DB error.
 */
int db_add_users(size_t n_users, char email_flat[n_users * DB_EMAIL_MAX_LEN]);

/**
 * @brief Look up a user by id and optionally return email.
 * Works with any order of ids_flat:
   - makes a local sorted copy
   - runs a single cursor merge-walk
   - if alloc fails, falls back to mdb_get loop
 * @param id User ID.
 * @param out_email Output email.
 * @return 0 on success, -ENOENT if not found, -EIO on DB error.
 */
int db_user_find_by_id(const uint8_t id[DB_ID_SIZE],
                       char          out_email[DB_EMAIL_MAX_LEN]);

/**
 * @brief Look up a users by ids.
 * @param n_users amount of users
 * @param ids_flat flat array of ids.
 * @return 0 on success, -ENOENT if not found, -EIO on DB error.
 */
int db_user_find_by_ids(size_t        n_users,
                        const uint8_t ids_flat[n_users * DB_ID_SIZE]);

/**
 * @brief Look up a user id by email.
 * @param email User email.
 * @param out_id Output user ID.
 * @return 0 on success, -ENOENT if not found, -EIO on DB error.
 */
int db_user_find_by_email(const char email[DB_EMAIL_MAX_LEN],
                          uint8_t    out_id[DB_ID_SIZE]);

/**
 * @brief Share data with a user identified by email (grants 'U' presence).
 * @param owner Sharer user ID (must have O/S/U on this data).
 * @param data_id Data ID to share.
 * @param email Recipient email.
 * @return 0 on success, -ENOENT if user or data missing, -EIO on DB error, -EPERM on ACL.
 */
int db_user_share_data_with_user_email(const uint8_t owner[DB_ID_SIZE],
                                       const uint8_t data_id[DB_ID_SIZE],
                                       const char    email[DB_EMAIL_MAX_LEN]);

/**
 * @brief Update a user's role in the DB to viewer.
 * @param userId User ID.
 * @return 0 on success, -ENOENT if user missing, -EINVAL if bad role, -EIO on DB error.
 */
int db_user_set_role_viewer(uint8_t userId[DB_ID_SIZE]);

/**
 * @brief Update a user's role in the DB to publisher.
 * @param userId User ID.
 * @return 0 on success, -ENOENT if user missing, -EINVAL if bad role, -EIO on DB error.
 */
int db_user_set_role_publisher(uint8_t userId[DB_ID_SIZE]);

/**
 * @brief List all users.
 * @param out_ids Output user IDs (optional; can be NULL to just count).
 * @param inout_count_max Input capacity; output total count.
 * @return 0 on success, -EINVAL bad args, -EIO on error.
 */
int db_user_list_all(uint8_t* out_ids, size_t* inout_count_max);

/**
 * @brief List all publishers.
 * @param out_ids Output user IDs.
 * @param inout_count_max Input capacity; output total count.
 * @return 0 on success, -EINVAL bad args, -EIO on error.
 */
int db_user_list_publishers(uint8_t* out_ids, size_t* inout_count_max);

/**
 * @brief List all viewers.
 * @param out_ids Output user IDs.
 * @param inout_count_max Input capacity; output total count.
 * @return 0 on success, -EINVAL bad args, -EIO on error.
 */
int db_user_list_viewers(uint8_t* out_ids, size_t* inout_count_max);

/* --------------------------- Data ------------------------------- */

/**
 * @brief Given a data id, resolve the absolute filesystem path of its blob.
 * @param img_id Data ID.
 * @param out_path Output path.
 * @param out_sz Output buffer size.
 * @return 0 on success, -ENOENT if meta missing, -EINVAL bad args, -EIO on path error.
 */
int db_data_get_path(uint8_t img_id[DB_ID_SIZE], char* out_path,
                     unsigned long out_sz);

/**
 * @brief Owner-only delete that removes: forward ACLs, reverse ACLs, sha->data,
 *        data_meta, and the blob on disk (best-effort) in a single RW txn.
 * @param actor Acting user (must have 'O' on data).
 * @param data_id Data to delete.
 * @return 0 on success, -EPERM if actor not owner, -ENOENT if missing, -EIO otherwise.
 */
int db_data_delete(const uint8_t actor[DB_ID_SIZE],
                   const uint8_t data_id[DB_ID_SIZE]);

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
int db_data_add_from_fd(uint8_t owner[DB_ID_SIZE], int src_fd, const char* mime,
                        uint8_t out_data_id[DB_ID_SIZE]);

int db_data_get_meta(uint8_t data_id[DB_ID_SIZE], DataMeta* out_meta);
int db_data_get_path(uint8_t data_id[DB_ID_SIZE], char* out_path,
                     unsigned long out_sz);

/* ACL helpers and operations (reserved for future use) */
/*
 * int db_revoke_data_from_user_email(uint8_t owner[DB_ID_SIZE], uint8_t data_id[DB_ID_SIZE], const char email[DB_EMAIL_MAX_LEN]);
 * int db_revoke_data_from_user_id(uint8_t owner[DB_ID_SIZE], uint8_t data_id[DB_ID_SIZE], const uint8_t user_id[DB_ID_SIZE]);
 */

/* --------------------------- LMDB ENV ------------------------------- */

int db_env_metrics(uint64_t* used_bytes, uint64_t* mapsize_bytes,
                   uint32_t* page_size);

#ifdef __cplusplus
}
#endif

#endif /* DB_INTERFACE_H */
