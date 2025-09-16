/* src/tests/test_functionality.c */
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>

#include "test_utils.h"
#include "db_store.h"

/* ------------------------------ Test Cases -------------------------------- */

int t_open_creates_layout(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }
    char pmeta[PATH_MAX + 64];
    snprintf(pmeta, sizeof pmeta, "%s/meta", ctx.root);
    char psha[PATH_MAX + 64];
    snprintf(psha, sizeof psha, "%s/objects/sha256", ctx.root);
    EXPECT_TRUE(tu_is_dir(ctx.root));
    EXPECT_TRUE(tu_is_dir(pmeta));
    EXPECT_TRUE(tu_is_dir(psha));
    tu_teardown_store(&ctx);
    return 0;
}

int t_add_user_and_find(void)
{
    Ctx ctx = {0};
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    uint8_t id[DB_ID_SIZE]  = {0};
    uint8_t id2[DB_ID_SIZE] = {0};

    size_t  n_users         = 1;
    char   *emails          = tu_generate_email_list_seq(n_users, NULL, NULL);
    if(!emails)
    {
        tu_failf(__FILE__, __LINE__, "email alloc failed");
        tu_teardown_store(&ctx);
        return -1;
    }

    for(size_t i = 0; i < n_users; i++)
    {
        memset(id, 0, sizeof id);
        memset(id2, 0, sizeof id2);

        const char *email_in = emails + i * EMAIL_MAX_LEN;

        /* add new user */
        EXPECT_EQ_RC(db_add_user(email_in, id), 0);

        /* look it up by id */
        char email_out[EMAIL_MAX_LEN] = {0};
        EXPECT_EQ_RC(db_user_find_by_id(id, email_out), 0);
        EXPECT_TRUE(strncmp(email_out, email_in, EMAIL_MAX_LEN) == 0);

        /* duplicate add ⇒ -EEXIST and same id */
        EXPECT_EQ_RC(db_add_user(email_in, id2), -EEXIST);
        EXPECT_EQ_ID(id, id2);
    }

    free(emails);
    tu_teardown_store(&ctx);
    return 0;
}

int t_roles_and_listing(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }
    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0};
    char    ea[EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x");
    char eb[EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "b@x");
    db_add_user(ea, A);
    db_add_user(eb, B);

    /* A viewer, B publisher */
    EXPECT_EQ_RC(db_user_set_role_viewer(A), 0);
    EXPECT_EQ_RC(db_user_set_role_publisher(B), 0);

    /* Count viewers/publishers */
    size_t  n = 32;
    uint8_t buf[16 * 32];
    EXPECT_EQ_RC(db_user_list_viewers(buf, &n), 0);
    EXPECT_EQ_SIZE(n, (size_t)1);

    n = 32;
    EXPECT_EQ_RC(db_user_list_publishers(buf, &n), 0);
    EXPECT_EQ_SIZE(n, (size_t)1);

    tu_teardown_store(&ctx);
    return 0;
}

int t_upload_requires_publisher(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }
    uint8_t A[DB_ID_SIZE] = {0};
    char    ea[EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x");
    int fd = tu_make_blob("./.tmp_blob.dcm", "shared-seed-001");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};

    db_add_user(ea, A);

    /* A new user cannot upload*/
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), -EPERM);

    /* Viewer cannot upload */
    EXPECT_EQ_RC(db_user_set_role_viewer(A), 0);
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), -EPERM);

    /* Publisher can upload */
    EXPECT_EQ_RC(db_user_set_role_publisher(A), 0);
    lseek(fd, 0, SEEK_SET);
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), 0);

    close(fd);
    unlink("./.tmp_blob.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

int t_dedup_same_sha(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }
    uint8_t A[DB_ID_SIZE] = {0};
    char    ea[EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x");
    db_add_user(ea, A);
    db_user_set_role_publisher(A);

    int fd = tu_make_blob("./.tmp_blob2.dcm", "same-content");
    EXPECT_TRUE(fd >= 0);
    uint8_t D1[DB_ID_SIZE] = {0}, D2[DB_ID_SIZE] = {0};
    int     rc = db_upload_data_from_fd(A, fd, "application/dicom", D1);
    EXPECT_EQ_RC(rc, 0);

    lseek(fd, 0, SEEK_SET);
    rc = db_upload_data_from_fd(A, fd, "application/dicom", D2);
    EXPECT_EQ_RC(rc, -EEXIST);
    EXPECT_EQ_ID(D1, D2);

    close(fd);
    unlink("./.tmp_blob2.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

int t_share_by_email(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }
    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0};
    char    e_alice[EMAIL_MAX_LEN];
    snprintf(e_alice, sizeof e_alice, "%s", "alice@x");
    char e_bob[EMAIL_MAX_LEN];
    snprintf(e_bob, sizeof e_bob, "%s", "bob@x");
    db_add_user(e_alice, A);
    db_add_user(e_bob, B);
    db_user_set_role_publisher(A);

    int fd = tu_make_blob("./.tmp_blob3.dcm", "to-share");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), 0);

    /* share D with bob via email */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, e_bob), 0);

    close(fd);
    unlink("./.tmp_blob3.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

int t_resolve_path_points_to_object(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }
    uint8_t A[DB_ID_SIZE] = {0};
    char    ea[EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x");
    db_add_user(ea, A);
    db_user_set_role_publisher(A);

    int fd = tu_make_blob("./.tmp_blob4.dcm", "path-check");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), 0);

    char path[PATH_MAX];
    EXPECT_EQ_RC(db_resolve_data_path(D, path, sizeof path), 0);
    struct stat st;
    EXPECT_TRUE(stat(path, &st) == 0 && S_ISREG(st.st_mode));

    close(fd);
    unlink("./.tmp_blob4.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* A cannot share B's data until B gives A any presence (O/S/U) on that data. */
int t_share_requires_relationship(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    /* Users */
    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0}, Cc[DB_ID_SIZE] = {0};
    char    ea[EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x");
    char eb[EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "b@x");
    char ec[EMAIL_MAX_LEN];
    snprintf(ec, sizeof ec, "%s", "c@x");
    db_add_user(ea, A);
    db_add_user(eb, B);
    db_add_user(ec, Cc);
    db_user_set_role_publisher(B); /* B uploads */
    db_user_set_role_viewer(A);    /* A is only viewer globally (ok) */
    db_user_set_role_viewer(Cc);

    /* B uploads a blob */
    int fd = tu_make_blob("./.tmp_blob5.dcm", "owned-by-B");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_upload_data_from_fd(B, fd, "application/dicom", D), 0);

    /* A tries to share B's data to C -> should fail (-EPERM, no presence on D) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, ec), -EPERM);

    /* B shares to A first (gives A 'U' presence) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(B, D, ea), 0);

    /* Now A can re-share to C (U is enough in this presence-only policy) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, ec), 0);

    close(fd);
    unlink("./.tmp_blob5.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Non-owner cannot delete; owner delete cascades ACLs and blob. */
int t_owner_delete_cascade(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0}, U1[DB_ID_SIZE] = {0}, U2[DB_ID_SIZE] = {0};
    char    eo[EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "owner@x");
    char eu1[EMAIL_MAX_LEN];
    snprintf(eu1, sizeof eu1, "%s", "u1@x");
    char eu2[EMAIL_MAX_LEN];
    snprintf(eu2, sizeof eu2, "%s", "u2@x");
    db_add_user(eo, O);
    db_add_user(eu1, U1);
    db_add_user(eu2, U2);
    db_user_set_role_publisher(O);

    int fd = tu_make_blob("./.tmp_blob6.dcm", "delete-me");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_upload_data_from_fd(O, fd, "application/dicom", D), 0);

    /* share to both */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu1), 0);
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu2), 0);

    /* Non-owner cannot delete */
    EXPECT_EQ_RC(db_owner_delete_data(U1, D), -EPERM);

    /* path exists before delete */
    char path[PATH_MAX];
    EXPECT_EQ_RC(db_resolve_data_path(D, path, sizeof path), 0);
    struct stat st;
    EXPECT_TRUE(stat(path, &st) == 0 && S_ISREG(st.st_mode));

    /* Owner delete */
    EXPECT_EQ_RC(db_owner_delete_data(O, D), 0);

    /* path resolution now fails; blob gone */
    EXPECT_EQ_RC(db_resolve_data_path(D, path, sizeof path), -ENOENT);
    EXPECT_TRUE(stat(path, &st) != 0 && errno == ENOENT);

    /* any further share attempts fail due to missing data */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu1), -ENOENT);

    close(fd);
    unlink("./.tmp_blob6.dcm"); /* safe even if already unlinked */
    tu_teardown_store(&ctx);
    return 0;
}

/* Dedup branch grants owner presence to the new uploader too (multi-owner). */
int t_dedup_multi_owner_can_delete(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0};
    char    ea[EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x");
    char eb[EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "b@x");
    db_add_user(ea, A);
    db_user_set_role_publisher(A);
    db_add_user(eb, B);
    db_user_set_role_publisher(B);

    int fd = tu_make_blob("./.tmp_blob7.dcm", "same-bits");
    EXPECT_TRUE(fd >= 0);
    uint8_t D1[DB_ID_SIZE] = {0}, D2[DB_ID_SIZE] = {0};

    /* First upload by A creates the object */
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D1), 0);

    /* Second upload by B dedups, returns same id and grants B 'O' presence */
    lseek(fd, 0, SEEK_SET);
    int rc = db_upload_data_from_fd(B, fd, "application/dicom", D2);
    EXPECT_EQ_RC(rc, -EEXIST);
    EXPECT_EQ_ID(D1, D2);

    /* B, as another owner, can delete */
    EXPECT_EQ_RC(db_owner_delete_data(B, D1), 0);

    /* Resolution fails after delete */
    char path[PATH_MAX];
    EXPECT_EQ_RC(db_resolve_data_path(D1, path, sizeof path), -ENOENT);

    close(fd);
    unlink("./.tmp_blob7.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* ------------------------------ Registry ---------------------------------- */
static const TU_Test TESTS[] = {
    {"open_creates_layout", t_open_creates_layout},
    {"add_user_and_find", t_add_user_and_find},
    {"roles_and_listing", t_roles_and_listing},
    {"upload_requires_publisher", t_upload_requires_publisher},
    {"share_requires_relationship", t_share_requires_relationship},
    {"dedup_same_sha", t_dedup_same_sha},
    {"share_by_email", t_share_by_email},
    {"resolve_path_points_to_object", t_resolve_path_points_to_object},
    {"owner_delete_cascade", t_owner_delete_cascade},
    {"dedup_multi_owner_can_delete", t_dedup_multi_owner_can_delete},
};

static const size_t NTESTS = sizeof(TESTS) / sizeof(TESTS[0]);

int                 run_test_func(int argc, char **argv)
{
    return tu_run_suite("func", TESTS, NTESTS, argc, argv);
}