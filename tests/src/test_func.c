/* src/tests/test_functionality.c */
#include <sys/stat.h>

#include "db_interface.h"
#include "test_utils.h"

static int is_zero16(const uint8_t x[16])
{
    uint64_t a = 0, b = 0;
    memcpy(&a, x, 8);
    memcpy(&b, x + 8, 8);
    return (a | b) == 0;
}

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

    size_t n_users = 1;
    char  *emails  = tu_generate_email_list_seq(n_users, NULL, NULL);
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

        char *email_in = emails + i * DB_EMAIL_MAX_LEN;

        /* add new user */
        EXPECT_EQ_RC(db_add_user(email_in, id), 0);
        EXPECT_TRUE(!is_zero16(id));

        /* look it up by id */
        char email_out[DB_EMAIL_MAX_LEN] = {0};
        EXPECT_EQ_RC(db_user_find_by_id(id, email_out), 0);
        EXPECT_TRUE(strncmp(email_out, email_in, DB_EMAIL_MAX_LEN) == 0);

        /* duplicate add ⇒ -EEXIST and same id */
        EXPECT_EQ_RC(db_add_user(email_in, id2), -EEXIST);
        // EXPECT_EQ_ID(id, id2);
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
    uint8_t ID_A[DB_ID_SIZE] = {0}, ID_B[DB_ID_SIZE] = {0};
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "abc@xbc.com");
    char eb[DB_EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "bbc@xbc.com");
    db_add_user(ea, ID_A);
    db_add_user(eb, ID_B);

    /* A viewer, B publisher */
    EXPECT_EQ_RC(db_user_set_role_viewer(ID_A), 0);
    EXPECT_EQ_RC(db_user_set_role_publisher(ID_B), 0);

    /* Count viewers/publishers */
    size_t  n = 32;
    uint8_t buf[16 * 32];
    EXPECT_EQ_RC(db_user_list_viewers(buf, &n), 0);
    EXPECT_EQ_SIZE(n, (size_t)1);
    EXPECT_EQ_ID(buf, ID_A);

    n = 32;
    EXPECT_EQ_RC(db_user_list_publishers(buf, &n), 0);
    EXPECT_EQ_SIZE(n, (size_t)1);
    EXPECT_EQ_ID(buf, ID_B);

    EXPECT_EQ_RC(db_user_set_role_publisher(ID_A), 0);
    EXPECT_EQ_RC(db_user_list_viewers(buf, &n), 0);
    EXPECT_EQ_SIZE(n, (size_t)0);
    EXPECT_EQ_RC(db_user_list_publishers(buf, &n), 0);
    EXPECT_EQ_SIZE(n, (size_t)2);

    /* nothing happens for repeated operation */
    EXPECT_EQ_RC(db_user_set_role_publisher(ID_A), 0);

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
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x.com");
    int fd = tu_make_blob("./.tmp_blob.dcm", "shared-seed-001");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};

    EXPECT_EQ_RC(db_add_user(ea, A), 0);

    /* A new user cannot upload*/
    EXPECT_EQ_RC(db_data_add_from_fd(A, fd, "application/dicom", D), -EPERM);
    EXPECT_TRUE(is_zero16(D));

    /* Viewer cannot upload */
    EXPECT_EQ_RC(db_user_set_role_viewer(A), 0);
    EXPECT_EQ_RC(db_data_add_from_fd(A, fd, "application/dicom", D), -EPERM);
    EXPECT_TRUE(is_zero16(D));

    /* Publisher can upload */
    EXPECT_EQ_RC(db_user_set_role_publisher(A), 0);
    lseek(fd, 0, SEEK_SET);
    EXPECT_EQ_RC(db_data_add_from_fd(A, fd, "application/dicom", D), 0);
    EXPECT_TRUE(!is_zero16(D));

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

    int fd = tu_make_blob("./.tmp_blob2.dcm", "same-content");
    EXPECT_TRUE(fd >= 0);
    lseek(fd, 0, SEEK_SET);
    uint8_t D1[DB_ID_SIZE] = {0}, D2[DB_ID_SIZE] = {0};

    uint8_t A[DB_ID_SIZE] = {0};
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x.com");

    EXPECT_EQ_RC(db_add_user(ea, A), 0);
    EXPECT_EQ_RC(db_user_set_role_publisher(A), 0);
    int rc = db_data_add_from_fd(A, fd, "application/dicom", D1);
    EXPECT_EQ_RC(rc, 0);

    lseek(fd, 0, SEEK_SET);
    rc = db_data_add_from_fd(A, fd, "application/dicom", D2);
    EXPECT_EQ_RC(rc, -EEXIST);
    EXPECT_TRUE(is_zero16(D2));

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
    char    e_alice[DB_EMAIL_MAX_LEN];
    snprintf(e_alice, sizeof e_alice, "%s", "alice@x.com");
    char e_bob[DB_EMAIL_MAX_LEN];
    snprintf(e_bob, sizeof e_bob, "%s", "bob@x.com");
    db_add_user(e_alice, A);
    db_add_user(e_bob, B);
    db_user_set_role_publisher(A);

    int fd = tu_make_blob("./.tmp_blob3.dcm", "to-share");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(A, fd, "application/dicom", D), 0);

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
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x.com");
    db_add_user(ea, A);
    db_user_set_role_publisher(A);

    int fd = tu_make_blob("./.tmp_blob4.dcm", "path-check");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(A, fd, "application/dicom", D), 0);

    char path[PATH_MAX];
    EXPECT_EQ_RC(db_data_get_path(D, path, sizeof path), 0);
    struct stat st;
    EXPECT_TRUE(stat(path, &st) == 0 && S_ISREG(st.st_mode));

    close(fd);
    unlink("./.tmp_blob4.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Only owners can share. Viewer has no re-share rights. */ int
t_share_requires_relationship(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0}, Cc[DB_ID_SIZE] = {0};
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x.com");
    char eb[DB_EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "b@x.com");
    char ec[DB_EMAIL_MAX_LEN];
    snprintf(ec, sizeof ec, "%s", "c@x.com");
    db_add_user(ea, A);
    db_add_user(eb, B);
    db_add_user(ec, Cc);
    db_user_set_role_publisher(B);
    db_user_set_role_viewer(A);
    db_user_set_role_viewer(Cc);

    int fd = tu_make_blob("./.tmp_blob5.dcm", "owned-by-B");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(B, fd, "application/dicom", D), 0);

    /* A cannot share (not owner) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, ec), -EPERM);

    /* B shares to A (VIEW) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(B, D, ea), 0);

    /* A still cannot re-share (policy: no re-share) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, ec), -EPERM);

    /* B shares to C */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(B, D, ec), 0);

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
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "owner@x.com");
    char eu1[DB_EMAIL_MAX_LEN];
    snprintf(eu1, sizeof eu1, "%s", "u1@x.com");
    char eu2[DB_EMAIL_MAX_LEN];
    snprintf(eu2, sizeof eu2, "%s", "u2@x.com");
    db_add_user(eo, O);
    db_add_user(eu1, U1);
    db_add_user(eu2, U2);
    db_user_set_role_publisher(O);

    int fd = tu_make_blob("./.tmp_blob6.dcm", "delete-me");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "application/dicom", D), 0);

    /* share to both */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu1), 0);
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu2), 0);

    /* Non-owner cannot delete */
    EXPECT_EQ_RC(db_data_delete(U1, D), -ENOENT);

    /* path exists before delete */
    char        path[PATH_MAX];
    struct stat st;
    EXPECT_EQ_RC(db_data_get_path(D, path, sizeof path), 0);
    EXPECT_TRUE(stat(path, &st) == 0 && S_ISREG(st.st_mode));

    /* Owner delete (hard): nukes ACLs+meta+sha and removes blob */
    EXPECT_EQ_RC(db_data_delete(O, D), 0);

    /* path resolution now fails; blob gone */
    EXPECT_EQ_RC(db_data_get_path(D, path, sizeof path), -ENOENT);
    EXPECT_TRUE(stat(path, &st) != 0 && errno == ENOENT);

    /* any further share attempts fail due to missing data */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu1), -ENOENT);

    close(fd);
    unlink("./.tmp_blob6.dcm"); /* safe even if already unlinked */
    tu_teardown_store(&ctx);
    return 0;
}

/* No dedup: second upload with same SHA must fail with -EEXIST; only the
 * original owner can delete. (Covers “different uploader second upload”.) */
int t_no_dedup_second_upload_fails_and_owner_deletes(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    int fd = tu_make_blob("./.tmp_blob7.dcm", "same-bits");
    EXPECT_TRUE(fd >= 0);

    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0};
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "a@x.com");
    char eb[DB_EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "b@x.com");
    db_add_user(ea, A);
    db_user_set_role_publisher(A);
    db_add_user(eb, B);
    db_user_set_role_publisher(B);

    uint8_t D1[DB_ID_SIZE] = {0}, D2[DB_ID_SIZE] = {0};

    /* First upload creates object */
    EXPECT_EQ_RC(db_data_add_from_fd(A, fd, "application/dicom", D1), 0);

    /* Second upload by B with same bits: must fail (-EEXIST), out id untouched/zero */
    lseek(fd, 0, SEEK_SET);
    int rc = db_data_add_from_fd(B, fd, "application/dicom", D2);
    EXPECT_EQ_RC(rc, -EEXIST);
    EXPECT_TRUE(is_zero16(D2));

    /* B cannot delete (not an owner) */
    EXPECT_EQ_RC(db_data_delete(B, D1), -ENOENT);

    /* Resolution still works after B's failed delete */
    char path[PATH_MAX];
    EXPECT_EQ_RC(db_data_get_path(D1, path, sizeof path), 0);

    /* A can delete */
    EXPECT_EQ_RC(db_data_delete(A, D1), 0);

    /* Resolution fails after delete */
    EXPECT_EQ_RC(db_data_get_path(D1, path, sizeof path), -ENOENT);

    close(fd);
    unlink("./.tmp_blob7.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Owner sharing to same email twice: idempotent. */
int t_share_idempotent(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0}, U[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "own@x.com");
    char eu[DB_EMAIL_MAX_LEN];
    snprintf(eu, sizeof eu, "%s", "u@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);
    db_add_user(eu, U);
    db_user_set_role_viewer(U);

    int fd = tu_make_blob("./.tmp_blob_idem.dcm", "idem");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D), 0);

    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu), 0);
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu),
                 0); /* idempotent */

    close(fd);
    unlink("./.tmp_blob_idem.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Self-share is a no-op (0). */
int t_share_self_noop(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "self@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);

    int fd = tu_make_blob("./.tmp_blob_self.dcm", "self");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D), 0);

    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eo), 0);

    close(fd);
    unlink("./.tmp_blob_self.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Sharing to non-existent email → -ENOENT. */
int t_share_to_missing_email(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    char    nob[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "o@x.com");
    snprintf(nob, sizeof nob, "%s", "nobody@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);

    int fd = tu_make_blob("./.tmp_blob_missing.dcm", "x");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D), 0);

    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, nob), -ENOENT);

    close(fd);
    unlink("./.tmp_blob_missing.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Viewer cannot share. */
int t_share_denied_when_not_owner(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0}, V[DB_ID_SIZE] = {0}, Z[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "o@x.com");
    char ev[DB_EMAIL_MAX_LEN];
    snprintf(ev, sizeof ev, "%s", "v@x.com");
    char ez[DB_EMAIL_MAX_LEN];
    snprintf(ez, sizeof ez, "%s", "z@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);
    db_add_user(ev, V);
    db_user_set_role_viewer(V);
    db_add_user(ez, Z);
    db_user_set_role_viewer(Z);

    int fd = tu_make_blob("./.tmp_blob_noshare.dcm", "x");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D), 0);

    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, ev),
                 0); /* grant view */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(V, D, ez),
                 -EPERM); /* viewer cannot re-share */

    close(fd);
    unlink("./.tmp_blob_noshare.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Double delete: first OK, second nonzero; path gone after first. */
int t_double_delete_semantics(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "o2@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);

    int fd = tu_make_blob("./.tmp_blob_dd.dcm", "x");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D), 0);

    char path[PATH_MAX];
    EXPECT_EQ_RC(db_data_get_path(D, path, sizeof path), 0);

    EXPECT_EQ_RC(db_data_delete(O, D), 0);
    EXPECT_EQ_RC(db_data_get_path(D, path, sizeof path), -ENOENT);
    EXPECT_EQ_RC(db_data_delete(O, D), -ENOENT);

    close(fd);
    unlink("./.tmp_blob_dd.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* No dedup: second upload with same SHA fails for same uploader too. */
int t_same_user_second_upload_fails(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t P[DB_ID_SIZE] = {0};
    char    ep[DB_EMAIL_MAX_LEN];
    snprintf(ep, sizeof ep, "%s", "p@x.com");
    db_add_user(ep, P);
    db_user_set_role_publisher(P);

    int fd = tu_make_blob("./.tmp_blob_sameuser.dcm", "abc");
    EXPECT_TRUE(fd >= 0);

    uint8_t D1[DB_ID_SIZE] = {0}, D2[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(P, fd, "x/bin", D1), 0);
    lseek(fd, 0, SEEK_SET);
    int rc = db_data_add_from_fd(P, fd, "x/bin", D2);
    EXPECT_EQ_RC(rc, -EEXIST);
    EXPECT_TRUE(is_zero16(D2));

    close(fd);
    unlink("./.tmp_blob_sameuser.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* After hard delete, re-upload same bytes creates a fresh object (new id). */
int t_reupload_after_delete_new_id(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "o3@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);

    int fd = tu_make_blob("./.tmp_blob_reup.dcm", "zz");
    EXPECT_TRUE(fd >= 0);

    uint8_t D1[DB_ID_SIZE] = {0}, D2[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D1), 0);
    EXPECT_EQ_RC(db_data_delete(O, D1), 0);

    lseek(fd, 0, SEEK_SET);
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D2), 0);
    EXPECT_TRUE(memcmp(D1, D2, DB_ID_SIZE) != 0);

    close(fd);
    unlink("./.tmp_blob_reup.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Share after delete fails (-ENOENT). */
int t_cannot_share_after_delete(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0}, U[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "ow@x.com");
    char eu[DB_EMAIL_MAX_LEN];
    snprintf(eu, sizeof eu, "%s", "uu@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);
    db_add_user(eu, U);
    db_user_set_role_viewer(U);

    int fd = tu_make_blob("./.tmp_blob_sad.dcm", "sad");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D), 0);
    EXPECT_EQ_RC(db_data_delete(O, D), 0);

    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu), -ENOENT);

    close(fd);
    unlink("./.tmp_blob_sad.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Invalid email (empty) rejected. */
int t_share_invalid_email_empty(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t O[DB_ID_SIZE] = {0};
    char    eo[DB_EMAIL_MAX_LEN];
    snprintf(eo, sizeof eo, "%s", "ow2@x.com");
    db_add_user(eo, O);
    db_user_set_role_publisher(O);

    int fd = tu_make_blob("./.tmp_blob_inv.dcm", "inv");
    EXPECT_TRUE(fd >= 0);
    uint8_t D[DB_ID_SIZE] = {0};
    EXPECT_EQ_RC(db_data_add_from_fd(O, fd, "x/bin", D), 0);

    char empty[DB_EMAIL_MAX_LEN] = {0};
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, empty), -EINVAL);

    close(fd);
    unlink("./.tmp_blob_inv.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* Open with bad args returns -EINVAL. */
int t_open_invalid_args(void)
{
    EXPECT_EQ_RC(db_open(NULL, 0), -EINVAL);
    EXPECT_EQ_RC(db_open(NULL, 123), -EINVAL);
    EXPECT_EQ_RC(db_open("./whatever", 0), -EINVAL);
    return 0;
}

/* db_user_find_by_ids: all-found -> 0; missing -> -ENOENT. */
int t_find_by_ids_mixed(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0};
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "fa@x.com");
    char eb[DB_EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "fb@x.com");
    db_add_user(ea, A);
    db_add_user(eb, B);

    /* All ok */
    uint8_t ids_ok[2 * DB_ID_SIZE];
    memcpy(ids_ok, A, 16);
    memcpy(ids_ok + 16, B, 16);
    EXPECT_EQ_RC(db_user_find_by_ids(2, ids_ok), 0);

    /* One bogus -> -ENOENT */
    uint8_t ids_bad[2 * DB_ID_SIZE];
    memcpy(ids_bad, A, 16);
    memset(ids_bad + 16, 0x77, 16);
    EXPECT_EQ_RC(db_user_find_by_ids(2, ids_bad), -ENOENT);

    tu_teardown_store(&ctx);
    return 0;
}

/* DataMeta fields are sane and match what we wrote. */
int t_data_meta_sane(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t U[DB_ID_SIZE] = {0};
    char    eu[DB_EMAIL_MAX_LEN];
    snprintf(eu, sizeof eu, "%s", "m@x.com");
    db_add_user(eu, U);
    db_user_set_role_publisher(U);

    int fd = tu_make_blob("./.tmp_meta.dcm", "payload-xyz");
    EXPECT_TRUE(fd >= 0);
    uint8_t     D[DB_ID_SIZE] = {0};
    const char *mime          = "application/dicom";
    EXPECT_EQ_RC(db_data_add_from_fd(U, fd, mime, D), 0);

    DataMeta m = {0};
    EXPECT_EQ_RC(db_data_get_meta(D, &m), 0);

    /* Owner matches */
    EXPECT_TRUE(memcmp(m.owner, U, DB_ID_SIZE) == 0);
    /* MIME echoed */
    EXPECT_TRUE(strncmp(m.mime, mime, sizeof m.mime) == 0);
    /* Size equals file size */
    char        path[PATH_MAX];
    struct stat st;
    EXPECT_EQ_RC(db_data_get_path(D, path, sizeof path), 0);
    EXPECT_TRUE(stat(path, &st) == 0 && (uint64_t)st.st_size == m.size);
    /* created_at is non-zero */
    EXPECT_TRUE(m.created_at != 0);

    close(fd);
    unlink("./.tmp_meta.dcm");
    tu_teardown_store(&ctx);
    return 0;
}

/* db_data_get_path invalid args. */
int t_get_path_invalid_args(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t dummy[DB_ID_SIZE] = {0};
    char    path[16];
    EXPECT_EQ_RC(db_data_get_path(NULL, path, sizeof path), -EINVAL);
    EXPECT_EQ_RC(db_data_get_path(dummy, NULL, 128), -EINVAL);
    EXPECT_EQ_RC(db_data_get_path(dummy, path, 0), -EINVAL);

    tu_teardown_store(&ctx);
    return 0;
}

/* env metrics look sensible. */
int t_env_metrics_sane(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }
    uint64_t used = 0, map = 0;
    uint32_t pz = 0;
    EXPECT_EQ_RC(db_env_metrics(&used, &map, &pz), 0);
    EXPECT_TRUE(pz >= 1024); /* LMDB pages >= 1 KB */
    EXPECT_TRUE(map >= used);
    tu_teardown_store(&ctx);
    return 0;
}

/* Role listings reflect changes. */
int t_list_publishers_viewers(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup");
        return -1;
    }

    uint8_t A[DB_ID_SIZE] = {0}, B[DB_ID_SIZE] = {0}, Cc[DB_ID_SIZE] = {0};
    char    ea[DB_EMAIL_MAX_LEN];
    snprintf(ea, sizeof ea, "%s", "ra@x.com");
    char eb[DB_EMAIL_MAX_LEN];
    snprintf(eb, sizeof eb, "%s", "rb@x.com");
    char ec[DB_EMAIL_MAX_LEN];
    snprintf(ec, sizeof ec, "%s", "rc@x.com");
    db_add_user(ea, A);
    db_add_user(eb, B);
    db_add_user(ec, Cc);

    db_user_set_role_publisher(A);
    db_user_set_role_viewer(B);
    db_user_set_role_viewer(Cc);

    uint8_t ids[32 * 16];
    size_t  n = 32;

    size_t np = n;
    EXPECT_EQ_RC(db_user_list_publishers(ids, &np), 0);
    EXPECT_TRUE(np >= 1);
    /* ensure A is in publishers list (simple membership scan) */
    bool foundA = false;
    for(size_t i = 0; i < np; i++)
        if(memcmp(ids + i * 16, A, 16) == 0)
        {
            foundA = true;
            break;
        }
    EXPECT_TRUE(foundA);

    size_t nv = n;
    EXPECT_EQ_RC(db_user_list_viewers(ids, &nv), 0);
    /* B and Cc should be viewers */
    bool foundB = false, foundC = false;
    for(size_t i = 0; i < nv; i++)
    {
        if(memcmp(ids + i * 16, B, 16) == 0) foundB = true;
        if(memcmp(ids + i * 16, Cc, 16) == 0) foundC = true;
    }
    EXPECT_TRUE(foundB && foundC);

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
    {"share_by_email", t_share_by_email},
    {"resolve_path_points_to_object", t_resolve_path_points_to_object},
    {"owner_delete_cascade", t_owner_delete_cascade},

    /* no-dedup semantics */
    {"no_dedup_second_upload_fails_and_owner_deletes",
     t_no_dedup_second_upload_fails_and_owner_deletes},
    {"same_user_second_upload_fails", t_same_user_second_upload_fails},
    {"reupload_after_delete_new_id", t_reupload_after_delete_new_id},

    /* sharing edges */
    {"share_idempotent", t_share_idempotent},
    {"share_self_noop", t_share_self_noop},
    {"share_to_missing_email", t_share_to_missing_email},
    {"share_denied_when_not_owner", t_share_denied_when_not_owner},

    /* life-cycle edges */
    {"double_delete_semantics", t_double_delete_semantics},
    {"cannot_share_after_delete", t_cannot_share_after_delete},
    {"share_invalid_email_empty", t_share_invalid_email_empty},

    /* interface-only extras */
    {"open_invalid_args", t_open_invalid_args},
    {"find_by_ids_mixed", t_find_by_ids_mixed},
    {"data_meta_sane", t_data_meta_sane},
    {"get_path_invalid_args", t_get_path_invalid_args},
    {"env_metrics_sane", t_env_metrics_sane},
    {"list_publishers_viewers", t_list_publishers_viewers},
};

static const size_t NTESTS = sizeof(TESTS) / sizeof(TESTS[0]);

int run_test_func(int argc, char **argv)
{
    return tu_run_suite("func", TESTS, NTESTS, argc, argv);
}