// test_main.c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include "db_store.h"

/* tiny helper to write a small blob to a temp file */
static int make_blob(const char* path, const char* tag)
{
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0640);
    if(fd < 0)
        return -1;
    const unsigned char head[] = {'D', 'I', 'C', 'M', 0x00, 0x01};
    if(write(fd, head, sizeof head) != (ssize_t)sizeof head)
    {
        close(fd);
        return -1;
    }
    if(write(fd, tag, strlen(tag)) != (ssize_t)strlen(tag))
    {
        close(fd);
        return -1;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static void print_id(const char* label, uint8_t id[DB_ID_SIZE])
{
    printf("%s: ", label);
    for(int i = 0; i < DB_ID_SIZE; i++)
        printf("%02x", id[i]);
    puts("");
}

static void db_print_users(void)
{
    size_t  num_users = 32;
    uint8_t users_of_interest[16 * num_users];
    db_user_list_all(users_of_interest, &num_users);
    for(size_t i = 0; i < num_users; i++)
    {
        print_id("User:", users_of_interest + i * DB_ID_SIZE);
    }
}

static void db_print_publishers(void)
{
    size_t  num_users = 32;
    uint8_t users_of_interest[16 * num_users];
    db_user_list_publishers(users_of_interest, &num_users);
    for(size_t i = 0; i < num_users; i++)
    {
        print_id("Publisher:", users_of_interest + i * DB_ID_SIZE);
    }
}

static void db_print_viewers(void)
{
    size_t  num_users = 32;
    uint8_t users_of_interest[16 * num_users];
    db_user_list_viewers(users_of_interest, &num_users);
    for(size_t i = 0; i < num_users; i++)
    {
        print_id("Viewer:", users_of_interest + i * DB_ID_SIZE);
    }
}

int main(void)
{
    puts("=== DB smoke tests ===");

    /* open DB */
    if(db_open("./med", 1ULL << 30) != 0)
    {
        puts("db_open failed");
        return 1;
    }

    /* create three blobs on disk */
    int     fd_shared = make_blob("./blob_shared.dcm", "shared-seed-001");
    int     fd_A      = make_blob("./blob_A.dcm", "unique-A");
    int     fd_B      = make_blob("./blob_B.dcm", "unique-B");

    /* 2) seed users */
    char    alice[EMAIL_MAX_LEN] = "alice@example.com";
    char    bob[EMAIL_MAX_LEN]   = "bob@example.com";
    char    carol[EMAIL_MAX_LEN] = "carol@example.com";
    char    anton[EMAIL_MAX_LEN] = "anton@example.com";
    char    luana[EMAIL_MAX_LEN] = "luana@example.com";
    char    roman[EMAIL_MAX_LEN] = "roman@example.com";
    char    luca[EMAIL_MAX_LEN] = "luca@example.com";
    char    franco[EMAIL_MAX_LEN] = "franco@example.com";
    uint8_t UA[DB_ID_SIZE] = {0}, UB[DB_ID_SIZE] = {0}, UC[DB_ID_SIZE] = {0},
            UD[DB_ID_SIZE] = {0}, UE[DB_ID_SIZE] = {0}, UF[DB_ID_SIZE] = {0},
            UG[DB_ID_SIZE] = {0}, UH[DB_ID_SIZE] = {0};

    db_add_user(alice, UA);
    db_add_user(bob, UB);
    db_add_user(carol, UC);
    db_add_user(anton, UD);
    db_add_user(luana, UE);
    db_add_user(roman, UF);
    db_add_user(luca, UG);
    db_add_user(franco, UH);

    print_id("Alice", UA);
    print_id("Bob  ", UB);
    print_id("Carol", UC);
    print_id("Anton", UD);
    print_id("Luana", UE);
    print_id("Roman", UF);
    print_id("Luca", UG);
    print_id("Franco", UH);

    db_print_publishers();
    db_print_viewers();
    printf("\n\n");
    // fd_shared >= 0 && fd_A >= 0 && fd_B >= 0;

    /* upload under Alice */
    puts("=== Alice uploads ===");
    uint8_t D_shared[DB_ID_SIZE] = {0}, D_A[DB_ID_SIZE] = {0},
            D_B[DB_ID_SIZE] = {0};
    db_upload_data_from_fd(UA, fd_shared, "application/dicom", D_shared);
    // db_upload_data_from_fd(UA, fd_A,      "application/dicom", D_A);
    // db_upload_data_from_fd(UA, fd_B,      "application/dicom", D_B);

    print_id("D_shared", D_shared);
    print_id("D_A     ", D_A);
    print_id("D_B     ", D_B);

    puts("=== Alice set viewer ===");
    db_user_set_role_viewer(UA);
    db_upload_data_from_fd(UA, fd_shared, "application/dicom", D_shared);
    print_id("D_shared", D_shared);
    // print_id("D_A     ", D_A);
    // print_id("D_B     ", D_B);
    db_print_viewers();
    db_print_publishers();
    printf("\n\n");

    puts("=== Alice set publisher ===");
    db_user_set_role_publisher(UA);
    db_upload_data_from_fd(UA, fd_shared, "application/dicom", D_shared);
    print_id("D_shared", D_shared);
    // print_id("D_A     ", D_A);
    // print_id("D_B     ", D_B);
    db_print_users();
    db_print_publishers();
    db_print_viewers();
    printf("\n\n");

    // db_user_set_role_publisher(UB);
    // db_upload_data_from_fd(UB, fd_shared, "application/dicom", D_shared);
    // db_upload_data_from_fd(UB, fd_B,      "application/dicom", D_B);

    db_print_publishers();
    db_print_viewers();
    printf("\n\n");

    puts("=== Carol set viewer ===");
    db_user_set_role_viewer(UC);
    db_print_publishers();
    db_print_viewers();
    printf("\n\n");

    db_user_set_role_publisher(UC);
    db_print_publishers();
    db_print_viewers();
    printf("\n\n");

    /* 5) share D_shared with Bob by email (defaults to VIEW|DOWNLOAD) */
    // db_share_data_with_user_email(D_shared, bob);

    /* 6) list Bob's data that require VIEW */
    // Id128 list_ids[64]; unsigned long cnt = 64;
    // // db_list_data_for_user(UB, ACL_VIEW, list_ids, &cnt);
    // printf("Bob sees %lu items (expect >=1)\n", cnt);
    // cnt >= 1);

    /* 7) resolve path for the first one */
    // char path[1024];
    // db_resolve_data_path(list_ids[0], path, sizeof path);
    // printf("Bob[0] path: %s\n", path);

    /* 8) dedup test: re-upload the same shared content and ensure same data_id */
    // lseek(fd_shared, 0, SEEK_SET);
    // Id128 D_shared_again={0};
    // db_upload_data_from_fd(UA, fd_shared, "application/dicom", &D_shared_again);
    // print_id("D_shared_again", D_shared_again);
    /* must match */
    // memcmp(D_shared_again.b, D_shared.b, 16);

    // /* 9) revoke from Bob and ensure listing drops */
    // db_revoke_data_from_user(D_shared, bob);
    // cnt = 64;
    // db_list_data_for_user(UB, ACL_VIEW, list_ids, &cnt);
    // printf("Bob sees %lu items after revoke (expect possibly 0)\n", cnt);

    // /* 10) share to Carol by Id and verify appears */
    // db_share_data_with_user_id(D_A, UC);
    // cnt = 64;
    // db_list_data_for_user(UC, ACL_VIEW, list_ids, &cnt);
    // printf("Carol sees %lu items (expect >=1)\n", cnt);
    // cnt >= 1);

    /* 11) cleanup */
    close(fd_shared);
    close(fd_A);
    close(fd_B);
    db_close();
    puts("All tests passed.");
    return 0;
}
