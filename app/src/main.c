// test_main.c
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "auth_interface.h"

#define CHECK(x)                              \
    do                                        \
    {                                         \
        int __rc = (x);                       \
        if(__rc)                              \
        {                                     \
            printf(#x " failed: %d\n", __rc); \
            exit(1);                          \
        }                                     \
    } while(0)

// /* tiny helper to write a small blob to a temp file */
// static int make_blob(const char* path, const char* tag)
// {
//     int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0640);
//     if(fd < 0) return -1;
//     const unsigned char head[] = {'D', 'I', 'C', 'M', 0x00, 0x01};
//     if(write(fd, head, sizeof head) != (ssize_t)sizeof head)
//     {
//         close(fd);
//         return -1;
//     }
//     if(write(fd, tag, strlen(tag)) != (ssize_t)strlen(tag))
//     {
//         close(fd);
//         return -1;
//     }
//     lseek(fd, 0, SEEK_SET);
//     return fd;
// }

// static void print_id(const char* label, uint8_t id[])
// {
//     printf("%s: ", label);
//     for(int i = 0; i < ; i++)
//         printf("%02x", id[i]);
//     puts("");
// }

// static void db_print_users(void)
// {
//     size_t  num_users = 32;
//     uint8_t users_of_interest[16 * num_users];
//     db_user_list_all(users_of_interest, &num_users);
//     for(size_t i = 0; i < num_users; i++)
//     {
//         print_id("User:", users_of_interest + i * );
//     }
// }

// static void db_print_publishers(void)
// {
//     size_t  num_users = 32;
//     uint8_t users_of_interest[16 * num_users];
//     db_user_list_publishers(users_of_interest, &num_users);
//     for(size_t i = 0; i < num_users; i++)
//     {
//         print_id("Publisher:", users_of_interest + i * );
//     }
// }

// static void db_print_viewers(void)
// {
//     size_t  num_users = 32;
//     uint8_t users_of_interest[16 * num_users];
//     db_user_list_viewers(users_of_interest, &num_users);
//     for(size_t i = 0; i < num_users; i++)
//     {
//         print_id("Viewer:", users_of_interest + i * );
//     }
// }

int main(void)
{
    puts("=== DB smoke tests ===");

    // /* create three blobs on disk */
    // int fd_shared = make_blob("./blob_shared.dcm", "shared-seed-001");
    // int fd_A      = make_blob("./blob_A.dcm", "unique-A");
    // int fd_B      = make_blob("./blob_B.dcm", "unique-B");

    /* 2) seed users */
    char alice[] = "alice@example.com";
    char luana[] = "luana@example.com";
    char roman[] = "roman@example.com";
    // char luca[]   = "luca@example.com";
    // char franco[] = "franco@example.com";
    // uint8_t UA[] = {0}, UB[] = {0},
    //         UC[] = {0}, UD[] = {0},
    //         UE[] = {0}, UF[] = {0},
    //         UG[] = {0}, UH[] = {0};

    CHECK(auth_register_new(alice));
    CHECK(auth_register_new(roman));
    CHECK(auth_register_new(luana));

    // CHECK(auth_register_new(alice, UA));
    // CHECK(db_add_user(bob, UB));
    // CHECK(db_add_user(carol, UC));
    // CHECK(db_add_user(anton, UD));
    // CHECK(db_add_user(luana, UE));
    // CHECK(db_add_user(roman, UF));
    // CHECK(db_add_user(luca, UG));
    // CHECK(db_add_user(franco, UH));

    // print_id("Alice", UA);
    // print_id("Bob  ", UB);
    // print_id("Carol", UC);
    // print_id("Anton", UD);
    // print_id("Luana", UE);
    // print_id("Roman", UF);
    // print_id("Luca", UG);
    // print_id("Franco", UH);

    // db_print_publishers();
    // db_print_viewers();
    // printf("\n\n");
    // // fd_shared >= 0 && fd_A >= 0 && fd_B >= 0;

    // /* upload under Alice */
    // puts("=== Alice uploads ===");
    // uint8_t D_shared[] = {0}, D_A[] = {0},
    //         D_B[] = {0};
    // db_data_add_from_fd(UA, fd_shared, "application/dicom", D_shared);
    // // db_data_add_from_fd(UA, fd_A,      "application/dicom", D_A);
    // // db_data_add_from_fd(UA, fd_B,      "application/dicom", D_B);

    // print_id("D_shared", D_shared);
    // print_id("D_A     ", D_A);
    // print_id("D_B     ", D_B);

    // puts("=== Alice and Bob set viewer ===");
    // db_user_set_role_viewer(UA);
    // db_data_add_from_fd(UA, fd_shared, "application/dicom", D_shared);
    // puts("=== Print D_shared id ===");
    // print_id("D_shared", D_shared);
    // db_print_viewers();
    // db_print_publishers();
    // printf("\n\n");

    // puts("=== Alice set publisher ===");
    // db_user_set_role_publisher(UA);
    // db_data_add_from_fd(UA, fd_shared, "application/dicom", D_shared);
    // print_id("D_shared", D_shared);
    // // print_id("D_A     ", D_A);
    // // print_id("D_B     ", D_B);
    // db_print_users();
    // db_print_publishers();
    // db_print_viewers();
    // printf("\n\n");

    // // db_user_set_role_publisher(UB);
    // // db_data_add_from_fd(UB, fd_shared, "application/dicom", D_shared);
    // // db_data_add_from_fd(UB, fd_B,      "application/dicom", D_B);

    // db_print_publishers();
    // db_print_viewers();
    // printf("\n\n");

    // puts("=== Carol set viewer ===");
    // db_user_set_role_viewer(UC);
    // db_print_publishers();
    // db_print_viewers();
    // printf("\n\n");

    // db_user_set_role_publisher(UC);
    // db_print_publishers();
    // db_print_viewers();
    // printf("\n\n");

    // /* 11) cleanup */
    // close(fd_shared);
    // close(fd_A);
    // close(fd_B);
    // db_close();
    // puts("All tests passed.");
    return 0;
}
