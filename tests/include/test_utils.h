#pragma once
#define _XOPEN_SOURCE 700
#include <errno.h>
#include <fcntl.h>   // open, O_CREAT, O_WRONLY, O_TRUNC
#include <limits.h>  // PATH_MAX
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>  // write, lseek, close

#ifndef PATH_MAX
#    define PATH_MAX 4096
#endif

/* ------------------------------- Colors ---------------------------------- */
#define C_RESET "\x1b[0m"
#define C_RED   "\x1b[31m"
#define C_GRN   "\x1b[32m"
#define C_YEL   "\x1b[33m"
#define C_CYN   "\x1b[36m"

/* ------------------------------ Timing ----------------------------------- */
inline double tu_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* ------------------------------ Test API --------------------------------- */
typedef int (*test_fn)(void);
/* Per-suite test entry */
typedef struct
{
    const char* name;
    test_fn     fn;
} TU_Test;

/* Run all tests of a suite. Only supports:
   --list, --repeat N, --help */
int tu_run_suite(const char* suite_name, const TU_Test* tests, size_t ntests,
                 int argc, char** argv);

/* Optional: run one test and print timing on the same line. */
int tu_run_and_time(const char* name, test_fn fn);

/* ------------------------------ Fixture ---------------------------------- */
typedef struct
{
    char root[PATH_MAX];
} Ctx;
int  tu_setup_store(Ctx* c);
void tu_teardown_store(Ctx* c);

/* ----------------------------- Helpers ----------------------------------- */
const char* tu_errname(int rc);
int         tu_rm_rf(const char* path);
bool        tu_is_dir(const char* p);
int         tu_make_blob(const char* path, const char* tag);
char*       tu_generate_email_list_seq(size_t n, const char* prefix,
                                       const char* domain);
char*       tu_generate_email_list_sub_seq(const char* all_emails, size_t M,
                                           size_t N);
void        tu_hex16(char out[33], const uint8_t id[16]);
void        tu_failf(const char* file, int line, const char* fmt, ...);

/* ----------------------------- Output control ---------------------------- */
/* Preferred printing: writes to configurable sinks (default: stdout/stderr). */
void     tu_out(const char* fmt, ...);
void     tu_err(const char* fmt, ...);
void     tu_io_reset(void);                     /* back to stdout/stderr   */
int      tu_io_set(FILE* out, FILE* err);       /* set sinks (no ownership) */
int      tu_io_set_files(const char* out_path,
                         const char* err_path); /* owns files */
uint64_t tu_dir_size_bytes(const char* path);

/* Optional: hard redirect process stdio (affects printf). */
int tu_redirect_stdio_begin(
    const char* out_path, const char* err_path,
    int saved_fd[2]); /* saved_fd[0]=stdout, [1]=stderr */
int tu_redirect_stdio_end(int saved_fd[2]);

/* ----------------------------- Assertions -------------------------------- */
extern int g_failures;
void       tu_failf(const char* file, int line, const char* fmt, ...);

#define EXPECT_TRUE(cond)                                                  \
    do                                                                     \
    {                                                                      \
        if(!(cond))                                                        \
            tu_failf(__FILE__, __LINE__, "EXPECT_TRUE(%s) failed", #cond); \
    } while(0)
#define EXPECT_EQ_INT(a, b)                                                   \
    do                                                                        \
    {                                                                         \
        long _A = (long)(a), _B = (long)(b);                                  \
        if(_A != _B)                                                          \
            tu_failf(__FILE__, __LINE__, "EXPECT_EQ_INT(%s=%ld, %s=%ld)", #a, \
                     _A, #b, _B);                                             \
    } while(0)
#define EXPECT_EQ_SIZE(a, b)                                                   \
    do                                                                         \
    {                                                                          \
        size_t _A = (size_t)(a), _B = (size_t)(b);                             \
        if(_A != _B)                                                           \
            tu_failf(__FILE__, __LINE__, "EXPECT_EQ_SIZE(%s=%zu, %s=%zu)", #a, \
                     _A, #b, _B);                                              \
    } while(0)
#define EXPECT_EQ_RC(rc, exp)                                             \
    do                                                                    \
    {                                                                     \
        int _r = (rc), _e = (exp);                                        \
        if(_r != _e)                                                      \
            tu_failf(__FILE__, __LINE__, "rc=%d(%s) expected %d(%s)", _r, \
                     tu_errname(_r), _e, tu_errname(_e));                 \
    } while(0)
#define EXPECT_EQ_ID(a, b)                                                  \
    do                                                                      \
    {                                                                       \
        if(memcmp((a), (b), 16) != 0)                                       \
        {                                                                   \
            char _ha[33], _hb[33];                                          \
            tu_hex16(_ha, (a));                                             \
            tu_hex16(_hb, (b));                                             \
            tu_failf(__FILE__, __LINE__, "IDs differ: %s != %s", _ha, _hb); \
        }                                                                   \
    } while(0)
