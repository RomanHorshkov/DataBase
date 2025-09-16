/* tests/src/test_load.c */
#include "test_utils.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "db_store.h"

/* Env knobs (with safe defaults) */
static size_t env_sz(const char* key, size_t def)
{
    const char* s = getenv(key); if (!s || !*s) return def;
    size_t v = strtoull(s, NULL, 10); return v>0 ? v : def;
}

static int tl_add_many_users_sample_lookup(void)
{
    Ctx ctx; if (tu_setup_store(&ctx)!=0){ tu_failf(__FILE__,__LINE__,"setup failed"); return -1; }

    const size_t N      = env_sz("STRESS_USERS", 10000);   /* total users to insert */
    const size_t SAMPLE = env_sz("STRESS_SAMPLE", 1000);    /* lookups after insert */

    char* emails = tu_generate_email_list_seq(N, "u_", "@x");
    if (!emails){ tu_teardown_store(&ctx); tu_failf(__FILE__,__LINE__,"email alloc failed"); return -1; }
    char* subset = tu_generate_email_list_sub_seq(emails, N, SAMPLE);
    if (!subset){ free(emails); tu_teardown_store(&ctx); tu_failf(__FILE__,__LINE__,"subset alloc failed"); return -1; }


    uint8_t* ids = calloc(N, 16);
    if (!ids){ free(emails); tu_teardown_store(&ctx); tu_failf(__FILE__,__LINE__,"id alloc failed"); return -1; }

    double t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    t0 = tu_now_ms();
    for (size_t i = 0; i < N; i++)
    {
        db_add_user(emails + i*EMAIL_MAX_LEN, ids + i*16);
        // int rc = db_add_user(emails + i*EMAIL_MAX_LEN, ids + i*16);
        // if (rc != 0 && rc != -EEXIST){ tu_failf(__FILE__,__LINE__,"add_user rc=%d", rc); free(ids); free(emails); tu_teardown_store(&ctx); return -1; }
        // if ((i+1)%100 == 0) fprintf(stderr, C_CYN "  inserted %zu\n" C_RESET, i+1);
    }
    t1 = tu_now_ms();

    for (size_t i = 0; i < SAMPLE; i++)
    {
        if (db_user_find_by_id(ids + i*16, NULL) != 0)
        {
            tu_failf(__FILE__,__LINE__,"lookup id=%s at i=%zu", ids + i*16, i);
            free(ids);
            free(emails);
            tu_teardown_store(&ctx);
            return -1;
        }
    }
    t2 = tu_now_ms();
    for (size_t i = 0; i < SAMPLE; i++)
    {
        int rc = db_user_find_by_email(subset + i*EMAIL_MAX_LEN, NULL);
        if (rc != 0){ tu_failf(__FILE__,__LINE__,"lookup rc=%d at i=%zu", rc, i); free(ids); free(emails); tu_teardown_store(&ctx); return -1; }
        // EXPECT_TRUE(strncmp(email_out, emails + i*EMAIL_MAX_LEN, EMAIL_MAX_LEN)==0);
    }
    t3 = tu_now_ms();

    fprintf(stderr, C_YEL "insert %zu users: %.1f ms (%.1f µs/user)\n" C_RESET,
            N, t1-t0, 1000.0*(t1-t0)/(double)N);
    fprintf(stderr, C_YEL "sample %zu id-lookups: %.1f ms (%.1f µs/op)\n" C_RESET,
            SAMPLE, t2-t1, 1000.0*(t2-t1)/(double)SAMPLE);
    fprintf(stderr, C_YEL "sample %zu email-lookups: %.1f ms (%.1f µs/op)\n" C_RESET,
            SAMPLE, t3-t2, 1000.0*(t3-t2)/(double)SAMPLE);

    free(ids); free(emails); tu_teardown_store(&ctx); return 0;
}

/* ------------------------------ Registry + runner ------------------------- */
static int tl_add_many_users_sample_lookup_declared(void)
{
    return tl_add_many_users_sample_lookup();
}

static const TU_Test LOAD_TESTS[] = {
    {"add_many_users_sample_lookup", tl_add_many_users_sample_lookup_declared},
};
    
static const size_t NLOAD = sizeof(LOAD_TESTS)/sizeof(LOAD_TESTS[0]);

int run_test_load(int argc, char** argv)
{
    return tu_run_suite("load", LOAD_TESTS, NLOAD, argc, argv);
}
