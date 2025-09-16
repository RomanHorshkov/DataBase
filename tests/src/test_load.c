/* tests/src/test_load.c */
#include "test_utils.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <lmdb.h>
#include <inttypes.h>   // for PRIu64
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

    const size_t N      = env_sz("STRESS_USERS", 1000);   /* total users to insert */
    const size_t SAMPLE = env_sz("STRESS_SAMPLE", 100);    /* lookups after insert */

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
        if (db_add_user(emails + i*EMAIL_MAX_LEN, ids + i*16) != 0)
        {
            tu_failf(__FILE__,__LINE__,"add_user id=%s at i=%zu", ids + i*16, i);
            free(ids);
            free(emails);
            tu_teardown_store(&ctx);
            return -1;
        }
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

static int tl_db_measure_size(void){
    Ctx ctx; if (tu_setup_store(&ctx)!=0){ tu_failf(__FILE__,__LINE__,"setup failed"); return -1; }

    const size_t N      = env_sz("STRESS_USERS", 100000);  /* total inserts */
    const size_t STEP   = env_sz("STRESS_STEP",   5000);  /* report every STEP */

    char* emails = tu_generate_email_list_seq(N, NULL, NULL);
    if (!emails){ tu_teardown_store(&ctx); tu_failf(__FILE__,__LINE__,"email alloc failed"); return -1; }

    uint8_t* ids = (uint8_t*)calloc(N, 16);
    if (!ids){ free(emails); tu_teardown_store(&ctx); tu_failf(__FILE__,__LINE__,"id alloc failed"); return -1; }

    char meta_dir[PATH_MAX];
    {
        const char suffix[] = "/meta";
        size_t rl = strnlen(ctx.root, sizeof meta_dir);
        if (rl + sizeof(suffix) > sizeof meta_dir){   // includes '\0'
            free(ids); free(emails); tu_teardown_store(&ctx);
            tu_failf(__FILE__,__LINE__,"path too long");
            return -1;
        }
        memcpy(meta_dir, ctx.root, rl);
        memcpy(meta_dir + rl, suffix, sizeof(suffix));  // copies '\0'
    }

    for (size_t i = 0; i < N; ++i)
    {
        if (db_add_user(emails + i*EMAIL_MAX_LEN, ids + i*16) != 0)
        {
            tu_failf(__FILE__,__LINE__,"add_user id=%s at i=%zu", ids + i*16, i);
            free(ids);
            free(emails);
            tu_teardown_store(&ctx);
            return -1;
        }

        if (((i+1) % STEP) == 0 || (i+1) == N)
        {
            char email_check[128] = {0};
            if (db_user_find_by_id(ids + i*16, email_check) != 0)
            {
                tu_failf(__FILE__,__LINE__,"lookup id=%d at i=%zu, email: %s", ids + i*16, i, emails + i*EMAIL_MAX_LEN);
                free(ids); free(emails); tu_teardown_store(&ctx);
                return -1;
            }
            
            uint64_t du_total = tu_dir_size_bytes(ctx.root);
            uint64_t du_meta  = tu_dir_size_bytes(meta_dir);

            uint64_t lmdb_used=0, lmdb_map=0; uint32_t psize=0;
            // (void)lmdb_metrics(meta_dir, &lmdb_used, &lmdb_map, &psize);
            (void)db_env_metrics(&lmdb_used, &lmdb_map, &psize);

            fprintf(stderr,
                C_CYN "%6zu/%zu users" C_RESET " usr %d "
                "total=%" PRIu64 " KB  meta=%" PRIu64 " KB  "
                "lmdb_used=%" PRIu64 " KB  lmdb_map=%" PRIu64 " KB  psize=%u\n",
                i+1, N,
                emails[i*EMAIL_MAX_LEN],
                du_total/1024, du_meta/1024,
                lmdb_used/1024, lmdb_map/1024, psize);
            fflush(stderr);
        }
    }

    free(ids); free(emails); tu_teardown_store(&ctx);
    return 0;
}

/* ------------------------------ Registry + runner ------------------------- */
static int tl_add_many_users_sample_lookup_declared(void)
{
    return tl_add_many_users_sample_lookup();
}

static int tl_db_measure_size_declared(void)
{
    return tl_db_measure_size();
}


static const TU_Test LOAD_TESTS[] = {
    {"add_many_users_sample_lookup", tl_add_many_users_sample_lookup_declared},
    {"db_measure_size",              tl_db_measure_size_declared},
};
    
static const size_t NLOAD = sizeof(LOAD_TESTS)/sizeof(LOAD_TESTS[0]);

int run_test_load(int argc, char** argv)
{
    return tu_run_suite("load", LOAD_TESTS, NLOAD, argc, argv);
}
