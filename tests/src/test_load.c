/* tests/src/test_load.c */
#include "test_utils.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <lmdb.h>
#include <inttypes.h>  // for PRIu64
#include "db_interface.h"

/* Env knobs (with safe defaults) */
static size_t env_sz(const char* key, size_t def)
{
    const char* s = getenv(key);
    if(!s || !*s)
        return def;
    size_t v = strtoull(s, NULL, 10);
    return v > 0 ? v : def;
}

static int tl_add_many_users_sample_lookup(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    const size_t N = env_sz("STRESS_USERS", 5000); /* total users to insert */
    const size_t SAMPLE =
        env_sz("STRESS_SAMPLE", 2000); /* lookups after insert */

    char* emails = tu_generate_email_list_seq(N, "u_", "@x.com");
    if(!emails)
    {
        tu_teardown_store(&ctx);
        tu_failf(__FILE__, __LINE__, "email alloc failed");
        return -1;
    }
    char* subset = tu_generate_email_list_sub_seq(emails, N, SAMPLE);
    if(!subset)
    {
        free(emails);
        tu_teardown_store(&ctx);
        tu_failf(__FILE__, __LINE__, "subset alloc failed");
        return -1;
    }

    uint8_t* ids = calloc(N, 16);
    if(!ids)
    {
        free(emails);
        tu_teardown_store(&ctx);
        tu_failf(__FILE__, __LINE__, "id alloc failed");
        return -1;
    }

    double t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;
    t0 = tu_now_ms();
    if(db_add_users(N, emails))
    {
        tu_failf(__FILE__, __LINE__, "add_users failed");
        free(ids);
        free(emails);
        tu_teardown_store(&ctx);
        return -1;
    }

    t1 = tu_now_ms();

    /* collect all user IDs we just inserted */
    size_t cap = N;
    EXPECT_EQ_RC(db_user_list_all(ids, &cap), 0);
    EXPECT_EQ_INT(cap, N);

    t2 = tu_now_ms();

    /* verify they all exist via the batch checker */
    EXPECT_EQ_RC(db_user_find_by_ids(N, ids), 0);

    t3 = tu_now_ms();
    for(size_t i = 0; i < SAMPLE; i++)
    {
        EXPECT_EQ_RC(db_user_find_by_email(subset + i * DB_EMAIL_MAX_LEN, NULL),
                     0);
    }
    t4 = tu_now_ms();

    fprintf(stderr,
            C_YEL "batch insert %zu users: %.2f ms (%.2f µs/user)\n" C_RESET, N,
            t1 - t0, 1000.0 * (t1 - t0) / (double)N);
    fprintf(stderr,
            C_YEL
            "batch list, get ids %zu users: %.2f ms (%.2f µs/user)\n" C_RESET,
            N, t2 - t1, 1000.0 * (t2 - t1) / (double)N);
    fprintf(stderr,
            C_YEL "batch sample %zu id-lookups: %.2f ms (%.2f µs/op)\n" C_RESET,
            SAMPLE, t3 - t2, 1000.0 * (t3 - t2) / (double)SAMPLE);
    fprintf(stderr,
            C_YEL
            "single sample %zu email-lookups: %.2f ms (%.2f µs/op)\n" C_RESET,
            SAMPLE, t4 - t3, 1000.0 * (t4 - t3) / (double)SAMPLE);

    free(ids);
    free(emails);
    tu_teardown_store(&ctx);
    return 0;
}

static int tl_db_measure_size(void)
{
    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    /* knobs */
    const size_t N     = env_sz("STRESS_USERS", 1000000); /* total inserts */
    const size_t CHUNK = env_sz("STRESS_CHUNK", N / 10);  /* batch size */
    const int    DO_DU = getenv("DU") ? atoi(getenv("DU")) : 0; /* dir walk? */

    /* meta dir path */
    char meta_dir[PATH_MAX];
    {
        const char suffix[] = "/meta";
        size_t     rl       = strnlen(ctx.root, sizeof meta_dir);
        if(rl + sizeof(suffix) > sizeof meta_dir)
        {
            tu_failf(__FILE__, __LINE__, "path too long");
            tu_teardown_store(&ctx);
            return -1;
        }
        memcpy(meta_dir, ctx.root, rl);
        memcpy(meta_dir + rl, suffix, sizeof suffix); /* copies '\0' */
    }

    /* batch buffer */
    char* batch = (char*)calloc(CHUNK, DB_EMAIL_MAX_LEN);
    if(!batch)
    {
        tu_failf(__FILE__, __LINE__, "batch alloc failed");
        tu_teardown_store(&ctx);
        return -1;
    }

    uint64_t used = 0, map = 0;
    uint32_t psize = 0;

    size_t inserted  = 0;
    size_t last_step = 0;

    while(inserted < N)
    {
        const size_t want = N - inserted;
        const size_t m    = (want < CHUNK) ? want : CHUNK;

        /* generate emails for this chunk */
        for(size_t j = 0; j < m; ++j)
        {
            char* dst = batch + j * DB_EMAIL_MAX_LEN;
            int   n =
                snprintf(dst, DB_EMAIL_MAX_LEN, "u_%zu@x.com", inserted + j);
            if(n <= 0 || n >= (int)DB_EMAIL_MAX_LEN)
            {
                tu_failf(__FILE__, __LINE__, "email format overflow");
                free(batch);
                tu_teardown_store(&ctx);
                return -1;
            }
        }

        /* bulk insert */
        int rc = db_add_users(m, batch);
        if(rc != 0)
        {
            tu_failf(__FILE__, __LINE__, "db_add_users rc=%d (at %zu)", rc,
                     inserted);
            free(batch);
            tu_teardown_store(&ctx);
            return -1;
        }
        inserted += m;

        /* 10 fixed progress steps: 10%,20%,...,100% */
        size_t step = (inserted * 10) / (N ? N : 1); /* 0..10 */
        if(step > last_step || inserted == N)
        {
            (void)db_env_metrics(&used, &map, &psize);

            if(DO_DU)
            {
                uint64_t du_total = tu_dir_size_bytes(ctx.root);
                uint64_t du_meta  = tu_dir_size_bytes(meta_dir);
                fprintf(stderr,
                        C_CYN "%7zu/%zu users" C_RESET "  lmdb_used=%" PRIu64
                              " KB  map=%" PRIu64
                              " KB  psize=%u"
                              "  total=%" PRIu64 " KB  meta=%" PRIu64 " KB\n",
                        inserted, N, used / 1024, map / 1024, psize,
                        du_total / 1024, du_meta / 1024);
            }
            else
            {
                fprintf(stderr,
                        C_CYN "%7zu/%zu users" C_RESET "  lmdb_used=%" PRIu64
                              " KB  map=%" PRIu64 " KB  psize=%u\n",
                        inserted, N, used / 1024, map / 1024, psize);
            }
            fflush(stderr);
            last_step = step;
        }
    }

    free(batch);
    tu_teardown_store(&ctx);
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
    {"db_measure_size", tl_db_measure_size_declared},
};

static const size_t NLOAD = sizeof(LOAD_TESTS) / sizeof(LOAD_TESTS[0]);

int run_test_load(int argc, char** argv)
{
    return tu_run_suite("load", LOAD_TESTS, NLOAD, argc, argv);
}
