/* tests/src/test_load.c */

#include <lmdb.h>
#include <inttypes.h>  // for PRIu64

#include "test_utils.h"
#include "db_interface.h"

/* helper: create file of `size` with deterministic content */
static int make_blob_sized(const char* path, size_t size, uint32_t seed)
{
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0640);  // <-- O_RDWR
    if(fd < 0)
        return -1;

    unsigned char hdr[16] = {'D', 'I', 'C', 'M', 0x00, 0x01, 0, 0,
                             0,   0,   0,   0,   0,    0,    0, 0};
    hdr[6]                = (unsigned char)((seed >> 24) & 0xFFu);
    hdr[7]                = (unsigned char)((seed >> 16) & 0xFFu);
    hdr[8]                = (unsigned char)((seed >> 8) & 0xFFu);
    hdr[9]                = (unsigned char)((seed >> 0) & 0xFFu);
    if(write(fd, hdr, (size_t)sizeof hdr) != (ssize_t)sizeof hdr)
    {
        close(fd);
        return -1;
    }

    size_t        written = sizeof hdr;
    unsigned char buf[64 * 1024];
    uint32_t      x = seed ? seed : 0xA5A5A5A5u;
    for(size_t i = 0; i < sizeof buf; ++i)
    {
        x      ^= x << 13;
        x      ^= x >> 17;
        x      ^= x << 5;
        buf[i]  = (unsigned char)(x & 0xFFu);
    }
    while(written < size)
    {
        size_t chunk = size - written;
        if(chunk > sizeof buf)
            chunk = sizeof buf;
        if(write(fd, buf, chunk) != (ssize_t)chunk)
        {
            close(fd);
            return -1;
        }
        written += chunk;
    }
    (void)lseek(fd, 0, SEEK_SET);
    return fd;
}

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

/* Upload mixed sizes (100×1KiB, 100×1MiB, 100×10MiB), then share fanout with metrics.
 * Robust to individual upload failures: we count them and only share successful objects. */
static int tl_upload_mixed_sizes_and_share_details(void)
{
    /* knobs (env-tunable) */
    const size_t N1 = env_sz("MIX_N_1KIB", 100);
    const size_t N2 = env_sz("MIX_N_1MIB", 100);
    const size_t N3 = env_sz("MIX_N_10MIB", 100);
    const size_t S1 = env_sz("MIX_SZ_1KIB", 1ULL * 1024ULL);
    const size_t S2 = env_sz("MIX_SZ_1MIB", 1ULL * 1024ULL * 1024ULL);
    const size_t S3 = env_sz("MIX_SZ_10MIB", 10ULL * 1024ULL * 1024ULL);
    const size_t SHARES_PER_OBJ = env_sz("MIX_SHARES_PER_OBJ", 8);
    const size_t NU             = env_sz("MIX_USERS", 8000);

    Ctx ctx;
    if(tu_setup_store(&ctx) != 0)
    {
        tu_failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    /* users pool */
    char* emails = tu_generate_email_list_seq(NU, "mix_", "@x.com");
    if(!emails)
    {
        tu_teardown_store(&ctx);
        tu_failf(__FILE__, __LINE__, "email alloc");
        return -1;
    }
    if(db_add_users(NU, emails) != 0)
    {
        free(emails);
        tu_teardown_store(&ctx);
        tu_failf(__FILE__, __LINE__, "add_users");
        return -1;
    }

    /* owner (idx 0) */
    uint8_t owner[DB_ID_SIZE] = {0};
    if(db_user_find_by_email(emails, owner) != 0)
    {
        free(emails);
        tu_teardown_store(&ctx);
        tu_failf(__FILE__, __LINE__, "owner lookup");
        return -1;
    }
    if(db_user_set_role_publisher(owner) != 0)
    {
        free(emails);
        tu_teardown_store(&ctx);
        tu_failf(__FILE__, __LINE__, "owner->publisher");
        return -1;
    }

    struct Bucket
    {
        const char* name;
        size_t      n;
        size_t      bytes;
        uint8_t*    dids;
        uint8_t*    ok;
    };
    struct Bucket  b1         = {"1KiB", N1, S1, NULL, NULL};
    struct Bucket  b2         = {"1MiB", N2, S2, NULL, NULL};
    struct Bucket  b3         = {"10MiB", N3, S3, NULL, NULL};
    struct Bucket* buckets[3] = {&b1, &b2, &b3};

    double   t_upload_total_ms = 0.0;
    uint64_t bytes_total_ok    = 0;

    for(int bi = 0; bi < 3; ++bi)
    {
        struct Bucket* b = buckets[bi];
        b->dids          = (uint8_t*)calloc(b->n, DB_ID_SIZE);
        b->ok            = (uint8_t*)calloc(b->n, 1);
        if(!b->dids || !b->ok)
        {
            tu_failf(__FILE__, __LINE__, "alloc ids/ok");
            free(emails);
            tu_teardown_store(&ctx);
            return -1;
        }

        size_t ok_cnt = 0, fail_cnt = 0;
        double t0 = tu_now_ms();
        for(size_t i = 0; i < b->n; i++)
        {
            char p[PATH_MAX];
            snprintf(p, sizeof p, "./.tmp_mix_%s_%zu.bin", b->name, i);
            uint32_t seed =
                0x1234u + ((uint32_t)bi << 20) + (uint32_t)i; /* unique */
            int fd = make_blob_sized(p, b->bytes, seed);
            if(fd < 0)
            {
                fail_cnt++;
                continue;
            }
            int rc = db_data_add_from_fd(owner, fd, "application/octet-stream",
                                         b->dids + i * DB_ID_SIZE);
            close(fd);
            unlink(p);
            if(rc == 0)
            {
                b->ok[i] = 1;
                ok_cnt++;
            }
            else
            {
                /* record but do not fail the whole load test */
                fail_cnt++;
                /* optional: first few failures detail */
                if(fail_cnt <= 3)
                {
                    tu_err("upload %s[%zu] rc=%d(%s)\n", b->name, i, rc,
                           tu_errname(rc));
                }
            }
        }
        double t1 = tu_now_ms();
        double dt = t1 - t0;

        /* metrics use only successful uploads */
        double mib_ok = ((double)ok_cnt * (double)b->bytes) / (1024.0 * 1024.0);
        double us_per = ok_cnt ? (1000.0 * dt / (double)ok_cnt) : 0.0;
        double mibs   = (dt > 0.0) ? (mib_ok / (dt / 1000.0)) : 0.0;

        t_upload_total_ms += dt;
        bytes_total_ok    += (uint64_t)ok_cnt * (uint64_t)b->bytes;

        fprintf(stderr,
                C_YEL
                "upload %-6s ok=%5zu/%-5zu  %7.2f MiB: %.1f ms  (%.1f µs/op)  "
                "[%.2f MiB/s]\n" C_RESET,
                b->name, ok_cnt, b->n, mib_ok, dt, us_per, mibs);
    }

    /* overall upload */
    {
        size_t total_ok = 0;
        for(int bi = 0; bi < 3; ++bi)
        {
            struct Bucket* b = buckets[bi];
            for(size_t i = 0; i < b->n; i++)
                total_ok += (size_t)b->ok[i];
        }
        double mib_ok = (double)bytes_total_ok / (1024.0 * 1024.0);
        double us_per =
            total_ok ? (1000.0 * t_upload_total_ms / (double)total_ok) : 0.0;
        double mibs = (t_upload_total_ms > 0.0)
                          ? (mib_ok / (t_upload_total_ms / 1000.0))
                          : 0.0;
        fprintf(stderr,
                C_CYN
                "upload TOTAL  ok=%5zu objs  %7.2f MiB: %.1f ms  (%.1f µs/op)  "
                "[%.2f MiB/s]\n" C_RESET,
                total_ok, mib_ok, t_upload_total_ms, us_per, mibs);
    }

    /* share fan-out only over successful objects */
    srand(123);
    size_t total_share_ops  = 0;
    double t_share_total_ms = 0.0;

    for(int bi = 0; bi < 3; ++bi)
    {
        struct Bucket* b  = buckets[bi];
        size_t         ok = 0, exist = 0, err = 0, ops = 0;

        double t0 = tu_now_ms();
        for(size_t i = 0; i < b->n; i++)
        {
            if(!b->ok[i])
                continue; /* skip failed uploads */
            const uint8_t* did = b->dids + i * DB_ID_SIZE;
            for(size_t s = 0; s < SHARES_PER_OBJ; s++)
            {
                size_t uidx;
                do
                {
                    uidx = (size_t)(rand() % (int)NU);
                } while(uidx == 0); /* avoid owner */
                const char* email = emails + uidx * DB_EMAIL_MAX_LEN;
                int rc = db_user_share_data_with_user_email(owner, did, email);
                if(rc == 0)
                    ok++;
                else if(rc == -EEXIST)
                    exist++;
                else
                {
                    err++;
                }
                ops++;
            }
        }
        double t1 = tu_now_ms();
        double dt = t1 - t0;

        total_share_ops  += ops;
        t_share_total_ms += dt;

        double us_per = ops ? (1000.0 * dt / (double)ops) : 0.0;
        fprintf(stderr,
                C_YEL
                "share  %-6s ops=%zu: %.1f ms  (%.1f µs/op)  OK=%zu  EXIST=%zu "
                " ERR=%zu\n" C_RESET,
                b->name, ops, dt, us_per, ok, exist, err);
    }

    /* overall share */
    {
        double us_per =
            total_share_ops
                ? (1000.0 * t_share_total_ms / (double)total_share_ops)
                : 0.0;
        fprintf(stderr,
                C_CYN "share  TOTAL  ops=%zu: %.1f ms  (%.1f µs/op)\n" C_RESET,
                total_share_ops, t_share_total_ms, us_per);
    }

    /* cleanup */
    free(b1.dids);
    free(b1.ok);
    free(b2.dids);
    free(b2.ok);
    free(b3.dids);
    free(b3.ok);
    free(emails);
    tu_teardown_store(&ctx);
    return 0;
}

static const TU_Test LOAD_TESTS[] = {
    {"add_many_users_sample_lookup", tl_add_many_users_sample_lookup},
    {"db_measure_size", tl_db_measure_size},
    {"upload_mixed_sizes_and_share_details",
     tl_upload_mixed_sizes_and_share_details},
};

static const size_t NLOAD = sizeof(LOAD_TESTS) / sizeof(LOAD_TESTS[0]);

int run_test_load(int argc, char** argv)
{
    return tu_run_suite("load", LOAD_TESTS, NLOAD, argc, argv);
}