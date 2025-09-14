#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "db_store.h"
#include "fsutil.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ------------------------------- Colors ---------------------------------- */
#define C_RESET  "\x1b[0m"
#define C_RED    "\x1b[31m"
#define C_GRN    "\x1b[32m"
#define C_YEL    "\x1b[33m"
#define C_CYN    "\x1b[36m"

/* ------------------------------ Timing ----------------------------------- */
static double now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec*1000.0 + (double)ts.tv_nsec/1e6;
}

/* ------------------------------ Helpers ---------------------------------- */
static const char* errname(int rc){
    if (rc >= 0) return "OK";
    switch (-rc){
        case EINVAL: return "EINVAL";
        case ENOENT: return "ENOENT";
        case EEXIST: return "EEXIST";
        case EPERM:  return "EPERM";
        case EIO:    return "EIO";
        default:     return "ERR";
    }
}

static int rm_rf(const char* path){
    struct stat st;
    if (lstat(path, &st) != 0) return (errno==ENOENT)?0:-1;
    if (S_ISDIR(st.st_mode)){
        DIR* d = opendir(path); if (!d) return -1;
        struct dirent* e;
        while ((e=readdir(d))){
            if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
            char p[PATH_MAX];
            snprintf(p, sizeof p, "%s/%s", path, e->d_name);
            if (rm_rf(p) != 0){ closedir(d); return -1; }
        }
        closedir(d);
        return rmdir(path);
    } else {
        return unlink(path);
    }
}

static bool is_dir(const char* p){
    struct stat st; return stat(p,&st)==0 && S_ISDIR(st.st_mode);
}

static int make_blob(const char* path, const char* tag){
    int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0640);
    if (fd < 0) return -1;
    const unsigned char head[] = { 'D','I','C','M', 0x00, 0x01 };
    if (write(fd, head, sizeof head) != (ssize_t)sizeof head) { close(fd); return -1; }
    if (write(fd, tag, strlen(tag))  != (ssize_t)strlen(tag))  { close(fd); return -1; }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static char *generate_email_list_seq(size_t n, const char *prefix, const char *domain)
{
    if (!domain) domain = "@example.com";
    if (!prefix) prefix = "user_";

    char *buf = calloc(n, EMAIL_MAX_LEN);
    if (!buf) return NULL;

    const size_t dom_len = strlen(domain);
    for (size_t i = 0; i < n; ++i)
    {
        char *slot = buf + i * EMAIL_MAX_LEN;
        // Worst-case length guard
        // local part = prefix + digits of i
        char tmp[64];
        int digits = snprintf(tmp, sizeof tmp, "%zu", i);
        size_t need = strlen(prefix) + (size_t)digits + dom_len + 1; // +1 for '\0'
        if (need > EMAIL_MAX_LEN) { free(buf); return NULL; }

        // Write
        int w = snprintf(slot, EMAIL_MAX_LEN, "%s%zu%s", prefix, i, domain);
        if (w < 0 || (size_t)w >= EMAIL_MAX_LEN) { free(buf); return NULL; }
    }
    return buf; // caller frees
}


static void hex16(char out[33], const uint8_t id[DB_ID_SIZE]){
    static const char* hexd = "0123456789abcdef";
    for (int i=0;i<16;i++){ out[i*2]=hexd[id[i]>>4]; out[i*2+1]=hexd[id[i]&0xF]; }
    out[32]='\0';
}

/* ------------------------------ Assertions -------------------------------- */
static int g_failures = 0;

static void failf(const char* file, int line, const char* fmt, ...){
    g_failures++;
    fprintf(stderr, C_RED "  ✘ %s:%d: " C_RESET, file, line);
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}

#define EXPECT_TRUE(cond) do{ if(!(cond)) failf(__FILE__,__LINE__,"EXPECT_TRUE(%s) failed", #cond); }while(0)
#define EXPECT_EQ_INT(a,b) do{ long _A=(long)(a), _B=(long)(b); if(_A!=_B) failf(__FILE__,__LINE__,"EXPECT_EQ_INT(%s=%ld, %s=%ld)", #a,_A,#b,_B); }while(0)
#define EXPECT_EQ_SIZE(a,b) do{ size_t _A=(size_t)(a), _B=(size_t)(b); if(_A!=_B) failf(__FILE__,__LINE__,"EXPECT_EQ_SIZE(%s=%zu, %s=%zu)", #a,_A,#b,_B); }while(0)
#define EXPECT_EQ_RC(rc,exp) do{ int _r=(rc), _e=(exp); if(_r!=_e) failf(__FILE__,__LINE__,"rc=%d(%s) expected %d(%s)", _r, errname(_r), _e, errname(_e)); }while(0)
#define EXPECT_EQ_ID(a,b) do{ if(memcmp((a),(b),DB_ID_SIZE)!=0){ char _ha[33],_hb[33]; hex16(_ha,(a)); hex16(_hb,(b)); failf(__FILE__,__LINE__,"IDs differ: %s != %s", _ha,_hb);} }while(0)

/* ------------------------------- Fixture ---------------------------------- */
typedef struct {
    char root[PATH_MAX];
} Ctx;

static int setup_store(Ctx* c){
    snprintf(c->root, sizeof c->root, "./.testdb_%ld_XXXXXX", (long)getpid());
    if (!mkdtemp(c->root)) return -1;
    if (db_open(c->root, 1ULL<<28) != 0) return -1; /* 256 MiB is plenty for tests */
    return 0;
}

static void teardown_store(Ctx* c){
    db_close();
    rm_rf(c->root);
}

/* ------------------------------ Test Cases -------------------------------- */

static int t_open_creates_layout(void){
    Ctx ctx; if (setup_store(&ctx)!=0) { failf(__FILE__,__LINE__,"setup failed"); return -1; }
    char pmeta[PATH_MAX + 64]; snprintf(pmeta,sizeof pmeta, "%s/meta", ctx.root);
    char psha [PATH_MAX + 64]; snprintf(psha, sizeof psha,  "%s/objects/sha256", ctx.root);
    EXPECT_TRUE(is_dir(ctx.root));
    EXPECT_TRUE(is_dir(pmeta));
    EXPECT_TRUE(is_dir(psha));
    teardown_store(&ctx); return 0;
}

static int t_add_user_and_find(void)
{
    Ctx ctx = {0};
    if (setup_store(&ctx) != 0) {
        failf(__FILE__, __LINE__, "setup failed");
        return -1;
    }

    uint8_t id[DB_ID_SIZE]  = {0};
    uint8_t id2[DB_ID_SIZE] = {0};

    size_t n_users = 1;
    char *emails = generate_email_list_seq(n_users, NULL, NULL);
    if (!emails) {
        failf(__FILE__, __LINE__, "email alloc failed");
        teardown_store(&ctx);
        return -1;
    }

    for (size_t i = 0; i < n_users; i++) {
        memset(id,  0, sizeof id);
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
    teardown_store(&ctx);
    return 0;
}


static int t_roles_and_listing(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }
    uint8_t A[DB_ID_SIZE]={0}, B[DB_ID_SIZE]={0};
    char ea[EMAIL_MAX_LEN]; snprintf(ea,sizeof ea,"%s","a@x");
    char eb[EMAIL_MAX_LEN]; snprintf(eb,sizeof eb,"%s","b@x");
    db_add_user(ea, A);
    db_add_user(eb, B);

    /* A viewer, B publisher */
    EXPECT_EQ_RC(db_user_set_role_viewer(A), 0);
    EXPECT_EQ_RC(db_user_set_role_publisher(B), 0);

    /* Count viewers/publishers */
    size_t n=32; uint8_t buf[16*32];
    EXPECT_EQ_RC(db_user_list_viewers(buf,&n), 0);
    EXPECT_EQ_SIZE(n, (size_t)1);

    n=32;
    EXPECT_EQ_RC(db_user_list_publishers(buf,&n), 0);
    EXPECT_EQ_SIZE(n, (size_t)1);

    teardown_store(&ctx); return 0;
}

static int t_upload_requires_publisher(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }
    uint8_t A[DB_ID_SIZE]={0};
    char ea[EMAIL_MAX_LEN]; snprintf(ea,sizeof ea,"%s","a@x");
    int fd = make_blob("./.tmp_blob.dcm","shared-seed-001"); EXPECT_TRUE(fd>=0);
    uint8_t D[DB_ID_SIZE]={0};

    db_add_user(ea, A);

    /* A new user cannot upload*/
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), -EPERM);

    /* Viewer cannot upload */
    EXPECT_EQ_RC(db_user_set_role_viewer(A), 0);
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), -EPERM);

    /* Publisher can upload */
    EXPECT_EQ_RC(db_user_set_role_publisher(A), 0);
    lseek(fd,0,SEEK_SET);
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), 0);

    close(fd); unlink("./.tmp_blob.dcm");
    teardown_store(&ctx); return 0;
}

static int t_dedup_same_sha(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }
    uint8_t A[DB_ID_SIZE]={0};
    char ea[EMAIL_MAX_LEN]; snprintf(ea,sizeof ea,"%s","a@x");
    db_add_user(ea, A);
    db_user_set_role_publisher(A);

    int fd = make_blob("./.tmp_blob2.dcm","same-content"); EXPECT_TRUE(fd>=0);
    uint8_t D1[DB_ID_SIZE]={0}, D2[DB_ID_SIZE]={0};
    int rc = db_upload_data_from_fd(A, fd, "application/dicom", D1);
    EXPECT_EQ_RC(rc, 0);

    lseek(fd,0,SEEK_SET);
    rc = db_upload_data_from_fd(A, fd, "application/dicom", D2);
    EXPECT_EQ_RC(rc, -EEXIST);
    EXPECT_EQ_ID(D1,D2);

    close(fd); unlink("./.tmp_blob2.dcm");
    teardown_store(&ctx); return 0;
}

static int t_share_by_email(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }
    uint8_t A[DB_ID_SIZE]={0}, B[DB_ID_SIZE]={0};
    char e_alice[EMAIL_MAX_LEN]; snprintf(e_alice,sizeof e_alice,"%s","alice@x");
    char e_bob  [EMAIL_MAX_LEN]; snprintf(e_bob,  sizeof e_bob,  "%s","bob@x");
    db_add_user(e_alice, A);
    db_add_user(e_bob,   B);
    db_user_set_role_publisher(A);

    int fd = make_blob("./.tmp_blob3.dcm","to-share"); EXPECT_TRUE(fd>=0);
    uint8_t D[DB_ID_SIZE]={0};
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), 0);

    /* share D with bob via email */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, e_bob), 0);

    close(fd); unlink("./.tmp_blob3.dcm");
    teardown_store(&ctx); return 0;
}

static int t_resolve_path_points_to_object(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }
    uint8_t A[DB_ID_SIZE]={0};
    char ea[EMAIL_MAX_LEN]; snprintf(ea,sizeof ea,"%s","a@x");
    db_add_user(ea, A); db_user_set_role_publisher(A);

    int fd = make_blob("./.tmp_blob4.dcm","path-check"); EXPECT_TRUE(fd>=0);
    uint8_t D[DB_ID_SIZE]={0};
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D), 0);

    char path[PATH_MAX];
    EXPECT_EQ_RC(db_resolve_data_path(D, path, sizeof path), 0);
    struct stat st; EXPECT_TRUE(stat(path,&st)==0 && S_ISREG(st.st_mode));

    close(fd); unlink("./.tmp_blob4.dcm");
    teardown_store(&ctx); return 0;
}

/* A cannot share B's data until B gives A any presence (O/S/U) on that data. */
static int t_share_requires_relationship(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }

    /* Users */
    uint8_t A[DB_ID_SIZE]={0}, B[DB_ID_SIZE]={0}, Cc[DB_ID_SIZE]={0};
    char ea[EMAIL_MAX_LEN]; snprintf(ea,sizeof ea,"%s","a@x");
    char eb[EMAIL_MAX_LEN]; snprintf(eb,sizeof eb,"%s","b@x");
    char ec[EMAIL_MAX_LEN]; snprintf(ec,sizeof ec,"%s","c@x");
    db_add_user(ea, A);
    db_add_user(eb, B);
    db_add_user(ec, Cc);
    db_user_set_role_publisher(B);   /* B uploads */
    db_user_set_role_viewer(A);      /* A is only viewer globally (ok) */
    db_user_set_role_viewer(Cc);

    /* B uploads a blob */
    int fd = make_blob("./.tmp_blob5.dcm","owned-by-B"); EXPECT_TRUE(fd>=0);
    uint8_t D[DB_ID_SIZE]={0};
    EXPECT_EQ_RC(db_upload_data_from_fd(B, fd, "application/dicom", D), 0);

    /* A tries to share B's data to C -> should fail (-EPERM, no presence on D) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, ec), -EPERM);

    /* B shares to A first (gives A 'U' presence) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(B, D, ea), 0);

    /* Now A can re-share to C (U is enough in this presence-only policy) */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(A, D, ec), 0);

    close(fd); unlink("./.tmp_blob5.dcm");
    teardown_store(&ctx); return 0;
}

/* Non-owner cannot delete; owner delete cascades ACLs and blob. */
static int t_owner_delete_cascade(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }

    uint8_t O[DB_ID_SIZE]={0}, U1[DB_ID_SIZE]={0}, U2[DB_ID_SIZE]={0};
    char eo[EMAIL_MAX_LEN];  snprintf(eo, sizeof eo,  "%s","owner@x");
    char eu1[EMAIL_MAX_LEN]; snprintf(eu1,sizeof eu1, "%s","u1@x");
    char eu2[EMAIL_MAX_LEN]; snprintf(eu2,sizeof eu2, "%s","u2@x");
    db_add_user(eo, O);
    db_add_user(eu1,U1);
    db_add_user(eu2,U2);
    db_user_set_role_publisher(O);

    int fd = make_blob("./.tmp_blob6.dcm","delete-me"); EXPECT_TRUE(fd>=0);
    uint8_t D[DB_ID_SIZE]={0};
    EXPECT_EQ_RC(db_upload_data_from_fd(O, fd, "application/dicom", D), 0);

    /* share to both */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu1), 0);
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu2), 0);

    /* Non-owner cannot delete */
    EXPECT_EQ_RC(db_owner_delete_data(U1, D), -EPERM);

    /* path exists before delete */
    char path[PATH_MAX];
    EXPECT_EQ_RC(db_resolve_data_path(D, path, sizeof path), 0);
    struct stat st; EXPECT_TRUE(stat(path,&st)==0 && S_ISREG(st.st_mode));

    /* Owner delete */
    EXPECT_EQ_RC(db_owner_delete_data(O, D), 0);

    /* path resolution now fails; blob gone */
    EXPECT_EQ_RC(db_resolve_data_path(D, path, sizeof path), -ENOENT);
    EXPECT_TRUE(stat(path,&st)!=0 && errno==ENOENT);

    /* any further share attempts fail due to missing data */
    EXPECT_EQ_RC(db_user_share_data_with_user_email(O, D, eu1), -ENOENT);

    close(fd); unlink("./.tmp_blob6.dcm"); /* safe even if already unlinked */
    teardown_store(&ctx); return 0;
}

/* Dedup branch grants owner presence to the new uploader too (multi-owner). */
static int t_dedup_multi_owner_can_delete(void){
    Ctx ctx; if (setup_store(&ctx)!=0){ failf(__FILE__,__LINE__,"setup failed"); return -1; }

    uint8_t A[DB_ID_SIZE]={0}, B[DB_ID_SIZE]={0};
    char ea[EMAIL_MAX_LEN]; snprintf(ea,sizeof ea,"%s","a@x");
    char eb[EMAIL_MAX_LEN]; snprintf(eb,sizeof eb,"%s","b@x");
    db_add_user(ea, A); db_user_set_role_publisher(A);
    db_add_user(eb, B); db_user_set_role_publisher(B);

    int fd = make_blob("./.tmp_blob7.dcm","same-bits" ); EXPECT_TRUE(fd>=0);
    uint8_t D1[DB_ID_SIZE]={0}, D2[DB_ID_SIZE]={0};

    /* First upload by A creates the object */
    EXPECT_EQ_RC(db_upload_data_from_fd(A, fd, "application/dicom", D1), 0);

    /* Second upload by B dedups, returns same id and grants B 'O' presence */
    lseek(fd,0,SEEK_SET);
    int rc = db_upload_data_from_fd(B, fd, "application/dicom", D2);
    EXPECT_EQ_RC(rc, -EEXIST);
    EXPECT_EQ_ID(D1,D2);

    /* B, as another owner, can delete */
    EXPECT_EQ_RC(db_owner_delete_data(B, D1), 0);

    /* Resolution fails after delete */
    char path[PATH_MAX];
    EXPECT_EQ_RC(db_resolve_data_path(D1, path, sizeof path), -ENOENT);

    close(fd); unlink("./.tmp_blob7.dcm");
    teardown_store(&ctx); return 0;
}

/* ------------------------------ Registry ---------------------------------- */
typedef int (*test_fn)(void);
typedef struct { const char* name; test_fn fn; } Test;
static Test TESTS[] = {
    {"open_creates_layout",           t_open_creates_layout},
    {"add_user_and_find",             t_add_user_and_find},
    {"roles_and_listing",             t_roles_and_listing},
    {"upload_requires_publisher",     t_upload_requires_publisher},
    {"share_requires_relationship",   t_share_requires_relationship},
    {"dedup_same_sha",                t_dedup_same_sha},
    {"share_by_email",                t_share_by_email},
    {"resolve_path_points_to_object", t_resolve_path_points_to_object},
    {"owner_delete_cascade",          t_owner_delete_cascade},
    {"dedup_multi_owner_can_delete",  t_dedup_multi_owner_can_delete},
};
static const size_t NTESTS = sizeof(TESTS)/sizeof(TESTS[0]);

/* ---------------------------- CLI + Runner -------------------------------- */
static void usage(const char* prog){
    fprintf(stderr,
        "Usage: %s [--list] [--filter SUBSTR] [--stop] [--repeat N]\n"
        "  --list           list test names and exit\n"
        "  --filter SUBSTR  run only tests whose name contains SUBSTR\n"
        "  --stop           stop on first failure\n"
        "  --repeat N       repeat the whole suite N times\n", prog);
}

int main(int argc, char** argv){
    const char* filter = NULL;
    bool list=false, stop=false; int repeat=1;

    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i],"--list")) list=true;
        else if (!strcmp(argv[i],"--filter") && i+1<argc) filter=argv[++i];
        else if (!strcmp(argv[i],"--stop")) stop=true;
        else if (!strcmp(argv[i],"--repeat") && i+1<argc) repeat=atoi(argv[++i]);
        else { usage(argv[0]); return 2; }
    }

    if (list){
        for (size_t i=0;i<NTESTS;i++) puts(TESTS[i].name);
        return 0;
    }

    int grand_fail = 0, grand_run = 0;
    for (int r=0;r<repeat;r++){
        if (repeat>1) printf(C_CYN "=== Run %d/%d ===" C_RESET "\n", r+1, repeat);
        for (size_t i=0;i<NTESTS;i++){
            if (filter && !strstr(TESTS[i].name, filter)) continue;
            g_failures = 0;
            double t0 = now_ms();
            printf("• %s ", TESTS[i].name); fflush(stdout);
            int rc = TESTS[i].fn();
            double dt = now_ms()-t0;
            grand_run++;
            if (rc==0 && g_failures==0){
                printf(C_GRN "OK" C_RESET " (%.1f ms)\n", dt);
            } else {
                printf(C_RED "FAIL" C_RESET " (%.1f ms)\n", dt);
                grand_fail++;
                if (stop) break;
            }
        }
        if (stop && grand_fail) break;
    }

    if (grand_fail==0){
        printf(C_GRN "\nAll %d test(s) passed.\n" C_RESET, grand_run);
        return 0;
    } else {
        printf(C_RED "\n%d/%d test(s) failed.\n" C_RESET, grand_fail, grand_run);
        return 1;
    }
}
