/* tests/src/test_util.c */
#define _XOPEN_SOURCE 700
#include "test_utils.h"

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>

/* app headers */
#include "db_store.h"
#include "fsutil.h"

/* ========================================================================== */
/*                               Global state                                 */
/* ========================================================================== */

int g_failures = 0;

/* Log sinks (default to stdio; we don’t own them). */
static FILE* g_out = NULL;
static FILE* g_err = NULL;

/* If set via tu_io_set_files, we own and must close. */
static FILE* g_out_owned = NULL;
static FILE* g_err_owned = NULL;

/* Helpers to get defaulted sinks */
static inline FILE* SOUT(void){ return g_out ? g_out : stdout; }
static inline FILE* SERR(void){ return g_err ? g_err : stderr; }

/* ========================================================================== */
/*                               Fail formatting                              */
/* ========================================================================== */

void tu_failf(const char* file, int line, const char* fmt, ...){
    g_failures++;
    fprintf(SERR(), C_RED "  ✘ %s:%d: " C_RESET, file, line);
    va_list ap; va_start(ap, fmt); vfprintf(SERR(), fmt, ap); va_end(ap);
    fputc('\n', SERR());
}

const char* tu_errname(int rc){
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

/* ========================================================================== */
/*  Input fixtures                                                            */
/* ========================================================================== */

static int tu_sample_indices(size_t M, size_t N, size_t* out_indices){
    if (!out_indices || N > M) return -1;

    /* partial Fisher–Yates: shuffle only the first N positions */
    size_t* idx = (size_t*)malloc(M * sizeof(size_t));
    if (!idx) return -1;

    for (size_t i = 0; i < M; ++i) idx[i] = i;

    for (size_t i = 0; i < N; ++i){
        /* j in [i..M-1] */
        size_t span = M - i;
        size_t j = i + (size_t)(rand() % (int)span);
        size_t t = idx[i]; idx[i] = idx[j]; idx[j] = t;
        out_indices[i] = idx[i];
    }

    free(idx);
    return 0;
}

static int tu_du_inner(const char* path, uint64_t* total){
    struct stat st;
    if (lstat(path, &st) != 0) return (errno==ENOENT) ? 0 : -1;

    if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
        *total += (uint64_t)st.st_size;
        return 0;
    }
    if (!S_ISDIR(st.st_mode)) return 0;

    DIR* d = opendir(path);
    if (!d) return -1;

    struct dirent* e;
    while ((e = readdir(d))){
        if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
        char p[PATH_MAX];
        snprintf(p, sizeof p, "%s/%s", path, e->d_name);
        if (tu_du_inner(p, total) != 0){ closedir(d); return -1; }
    }
    closedir(d);
    return 0;
}

char* tu_generate_email_list_seq(size_t n, const char* prefix, const char* domain){
    if (!domain) domain = "@example.com";
    if (!prefix) prefix = "user_";
    char *buf = calloc(n, EMAIL_MAX_LEN);
    if (!buf) return NULL;
    const size_t dom_len = strlen(domain);
    for (size_t i = 0; i < n; ++i){
        char *slot = buf + i * EMAIL_MAX_LEN;
        char tmp[64];
        int digits = snprintf(tmp, sizeof tmp, "%zu", i);
        size_t need = strlen(prefix) + (size_t)digits + dom_len + 1;
        if (need > EMAIL_MAX_LEN) { free(buf); return NULL; }
        int w = snprintf(slot, EMAIL_MAX_LEN, "%s%zu%s", prefix, i, domain);
        if (w < 0 || (size_t)w >= EMAIL_MAX_LEN) { free(buf); return NULL; }
    }
    return buf;
}


char* tu_generate_email_list_sub_seq(const char* all_emails, size_t M, size_t N){
    if (!all_emails || N > M) return NULL;

    size_t* picks = (size_t*)malloc(N * sizeof(size_t));
    if (!picks) return NULL;

    if (tu_sample_indices(M, N, picks) != 0){
        free(picks);
        return NULL;
    }

    char* out = (char*)calloc(N, EMAIL_MAX_LEN);
    if (!out){
        free(picks);
        return NULL;
    }

    for (size_t k = 0; k < N; ++k){
        const size_t i = picks[k];
        const char* src = all_emails + i * EMAIL_MAX_LEN;
        char* dst = out + k * EMAIL_MAX_LEN;
        /* copy up to EMAIL_MAX_LEN including terminator if present */
        memcpy(dst, src, EMAIL_MAX_LEN);
        dst[EMAIL_MAX_LEN-1] = '\0'; /* safety */
    }

    free(picks);
    return out; /* caller free() */
}



/* ========================================================================== */
/*                             FS + test fixtures                             */
/* ========================================================================== */

int tu_rm_rf(const char* path){
    struct stat st;
    if (lstat(path, &st) != 0) return (errno==ENOENT)?0:-1;
    if (S_ISDIR(st.st_mode)){
        DIR* d = opendir(path); if (!d) return -1;
        struct dirent* e;
        while ((e=readdir(d))){
            if (!strcmp(e->d_name,".") || !strcmp(e->d_name,"..")) continue;
            char p[PATH_MAX];
            snprintf(p, sizeof p, "%s/%s", path, e->d_name);
            if (tu_rm_rf(p) != 0){ closedir(d); return -1; }
        }
        closedir(d);
        return rmdir(path);
    } else {
        return unlink(path);
    }
}

bool tu_is_dir(const char* p){ struct stat st; return stat(p,&st)==0 && S_ISDIR(st.st_mode); }

int tu_make_blob(const char* path, const char* tag){
    int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, 0640);
    if (fd < 0) return -1;
    const unsigned char head[] = { 'D','I','C','M', 0x00, 0x01 };
    if (write(fd, head, sizeof head) != (ssize_t)sizeof head) { close(fd); return -1; }
    if (write(fd, tag, strlen(tag))  != (ssize_t)strlen(tag))  { close(fd); return -1; }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

void tu_hex16(char out[33], const uint8_t id[16]){
    static const char* hexd = "0123456789abcdef";
    for (int i=0;i<16;i++){ out[i*2]=hexd[id[i]>>4]; out[i*2+1]=hexd[id[i]&0xF]; }
    out[32]='\0';
}

int tu_setup_store(Ctx* c){
    snprintf(c->root, sizeof c->root, "./.testdb_%ld_XXXXXX", (long)getpid());
    if (!mkdtemp(c->root)) return -1;
    const char* ms = getenv("LMDB_MAPSIZE_MB");
    unsigned long long map_mb = ms ? strtoull(ms, NULL, 10) : 256ULL;
    if (db_open(c->root, map_mb<<20) != 0) return -1;
    return 0;
}

void tu_teardown_store(Ctx* c){
    db_close();
    tu_rm_rf(c->root);
}


/* ========================================================================== */
/*                                I/O control                                 */
/* ========================================================================== */

void tu_io_reset(void){
    if (g_out_owned){ fclose(g_out_owned); g_out_owned = NULL; }
    if (g_err_owned){ fclose(g_err_owned); g_err_owned = NULL; }
    g_out = NULL; g_err = NULL; /* back to stdout/stderr */
}

int tu_io_set(FILE* out, FILE* err){
    /* no ownership */
    if (g_out_owned || g_err_owned){ tu_io_reset(); }
    g_out = out; g_err = err;
    return 0;
}

int tu_io_set_files(const char* out_path, const char* err_path){
    tu_io_reset();
    if (out_path){
        g_out_owned = fopen(out_path, "w");
        if (!g_out_owned) return -1;
        g_out = g_out_owned;
    }
    if (err_path){
        g_err_owned = fopen(err_path, "w");
        if (!g_err_owned){ tu_io_reset(); return -1; }
        g_err = g_err_owned;
    }
    return 0;
}

uint64_t tu_dir_size_bytes(const char* path)
{
    uint64_t tot = 0;
    (void)tu_du_inner(path, &tot);
    return tot;
}

void tu_out(const char* fmt, ...){
    va_list ap; va_start(ap, fmt);
    vfprintf(SOUT(), fmt, ap);
    va_end(ap);
    fflush(SOUT());
}

void tu_err(const char* fmt, ...){
    va_list ap; va_start(ap, fmt);
    vfprintf(SERR(), fmt, ap);
    va_end(ap);
    fflush(SERR());
}

/* Hard stdio redirect (affects printf). */
int tu_redirect_stdio_begin(const char* out_path, const char* err_path, int saved_fd[2]){
    saved_fd[0] = -1; saved_fd[1] = -1;
    if (out_path){
        int fd = open(out_path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (fd < 0) return -1;
        int dupold = dup(STDOUT_FILENO);
        if (dupold < 0){ close(fd); return -1; }
        if (dup2(fd, STDOUT_FILENO) < 0){ close(fd); close(dupold); return -1; }
        close(fd);
        saved_fd[0] = dupold;
    }
    if (err_path){
        int fd = open(err_path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
        if (fd < 0) return -1;
        int dupold = dup(STDERR_FILENO);
        if (dupold < 0){ close(fd); return -1; }
        if (dup2(fd, STDERR_FILENO) < 0){ close(fd); close(dupold); return -1; }
        close(fd);
        saved_fd[1] = dupold;
    }
    return 0;
}

int tu_redirect_stdio_end(int saved_fd[2]){
    int rc = 0;
    if (saved_fd[0] >= 0){
        if (dup2(saved_fd[0], STDOUT_FILENO) < 0) rc = -1;
        close(saved_fd[0]);
        saved_fd[0] = -1;
    }
    if (saved_fd[1] >= 0){
        if (dup2(saved_fd[1], STDERR_FILENO) < 0) rc = -1;
        close(saved_fd[1]);
        saved_fd[1] = -1;
    }
    return rc;
}

/* ========================================================================== */
/*                                   Runner                                   */
/* ========================================================================== */

static void print_usage(const char* prog, const char* suite){
    fprintf(SERR(),
      "Usage: %s [suite:%s] [--list] [--repeat N] [--help]\n",
      prog, suite);
}

/* one line result */
static void tu_print_result_line(const char* suite, const char* name, int rc){
    fprintf(SOUT(), "[%s] • %s %s\n",
            suite, name, (rc==0 && g_failures==0)? C_GRN "OK" C_RESET : C_RED "FAIL" C_RESET);
}

int tu_run_suite(const char* suite_name,
                 const TU_Test* tests, size_t ntests,
                 int argc, char** argv)
{
    bool list=false; int repeat=1;

    for (int i=1;i<argc;i++){
        if (!strcmp(argv[i],"--list")) list=true;
        else if (!strcmp(argv[i],"--repeat") && i+1<argc) repeat = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--help")) { print_usage(argv[0], suite_name); return 2; }
        else if (!strncmp(argv[i], "--suite", 7)) { if (i+1<argc) i++; /* ignored */ }
        else { /* ignore unknowns to keep it simple */ }
    }

    if (list)
    {
        for (size_t i=0;i<ntests;i++) fprintf(SOUT(), "%s/%s\n", suite_name, tests[i].name);
        return 0;
    }

    int grand_fail = 0, grand_run = 0;
    for (int r=0; r<repeat; r++){
        if (repeat>1) fprintf(SOUT(), C_CYN "=== %s run %d/%d ===" C_RESET "\n", suite_name, r+1, repeat);
        for (size_t i=0; i<ntests; i++){
            g_failures = 0;
            int rc = tests[i].fn();
            tu_print_result_line(suite_name, tests[i].name, rc);
            grand_run++;
            if (rc!=0 || g_failures) { grand_fail++; break; }
        }
        if (grand_fail) break;
    }

    if (grand_fail==0){
        fprintf(SOUT(), C_GRN "\n[%s] All %d test(s) passed.\n" C_RESET, suite_name, grand_run);
        return 0;
    } else {
        fprintf(SOUT(), C_RED "\n[%s] %d/%d test(s) failed.\n" C_RESET, suite_name, grand_fail, grand_run);
        return 1;
    }
}

/* Optional timing helper for tests that want their own stopwatch. */
int tu_run_and_time(const char* name, test_fn fn)
{
    g_failures = 0;
    double t0 = tu_now_ms();
    int rc = fn();
    double dt = tu_now_ms()-t0;
    if (rc==0 && g_failures==0){
        fprintf(SOUT(), "[time] • %s " C_GRN "OK" C_RESET " (%.1f ms)\n", name, dt);
        return 0;
    } else {
        fprintf(SOUT(), "[time] • %s " C_RED "FAIL" C_RESET " (%.1f ms)\n", name, dt);
        return 1;
    }
}
