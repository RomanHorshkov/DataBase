#include "fsutil.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

static int mkdir_one(const char* path, mode_t mode) {
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) {
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    }
    return -1;
}

int mkdir_p(const char* path, mode_t mode) {
    if (!path || !*path) return -1;
    char* tmp = strdup(path);
    if (!tmp) return -1;

    for (char* p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir_one(tmp, mode) != 0) { free(tmp); return -1; }
            *p = '/';
        }
    }
    if (mkdir_one(tmp, mode) != 0) { free(tmp); return -1; }
    free(tmp);
    return 0;
}

int path_sha256(char* out, size_t out_sz, const char* root, const char* sha_hex64) {
    if (!out || !root || !sha_hex64 || strlen(sha_hex64) != 64) return -1;
    snprintf(out, out_sz, "%s/objects/sha256/%.2s/%.2s/%s",
             root, sha_hex64, sha_hex64 + 2, sha_hex64);
    return 0;
}

static int fsync_parent_dir(const char* path) {
    char* dup = strdup(path);
    if (!dup) return -1;
    char* dir = dirname(dup);
    int dfd = open(dir, O_RDONLY
#ifdef O_DIRECTORY
                   | O_DIRECTORY
#endif
    );
    if (dfd >= 0) { (void)fsync(dfd); close(dfd); }
    free(dup);
    return 0;
}

int write_object_atomic_from_fd(const char* dst_path, int src_fd) {
    struct stat st;
    if (stat(dst_path, &st) == 0) return 0; // already exists

    // ensure parent exists
    {
        char* dup = strdup(dst_path);
        if (!dup) return -1;
        char* dir = dirname(dup);
        if (mkdir_p(dir, 0770) != 0 && errno != EEXIST) { free(dup); return -1; }
        free(dup);
    }

    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s.tmp.%d", dst_path, (int)getpid());
    int wfd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0640);
    if (wfd < 0) return -1;

    u_int8_t buf[1<<16];
    ssize_t rd;
    if (lseek(src_fd, 0, SEEK_SET) == (off_t)-1) { /* fine if not seekable */ }
    while ((rd = read(src_fd, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < rd) {
            ssize_t wr = write(wfd, buf + off, (size_t)(rd - off));
            if (wr <= 0) { close(wfd); unlink(tmp); return -1; }
            off += wr;
        }
    }
    (void)fsync(wfd);
    close(wfd);

    if (rename(tmp, dst_path) != 0) { unlink(tmp); return -1; }
    fsync_parent_dir(dst_path);
    return 0;
}

int ensure_symlink(const char* link_path, const char* target) {
    struct stat st;
    if (lstat(link_path, &st) == 0) return 0;

    // ensure parent exists
    {
        char* dup = strdup(link_path);
        if (!dup) return -1;
        char* dir = dirname(dup);
        if (mkdir_p(dir, 0770) != 0 && errno != EEXIST) { free(dup); return -1; }
        free(dup);
    }

    if (symlink(target, link_path) != 0 && errno != EEXIST) return -1;
    return 0;
}
