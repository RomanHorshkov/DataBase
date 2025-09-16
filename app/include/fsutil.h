#ifndef FSUTIL_H
#define FSUTIL_H
#include <sys/stat.h>
#include <stddef.h>

int mkdir_p(const char* path, mode_t mode);
int path_sha256(char* out, size_t out_sz, const char* root, const char* sha_hex64);
int write_object_atomic_from_fd(const char* dst_path, int src_fd);
int ensure_symlink(const char* link_path, const char* target);

#endif
