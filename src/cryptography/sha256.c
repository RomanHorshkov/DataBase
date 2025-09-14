#include "cryptography/sha256.h"
#include "fsutil.h"            // mkdir_p, path_sha256
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#ifndef CRYPTO_READ_BUFSZ
#define CRYPTO_READ_BUFSZ (1<<16)
#endif

/* hex */
void crypt_sha256_hex(const Sha256* d, char out[65]) {
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; ++i)
    {
        out[i*2] = H[d->b[i]>>4];
        out[i*2+1] = H[d->b[i]&0xF];
    }
    out[64] = '\0';
}

int crypt_rand_bytes(void* buf, size_t n) {
    if (!buf && n) return -1;
    return RAND_bytes((unsigned char*)buf, (int)n) == 1 ? 0 : -1;
}

/* read+digest core */
static int digest_fd_evp(int fd, Sha256* out, size_t* size_out) {
    if (!out) return -1;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new(); if (!ctx) return -1;
    int rc = -1;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;

    uint8_t buf[CRYPTO_READ_BUFSZ];
    size_t total = 0;

    for (;;) {
        ssize_t rd = read(fd, buf, sizeof buf);
        if (rd > 0) {
            if (EVP_DigestUpdate(ctx, buf, (size_t)rd) != 1) goto done;
            total += (size_t)rd;
            continue;
        }
        if (rd == 0) break; // EOF
        if (rd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd p = { .fd = fd, .events = POLLIN };
                int pr = poll(&p, 1, -1);
                if (pr > 0 || (pr < 0 && errno == EINTR)) continue;
            }
            goto done;
        }
    }

    unsigned int outlen = 0;
    if (EVP_DigestFinal_ex(ctx, out->b, &outlen) != 1 || outlen != 32) goto done;
    if (size_out) *size_out = total;
    rc = 0;
done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

int crypt_sha256_fd(int fd, Sha256* out, size_t* size_out) {
    off_t cur = lseek(fd, 0, SEEK_CUR);
    if (cur != (off_t)-1) (void)lseek(fd, 0, SEEK_SET);
    int rc = digest_fd_evp(fd, out, size_out);
    if (cur != (off_t)-1) (void)lseek(fd, cur, SEEK_SET);
    return rc;
}

int crypt_sha256_file(const char* path, Sha256* out, size_t* size_out) {
    if (!path || !out) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int rc = digest_fd_evp(fd, out, size_out);
    close(fd);
    return rc;
}

/* tmp file inside dir using openat + random name */
static int make_tmp_in_dir(const char* tmpdir, char out_path[PATH_MAX]) {
    int dfd = open(tmpdir, O_DIRECTORY | O_RDONLY);
    if (dfd < 0) return -1;

    for (int tries = 0; tries < 128; ++tries) {
        unsigned char rnd[16];
        if (crypt_rand_bytes(rnd, sizeof rnd) != 0) { close(dfd); return -1; }

        char name[64]; static const char* hex = "0123456789abcdef";
        memcpy(name, ".ingest.", 8);
        for (int i = 0; i < 16; ++i) { name[8+i*2] = hex[rnd[i]>>4]; name[9+i*2] = hex[rnd[i]&0xF]; }
        name[8+32] = '\0';

        int fd = openat(dfd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0660);
        if (fd >= 0) {
            size_t dlen = strlen(tmpdir);
            if (dlen >= PATH_MAX) { close(fd); close(dfd); errno = ENAMETOOLONG; return -1; }
            if (dlen + 1 + strlen(name) + 1 >= PATH_MAX) { close(fd); close(dfd); errno = ENAMETOOLONG; return -1; }
            memcpy(out_path, tmpdir, dlen); out_path[dlen] = '/'; strcpy(out_path + dlen + 1, name);
            close(dfd);
            return fd;
        }
        if (errno != EEXIST) { close(dfd); return -1; }
    }
    close(dfd);
    errno = EEXIST;
    return -1;
}

static int publish_or_discard(const char* root, const Sha256* d, const char* tmp_path) {
    char hex[65]; crypt_sha256_hex(d, hex);

    char sharddir[2048];
    if (snprintf(sharddir, sizeof sharddir, "%s/objects/sha256/%.2s/%.2s", root, hex, hex+2) >= (int)sizeof sharddir)
        { unlink(tmp_path); errno = ENAMETOOLONG; return -1; }
    if (mkdir_p(sharddir, 0770) != 0 && errno != EEXIST) { unlink(tmp_path); return -1; }

    char final_path[2048];
    if (path_sha256(final_path, sizeof final_path, root, hex) < 0) { unlink(tmp_path); return -1; }

    struct stat st;
    if (stat(final_path, &st) == 0) { unlink(tmp_path); return 0; }  // dedup

    if (rename(tmp_path, final_path) == 0) return 0;
    if (link(tmp_path, final_path) == 0) { unlink(tmp_path); return 0; }
    unlink(tmp_path);
    return -1;
}

int crypt_store_sha256_object_from_fd(const char* root, int src_fd,
                                      Sha256* digest_out, size_t* size_out) {
    if (!root) return -1;

    char tmpdir[2048];
    if (snprintf(tmpdir, sizeof tmpdir, "%s/objects/sha256", root) >= (int)sizeof tmpdir)
        { errno = ENAMETOOLONG; return -1; }
    if (mkdir_p(tmpdir, 0770) != 0 && errno != EEXIST) return -1;

    char tmp_path[PATH_MAX];
    int tmpfd = make_tmp_in_dir(tmpdir, tmp_path);
    if (tmpfd < 0) return -1;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { close(tmpfd); unlink(tmp_path); return -1; }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); close(tmpfd); unlink(tmp_path); return -1;
    }

    uint8_t buf[CRYPTO_READ_BUFSZ];
    size_t total = 0;

    for (;;) {
        ssize_t rd = read(src_fd, buf, sizeof buf);
        if (rd > 0) {
            ssize_t off = 0;
            while (off < rd) {
                ssize_t wr = write(tmpfd, buf + off, (size_t)(rd - off));
                if (wr > 0) off += wr;
                else if (wr < 0 && errno == EINTR) continue;
                else { EVP_MD_CTX_free(ctx); close(tmpfd); unlink(tmp_path); return -1; }
            }
            if (EVP_DigestUpdate(ctx, buf, (size_t)rd) != 1) {
                EVP_MD_CTX_free(ctx); close(tmpfd); unlink(tmp_path); return -1;
            }
            total += (size_t)rd;
            continue;
        }
        if (rd == 0) break;
        if (rd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd p = { .fd = src_fd, .events = POLLIN };
                int pr = poll(&p, 1, -1);
                if (pr > 0 || (pr < 0 && errno == EINTR)) continue;
            }
            EVP_MD_CTX_free(ctx); close(tmpfd); unlink(tmp_path); return -1;
        }
    }

    unsigned int outlen = 0;
    Sha256 d = {0};
    if (EVP_DigestFinal_ex(ctx, d.b, &outlen) != 1 || outlen != 32) {
        EVP_MD_CTX_free(ctx); close(tmpfd); unlink(tmp_path); return -1;
    }
    EVP_MD_CTX_free(ctx);

    if (fsync(tmpfd) != 0) { close(tmpfd); unlink(tmp_path); return -1; }
    close(tmpfd);

    if (publish_or_discard(root, &d, tmp_path) != 0) return -1;

    if (digest_out) *digest_out = d;
    if (size_out) *size_out = total;
    return 0;
}
