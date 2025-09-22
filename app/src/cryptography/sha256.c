/**
 * @file sha256.c
 * @brief
 *
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "sha256.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef CRYPTO_READ_BUFSZ
#    define CRYPTO_READ_BUFSZ (1u << 16)
#endif

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static int write_all(int fd, const uint8_t* p, size_t n)
{
    size_t off = 0;
    while(off < n)
    {
        ssize_t wr = write(fd, p + off, n - off);
        if(wr > 0)
        {
            off += (size_t)wr;
            continue;
        }
        if(wr < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int fsync_parent_dir(const char* path)
{
    char   tmp[PATH_MAX];
    size_t len = strnlen(path, sizeof tmp);
    if(len == 0 || len >= sizeof tmp)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(tmp, path, len + 1);

    /* find last '/' */
    char* last = strrchr(tmp, '/');
    if(!last)
    { /* file in cwd: fsync(".") is not portable; open(".") */
        int dfd = open(".", O_RDONLY | O_DIRECTORY);
        if(dfd < 0) return -1;
        int rc = fsync(dfd);
        int e  = errno;
        close(dfd);
        if(rc != 0)
        {
            errno = e;
            return -1;
        }
        return 0;
    }
    *last   = '\0';
    int dfd = open(tmp, O_RDONLY | O_DIRECTORY);
    if(dfd < 0) return -1;
    int rc = fsync(dfd);
    int e  = errno;
    close(dfd);
    if(rc != 0)
    {
        errno = e;
        return -1;
    }
    return 0;
}

static int digest_fd_evp(int fd, Sha256* out, size_t* size_out)
{
    if(!out)
    {
        errno = EINVAL;
        return -1;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx)
    {
        errno = ENOMEM;
        return -1;
    }

    int     rc = -1;
    uint8_t buf[CRYPTO_READ_BUFSZ];
    size_t  total = 0;

    if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
    {
        errno = EIO;
        goto done;
    }

    for(;;)
    {
        ssize_t rd = read(fd, buf, sizeof buf);
        if(rd > 0)
        {
            if(EVP_DigestUpdate(ctx, buf, (size_t)rd) != 1)
            {
                errno = EIO;
                goto done;
            }
            total += (size_t)rd;
            continue;
        }
        if(rd == 0) break;
        if(errno == EINTR) continue;

        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            struct pollfd p  = {.fd = fd, .events = POLLIN};
            int           pr = poll(&p, 1, -1);
            if(pr > 0 || (pr < 0 && errno == EINTR)) continue;
        }
        goto done;
    }

    unsigned outlen = 0;
    if(EVP_DigestFinal_ex(ctx, out->b, &outlen) != 1 || outlen != 32)
    {
        errno = EIO;
        goto done;
    }
    if(size_out) *size_out = total;
    rc = 0;
done:
    EVP_MD_CTX_free(ctx);
    return rc;
}

/* --- public API ---------------------------------------------------------- */

void crypt_sha256_hex(const Sha256* d, char out[65])
{
    static const char* H = "0123456789abcdef";
    for(int i = 0; i < 32; ++i)
    {
        out[i * 2]     = H[d->b[i] >> 4];
        out[i * 2 + 1] = H[d->b[i] & 0xF];
    }
    out[64] = '\0';
}

int crypt_rand_bytes(void* buf, size_t n)
{
    if(!buf && n)
    {
        errno = EINVAL;
        return -1;
    }
    return RAND_bytes((unsigned char*)buf, (int)n) == 1 ? 0 : (errno = EIO, -1);
}

int crypt_sha256_fd(int fd, Sha256* out, size_t* size_out)
{
    /* If seekable, don’t change caller’s file position. */
    off_t cur = lseek(fd, 0, SEEK_CUR);
    if(cur != (off_t)-1) (void)lseek(fd, 0, SEEK_SET);
    int rc = digest_fd_evp(fd, out, size_out);
    if(cur != (off_t)-1) (void)lseek(fd, cur, SEEK_SET);
    return rc;
}

int crypt_sha256_file(const char* path, Sha256* out, size_t* size_out)
{
    if(!path || !out)
    {
        errno = EINVAL;
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if(fd < 0) return -1;
    int rc = digest_fd_evp(fd, out, size_out);
    int e  = errno;
    close(fd);
    if(rc != 0)
    {
        errno = e;
        return -1;
    }
    return 0;
}

/* tmp file in <dir>.name pattern; returns fd + path. */
static int tmp_in_dir(const char* dir, char out_path[PATH_MAX])
{
    if(!dir)
    {
        errno = EINVAL;
        return -1;
    }

    int dfd = open(dir, O_RDONLY | O_DIRECTORY);
    if(dfd < 0) return -1;

    for(int tries = 0; tries < 128; ++tries)
    {
        unsigned char rnd[16];
        if(crypt_rand_bytes(rnd, sizeof rnd) != 0)
        {
            int e = errno;
            close(dfd);
            errno = e;
            return -1;
        }

        static const char* hex = "0123456789abcdef";
        char               name[64];
        memcpy(name, ".ingest.", 8);
        for(int i = 0; i < 16; ++i)
        {
            name[8 + i * 2] = hex[rnd[i] >> 4];
            name[9 + i * 2] = hex[rnd[i] & 0xF];
        }
        name[8 + 32] = '\0';

        int fd = openat(dfd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0660);
        if(fd >= 0)
        {
            size_t dlen = strnlen(dir, PATH_MAX);
            if(dlen + 1 + strlen(name) + 1 >= PATH_MAX)
            {
                int e = ENAMETOOLONG;
                close(fd);
                close(dfd);
                errno = e;
                return -1;
            }
            memcpy(out_path, dir, dlen);
            out_path[dlen] = '/';
            strcpy(out_path + dlen + 1, name);
            close(dfd);
            return fd;
        }
        if(errno != EEXIST)
        {
            int e = errno;
            close(dfd);
            errno = e;
            return -1;
        }
    }
    close(dfd);
    errno = EEXIST;
    return -1;
}

static int publish_or_discard(const char* root, const Sha256* d,
                              const char* tmp_path)
{
    char hex[65];
    crypt_sha256_hex(d, hex);

    char sharddir[2048];
    if(snprintf(sharddir, sizeof sharddir, "%s/objects/sha256/%.2s/%.2s", root,
                hex, hex + 2) >= (int)sizeof sharddir)
    {
        unlink(tmp_path);
        errno = ENAMETOOLONG;
        return -1;
    }

    if(mkdir_p(sharddir, 0770) != 0 && errno != EEXIST)
    {
        unlink(tmp_path);
        return -1;
    }

    char final_path[2048];
    if(path_sha256(final_path, sizeof final_path, root, hex) < 0)
    {
        unlink(tmp_path);
        return -1;
    }

    struct stat st;
    if(stat(final_path, &st) == 0)
    { /* dedup */
        unlink(tmp_path);
        return 0;
    }

    if(rename(tmp_path, final_path) != 0)
    {
        /* If rename fails due to cross-device, try link+unlink */
        if(link(tmp_path, final_path) == 0)
        {
            unlink(tmp_path);
        }
        else
        {
            int e = errno;
            unlink(tmp_path);
            errno = e;
            return -1;
        }
    }

    /* Durability: fsync parent directory of final_path */
    if(fsync_parent_dir(final_path) != 0) return -1;
    return 0;
}

int crypt_store_sha256_object_from_fd(const char* root, int src_fd,
                                      Sha256* digest_out, size_t* size_out)
{
    if(!root)
    {
        errno = EINVAL;
        return -1;
    }

    char objdir[PATH_MAX];
    if(snprintf(objdir, sizeof objdir, "%s/objects/sha256", root) >=
       (int)sizeof objdir)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    if(mkdir_p(objdir, 0770) != 0 && errno != EEXIST) return -1;

    char tmp_path[PATH_MAX];
    int  tmpfd = tmp_in_dir(objdir, tmp_path);
    if(tmpfd < 0) return -1;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx)
    {
        int e = ENOMEM;
        close(tmpfd);
        unlink(tmp_path);
        errno = e;
        return -1;
    }
    if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
    {
        int e = EIO;
        EVP_MD_CTX_free(ctx);
        close(tmpfd);
        unlink(tmp_path);
        errno = e;
        return -1;
    }

    uint8_t buf[CRYPTO_READ_BUFSZ];
    size_t  total = 0;

    for(;;)
    {
        ssize_t rd = read(src_fd, buf, sizeof buf);
        if(rd > 0)
        {
            if(write_all(tmpfd, buf, (size_t)rd) != 0)
            {
                int e = errno;
                EVP_MD_CTX_free(ctx);
                close(tmpfd);
                unlink(tmp_path);
                errno = e;
                return -1;
            }
            if(EVP_DigestUpdate(ctx, buf, (size_t)rd) != 1)
            {
                int e = EIO;
                EVP_MD_CTX_free(ctx);
                close(tmpfd);
                unlink(tmp_path);
                errno = e;
                return -1;
            }
            total += (size_t)rd;
            continue;
        }
        if(rd == 0) break;
        if(errno == EINTR) continue;
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            struct pollfd p  = {.fd = src_fd, .events = POLLIN};
            int           pr = poll(&p, 1, -1);
            if(pr > 0 || (pr < 0 && errno == EINTR)) continue;
        }
        /* hard error */
        {
            int e = errno;
            EVP_MD_CTX_free(ctx);
            close(tmpfd);
            unlink(tmp_path);
            errno = e;
            return -1;
        }
    }

    unsigned outlen = 0;
    Sha256   d      = {0};
    if(EVP_DigestFinal_ex(ctx, d.b, &outlen) != 1 || outlen != 32)
    {
        int e = EIO;
        EVP_MD_CTX_free(ctx);
        close(tmpfd);
        unlink(tmp_path);
        errno = e;
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    if(fsync(tmpfd) != 0)
    {
        int e = errno;
        close(tmpfd);
        unlink(tmp_path);
        errno = e;
        return -1;
    }
    close(tmpfd);

    if(publish_or_discard(root, &d, tmp_path) != 0) return -1;

    if(digest_out) *digest_out = d;
    if(size_out) *size_out = total;
    return 0;
}
