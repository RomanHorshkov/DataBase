#ifndef CRYPTOGRAPHY_SHA256_H
#define CRYPTOGRAPHY_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    uint8_t b[32];
} Sha256;

/* Lowercase hex (out[65], NUL-terminated). */
void crypt_sha256_hex(const Sha256* d, char out[65]);

/* Hash the entire file at path. Returns 0 on success. */
int crypt_sha256_file(const char* path, Sha256* out, size_t* size_out);

/* Stream-hash from any fd (file, pipe, socket). Blocks until EOF.
   Handles EINTR; if non-blocking and EAGAIN/EWOULDBLOCK, waits with poll().
   Returns 0 on success. */
int crypt_sha256_fd(int fd, Sha256* out, size_t* size_out);

/* High-level ingest:
   Read from src_fd, hash while copying to a temp under root, fsync,
   then atomically rename to objects/sha256/aa/bb/<hex> (dedup if exists).
   On success: set digest_out + size_out. Returns 0. */
int crypt_store_sha256_object_from_fd(const char* root, int src_fd,
                                      Sha256* digest_out, size_t* size_out);

/* Cryptographically strong random bytes. Returns 0 on success. */
int crypt_rand_bytes(void* buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif /* CRYPTOGRAPHY_SHA256_H */
