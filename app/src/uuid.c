#include "uuid.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#if defined(__linux__)
/* try getrandom first (non-blocking semantics with urandom pool after init)*/
#include <sys/random.h>
#endif
static int fill_random(void* p, size_t n)
{
#if defined(__linux__)
    ssize_t r = getrandom(p, n, 0);
    if(r == (ssize_t)n)
        return 0;
#endif
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0)
    {
        size_t off = 0;
        while(off < n)
        {
            ssize_t rd = read(fd, (uint8_t*)p + off, n - off);
            if(rd <= 0)
            {
                close(fd);
                return -1;
            }
            off += (size_t)rd;
        }
        close(fd);
        return 0;
    }
    // very weak fallback
    for(size_t i = 0; i < n; ++i)
        ((uint8_t*)p)[i] = (uint8_t)(0xA5 ^ (i * 41));
    return 0;
}

int uuid_v4(uint8_t out[DB_ID_SIZE])
{
    if(fill_random(out, 16) != 0)
        return -1;
    out[6] = (out[6] & 0x0F) | 0x40;  // version 4
    out[8] = (out[8] & 0x3F) | 0x80;  // variant RFC 4122 (10xx xxxx)
    return 0;
}

int uuid_v7(uint8_t out[DB_ID_SIZE])
{
    // timestamp (ms since Unix epoch), 48 bits big-endian
    struct timespec ts;
    if(clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return -1;
    uint64_t ms =
        (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);

    // random parts: 12-bit rand_a, 62-bit rand_b
    uint8_t ra[2], rb[8];
    if(fill_random(ra, sizeof ra) != 0)
        return -1;
    if(fill_random(rb, sizeof rb) != 0)
        return -1;

    uint16_t rand_a  = ((uint16_t)ra[0] << 8) | ra[1];
    rand_a          &= 0x0FFF;  // 12 bits

    // write timestamp (48 bits)
    out[0]           = (uint8_t)((ms >> 40) & 0xFF);
    out[1]           = (uint8_t)((ms >> 32) & 0xFF);
    out[2]           = (uint8_t)((ms >> 24) & 0xFF);
    out[3]           = (uint8_t)((ms >> 16) & 0xFF);
    out[4]           = (uint8_t)((ms >> 8) & 0xFF);
    out[5]           = (uint8_t)((ms >> 0) & 0xFF);

    // version (7) in high nibble, high 4 bits of rand_a in low nibble
    out[6]           = (uint8_t)(0x70 | ((rand_a >> 8) & 0x0F));
    // low 8 bits of rand_a
    out[7]           = (uint8_t)(rand_a & 0xFF);

    // variant (10) in the top 2 bits, then top 6 bits of rand_b
    out[8]           = (uint8_t)((rb[0] & 0x3F) | 0x80);
    // remaining 56 bits of rand_b
    out[9]           = rb[1];
    out[10]          = rb[2];
    out[11]          = rb[3];
    out[12]          = rb[4];
    out[13]          = rb[5];
    out[14]          = rb[6];
    out[15]          = rb[7];

    return 0;
}

void uuid_to_hex(uint8_t id[DB_ID_SIZE], char out32[33])
{
    static const char* h = "0123456789abcdef";
    for(int i = 0; i < 16; ++i)
    {
        out32[i * 2]     = h[(id[i] >> 4) & 0xF];
        out32[i * 2 + 1] = h[id[i] & 0xF];
    }
    out32[32] = '\0';
}
