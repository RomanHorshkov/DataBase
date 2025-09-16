#include "uuid.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

static void hex32_id(uint8_t id[DB_ID_SIZE], char out[33])
{
    static const char *h = "0123456789abcdef";
    for(int i = 0; i < 16; ++i)
    {
        out[i * 2]     = h[(id[i] >> 4) & 0xF];
        out[i * 2 + 1] = h[id[i] & 0xF];
    }
    out[32] = '\0';
}

void id128_to_hex(uint8_t id[DB_ID_SIZE], char out32[33])
{
    hex32_id(id, out32);
}

int id128_equal(uint8_t a_id[DB_ID_SIZE], uint8_t b_id[DB_ID_SIZE])
{
    return memcmp(a_id, b_id, DB_ID_SIZE) == 0;
}

int id128_rand(uint8_t val[DB_ID_SIZE])
{
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0)
    {
        ssize_t rd = read(fd, val, DB_ID_SIZE);
        close(fd);
        if(rd == DB_ID_SIZE)
            return 0;
    }
    // Fallback (not cryptographically strong)
    for(int i = 0; i < DB_ID_SIZE; ++i)
        val[i] = (uint8_t)(0xA5 ^ (i * 41));
    return 0;
}
