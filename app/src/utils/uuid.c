/**
 * @file uuid.c
 * @brief
 * 
 * @author  Roman Horshkov <roman.horshkov@gmail.com>
 * @date    2025
 * (c) 2025
 */

#include "uuid.h"
#include <stdatomic.h>
#include <time.h>
#include "utils_interface.h"

#if defined(__linux__)
/* try getrandom first (non-blocking semantics with urandom pool after init)*/
#    include <sys/random.h>
#endif

/****************************************************************************
 * PRIVATE DEFINES
 ****************************************************************************
 */

#define UUID_BYTES_SIZE 16

/****************************************************************************
 * PRIVATE STUCTURED VARIABLES
 ****************************************************************************
 */
/* None */

/****************************************************************************
 * PRIVATE VARIABLES
 ****************************************************************************
 */

static _Atomic uint64_t g_v7_state = 0;

/****************************************************************************
 * PRIVATE FUNCTIONS PROTOTYPES
 ****************************************************************************
 */

static inline uint64_t realtime_ms(void);
static int             fill_random(void* p, size_t n);

/****************************************************************************
 * PUBLIC FUNCTIONS DEFINITIONS
 ****************************************************************************
 */
int uuid_v4(uint8_t* out)
{
    if(fill_random(out, 16) != 0) return -1;
    out[6] = (out[6] & 0x0F) | 0x40;  // version 4
    out[8] = (out[8] & 0x3F) | 0x80;  // variant RFC 4122 (10xx xxxx)
    return 0;
}

int uuid_v7(uint8_t* out)
{
    static uint8_t last_id[UUID_BYTES_SIZE] = {0}; /* monotonic guard */
    /* Reserve strictly increasing (ms,seq) using a CAS loop */
    uint64_t use_ms;
    uint16_t seq12;

restart:
    for(;;)
    {
        uint64_t now_ms = realtime_ms();

        uint64_t prev = atomic_load_explicit(&g_v7_state, memory_order_relaxed);
        uint64_t prev_ms  = prev >> 12;
        uint16_t prev_seq = (uint16_t)(prev & 0x0FFFu);

        /* Clamp time to be non-decreasing */
        use_ms = (now_ms > prev_ms) ? now_ms : prev_ms;

        /* If same ms as previous, bump sequence; otherwise start at 0 */
        uint16_t next_seq =
            (use_ms == prev_ms) ? (uint16_t)(prev_seq + 1u) : 0u;

        /* If the 12-bit space overflows within the same ms, wait for next ms */
        if(use_ms == prev_ms && next_seq == 0u)
        {
            /* Busy-wait until the clock ticks to the next millisecond */
            do
            {
                now_ms = realtime_ms();
            } while(now_ms <= prev_ms);
            /* Try again; next iteration will see use_ms > prev_ms and seq=0 */
            continue;
        }

        uint64_t next = (use_ms << 12) | (uint64_t)next_seq;

        if(atomic_compare_exchange_weak_explicit(&g_v7_state, &prev, next,
                                                 memory_order_acq_rel,
                                                 memory_order_relaxed))
        {
            seq12 = next_seq;
            break; /* we own (use_ms, seq12) */
        }
        /* else: retry with updated prev */
    }

    /* Random 62 bits for the tail (rb) */
    uint8_t rb[8];
    if(fill_random(rb, sizeof rb) != 0) return -1;

    /* Layout per UUIDv7 (RFC 4122bis):
       - 48-bit timestamp (big-endian)
       - 4-bit version (7), 12-bit rand_a  -> we use seq here for monotonicity
       - 2-bit variant (10), 62-bit rand_b
    */

    /* timestamp 48-bit BE */
    out[0] = (uint8_t)((use_ms >> 40) & 0xFF);
    out[1] = (uint8_t)((use_ms >> 32) & 0xFF);
    out[2] = (uint8_t)((use_ms >> 24) & 0xFF);
    out[3] = (uint8_t)((use_ms >> 16) & 0xFF);
    out[4] = (uint8_t)((use_ms >> 8) & 0xFF);
    out[5] = (uint8_t)((use_ms >> 0) & 0xFF);

    /* version(7) | high 4 bits of seq */
    out[6] = (uint8_t)(0x70 | ((seq12 >> 8) & 0x0F));
    /* low 8 bits of seq */
    out[7] = (uint8_t)(seq12 & 0xFF);

    /* variant(10) in top 2 bits, then top 6 bits of rb[0] */
    out[8]  = (uint8_t)((rb[0] & 0x3Fu) | 0x80u);
    out[9]  = rb[1];
    out[10] = rb[2];
    out[11] = rb[3];
    out[12] = rb[4];
    out[13] = rb[5];
    out[14] = rb[6];
    out[15] = rb[7];

    if(memcmp(last_id, out, UUID_BYTES_SIZE) == 0)
    {
        memcpy(last_id, out, UUID_BYTES_SIZE);
        goto restart;
    }

    return 0;
}

void uuid_to_hex(uint8_t id[UUID_BYTES_SIZE], char out32[33])
{
    static const char* h = "0123456789abcdef";
    for(int i = 0; i < 16; ++i)
    {
        out32[i * 2]     = h[(id[i] >> 4) & 0xF];
        out32[i * 2 + 1] = h[id[i] & 0xF];
    }
    out32[32] = '\0';
}

/****************************************************************************
 * PRIVATE FUNCTIONS DEFINITIONS
 ****************************************************************************
 */

static inline uint64_t realtime_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

static int fill_random(void* p, size_t n)
{
#if defined(__linux__)
    ssize_t r = getrandom(p, n, 0);
    if(r == (ssize_t)n) return 0;
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
