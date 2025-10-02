// src/uuid.c
#include "uuid.h"

#include <sodium.h>  // randombytes_buf()
#include <stdatomic.h>
#include <string.h>
#include <time.h>

/* Monotonic state: upper 52 bits = millis, lower 12 bits = seq */
static _Atomic uint64_t g_v7_state = 0;

/* --- helpers -------------------------------------------------------------- */

static inline uint64_t realtime_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}

static inline void rand8(uint8_t out[8])
{
    /* libsodium is already a dep (auth). It’s fast & good. */
    randombytes_buf(out, 8);
}

/* --- public ---------------------------------------------------------------- */

int uuid_gen(uint8_t* out)
{
    if(!out) return -1;

    uint64_t use_ms;
    uint16_t seq12;

    /* Reserve strictly increasing (ms,seq) using a CAS loop */
    for(;;)
    {
        const uint64_t now_ms = realtime_ms();

        uint64_t prev = atomic_load_explicit(&g_v7_state, memory_order_relaxed);
        const uint64_t prev_ms  = prev >> 12;
        const uint16_t prev_seq = (uint16_t)(prev & 0x0FFFu);

        /* clamp to non-decreasing ms */
        use_ms = (now_ms >= prev_ms) ? now_ms : prev_ms;

        /* same ms => bump seq; new ms => seq=0 */
        uint16_t next_seq =
            (use_ms == prev_ms) ? (uint16_t)((prev_seq + 1u) & 0x0FFFu) : 0u;

        /* if we wrapped within same ms, wait for the next ms and retry */
        if(use_ms == prev_ms && next_seq == 0u) continue;

        const uint64_t next = (use_ms << 12) | (uint64_t)next_seq;
        if(atomic_compare_exchange_weak_explicit(&g_v7_state, &prev, next,
                                                 memory_order_acq_rel,
                                                 memory_order_relaxed))
        {
            seq12 = next_seq;
            break;
        }
    }

    /* random tail (62 bits go after the variant) */
    uint8_t rb[8];
    rand8(rb);

    /* UUIDv7 (RFC4122bis):
       - bytes 0..5 : 48-bit unix ms (big-endian)
       - byte    6  : version (0b0111) in high nibble | high 4 bits of seq
       - byte    7  : low 8 bits of seq
       - byte    8  : variant (10xxxxxx) | top 6 bits of rb[0]
       - bytes 9..15: remaining 7 bytes from rb[1..7]
    */
    out[0] = (uint8_t)((use_ms >> 40) & 0xFF);
    out[1] = (uint8_t)((use_ms >> 32) & 0xFF);
    out[2] = (uint8_t)((use_ms >> 24) & 0xFF);
    out[3] = (uint8_t)((use_ms >> 16) & 0xFF);
    out[4] = (uint8_t)((use_ms >> 8) & 0xFF);
    out[5] = (uint8_t)((use_ms >> 0) & 0xFF);

    out[6] = (uint8_t)((0x7u << 4) | ((seq12 >> 8) & 0x0Fu));  // version = 7
    out[7] = (uint8_t)(seq12 & 0xFFu);

    out[8]  = (uint8_t)((rb[0] & 0x3Fu) | 0x80u);  // variant = 10xxxxxx
    out[9]  = rb[1];
    out[10] = rb[2];
    out[11] = rb[3];
    out[12] = rb[4];
    out[13] = rb[5];
    out[14] = rb[6];
    out[15] = rb[7];

    return 0;
}
