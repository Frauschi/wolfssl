/* Log every ELS SFR access CLNS makes, so a trace from silicon can be compared
 * against the emulator's. Pulled in with -include, ahead of everything: the
 * real definitions come first and are then replaced, which the include guard
 * makes safe. */
#ifndef ELS_SFR_TRACE_H
#define ELS_SFR_TRACE_H

#include <internal/mcuxClEls_SfrAccess.h>
#include <stdint.h>

void els_trace_rec(char op, const char *name, uint32_t val);

static inline uint32_t els_trace_rd(const char *name, uint32_t v)
{
    els_trace_rec('R', name, v);
    return v;
}

static inline uint32_t els_trace_pkc_rd(const char *name, uint32_t v)
{
    els_trace_rec('Q', name, v);
    return v;
}

/* MCUXCLELS_SFR_READ is deliberately left alone. CLNS takes its address to
 * walk the key store window as an array
 * (mcuxClEls_KeyManagement.c: &MCUXCLELS_SFR_READ(ELS_KS0))[keyIdx]), so it
 * has to stay an lvalue naming the register. Status polling still shows up
 * through BITREAD below. */

#undef MCUXCLELS_SFR_WRITE
#define MCUXCLELS_SFR_WRITE(sfr, value) \
    do { \
        uint32_t _v = (uint32_t)(value); \
        els_trace_rec('W', #sfr, _v); \
        ELS_SFR_BASE->ELS_SFR_NAME(sfr) = _v; \
    } while (0)

#undef MCUXCLELS_SFR_BITREAD
#define MCUXCLELS_SFR_BITREAD(sfr, bit) \
    ((els_trace_rd(#sfr, ELS_SFR_BASE->ELS_SFR_NAME(sfr)) \
      & MCUXCLELS_SFR_FIELD_MASK(sfr, bit)) \
     >> MCUXCLELS_SFR_FIELD_SHIFT(sfr, bit))

#undef MCUXCLELS_SFR_BITSET
#define MCUXCLELS_SFR_BITSET(sfr, bit) \
    do { \
        uint32_t _v = ELS_SFR_BASE->ELS_SFR_NAME(sfr) \
                      | MCUXCLELS_SFR_FIELD_MASK(sfr, bit); \
        els_trace_rec('W', #sfr, _v); \
        ELS_SFR_BASE->ELS_SFR_NAME(sfr) = _v; \
    } while (0)

#undef MCUXCLELS_SFR_BITCLEAR
#define MCUXCLELS_SFR_BITCLEAR(sfr, bit) \
    do { \
        uint32_t _v = ELS_SFR_BASE->ELS_SFR_NAME(sfr) \
                      & (~(uint32_t)MCUXCLELS_SFR_FIELD_MASK(sfr, bit)); \
        els_trace_rec('W', #sfr, _v); \
        ELS_SFR_BASE->ELS_SFR_NAME(sfr) = _v; \
    } while (0)

#undef MCUXCLELS_SFR_BITVALSET
#define MCUXCLELS_SFR_BITVALSET(sfr, bit, val) \
    do { \
        uint32_t _t = ELS_SFR_BASE->ELS_SFR_NAME(sfr) \
                      & (~(uint32_t)MCUXCLELS_SFR_FIELD_MASK(sfr, bit)); \
        uint32_t _v = _t | (((val) << MCUXCLELS_SFR_FIELD_SHIFT(sfr, bit)) \
                            & MCUXCLELS_SFR_FIELD_MASK(sfr, bit)); \
        els_trace_rec('W', #sfr, _v); \
        ELS_SFR_BASE->ELS_SFR_NAME(sfr) = _v; \
    } while (0)

/* The PKC has the same six-macro shape behind PKC_SFR_BASE, and its
 * calculation modes are no more published than the ELS command numbers, so it
 * is traced the same way. MCUXCLPKC_SFR_READ is left alone for the same reason
 * as its ELS counterpart. */
#include <internal/mcuxClPkc_SfrAccess.h>

#undef MCUXCLPKC_SFR_WRITE
#define MCUXCLPKC_SFR_WRITE(sfr, value) \
    do { \
        uint32_t _v = (uint32_t)(value); \
        els_trace_rec('P', #sfr, _v); \
        PKC_SFR_BASE->PKC_SFR_NAME(sfr) = _v; \
    } while (0)

#undef MCUXCLPKC_SFR_BITREAD
#define MCUXCLPKC_SFR_BITREAD(sfr, bit) \
    ((els_trace_pkc_rd(#sfr, PKC_SFR_BASE->PKC_SFR_NAME(sfr)) \
      & MCUXCLPKC_SFR_BITMSK(sfr, bit)) >> MCUXCLPKC_SFR_BITPOS(sfr, bit))

#undef MCUXCLPKC_SFR_BITSET
#define MCUXCLPKC_SFR_BITSET(sfr, bit) \
    do { \
        uint32_t _v = PKC_SFR_BASE->PKC_SFR_NAME(sfr) \
                      | MCUXCLPKC_SFR_BITMSK(sfr, bit); \
        els_trace_rec('P', #sfr, _v); \
        PKC_SFR_BASE->PKC_SFR_NAME(sfr) = _v; \
    } while (0)

#undef MCUXCLPKC_SFR_BITCLEAR
#define MCUXCLPKC_SFR_BITCLEAR(sfr, bit) \
    do { \
        uint32_t _v = PKC_SFR_BASE->PKC_SFR_NAME(sfr) \
                      & (~(uint32_t)MCUXCLPKC_SFR_BITMSK(sfr, bit)); \
        els_trace_rec('P', #sfr, _v); \
        PKC_SFR_BASE->PKC_SFR_NAME(sfr) = _v; \
    } while (0)

#undef MCUXCLPKC_SFR_BITVALSET
#define MCUXCLPKC_SFR_BITVALSET(sfr, bit, val) \
    do { \
        uint32_t _t = PKC_SFR_BASE->PKC_SFR_NAME(sfr) \
                      & (~(uint32_t)MCUXCLPKC_SFR_BITMSK(sfr, bit)); \
        uint32_t _v = _t | (((val) << MCUXCLPKC_SFR_BITPOS(sfr, bit)) \
                            & MCUXCLPKC_SFR_BITMSK(sfr, bit)); \
        els_trace_rec('P', #sfr, _v); \
        PKC_SFR_BASE->PKC_SFR_NAME(sfr) = _v; \
    } while (0)

#endif /* ELS_SFR_TRACE_H */
