/* els_pkc_port.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* wolfCrypt crypto-callback port for the NXP EdgeLock secure subsystem (ELS).
 *
 * Two properties of the hardware shape everything here:
 *
 *  1. ELS is a *single* peripheral with global busy state. Every operation is
 *     an _Async call followed by mcuxClEls_WaitForOperation(), and nothing may
 *     start between the two. One lock is held across each pair.
 *
 *  2. ELS answers a rejected request by resetting the SoC, not by returning an
 *     error: a wrong key permission or a failed unwrap trips the Intrusion and
 *     Tamper Response Controller, which drives a chip reset. Validation must
 *     therefore happen in software *before* the call. Getting this wrong does
 *     not produce a bad result, it reboots the device.
 *
 * The lock below serializes wolfSSL's own callers and nothing else. ELS is a
 * system-wide peripheral: NXP's PSA driver, an application calling mcuxClEls
 * directly, or a second OS task can all drive it behind our back, and no mutex
 * held here can prevent that. An integration that mixes wolfSSL with another
 * ELS user has to arbitrate above both of them.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_ELS_PKC

#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <mcuxClEls.h>
#include <mcuxCsslFlowProtection.h>

/* per-SoC bring-up helper; els_pkc provides one for each supported platform */
#include <mcux_els.h>

#ifdef WOLFSSL_ZEPHYR
    #include <zephyr/kernel.h>
    #include <zephyr/irq.h>
#endif

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ---------------------------------------------------------------------------
 * Peripheral serialization
 * ------------------------------------------------------------------------ */

/* instrumentation: how many times the hardware path actually ran */
unsigned long wc_ElsPkc_HashOffloadCount = 0;
/* which completion path ran: interrupt-driven vs polled fallback */
unsigned long wc_ElsPkc_IrqWaitCount = 0;
unsigned long wc_ElsPkc_PollWaitCount = 0;
unsigned long wc_ElsPkc_TimeoutCount = 0;
#endif

static wolfSSL_Mutex elsLock;
/* Read from the crypto-callback path, written by init/cleanup. Volatile so a
 * compiler cannot cache the flag across the mutex operations that order them. */
static volatile int elsLockInit = 0;
static volatile int elsRegistered = 0;
/* Set only once the peripheral is actually up. */
static volatile int elsReady = 0;

static int ElsLock(void)
{
    /* elsReady as well as elsLockInit: the mutex is created before the
     * peripheral is enabled, so a failed wc_ElsPkc_Init() would otherwise let
     * the direct entry points issue commands to a block still in reset. */
    if (!elsLockInit || !elsReady) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (wc_LockMutex(&elsLock) != 0) {
        return WC_NO_ERR_TRACE(BAD_MUTEX_E);
    }
    return 0;
}

static void ElsUnlock(void)
{
    if (elsLockInit) {
        (void)wc_UnLockMutex(&elsLock);
    }
}

/* mcuxClEls_WaitForOperation() busy-spins with no timeout, and does so while
 * this port holds the ELS lock. Where a kernel is available the thread sleeps
 * on the completion interrupt instead and the vendor call only harvests the
 * status. The spin stays the fallback for ISR context and pre-IRQ bring-up.
 *
 * A late interrupt degrades to that synchronous wait, because cancelling is a
 * tamper event on the default ITRC configuration. An integration that has
 * retargeted the ITRC can define WOLFSSL_ELS_PKC_ALLOW_CANCEL to cancel and
 * fail the operation instead. */

#ifndef WOLFSSL_ELS_PKC_TIMEOUT_MS
    #define WOLFSSL_ELS_PKC_TIMEOUT_MS 1000
#endif

#ifdef WOLFSSL_ZEPHYR

static struct k_sem elsDone;
static volatile int elsIrqReady = 0;

static void ElsIsr(const void* arg)
{
    mcuxClEls_InterruptOptionRst_t rst;

    (void)arg;

    /* acknowledge at the peripheral before releasing the waiter, so a fast
     * follow-up operation cannot see a stale flag */
    rst.word.value = 0u;
    rst.bits.elsint = MCUXCLELS_ELS_RESET_CLEAR;
    (void)mcuxClEls_ResetIntFlags(rst);

    k_sem_give(&elsDone);
}

/* Arm the completion interrupt. Called once from wc_ElsPkc_Init(). */
static int ElsIrqInit(void)
{
    mcuxClEls_InterruptOptionEn_t en;

    if (elsIrqReady) {
        return 0;
    }

    k_sem_init(&elsDone, 0, 1);

    IRQ_CONNECT(ELS_IRQn, WOLFSSL_ELS_PKC_IRQ_PRIO, ElsIsr, NULL, 0);
    irq_enable(ELS_IRQn);

    en.word.value = 0u;
    en.bits.elsint = MCUXCLELS_ELS_INTERRUPT_ENABLE;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_SetIntEnableFlags(en));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_SetIntEnableFlags) != t) ||
        (MCUXCLELS_STATUS_OK != r)) {
        irq_disable(ELS_IRQn);
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    elsIrqReady = 1;

    return 0;
}

/* Can this context afford to sleep? */
static int ElsCanSleep(void)
{
    return elsIrqReady && !k_is_in_isr();
}

#endif /* WOLFSSL_ZEPHYR */

#if defined(WOLFSSL_ELS_PKC_ALLOW_CANCEL) && defined(WOLFSSL_ZEPHYR)
/* Abandon the operation the caller is waiting on.
 *
 * Out of reach unless the integration has retargeted the Intrusion and Tamper
 * Response Controller: on the reset-on-tamper default this call is itself a
 * tamper event and reboots the SoC rather than returning. */
static void ElsCancel(void)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_Reset_Async(MCUXCLELS_RESET_CANCEL));
    (void)r;
    (void)t;
    MCUX_CSSL_FP_FUNCTION_CALL_END();
}
#endif

/* Must be called with the lock held, and always paired with the _Async that
 * preceded it. */
static int ElsWait(void)
{
    int ret;
#ifdef WOLFSSL_ZEPHYR
    int timedOut = 0;
#ifdef WOLFSSL_ELS_PKC_ALLOW_CANCEL
    int cancelled = 0;
#endif

    if (ElsCanSleep()) {
        ELS_COUNT(wc_ElsPkc_IrqWaitCount);
        if (k_sem_take(&elsDone, K_MSEC(WOLFSSL_ELS_PKC_TIMEOUT_MS)) != 0) {
            timedOut = 1;
            ELS_COUNT(wc_ElsPkc_TimeoutCount);
            WOLFSSL_MSG("els_pkc: completion interrupt late");
#ifdef WOLFSSL_ELS_PKC_ALLOW_CANCEL
            /* Cancel, then fall through to the vendor wait below: the reset
             * is itself an async command, and returning while it is still in
             * flight would fail the next caller's operation with
             * CANNOT_INTERRUPT. The wait also reaches the drain below. */
            ElsCancel();
            cancelled = 1;
#endif
        }
    }
    else {
        ELS_COUNT(wc_ElsPkc_PollWaitCount);
    }
#else
    ELS_COUNT(wc_ElsPkc_PollWaitCount);
#endif

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(res, tok,
        mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != tok) ||
        (MCUXCLELS_STATUS_OK != res)) {
        ret = WC_NO_ERR_TRACE(WC_HW_E);
    }
    else {
        ret = 0;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

#ifdef WOLFSSL_ZEPHYR
    /* The interrupt for this operation lands eventually. Drop it, or it would
     * satisfy the next wait before that operation had finished. */
    if (timedOut) {
        k_sem_reset(&elsDone);
    }
#ifdef WOLFSSL_ELS_PKC_ALLOW_CANCEL
    /* A cancelled operation produced no result, whatever the wait reported. */
    if (cancelled) {
        ret = WC_NO_ERR_TRACE(WC_HW_E);
    }
#endif
#endif

    return ret;
}

/* els_pkc ships this helper for every platform it supports, so the port stays
 * SoC-agnostic. */
static int ElsEnable(void)
{
    if (ELS_PowerDownWakeupInit(ELS) != 0) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * SHA-256
 *
 * ELS keeps its hash state in the peripheral, which at first looks like it
 * rules out incremental hashing: a second digest, or any other ELS operation,
 * would trample a hash in progress. It does not, because the engine can hand
 * the intermediate state back and take it again later - hashoe writes it to
 * pDigest, hashld reloads it (verified on hardware: feeding two blocks in one
 * call and feeding them either side of a state round-trip give the same
 * result).
 *
 * So the state lives in the caller's wc_Sha256 rather than in the hardware,
 * and the lock is only ever held for the duration of one call. Holding it from
 * first update to final would have been simpler but deadlocks: TLS 1.3 keeps
 * several transcript hashes alive at once, so a second hash would wait for a
 * first that cannot finish, and any AES or ECDSA between update and final
 * would block on a mutex its own thread already holds.
 *
 * ELS also never pads - inputLength must be a whole number of blocks - so the
 * port carries a residual partial block and appends the SHA-256 padding itself.
 * ------------------------------------------------------------------------ */

#ifndef NO_SHA256

#define ELS_SHA256_BLOCK MCUXCLELS_HASH_BLOCK_SIZE_SHA_256
#define ELS_SHA256_STATE MCUXCLELS_HASH_STATE_SIZE_SHA_256

/* Contexts come from a fixed pool rather than the heap: this port runs on
 * parts that are routinely built with WOLFSSL_NO_MALLOC, and a bounded pool
 * degrades gracefully - when it is empty the hash simply runs in software. */
#ifndef WOLFSSL_ELS_PKC_HASH_CTX_COUNT
    #define WOLFSSL_ELS_PKC_HASH_CTX_COUNT 4
#endif

/* Parked in devCtx when the pool was empty at the first update, so later calls
 * on the same hash keep going to software instead of starting a fresh ELS
 * digest that would be missing everything already absorbed. */
#define ELS_HASH_DECLINED ((void*)(wc_ptr_t)1)

typedef struct ElsHashCtx {
    ALIGN32 byte state[ELS_SHA256_STATE]; /* intermediate digest */
    byte   buf[ELS_SHA256_BLOCK];         /* residual partial block */
    word32 buffered;
    word64 total;                         /* message length, for the padding */
    byte   started;                       /* has the engine seen a block yet */
    byte   inUse;
    void*  owner;                         /* the wc_Sha256 this belongs to */
} ElsHashCtx;

static ElsHashCtx elsHashPool[WOLFSSL_ELS_PKC_HASH_CTX_COUNT];

/* Claim a pool entry for this hash. Caller must hold the lock. */
static ElsHashCtx* ElsHashClaim(void* owner)
{
    int i;

    for (i = 0; i < WOLFSSL_ELS_PKC_HASH_CTX_COUNT; i++) {
        if (!elsHashPool[i].inUse) {
            XMEMSET(&elsHashPool[i], 0, sizeof(elsHashPool[i]));
            elsHashPool[i].inUse = 1;
            elsHashPool[i].owner = owner;
            return &elsHashPool[i];
        }
    }

    return NULL;
}

static void ElsHashRelease(ElsHashCtx* ctx)
{
    if (ctx != NULL) {
        ForceZero(ctx, sizeof(*ctx));
    }
}

/* Feed whole blocks to the engine, carrying the running state in and out.
 * Caller must hold the lock. len must be a multiple of the block size. */
static int ElsHashBlocks(ElsHashCtx* ctx, const byte* in, word32 len)
{
    mcuxClEls_HashOption_t opt;

    if (len == 0) {
        return 0;
    }

    opt.word.value = 0u;
    opt.bits.hashmd = MCUXCLELS_HASH_MODE_SHA_256;
    opt.bits.hashoe = MCUXCLELS_HASH_OUTPUT_ENABLE;
    if (ctx->started) {
        opt.bits.hashini = MCUXCLELS_HASH_INIT_DISABLE;
        opt.bits.hashld  = MCUXCLELS_HASH_LOAD_ENABLE;
    }
    else {
        opt.bits.hashini = MCUXCLELS_HASH_INIT_ENABLE;
        opt.bits.hashld  = MCUXCLELS_HASH_LOAD_DISABLE;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_Hash_Async(opt, in, len, ctx->state));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Hash_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    ctx->started = 1;

    return ElsWait();
}

static int ElsSha256Update(wc_Sha256* sha256, const byte* in, word32 inSz)
{
    ElsHashCtx* ctx;
    word32 take, whole;
    int ret;

    if (sha256->devCtx == ELS_HASH_DECLINED) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ctx = (ElsHashCtx*)sha256->devCtx;
    if (ctx == NULL) {
        ctx = ElsHashClaim(sha256);
        if (ctx == NULL) {
            /* pool empty - hand this hash to software, permanently */
            sha256->devCtx = ELS_HASH_DECLINED;
            ElsUnlock();
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        sha256->devCtx = ctx;
    }

    ctx->total += inSz;

    /* top up the residual block first */
    if (ctx->buffered > 0) {
        take = ELS_SHA256_BLOCK - ctx->buffered;
        if (take > inSz) {
            take = inSz;
        }
        XMEMCPY(ctx->buf + ctx->buffered, in, take);
        ctx->buffered += take;
        in += take;
        inSz -= take;

        if (ctx->buffered == ELS_SHA256_BLOCK) {
            ret = ElsHashBlocks(ctx, ctx->buf, ELS_SHA256_BLOCK);
            if (ret != 0) {
                goto out;
            }
            ctx->buffered = 0;
        }
    }

    /* whole blocks straight from the caller's buffer */
    whole = (inSz / ELS_SHA256_BLOCK) * ELS_SHA256_BLOCK;
    if (whole > 0) {
        ret = ElsHashBlocks(ctx, in, whole);
        if (ret != 0) {
            goto out;
        }
        in += whole;
        inSz -= whole;
    }

    /* keep whatever is left for next time */
    if (inSz > 0) {
        XMEMCPY(ctx->buf + ctx->buffered, in, inSz);
        ctx->buffered += inSz;
    }

out:
    ElsUnlock();

    return ret;
}

static int ElsSha256Final(wc_Sha256* sha256, byte* digest)
{
    ALIGN32 byte tail[2u * ELS_SHA256_BLOCK];
    ElsHashCtx* ctx;
    word32 tailSz;
    word64 bitLen;
    int ret;
    int i;

    if (sha256->devCtx == NULL || sha256->devCtx == ELS_HASH_DECLINED) {
        /* never claimed, so software holds the whole message */
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ctx = (ElsHashCtx*)sha256->devCtx;

    /* residual, then 0x80, zeros, and a 64-bit big-endian bit count. A second
     * block is needed when the remainder leaves no room for the length. */
    XMEMSET(tail, 0, sizeof(tail));
    if (ctx->buffered > 0) {
        XMEMCPY(tail, ctx->buf, ctx->buffered);
    }
    tail[ctx->buffered] = 0x80;
    tailSz = (ctx->buffered + 1u + 8u > ELS_SHA256_BLOCK)
                 ? (2u * ELS_SHA256_BLOCK) : ELS_SHA256_BLOCK;

    bitLen = ctx->total * 8u;
    for (i = 0; i < 8; i++) {
        tail[tailSz - 1u - (word32)i] = (byte)(bitLen >> (8 * i));
    }

    ret = ElsHashBlocks(ctx, tail, tailSz);
    if (ret == 0) {
        /* after the padded tail the running state IS the digest */
        XMEMCPY(digest, ctx->state, WC_SHA256_DIGEST_SIZE);
    }

    ElsHashRelease(ctx);
    sha256->devCtx = NULL;

    ElsUnlock();
    ForceZero(tail, sizeof(tail));

    return ret;
}

/* Release a pool entry when the caller frees its hash without finalising. */
static void ElsSha256FreeCtx(wc_Sha256* sha256)
{
    if (sha256 == NULL) {
        return;
    }
    if (sha256->devCtx == ELS_HASH_DECLINED) {
        sha256->devCtx = NULL;
        return;
    }
    if (sha256->devCtx != NULL) {
        if (ElsLock() == 0) {
            ElsHashRelease((ElsHashCtx*)sha256->devCtx);
            ElsUnlock();
        }
        sha256->devCtx = NULL;
    }
}

/* Duplicate a hash.
 *
 * wc_Sha256Copy() otherwise falls through to a struct-wide XMEMCPY, which
 * copies devCtx verbatim and leaves two wc_Sha256 objects sharing one pool
 * entry. That is not a corner case: wc_Sha256GetHash() is Copy-then-Final and
 * is how TLS 1.3 snapshots its transcript hash on every handshake. Finalising
 * the copy would write through the shared state and hand the entry back to the
 * pool while the original still pointed at it.
 *
 * Note the callback runs BEFORE wc_Sha256Copy()'s own XMEMCPY and returning
 * anything but CRYPTOCB_UNAVAILABLE makes it return immediately - so this
 * handler owns the entire duplication, struct included, not just the devCtx
 * fix-up.
 *
 * CRYPTOCB_UNAVAILABLE is returned only when the source has no hardware state,
 * where the plain struct copy is exactly right. When the source IS on hardware
 * there is no software state to fall back on, so pool exhaustion has to be an
 * error rather than a silent alias. */
static int ElsSha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    ElsHashCtx* srcCtx;
    ElsHashCtx* dstCtx;
    int ret;

    if (src == NULL || dst == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (src->devCtx == NULL || src->devCtx == ELS_HASH_DECLINED) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* mirror the wc_Sha256Free(dst) the software path does before its copy */
    ElsSha256FreeCtx(dst);

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    srcCtx = (ElsHashCtx*)src->devCtx;

    dstCtx = ElsHashClaim(dst);
    if (dstCtx == NULL) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(MEMORY_E);
    }

    /* running state first, then re-own it - the copy overwrote owner/inUse */
    XMEMCPY(dstCtx, srcCtx, sizeof(*dstCtx));
    dstCtx->owner = dst;
    dstCtx->inUse = 1;

    ElsUnlock();

    XMEMCPY(dst, src, sizeof(wc_Sha256));
    dst->devCtx = dstCtx;

    /* The fix-up wc_Sha256Copy() performs after its own XMEMCPY, which this
     * handler has skipped: every pointer the struct copy aliased onto the
     * source needs its own allocation. */
#ifdef WOLFSSL_SMALL_STACK_CACHE
    dst->W = (word32*)XMALLOC(sizeof(word32) * WC_SHA256_BLOCK_SIZE,
                              dst->heap, DYNAMIC_TYPE_DIGEST);
    if (dst->W == NULL) {
        ElsSha256FreeCtx(dst);
        XMEMSET(dst, 0, sizeof(wc_Sha256));
        return WC_NO_ERR_TRACE(MEMORY_E);
    }
#endif

#ifdef WOLFSSL_HASH_FLAGS
    dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif

#ifdef WOLFSSL_HASH_KEEP
    if (src->msg != NULL) {
        dst->msg = (byte*)XMALLOC(src->len, dst->heap,
                                  DYNAMIC_TYPE_TMP_BUFFER);
        if (dst->msg == NULL) {
            ElsSha256FreeCtx(dst);
            XMEMSET(dst, 0, sizeof(wc_Sha256));
            return WC_NO_ERR_TRACE(MEMORY_E);
        }
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

    return 0;
}

#endif /* !NO_SHA256 */

/* ---------------------------------------------------------------------------
 * AES-ECB / CBC / CTR
 *
 * Simpler than hashing: mcuxClEls_Cipher_Async takes the key and the data
 * together, so nothing has to survive between calls and the lock is held for
 * one operation. wolfCrypt keeps the raw key in aes->devKey precisely for
 * offload, and aes->reg carries the IV or counter, which ELS updates in place
 * through its in/out pIV - so chained calls continue correctly with no extra
 * bookkeeping here.
 *
 * ELS only knows 128- and 256-bit keys, and only whole blocks. AES-192 and any
 * trailing partial block are declined so software handles them; that is the
 * whole reason the fallback contract exists.
 * ------------------------------------------------------------------------ */

#ifndef NO_AES

unsigned long wc_ElsPkc_AesOffloadCount = 0;

static int ElsAesKeyOk(const Aes* aes)
{
    return (aes->keylen == 16 || aes->keylen == 32);
}

/* Issue one cipher command. Caller holds the lock. */
static int ElsCipherRun(mcuxClEls_CipherOption_t opt, Aes* aes,
                        const byte* in, word32 sz, byte* out, int useIv)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Cipher_Async(
        opt, 0u, (const uint8_t*)aes->devKey, (size_t)aes->keylen,
        in, sz, useIv ? (uint8_t*)aes->reg : NULL, out));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsAesCipher(Aes* aes, byte* out, const byte* in, word32 sz,
                        int mode, int encrypt, int useIv)
{
    mcuxClEls_CipherOption_t opt;
    byte lastCipher[MCUXCLELS_CIPHER_BLOCK_SIZE_AES];
    int ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* whole blocks only, and only key sizes the hardware represents */
    if (sz == 0 || (sz % MCUXCLELS_CIPHER_BLOCK_SIZE_AES) != 0 ||
        !ElsAesKeyOk(aes)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#ifdef WOLFSSL_AES_COUNTER
    /* CTR additionally needs an empty software keystream remainder. A partial
     * call leaves the unused tail of a generated block in aes->tmp and has
     * already advanced aes->reg past it, and the callback runs before that
     * remainder is consumed - so starting the hardware from aes->reg here
     * would silently drop it and desynchronise the stream. Hand the whole
     * message back to software once it has buffered anything. */
    if (mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR && aes->left != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
#endif

    opt.word.value = 0u;
    opt.bits.cphmde = (uint32_t)mode;
    opt.bits.dcrpt  = encrypt ? MCUXCLELS_CIPHER_ENCRYPT
                              : MCUXCLELS_CIPHER_DECRYPT;
    opt.bits.extkey = MCUXCLELS_CIPHER_EXTERNAL_KEY;
    if (useIv && mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR) {
        /* CTR: pIV carries the counter, and cphsoe is what makes ELS write the
         * updated counter back so a chained call continues correctly.
         *
         * NOT set for CBC. The documentation says both flags are ignored
         * there and pIV is always read and written - but setting them made
         * ELS produce output that was self-consistent yet disagreed with
         * software, i.e. it took pIV as an internal state blob rather than a
         * plain IV. Left off, CBC matches software exactly. */
        opt.bits.cphsie = MCUXCLELS_CIPHER_STATE_IN_ENABLE;
        opt.bits.cphsoe = MCUXCLELS_CIPHER_STATE_OUT_ENABLE;
    }

    /* CBC decrypt chains on the last ciphertext block, which is the input -
     * save it now because an in-place call is about to overwrite it. */
    if (mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC && !encrypt) {
        XMEMCPY(lastCipher, in + sz - MCUXCLELS_CIPHER_BLOCK_SIZE_AES,
                MCUXCLELS_CIPHER_BLOCK_SIZE_AES);
    }

    ret = ElsLock();
    if (ret == 0) {
        ret = ElsCipherRun(opt, aes, in, sz, out, useIv);
        ElsUnlock();
    }

    if (ret == 0) {
        /* Despite the documentation, this part does not write pIV back for
         * CBC, so a chained call would restart from the original IV. The next
         * IV is the last ciphertext block: the output when encrypting, the
         * saved input when decrypting. */
        if (mode == MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC) {
            if (encrypt) {
                XMEMCPY(aes->reg, out + sz - MCUXCLELS_CIPHER_BLOCK_SIZE_AES,
                        MCUXCLELS_CIPHER_BLOCK_SIZE_AES);
            }
            else {
                XMEMCPY(aes->reg, lastCipher,
                        MCUXCLELS_CIPHER_BLOCK_SIZE_AES);
            }
        }
        ELS_COUNT(wc_ElsPkc_AesOffloadCount);
    }

    ForceZero(lastCipher, sizeof(lastCipher));

    return ret;
}

#endif /* ELS_HAVE_AES_CIPHER */

/* ---------------------------------------------------------------------------
 * AES-GCM
 *
 * ELS drives GCM as a four-stage sequence - Init, UpdateAad, UpdateData,
 * Finalize - threaded through an 80-byte context. wolfCrypt's callback hands
 * the whole message over at once, so the sequence runs start to finish under a
 * single lock and no state has to survive between calls.
 *
 * Every stage consumes whole 16-byte blocks. The true AAD and data lengths
 * reach the hardware only through Finalize, plus msgendw for the final partial
 * data block; getting either wrong yields a clean-looking but wrong tag.
 * ------------------------------------------------------------------------ */

#ifdef HAVE_AESGCM

unsigned long wc_ElsPkc_GcmOffloadCount = 0;

#define ELS_GCM_BLOCK MCUXCLELS_AEAD_IV_BLOCK_SIZE

/* Constant-time compare, 0 when equal. Kept local rather than reaching for
 * misc.c's ConstantCompare, whose visibility depends on the inline-misc
 * build knobs. */
static int ElsCtCompare(const byte* a, const byte* b, word32 len)
{
    byte diff = 0;
    word32 i;

    for (i = 0; i < len; i++) {
        diff |= (byte)(a[i] ^ b[i]);
    }

    return (int)diff;
}

/* Each stage below is its own function so the flow-protection macro pair stays
 * within one scope, matching the rest of this port. Caller holds the lock. */

static int ElsGcmInit(mcuxClEls_AeadOption_t opt, const Aes* aes,
                      const byte* j0, byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_Init_Async(
        opt, 0u, (const uint8_t*)aes->devKey, (size_t)aes->keylen,
        j0, (size_t)ELS_GCM_BLOCK, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Init_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsGcmAadChunk(mcuxClEls_AeadOption_t opt, const Aes* aes,
                          const byte* aad, word32 len, byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_UpdateAad_Async(
        opt, 0u, (const uint8_t*)aes->devKey, (size_t)aes->keylen,
        aad, (size_t)len, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateAad_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsGcmDataChunk(mcuxClEls_AeadOption_t opt, const Aes* aes,
                           const byte* in, word32 len, byte* out,
                           byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_UpdateData_Async(
        opt, 0u, (const uint8_t*)aes->devKey, (size_t)aes->keylen,
        in, (size_t)len, out, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_UpdateData_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsGcmFinal(mcuxClEls_AeadOption_t opt, const Aes* aes,
                       word32 aadSz, word32 dataSz, byte* tag, byte* aeadCtx)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Aead_Finalize_Async(
        opt, 0u, (const uint8_t*)aes->devKey, (size_t)aes->keylen,
        (size_t)aadSz, (size_t)dataSz, tag, aeadCtx));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Aead_Finalize_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

/* AAD is fed as whole blocks; the tail goes through a zero-padded scratch
 * block, and Finalize's aadLength is what tells the hardware how much of that
 * last block was real. */
static int ElsGcmAad(mcuxClEls_AeadOption_t opt, const Aes* aes,
                     const byte* aad, word32 aadSz, byte* aeadCtx)
{
    ALIGN32 byte block[ELS_GCM_BLOCK];
    word32 full = aadSz & ~(word32)(ELS_GCM_BLOCK - 1u);
    word32 tail = aadSz - full;
    int ret = 0;

    if (full > 0u) {
        ret = ElsGcmAadChunk(opt, aes, aad, full, aeadCtx);
    }

    if (ret == 0 && tail > 0u) {
        XMEMSET(block, 0, sizeof(block));
        XMEMCPY(block, aad + full, tail);
        ret = ElsGcmAadChunk(opt, aes, block, ELS_GCM_BLOCK, aeadCtx);
        ForceZero(block, sizeof(block));
    }

    return ret;
}

static int ElsAesGcm(Aes* aes, byte* out, const byte* in, word32 sz,
                     const byte* iv, word32 ivSz,
                     byte* authTag, word32 authTagSz,
                     const byte* authIn, word32 authInSz, int encrypt)
{
    mcuxClEls_AeadOption_t opt;
    mcuxClEls_AeadOption_t stageOpt;
    ALIGN32 byte aeadCtx[MCUXCLELS_AEAD_CONTEXT_SIZE];
    ALIGN32 byte j0[ELS_GCM_BLOCK];
    ALIGN32 byte inBlock[ELS_GCM_BLOCK];
    ALIGN32 byte outBlock[ELS_GCM_BLOCK];
    byte   tag[MCUXCLELS_AEAD_TAG_SIZE];
    word32 full, tail;
    int ret;

    if (aes == NULL || iv == NULL || authTag == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if ((sz > 0 && (in == NULL || out == NULL)) ||
        (authInSz > 0 && authIn == NULL)) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* Decline what the hardware does not represent:
     *  - only a 12-byte IV maps onto the single-block J0 that Aead_Init takes;
     *    other lengths need the GHASH-based derivation via Aead_PartialInit.
     *  - ELS produces a 16-byte tag. A shorter one is its leftmost bytes,
     *    which is what GCM truncation means, so those are still served.
     *  - AES-192 has no ELS key size. */
    if (ivSz != GCM_NONCE_MID_SZ || authTagSz == 0 ||
        authTagSz > MCUXCLELS_AEAD_TAG_SIZE || !ElsAesKeyOk(aes)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* For a 96-bit IV, J0 is IV || 0x00000001 (SP 800-38D, 7.1). */
    XMEMSET(j0, 0, sizeof(j0));
    XMEMCPY(j0, iv, ivSz);
    j0[ELS_GCM_BLOCK - 1] = 0x01;

    opt.word.value   = 0u;
    opt.bits.dcrpt   = encrypt ? MCUXCLELS_AEAD_ENCRYPT
                               : MCUXCLELS_AEAD_DECRYPT;
    opt.bits.extkey  = MCUXCLELS_AEAD_EXTERN_KEY;
    opt.bits.acpsie  = MCUXCLELS_AEAD_STATE_IN_ENABLE;
    opt.bits.lastinit = MCUXCLELS_AEAD_LASTINIT_FALSE;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* Init builds the context rather than continuing one, so it is the single
     * stage that runs with state input disabled. */
    stageOpt = opt;
    stageOpt.bits.acpsie = MCUXCLELS_AEAD_STATE_IN_DISABLE;
    ret = ElsGcmInit(stageOpt, aes, j0, aeadCtx);

    if (ret == 0 && authInSz > 0) {
        ret = ElsGcmAad(opt, aes, authIn, authInSz, aeadCtx);
    }

    if (ret == 0 && sz > 0) {
        full = sz & ~(word32)(ELS_GCM_BLOCK - 1u);
        tail = sz - full;

        if (full > 0) {
            ret = ElsGcmDataChunk(opt, aes, in, full, out, aeadCtx);
        }
        if (ret == 0 && tail > 0) {
            /* msgendw carries the real byte count of the final block while the
             * block itself still arrives zero-padded - the same split between
             * padded buffer and true length that CMAC needs. */
            stageOpt = opt;
            stageOpt.bits.msgendw = (uint32_t)tail;

            XMEMSET(inBlock, 0, sizeof(inBlock));
            XMEMCPY(inBlock, in + full, tail);
            ret = ElsGcmDataChunk(stageOpt, aes, inBlock, ELS_GCM_BLOCK,
                                  outBlock, aeadCtx);
            if (ret == 0) {
                XMEMCPY(out + full, outBlock, tail);
            }
        }
    }

    if (ret == 0) {
        ret = ElsGcmFinal(opt, aes, authInSz, sz, tag, aeadCtx);
    }

    ElsUnlock();

    if (ret == 0) {
        if (encrypt) {
            XMEMCPY(authTag, tag, authTagSz);
        }
        else if (wc_ConstantCompare(tag, authTag, (int)authTagSz) != 0) {
            /* Match the software path: a failed tag check leaves no plaintext
             * behind for a caller that ignores the return value. */
            if (sz > 0) {
                XMEMSET(out, 0, sz);
            }
            ret = WC_NO_ERR_TRACE(AES_GCM_AUTH_E);
        }
        if (ret == 0) {
            ELS_COUNT(wc_ElsPkc_GcmOffloadCount);
        }
    }

    ForceZero(tag, sizeof(tag));
    ForceZero(j0, sizeof(j0));
    ForceZero(inBlock, sizeof(inBlock));
    ForceZero(outBlock, sizeof(outBlock));
    ForceZero(aeadCtx, sizeof(aeadCtx));

    return ret;
}

#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

/* ---------------------------------------------------------------------------
 * Random
 *
 * The one genuinely stateless primitive here: ELS hands over DRBG output with
 * nothing to carry between calls. Serving both WC_ALGO_TYPE_RNG and
 * WC_ALGO_TYPE_SEED means wolfCrypt's own Hash-DRBG is seeded from the
 * hardware too, rather than only the direct generate path being accelerated.
 * ------------------------------------------------------------------------ */

#ifndef WC_NO_RNG

unsigned long wc_ElsPkc_RngOffloadCount = 0;

static int ElsRandom(byte* out, word32 sz)
{
    int ret;

    if (out == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (sz == 0) {
        return 0;
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_Rng_DrbgRequest_Async(out, (size_t)sz));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Rng_DrbgRequest_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    ret = ElsWait();

    ElsUnlock();

    if (ret == 0) {
        wc_ElsPkc_RngOffloadCount++;
    }

    return ret;
}

#endif /* !WC_NO_RNG */

/* ---------------------------------------------------------------------------
 * AES-CMAC
 * ------------------------------------------------------------------------ */

/* pMac is [in, out] and carries the intermediate state, so it lives in the
 * caller's Cmac and the lock is held per call. */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES)

unsigned long wc_ElsPkc_CmacOffloadCount = 0;

#define ELS_CMAC_BLOCK MCUXCLELS_CIPHER_BLOCK_SIZE_AES
#define ELS_CMAC_STATE MCUXCLELS_CMAC_OUT_SIZE

#ifndef WOLFSSL_ELS_PKC_CMAC_CTX_COUNT
    #define WOLFSSL_ELS_PKC_CMAC_CTX_COUNT 2
#endif

typedef struct ElsCmacCtx {
    ALIGN32 byte state[ELS_CMAC_STATE];
    byte   key[32];
    word32 keySz;
    byte   buf[ELS_CMAC_BLOCK];
    word32 buffered;
    byte   started;
    byte   inUse;
    void*  owner;
} ElsCmacCtx;

static ElsCmacCtx elsCmacPool[WOLFSSL_ELS_PKC_CMAC_CTX_COUNT];

static ElsCmacCtx* ElsCmacClaim(void* owner)
{
    int i;

    for (i = 0; i < WOLFSSL_ELS_PKC_CMAC_CTX_COUNT; i++) {
        if (!elsCmacPool[i].inUse) {
            XMEMSET(&elsCmacPool[i], 0, sizeof(elsCmacPool[i]));
            elsCmacPool[i].inUse = 1;
            elsCmacPool[i].owner = owner;
            return &elsCmacPool[i];
        }
    }

    return NULL;
}

/* Feed one chunk. Caller holds the lock. */
static int ElsCmacChunk(ElsCmacCtx* ctx, const byte* in, word32 len, int final)
{
    mcuxClEls_CmacOption_t opt;

    opt.word.value = 0u;
    opt.bits.extkey = MCUXCLELS_CMAC_EXTERNAL_KEY_ENABLE;
    opt.bits.initialize = ctx->started ? MCUXCLELS_CMAC_INITIALIZE_DISABLE
                                       : MCUXCLELS_CMAC_INITIALIZE_ENABLE;
    opt.bits.finalize = final ? MCUXCLELS_CMAC_FINALIZE_ENABLE
                              : MCUXCLELS_CMAC_FINALIZE_DISABLE;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Cmac_Async(
        opt, 0u, ctx->key, (size_t)ctx->keySz, in, (size_t)len, ctx->state));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    ctx->started = 1;

    return ElsWait();
}

/* Release the pool entry behind an abandoned CMAC - one started on hardware
 * and dropped without a Final. Left alone the entry stays claimed forever, and
 * it also holds a plaintext AES key. */
static void ElsCmacFreeCtx(Cmac* cmac)
{
    if (cmac == NULL || cmac->devCtx == NULL) {
        return;
    }
    if (ElsLock() == 0) {
        ForceZero(cmac->devCtx, sizeof(ElsCmacCtx));
        ElsUnlock();
    }
    cmac->devCtx = NULL;
}

static int ElsCmacInit(Cmac* cmac, const byte* key, word32 keySz)
{
    ElsCmacCtx* ctx;
    int ret;

    if (cmac == NULL || key == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (keySz != 16 && keySz != 32) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ctx = ElsCmacClaim(cmac);
    if (ctx == NULL) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    XMEMCPY(ctx->key, key, keySz);
    ctx->keySz = keySz;
    cmac->devCtx = ctx;

    ElsUnlock();

    return 0;
}

static int ElsCmacUpdate(Cmac* cmac, const byte* in, word32 inSz)
{
    ElsCmacCtx* ctx;
    word32 take;
    int ret;

    if (cmac == NULL || cmac->devCtx == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* A zero-length update is legal and absorbs nothing; in may be NULL. */
    if (inSz == 0) {
        return 0;
    }
    if (in == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* CMAC uses a different subkey for the final chunk and only the final call
     * knows which that is, so a full buffer is flushed only once more data is
     * known to follow. */
    while (inSz > 0) {
        take = ELS_CMAC_BLOCK - cmac->bufferSz;
        if (take > inSz) {
            take = inSz;
        }
        XMEMCPY(cmac->buffer + cmac->bufferSz, in, take);
        cmac->bufferSz += take;
        in += take;
        inSz -= take;

        if (cmac->bufferSz == ELS_CMAC_BLOCK && inSz > 0) {
            ret = ElsCmacChunk(cmac, cmac->buffer, ELS_CMAC_BLOCK, 0);
            if (ret != 0) {
                goto out;
            }
            cmac->bufferSz = 0;
        }
    }

out:
    ElsUnlock();

    return ret;
}

static int ElsCmacFinal(Cmac* cmac, byte* out, word32* outSz)
{
    word32 buffered;
    int ret;

    if (cmac == NULL || cmac->devCtx == NULL || out == NULL || outSz == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* Truncation to any length in [WC_CMAC_TAG_MIN_SZ, WC_CMAC_TAG_MAX_SZ] is
     * what wc_AesCmacVerify_ex() asks for. Refusing it is not a fallback: the
     * message is already absorbed and no software state remains. */
    if (*outSz < WC_CMAC_TAG_MIN_SZ || *outSz > ELS_CMAC_STATE) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* ELS takes inputLength as the length *before* padding but expects the
     * block already padded per SP 800-38B. Getting this wrong is quiet: exact
     * block multiples come out correct and every other length is wrong. */
    buffered = cmac->bufferSz;
    if (buffered < ELS_CMAC_BLOCK) {
        cmac->buffer[buffered] = 0x80;
        if (buffered + 1u < ELS_CMAC_BLOCK) {
            XMEMSET(cmac->buffer + buffered + 1u, 0,
                    ELS_CMAC_BLOCK - buffered - 1u);
        }
    }

    ret = ElsCmacChunk(cmac, cmac->buffer, buffered, 1);
    if (ret == 0) {
        XMEMCPY(out, cmac->digest, *outSz);
        ELS_COUNT(wc_ElsPkc_CmacOffloadCount);
    }

    /* The key is not needed again, and wc_CmacFinalNoFree() leaves the object
     * to the caller. */
    ForceZero(cmac->k1, WC_AES_BLOCK_SIZE);
    ForceZero(cmac->k2, WC_AES_BLOCK_SIZE);
    cmac->bufferSz = 0;
    cmac->devCtx   = NULL;

    ElsUnlock();

    return ret;
}

#endif /* WOLFSSL_CMAC && !NO_AES */

/* ---------------------------------------------------------------------------
 * Dispatch
 * ------------------------------------------------------------------------ */

int wc_ElsPkc_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
#if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    ElsHashObj hobj;
#endif

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    switch (info->algo_type) {
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
        case WC_ALGO_TYPE_CMAC:
            if (info->cmac.type != WC_CMAC_AES) {
                break;
            }
            /* cmac.c drives this as init / update / final, distinguished by
             * which pointers are present (see wc_CryptoCb_Cmac call sites). */
            if (info->cmac.key != NULL && info->cmac.in == NULL &&
                info->cmac.out == NULL) {
                ret = ElsCmacInit(info->cmac.cmac, info->cmac.key,
                                  info->cmac.keySz);
            }
            else if (info->cmac.out == NULL &&
                     info->cmac.cmac->devCtx != NULL) {
                /* in == NULL with a zero length is a legal update, and for an
                 * object this port owns software has no key schedule to fall
                 * back on - init returned through the device. */
                ret = ElsCmacUpdate(info->cmac.cmac, info->cmac.in,
                                    info->cmac.inSz);
            }
            else if (info->cmac.out != NULL && info->cmac.key == NULL &&
                     info->cmac.in == NULL) {
                ret = ElsCmacFinal(info->cmac.cmac, info->cmac.out,
                                   info->cmac.outSz);
            }
            /* the one-shot form (key + in + out together) is left to software:
             * it would need init/update/final stitched here for no gain */
            break;
#endif

#ifndef WC_NO_RNG
        case WC_ALGO_TYPE_RNG:
            ret = ElsRandom(info->rng.out, info->rng.sz);
            break;

        case WC_ALGO_TYPE_SEED:
            ret = ElsRandom(info->seed.seed, info->seed.sz);
            break;
#endif

#ifndef NO_AES
        case WC_ALGO_TYPE_CIPHER:
            switch (info->cipher.type) {
    #ifdef HAVE_AESGCM
                case WC_CIPHER_AES_GCM:
                    if (info->cipher.enc) {
                        ret = ElsAesGcm(info->cipher.aesgcm_enc.aes,
                                info->cipher.aesgcm_enc.out,
                                info->cipher.aesgcm_enc.in,
                                info->cipher.aesgcm_enc.sz,
                                info->cipher.aesgcm_enc.iv,
                                info->cipher.aesgcm_enc.ivSz,
                                info->cipher.aesgcm_enc.authTag,
                                info->cipher.aesgcm_enc.authTagSz,
                                info->cipher.aesgcm_enc.authIn,
                                info->cipher.aesgcm_enc.authInSz, 1);
                    }
                    else {
                        /* the decrypt struct keeps authTag const; the port
                         * only ever compares against it */
                        ret = ElsAesGcm(info->cipher.aesgcm_dec.aes,
                                info->cipher.aesgcm_dec.out,
                                info->cipher.aesgcm_dec.in,
                                info->cipher.aesgcm_dec.sz,
                                info->cipher.aesgcm_dec.iv,
                                info->cipher.aesgcm_dec.ivSz,
                                (byte*)info->cipher.aesgcm_dec.authTag,
                                info->cipher.aesgcm_dec.authTagSz,
                                info->cipher.aesgcm_dec.authIn,
                                info->cipher.aesgcm_dec.authInSz, 0);
                    }
                    break;
    #endif
    #ifdef HAVE_AES_CBC
                case WC_CIPHER_AES_CBC:
                    ret = ElsAesCipher(info->cipher.aescbc.aes,
                            info->cipher.aescbc.out, info->cipher.aescbc.in,
                            info->cipher.aescbc.sz,
                            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC,
                            info->cipher.enc, 1);
                    break;
    #endif
    #ifdef WOLFSSL_AES_COUNTER
                case WC_CIPHER_AES_CTR:
                    /* CTR keystream is symmetric, so the hardware always runs
                     * the "encrypt" direction regardless of the caller's. */
                    ret = ElsAesCipher(info->cipher.aesctr.aes,
                            info->cipher.aesctr.out, info->cipher.aesctr.in,
                            info->cipher.aesctr.sz,
                            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CTR, 1, 1);
                    break;
    #endif
    #if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT)
                case WC_CIPHER_AES_ECB:
                    ret = ElsAesCipher(info->cipher.aesecb.aes,
                            info->cipher.aesecb.out, info->cipher.aesecb.in,
                            info->cipher.aesecb.sz,
                            MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_ECB,
                            info->cipher.enc, 0);
                    break;
    #endif
                default:
                    break;
            }
            break;
#endif /* !NO_AES */

#if !defined(NO_SHA256)
        case WC_ALGO_TYPE_HASH:
            if (info->hash.type != WC_HASH_TYPE_SHA256 ||
                info->hash.sha256 == NULL) {
                break;
            }
            /* sha256.c calls this two ways and never both at once: update
             * passes (data, len, NULL) and final passes (NULL, 0, digest).
             * Claim each separately - the running state lives in the caller's
             * context, so there is no reason to see the whole message at once. */
            if (info->hash.digest != NULL) {
                ret = ElsSha256Final(info->hash.sha256, info->hash.digest);
                if (ret == 0) {
                    wc_ElsPkc_HashOffloadCount++;
                }
            }
            else if (info->hash.in != NULL) {
                ret = ElsSha256Update(info->hash.sha256, info->hash.in,
                                      info->hash.inSz);
                if (ret == 0) {
                    wc_ElsPkc_HashOffloadCount++;
                }
            }
            else {
                /* update of zero bytes with no buffer: nothing to absorb */
                ret = 0;
            }
            break;
#endif

#if defined(WOLF_CRYPTO_CB_COPY) && !defined(NO_SHA256)
        case WC_ALGO_TYPE_COPY:
            if (info->copy.algo == WC_ALGO_TYPE_HASH &&
                info->copy.type == WC_HASH_TYPE_SHA256) {
                ret = ElsSha256Copy((wc_Sha256*)info->copy.src,
                                    (wc_Sha256*)info->copy.dst);
            }
            break;
#endif

#if defined(WOLF_CRYPTO_CB_FREE)
        case WC_ALGO_TYPE_FREE:
    #if !defined(NO_SHA256)
            if (info->free.algo == WC_ALGO_TYPE_HASH &&
                info->free.type == WC_HASH_TYPE_SHA256) {
                ElsSha256FreeCtx((wc_Sha256*)info->free.obj);
            }
    #endif
    #if defined(WOLFSSL_CMAC) && !defined(NO_AES)
            if (info->free.algo == WC_ALGO_TYPE_CMAC) {
                ElsCmacFreeCtx((Cmac*)info->free.obj);
            }
    #endif
            /* Deliberately still CRYPTOCB_UNAVAILABLE: wolfCrypt treats any
             * other return as "the callback owns the whole teardown" and skips
             * its own, which would leak everything it would have released. We
             * only reclaim our pool entry. */
            break;
#endif

        default:
            /* Anything not claimed above falls back to software. */
            break;
    }

    return ret;
}

/* ---------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------ */

int wc_ElsPkc_Init(void)
{
    int ret;

    /* Init is expected from a single boot-time context (a Zephyr SYS_INIT
     * hook, or the application before it starts threads). It is deliberately
     * not safe to call concurrently with itself: creating the mutex is the
     * very thing that would have to be protected. */
    if (!elsLockInit) {
        if (wc_InitMutex(&elsLock) != 0) {
            return WC_NO_ERR_TRACE(BAD_MUTEX_E);
        }
        elsLockInit = 1;
    }

    /* Bring the subsystem out of reset and enable it. Without this the first
     * offload would drive a disabled peripheral. Safe to repeat. */
    ret = ElsEnable();
    if (ret != 0) {
        WOLFSSL_MSG("els_pkc: enable failed");
        return ret;
    }
    elsReady = 1;

#ifdef WOLFSSL_ZEPHYR
    /* after ElsEnable(): the peripheral must be clocked and out of reset
     * before its interrupt configuration will stick */
    ret = ElsIrqInit();
    if (ret != 0) {
        WOLFSSL_MSG("els_pkc: interrupt setup failed, falling back to polling");
        /* not fatal - ElsWait() polls when the IRQ is not armed */
    }
#endif

    /* Always attempt registration rather than trusting a cached flag: a
     * wolfCrypt_Cleanup() elsewhere clears the device table, and a flag saying
     * "already registered" would then be a lie. ALREADY_E just means the entry
     * survived, which is the outcome we want either way. */
    ret = wc_CryptoCb_RegisterDevice(WOLFSSL_ELS_PKC_DEVID,
                                     wc_ElsPkc_CryptoCb, NULL);
    if (ret != 0 && ret != WC_NO_ERR_TRACE(ALREADY_E)) {
        WOLFSSL_MSG("els_pkc: RegisterDevice failed");
        return ret;
    }

    elsRegistered = 1;

    return 0;
}

int wc_ElsPkc_Cleanup(void)
{
    /* Unregister first, so no new operation can enter the callback, and take
     * the lock before tearing it down so an in-flight operation on another
     * thread has finished. Freeing the mutex under a running ELS call would
     * leave that call unserialized against whatever ran next. */
    if (elsRegistered) {
        wc_CryptoCb_UnRegisterDevice(WOLFSSL_ELS_PKC_DEVID);
        elsRegistered = 0;
    }

    if (elsLockInit) {
        if (wc_LockMutex(&elsLock) == 0) {
            /* Drop every claimed pool entry. Left alone they stay marked in
             * use across the cleanup, so a later wc_ElsPkc_Init() comes up
             * with reduced or zero offload capacity for no visible reason -
             * and unrecoverably, because once elsLockInit is clear the free
             * paths can no longer take the lock to release them. The CMAC
             * pool also holds plaintext keys, which must not outlive a
             * shutdown. Any live wc_Sha256 or Cmac must be freed first. */
            ForceZero(elsHashPool, sizeof(elsHashPool));
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
            ForceZero(elsCmacPool, sizeof(elsCmacPool));
#endif
            (void)wc_UnLockMutex(&elsLock);
        }
        elsLockInit = 0;
        wc_FreeMutex(&elsLock);
    }

#ifdef WOLFSSL_ZEPHYR
    /* Disarm the interrupt: the ISR gives a semaphore this port now considers
     * dead, and nothing else owns the ELS IRQ. */
    if (elsIrqReady) {
        irq_disable(ELS_IRQn);
        elsIrqReady = 0;
    }
#endif

    return 0;
}

#endif /* WOLFSSL_ELS_PKC */
