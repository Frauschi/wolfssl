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

static wolfSSL_Mutex elsLock;
/* Read from the crypto-callback path, written by init/cleanup. Volatile so a
 * compiler cannot cache the flag across the mutex operations that order them. */
static volatile int elsLockInit = 0;
static volatile int elsRegistered = 0;

static int ElsLock(void)
{
    if (!elsLockInit) {
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

/* Waiting for completion.
 *
 * mcuxClEls_WaitForOperation() busy-spins with no timeout, and it does so
 * while this port holds the global ELS lock - so a wedged peripheral would
 * block every other caller, and on an RTOS it burns a whole timeslice doing
 * nothing useful during a multi-millisecond public-key operation.
 *
 * ELS raises an interrupt on completion, so where a kernel is available the
 * thread sleeps on a semaphore with a real time bound instead. The vendor call
 * is still made afterwards to harvest the status: its wait loop exits at once
 * when the operation has already finished, leaving just the error-code read.
 *
 * The spin remains the fallback for contexts where sleeping is not allowed -
 * ISR context, and anything running before the IRQ is wired up. */

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

/* Must be called with the lock held, and always paired with the _Async that
 * preceded it. */
static int ElsWait(void)
{
    int ret;
#ifdef WOLFSSL_ZEPHYR
    int timedOut = 0;

    if (ElsCanSleep()) {
        wc_ElsPkc_IrqWaitCount++;
        if (k_sem_take(&elsDone, K_MSEC(WOLFSSL_ELS_PKC_TIMEOUT_MS)) != 0) {
            timedOut = 1;
            wc_ElsPkc_TimeoutCount++;
            WOLFSSL_MSG("els_pkc: completion interrupt late, finishing "
                        "synchronously");
            /* Deliberately does NOT cancel the operation.
             * mcuxClEls_Reset_Async(MCUXCLELS_RESET_CANCEL) on an in-flight
             * operation trips the tamper controller and reboots the SoC -
             * measured, not theorised - which is a worse outcome than the wait
             * this timeout exists to bound. So the timeout degrades to the
             * vendor's own synchronous wait rather than trying to abort the
             * hardware. It still buys the normal case: the thread sleeps
             * instead of spinning, and a late interrupt is reported rather
             * than silently absorbed. */
        }
    }
    else {
        wc_ElsPkc_PollWaitCount++;
    }
#else
    wc_ElsPkc_PollWaitCount++;
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
#endif

    return ret;
}

/* Bring the subsystem out of reset, clock it and enable it. The els_pkc module
 * ships this helper for every platform it supports (lpc, mcxn, mimxrt, rw61x),
 * so the port stays SoC-agnostic. Repeating it is harmless. */
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

    /* The struct copy the caller would otherwise have done, then point the
     * duplicate at its own hardware context. */
    XMEMCPY(dst, src, sizeof(wc_Sha256));
    dst->devCtx = dstCtx;

    /* Everything below is the fix-up wc_Sha256Copy() performs after its own
     * XMEMCPY. Returning success here skips that function entirely, so any
     * pointer the struct copy just aliased onto the source has to be given
     * back its own allocation - otherwise freeing both hashes frees the same
     * block twice. Omitted on purpose: the SiLabs, PIC32, ESP32, MAXQ, ARIA
     * and async hooks, none of which can be in a build that also drives ELS.
     */
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
 * Dispatch
 * ------------------------------------------------------------------------ */

int wc_ElsPkc_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    switch (info->algo_type) {
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

#if defined(WOLF_CRYPTO_CB_FREE) && !defined(NO_SHA256)
        case WC_ALGO_TYPE_FREE:
            if (info->free.algo == WC_ALGO_TYPE_HASH &&
                info->free.type == WC_HASH_TYPE_SHA256) {
                ElsSha256FreeCtx((wc_Sha256*)info->free.obj);
            }
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
            (void)wc_UnLockMutex(&elsLock);
        }
        elsLockInit = 0;
        wc_FreeMutex(&elsLock);
    }

    return 0;
}

#endif /* WOLFSSL_ELS_PKC */
