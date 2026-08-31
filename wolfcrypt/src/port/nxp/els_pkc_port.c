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
 * ELS is one peripheral with global busy state, so every _Async call and its
 * WaitForOperation run under the lock below. That lock serializes wolfSSL's
 * own callers only; any other ELS user has to be arbitrated above both. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

/* On Zephyr the vendor headers arrive with the els_pkc module, which is a
 * separate choice from asking for the port. Name the option that was left out
 * rather than fail on a missing mcuxClEls.h. */
#if defined(WOLFSSL_ELS_PKC) && defined(__ZEPHYR__) && \
    !defined(CONFIG_MCUX_ELS_PKC)
    #error WOLFSSL_ELS_PKC requires the NXP els_pkc module (CONFIG_MCUX_ELS_PKC=y)
#endif

#ifdef WOLFSSL_ELS_PKC

#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/asn.h>
#endif

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

/* instrumentation: how many times the hardware path actually ran. Guarded to
 * match the declaration in the header - a definition without a visible
 * declaration loses its WOLFSSL_API linkage decoration. */
#ifndef NO_SHA256
unsigned long wc_ElsPkc_HashOffloadCount = 0;
#endif
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

/* mcuxClEls_WaitForOperation() busy-spins with no timeout, and does so while
 * this port holds the ELS lock. Where a kernel is available the thread sleeps
 * on the completion interrupt instead and the vendor call only harvests the
 * status. The spin stays the fallback for ISR context and pre-IRQ bring-up. */

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
            /* Deliberately does not cancel: mcuxClEls_Reset_Async(CANCEL)
             * on an in-flight operation trips the tamper controller and
             * reboots the SoC. Degrade to the vendor's synchronous wait. */
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

/* els_pkc ships this helper for every platform it supports, so the port stays
 * SoC-agnostic. */
static int ElsEnable(void)
{
    if (ELS_PowerDownWakeupInit(ELS) != 0) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    return 0;
}

/* Constant-time compare, 0 when equal. Local because misc.c's ConstantCompare
 * is only visible under some inline-misc build knobs. */
static int ElsCtCompare(const byte* a, const byte* b, word32 len)
{
    byte diff = 0;
    word32 i;

    for (i = 0; i < len; i++) {
        diff |= (byte)(a[i] ^ b[i]);
    }

    return (int)diff;
}

/* ---------------------------------------------------------------------------
 * Slot references and permission validation
 * ------------------------------------------------------------------------ */

/* Public bound, so a caller can range-check a slot without the NXP headers. */
#if (WC_ELSPKC_MAX_SLOT + 1) != MCUXCLELS_KEY_SLOTS
    #error WC_ELSPKC_MAX_SLOT is out of step with MCUXCLELS_KEY_SLOTS
#endif

int wc_ElsPkc_MakeKeyRef(const wc_ElsPkc_KeyRef* ref, byte* out, word32* outSz)
{
    if (ref == NULL || outSz == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (out == NULL) {
        *outSz = WC_ELSPKC_KEYREF_SZ;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }
    if (*outSz < WC_ELSPKC_KEYREF_SZ) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }
    if (ref->keyClass == WC_ELSPKC_KEY_NONE ||
        ref->keyClass > WC_ELSPKC_KEY_HKDF ||
        ref->slot > WC_ELSPKC_MAX_SLOT) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    XMEMSET(out, 0, WC_ELSPKC_KEYREF_SZ);
    out[0] = WC_ELSPKC_KEYREF_MAGIC_0;
    out[1] = WC_ELSPKC_KEYREF_MAGIC_1;
    out[2] = WC_ELSPKC_KEYREF_VER;
    out[3] = ref->keyClass;
    out[4] = ref->slot;
    out[5] = ref->flags;
    /* out[6..7] stay zero - reserved */
    if (ref->flags & WC_ELSPKC_REF_FLAG_BIND) {
        XMEMCPY(out + 8, ref->bind, WC_ELSPKC_BIND_SZ);
    }

    *outSz = WC_ELSPKC_KEYREF_SZ;

    return 0;
}

int wc_ElsPkc_ParseKeyRef(const byte* in, word32 inSz, wc_ElsPkc_KeyRef* ref)
{
    if (in == NULL || ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* wolfPSA stores the reference followed by the public point, so a longer
     * blob is expected - only the prefix belongs to us. */
    if (inSz < WC_ELSPKC_KEYREF_SZ) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }
    if (in[0] != WC_ELSPKC_KEYREF_MAGIC_0 ||
        in[1] != WC_ELSPKC_KEYREF_MAGIC_1) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (in[2] != WC_ELSPKC_KEYREF_VER) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (in[3] == WC_ELSPKC_KEY_NONE || in[3] > WC_ELSPKC_KEY_HKDF) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (in[4] > WC_ELSPKC_MAX_SLOT) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    XMEMSET(ref, 0, sizeof(*ref));
    ref->keyClass = in[3];
    ref->slot     = in[4];
    ref->flags    = in[5];
    if (ref->flags & WC_ELSPKC_REF_FLAG_BIND) {
        XMEMCPY(ref->bind, in + 8, WC_ELSPKC_BIND_SZ);
    }

    return 0;
}

#ifndef NO_AES
int wc_ElsPkc_AesUseSlot(Aes* aes, const wc_ElsPkc_KeyRef* ref,
                         void* heap, int devId)
{
    byte   blob[WC_ELSPKC_KEYREF_SZ];
    word32 blobSz = sizeof(blob);
    int    ret;

    if (aes == NULL || ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
/* Only the classes an Aes could drive. A CMAC key gets its own reference on
 * the Cmac object, which has its own id[]. */
    if (ref->keyClass != WC_ELSPKC_KEY_AES &&
        ref->keyClass != WC_ELSPKC_KEY_KWK) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = wc_ElsPkc_MakeKeyRef(ref, blob, &blobSz);
    if (ret == 0) {
        /* keyInstalled stays clear: the key is in the slot, not in a software
         * schedule, so an unwired operation fails instead of running on
         * zeros. */
        ret = wc_AesInit_Id(aes, blob, (int)blobSz, heap, devId);
    }

    ForceZero(blob, sizeof(blob));

    return ret;
}
#endif /* !NO_AES */

/* Read a slot's properties. Caller holds the lock. */
static int ElsKsProps(byte slot, mcuxClEls_KeyProp_t* prop)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_GetKeyProperties((mcuxClEls_KeyIndex_t)slot, prop));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_GetKeyProperties) != t) ||
        (MCUXCLELS_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* The ELS permission bit each class stands for. */
static word32 ElsClassUsageBit(byte keyClass)
{
    switch (keyClass) {
        case WC_ELSPKC_KEY_ECC_SIGN: return MCUXCLELS_KEYPROPERTY_VALUE_ECSGN;
        case WC_ELSPKC_KEY_ECC_DH:   return MCUXCLELS_KEYPROPERTY_VALUE_ECDH;
        case WC_ELSPKC_KEY_AES:      return MCUXCLELS_KEYPROPERTY_VALUE_AES;
        case WC_ELSPKC_KEY_HMAC:     return MCUXCLELS_KEYPROPERTY_VALUE_HMAC;
        case WC_ELSPKC_KEY_CMAC:     return MCUXCLELS_KEYPROPERTY_VALUE_CMAC;
        case WC_ELSPKC_KEY_KWK:      return MCUXCLELS_KEYPROPERTY_VALUE_KWK;
        case WC_ELSPKC_KEY_CKDF:     return MCUXCLELS_KEYPROPERTY_VALUE_CKDF;
        case WC_ELSPKC_KEY_HKDF:     return MCUXCLELS_KEYPROPERTY_VALUE_HKDF;
        default:                     return 0;
    }
}

/* Confirm the slot is occupied and carries the permission the class needs.
 * The bit must be present, never exclusive - one slot legitimately carries
 * several usage bits. ELS answers a permission violation by signalling the
 * tamper controller, which resets the SoC. Caller must hold the lock. */
static int ElsCheckSlot(const wc_ElsPkc_KeyRef* ref, byte expectClass)
{
    mcuxClEls_KeyProp_t prop;
    word32 need;

    if (ref->keyClass != expectClass) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    need = ElsClassUsageBit(ref->keyClass);
    if (need == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_GetKeyProperties((mcuxClEls_KeyIndex_t)ref->slot, &prop));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_GetKeyProperties) != t) ||
        (MCUXCLELS_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* An empty slot reads as all-zero properties, which fails the usage test
     * below anyway - but check it explicitly so the error says what is wrong. */
    if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if ((prop.word.value & need) == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * SHA-256 / SHA-384 / SHA-512
 * ------------------------------------------------------------------------ */

/* The engine round-trips its intermediate state (hashoe writes it, hashld
 * reloads it), so the state lives in the caller's object and the lock is held
 * for one call - holding it from update to final deadlocks TLS 1.3, which
 * keeps several transcript hashes alive at once. ELS never pads. */

#if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)

#define ELS_SHA256_BLOCK MCUXCLELS_HASH_BLOCK_SIZE_SHA_256
#define ELS_SHA256_STATE MCUXCLELS_HASH_STATE_SIZE_SHA_256

/* SHA-384 and SHA-512 share the engine's block and state size, differing in
 * the mode selector, the digest truncation and a 128-bit length field. */
#if defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
    #define ELS_HASH_SHA512
    #define ELS_HASH_MAX_BLOCK MCUXCLELS_HASH_BLOCK_SIZE_SHA_512
    #define ELS_HASH_MAX_STATE MCUXCLELS_HASH_STATE_SIZE_SHA_512
#else
    #define ELS_HASH_MAX_BLOCK ELS_SHA256_BLOCK
    #define ELS_HASH_MAX_STATE ELS_SHA256_STATE
#endif

/* A fixed pool rather than the heap: these parts are routinely built with
 * WOLFSSL_NO_MALLOC, and an empty pool degrades to software. */
#ifndef WOLFSSL_ELS_PKC_HASH_CTX_COUNT
    #define WOLFSSL_ELS_PKC_HASH_CTX_COUNT 4
#endif

/* Parked in devCtx when the pool was empty at the first update, so later calls
 * keep going to software instead of starting a digest missing earlier data. */
#define ELS_HASH_DECLINED ((void*)(wc_ptr_t)1)

typedef struct ElsHashCtx {
    /* Set when a block failed to reach the engine. total then counts bytes the
     * hardware never absorbed, so a later Final would pad a length it cannot
     * honour. */
    byte   failed;
    ALIGN32 byte state[ELS_HASH_MAX_STATE]; /* intermediate digest */
    byte   buf[ELS_HASH_MAX_BLOCK];         /* residual partial block */
    word32 buffered;
    word64 total;                         /* message length, for the padding */
    byte   started;                       /* has the engine seen a block yet */
    byte   inUse;
    byte   mode;                          /* MCUXCLELS_HASH_MODE_* in force */
    void*  owner;                         /* the hash object this belongs to */
} ElsHashCtx;

static ElsHashCtx elsHashPool[WOLFSSL_ELS_PKC_HASH_CTX_COUNT];

/* Engine block size for a hash mode. */
static word32 ElsHashBlockSz(byte mode)
{
    (void)mode;

#ifdef ELS_HASH_SHA512
    if (mode == MCUXCLELS_HASH_MODE_SHA_384 ||
        mode == MCUXCLELS_HASH_MODE_SHA_512) {
        return (word32)MCUXCLELS_HASH_BLOCK_SIZE_SHA_512;
    }
#endif

    return (word32)ELS_SHA256_BLOCK;
}

/* Width of the length field the padding ends with. */
static word32 ElsHashLenSz(byte mode)
{
    (void)mode;

#ifdef ELS_HASH_SHA512
    if (mode == MCUXCLELS_HASH_MODE_SHA_384 ||
        mode == MCUXCLELS_HASH_MODE_SHA_512) {
        return 16u;
    }
#endif

    return 8u;
}

/* Claim a pool entry for this hash. Caller must hold the lock. */
static ElsHashCtx* ElsHashClaim(void* owner, byte mode)
{
    int i;

    for (i = 0; i < WOLFSSL_ELS_PKC_HASH_CTX_COUNT; i++) {
        if (!elsHashPool[i].inUse) {
            XMEMSET(&elsHashPool[i], 0, sizeof(elsHashPool[i]));
            elsHashPool[i].inUse = 1;
            elsHashPool[i].owner = owner;
            elsHashPool[i].mode  = mode;
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
    opt.bits.hashmd = ctx->mode;
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

/* Absorb bytes into the context hanging off *devCtx, claiming one on the first
 * call. Every wolfCrypt hash object the port serves keeps its state here, so
 * the caller passes the address of its devCtx rather than the object. */
static int ElsHashUpdate(void** devCtx, byte mode, const byte* in, word32 inSz)
{
    ElsHashCtx* ctx;
    word32 blockSz, take, whole;
    int ret;

    if (*devCtx == ELS_HASH_DECLINED) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ctx = (ElsHashCtx*)*devCtx;
    if (ctx == NULL) {
        ctx = ElsHashClaim(devCtx, mode);
        if (ctx == NULL) {
            /* pool empty - hand this hash to software, permanently */
            *devCtx = ELS_HASH_DECLINED;
            ElsUnlock();
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        *devCtx = ctx;
    }

    blockSz = ElsHashBlockSz(ctx->mode);
    ctx->total += inSz;

    /* top up the residual block first */
    if (ctx->buffered > 0) {
        take = blockSz - ctx->buffered;
        if (take > inSz) {
            take = inSz;
        }
        XMEMCPY(ctx->buf + ctx->buffered, in, take);
        ctx->buffered += take;
        in += take;
        inSz -= take;

        if (ctx->buffered == blockSz) {
            ret = ElsHashBlocks(ctx, ctx->buf, blockSz);
            if (ret != 0) {
                goto out;
            }
            ctx->buffered = 0;
        }
    }

    /* whole blocks straight from the caller's buffer */
    whole = (inSz / blockSz) * blockSz;
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
    if (ret != 0) {
        /* total now counts bytes the engine never saw, so anything this
         * context produces from here is wrong. */
        ctx->failed = 1;
    }
    ElsUnlock();

    return ret;
}

/* Pad, absorb the tail, and take the digest from the running state. */
static int ElsHashFinal(void** devCtx, byte* digest, word32 digestSz)
{
    ALIGN32 byte tail[2u * ELS_HASH_MAX_BLOCK];
    ElsHashCtx* ctx;
    word32 blockSz, lenSz, tailSz;
    word64 bitLen;
    int ret;
    int i;

    if (*devCtx == NULL || *devCtx == ELS_HASH_DECLINED) {
        /* never claimed, so software holds the whole message */
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ctx = (ElsHashCtx*)*devCtx;
    blockSz = ElsHashBlockSz(ctx->mode);
    lenSz   = ElsHashLenSz(ctx->mode);

    /* A block failed earlier, so the padding below would claim a length that
     * was never hashed. Fail rather than hand back a plausible digest. */
    if (ctx->failed) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }

    /* residual, then 0x80, zeros, and a big-endian bit count of lenSz bytes. A
     * second block is needed when the remainder leaves no room for it. */
    XMEMSET(tail, 0, sizeof(tail));
    if (ctx->buffered > 0) {
        XMEMCPY(tail, ctx->buf, ctx->buffered);
    }
    tail[ctx->buffered] = 0x80;
    tailSz = (ctx->buffered + 1u + lenSz > blockSz)
                 ? (2u * blockSz) : blockSz;

    bitLen = ctx->total * 8u;
    for (i = 0; i < 8; i++) {
        tail[tailSz - 1u - (word32)i] = (byte)(bitLen >> (8 * i));
    }

    ret = ElsHashBlocks(ctx, tail, tailSz);
    if (ret == 0) {
        /* after the padded tail the running state IS the digest, truncated
         * for the modes whose output is shorter than the state */
        XMEMCPY(digest, ctx->state, digestSz);
    }

    ElsHashRelease(ctx);
    *devCtx = NULL;

    ElsUnlock();
    ForceZero(tail, sizeof(tail));

    return ret;
}

/* Release a pool entry when the caller frees its hash without finalising. */
static void ElsHashFreeCtx(void** devCtx)
{
    if (*devCtx == ELS_HASH_DECLINED) {
        *devCtx = NULL;
        return;
    }
    if (*devCtx != NULL) {
        if (ElsLock() == 0) {
            ElsHashRelease((ElsHashCtx*)*devCtx);
            ElsUnlock();
        }
        *devCtx = NULL;
    }
}

/* Duplicate the hardware half of a hash. Caller has already established that
 * the source is on hardware, and owns the struct copy afterwards. */
static int ElsHashCopyCtx(void** srcCtx, void** dstCtx, void* dstOwner)
{
    ElsHashCtx* src;
    ElsHashCtx* dst;
    int ret;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    src = (ElsHashCtx*)*srcCtx;

    dst = ElsHashClaim(dstOwner, src->mode);
    if (dst == NULL) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(MEMORY_E);
    }

    /* running state first, then re-own it - the copy overwrote owner/inUse */
    XMEMCPY(dst, src, sizeof(*dst));
    dst->owner = dstOwner;
    dst->inUse = 1;

    ElsUnlock();

    *dstCtx = dst;

    return 0;
}


#ifndef NO_SHA256

/* Duplicate a hash. The callback runs BEFORE wc_Sha256Copy()'s own XMEMCPY and
 * returning anything but CRYPTOCB_UNAVAILABLE makes it return immediately, so
 * this handler owns the whole duplication, struct included. A source on
 * hardware has no software state to fall back on, so pool exhaustion errors. */
static int ElsSha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    void* dstCtx = NULL;
    int ret;

    if (src == NULL || dst == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (src->devCtx == NULL || src->devCtx == ELS_HASH_DECLINED) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* The full teardown, not just our pool entry: success here skips the free
     * wc_Sha256Copy() would have done, and the struct copy below would then
     * strand whatever dst->msg and dst->W already owned. */
    wc_Sha256Free(dst);

    ret = ElsHashCopyCtx(&src->devCtx, &dstCtx, dst);
    if (ret != 0) {
        return ret;
    }

    XMEMCPY(dst, src, sizeof(wc_Sha256));
    dst->devCtx = dstCtx;

    /* The fix-up wc_Sha256Copy() performs after its own XMEMCPY, which this
     * handler has skipped: every pointer the struct copy aliased onto the
     * source needs its own allocation. */
#ifdef WOLFSSL_SMALL_STACK_CACHE
    dst->W = (word32*)XMALLOC(sizeof(word32) * WC_SHA256_BLOCK_SIZE,
                              dst->heap, DYNAMIC_TYPE_DIGEST);
    if (dst->W == NULL) {
        ElsHashFreeCtx(&dst->devCtx);
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
            ElsHashFreeCtx(&dst->devCtx);
            XMEMSET(dst, 0, sizeof(wc_Sha256));
            return WC_NO_ERR_TRACE(MEMORY_E);
        }
        XMEMCPY(dst->msg, src->msg, src->len);
    }
#endif

    return 0;
}

#endif /* !NO_SHA256 */

#ifdef ELS_HASH_SHA512

/* The SHA-512 counterpart of ElsSha256Copy. wc_Sha512Copy() has no allocation
 * to hand back, so there is no fix-up after the struct copy. */
static int ElsSha512Copy(wc_Sha512* src, wc_Sha512* dst)
{
    void* dstCtx = NULL;
    int ret;

    if (src == NULL || dst == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (src->devCtx == NULL || src->devCtx == ELS_HASH_DECLINED) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    wc_Sha512Free(dst);

    ret = ElsHashCopyCtx(&src->devCtx, &dstCtx, dst);
    if (ret != 0) {
        return ret;
    }

    XMEMCPY(dst, src, sizeof(wc_Sha512));
    dst->devCtx = dstCtx;

#ifdef WOLFSSL_HASH_FLAGS
    dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif

    return 0;
}

#endif /* ELS_HASH_SHA512 */

#endif /* !NO_SHA256 || WOLFSSL_SHA384 || WOLFSSL_SHA512 */

/* ---------------------------------------------------------------------------
 * AES-ECB / CBC / CTR
 * ------------------------------------------------------------------------ */

/* ELS knows only 128- and 256-bit keys and only whole blocks. AES-192 and any
 * trailing partial block are declined so software handles them. */

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
        wc_ElsPkc_AesOffloadCount++;
    }

    ForceZero(lastCipher, sizeof(lastCipher));

    return ret;
}

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

    /* Init builds the context rather than continuing one. The vendor driver
     * clears the state-input bit here explicitly; this port never sets it, so
     * a zeroed option word already says the same thing and the stage is passed
     * through unchanged. */
    stageOpt = opt;
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
        else if (ElsCtCompare(tag, authTag, authTagSz) != 0) {
            /* Match the software path: a failed tag check leaves no plaintext
             * behind for a caller that ignores the return value. */
            if (sz > 0) {
                ForceZero(out, sz);
            }
            ret = WC_NO_ERR_TRACE(AES_GCM_AUTH_E);
        }
        if (ret == 0) {
            wc_ElsPkc_GcmOffloadCount++;
        }
    }

    ForceZero(tag, sizeof(tag));
    ForceZero(inBlock, sizeof(inBlock));
    ForceZero(outBlock, sizeof(outBlock));
    ForceZero(aeadCtx, sizeof(aeadCtx));

    return ret;
}

#endif /* HAVE_AESGCM */

#endif /* !NO_AES */

/* ---------------------------------------------------------------------------
 * ECC over slot keys
 * ------------------------------------------------------------------------ */

/* P-256 only: the key property word has no bit for RSA or the Ed curves. ELS
 * speaks raw X9.62 (X||Y, R||S) where the callback boundary is DER. */

#ifdef HAVE_ECC

unsigned long wc_ElsPkc_EccOffloadCount = 0;

#define ELS_ECC_COORD_SZ 32                          /* P-256 */
#define ELS_ECC_PUB_SZ   MCUXCLELS_ECC_PUBLICKEY_SIZE /* X||Y   */
#define ELS_ECC_SIG_SZ   MCUXCLELS_ECC_SIGNATURE_SIZE /* R||S   */

/* Read the slot reference an ecc_key carries, if it carries one at all. */
static int ElsEccRef(const ecc_key* key, wc_ElsPkc_KeyRef* ref)
{
    if (key == NULL || key->idLen <= 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return wc_ElsPkc_ParseKeyRef(key->id, (word32)key->idLen, ref);
}

/* P-256 is the only curve with a slot to reference. */
static int ElsEccCurveOk(const ecc_key* key)
{
    return (key != NULL && key->dp != NULL &&
            key->dp->id == ECC_SECP256R1);
}

int wc_ElsPkc_EccUseSlot(ecc_key* key, const wc_ElsPkc_KeyRef* ref,
                         void* heap, int devId)
{
    byte   blob[WC_ELSPKC_KEYREF_SZ];
    word32 blobSz = sizeof(blob);
    int    ret;

    if (key == NULL || ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (ref->keyClass != WC_ELSPKC_KEY_ECC_SIGN &&
        ref->keyClass != WC_ELSPKC_KEY_ECC_DH) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    ret = wc_ElsPkc_MakeKeyRef(ref, blob, &blobSz);
    if (ret == 0) {
        ret = wc_ecc_init_id(key, blob, (int)blobSz, heap, devId);
    }
    if (ret == 0) {
        /* Pin the curve now. Without it the first operation would have to
         * infer P-256 from a key whose private part it can never see. */
        ret = wc_ecc_set_curve(key, ELS_ECC_COORD_SZ, ECC_SECP256R1);
        if (ret != 0) {
            wc_ecc_free(key);
        }
    }

    ForceZero(blob, sizeof(blob));

    return ret;
}

/* Generate a key inside the slot the reference names. The reference is a
 * request, not a lookup: the slot is empty and the flags say what the key may
 * do. This is also the only moment the public point is available. */
static int ElsEccKeyGen(ecc_key* key)
{
    mcuxClEls_EccKeyGenOption_t opt;
    mcuxClEls_KeyProp_t         prop;
    wc_ElsPkc_KeyRef            ref;
    ALIGN32 byte pub[ELS_ECC_PUB_SZ];
    int ret;

    ret = ElsEccRef(key, &ref);
    if (ret != 0) {
        return ret;
    }
    if (!ElsEccCurveOk(key)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (ref.keyClass != WC_ELSPKC_KEY_ECC_SIGN &&
        ref.keyClass != WC_ELSPKC_KEY_ECC_DH) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* Ask for as little as possible. The usage bit, key size and slot kind are
     * set by the hardware from kgtypedh, and a property word ELS disagrees
     * with is a tamper event, not an error return. ElsCheckSlot() reads the
     * bits back before first use. */
    prop.word.value = 0u;
    prop.bits.upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_FALSE;
    prop.bits.upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_FALSE;
    if (ref.flags & WC_ELSPKC_REF_FLAG_EXPORTABLE) {
        prop.bits.wrpok = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;
    }
    /* WC_ELSPKC_REF_FLAG_PERSISTENT is parsed but not applied: retention is a
     * slot attribute, not something a generation requests. */

    opt.word.value  = 0u;
    opt.bits.kgsrc  = MCUXCLELS_ECC_OUTPUTKEY_RANDOM;
    opt.bits.kgtypedh = (ref.keyClass == WC_ELSPKC_KEY_ECC_DH)
                        ? MCUXCLELS_ECC_OUTPUTKEY_KEYEXCHANGE
                        : MCUXCLELS_ECC_OUTPUTKEY_SIGN;
    opt.bits.kgsign = MCUXCLELS_ECC_PUBLICKEY_SIGN_DISABLE;
    opt.bits.kgsign_rnd = MCUXCLELS_ECC_NO_RANDOM_DATA;
    opt.bits.skip_pbk = MCUXCLELS_ECC_GEN_PUBLIC_KEY;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* Validate the target even though it should still be empty, and refuse an
     * occupied slot: overwriting a key nobody asked to replace is not this
     * function's decision. */
    {
        mcuxClEls_KeyProp_t cur;

        ret = ElsKsProps(ref.slot, &cur);
        if (ret == 0 &&
            (cur.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE)) {
            ret = WC_NO_ERR_TRACE(BAD_STATE_E);
        }
        if (ret != 0) {
            ElsUnlock();
            return ret;
        }
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_EccKeyGen_Async(
        opt, 0u, (mcuxClEls_KeyIndex_t)ref.slot, prop, NULL, pub));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyGen_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    ret = ElsWait();

    ElsUnlock();

    if (ret == 0) {
        /* Keep the id[] reference: wc_ecc_import_unsigned would otherwise be
         * the last word on this key and the slot would be forgotten. */
        byte savedId[ECC_MAX_ID_LEN];
        int  savedLen = key->idLen;

        XMEMCPY(savedId, key->id, sizeof(savedId));

        ret = wc_ecc_import_unsigned(key, pub, pub + ELS_ECC_COORD_SZ,
                                     NULL, ECC_SECP256R1);
        if (ret == 0) {
            XMEMCPY(key->id, savedId, sizeof(savedId));
            key->idLen = savedLen;
            wc_ElsPkc_EccOffloadCount++;
        }
        ForceZero(savedId, sizeof(savedId));
    }

    ForceZero(pub, sizeof(pub));

    return ret;
}

/* Issue the sign command. Caller holds the lock and has validated the slot.
 * Split out so the flow-protection macro pair stays within one scope. */
static int ElsEccSignRun(mcuxClEls_EccSignOption_t opt, byte slot,
                         const byte* hash, byte* sig)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_EccSign_Async(
        opt, (mcuxClEls_KeyIndex_t)slot, hash, NULL, 0u, sig));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccSign_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsEccSign(const byte* in, word32 inlen, byte* out, word32* outlen,
                      ecc_key* key)
{
    mcuxClEls_EccSignOption_t opt;
    wc_ElsPkc_KeyRef ref;
    ALIGN32 byte hash[ELS_ECC_COORD_SZ];
    ALIGN32 byte sig[ELS_ECC_SIG_SZ];
    int ret;

    if (in == NULL || out == NULL || outlen == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    ret = ElsEccRef(key, &ref);
    if (ret != 0) {
        return ret;
    }
    if (!ElsEccCurveOk(key) || ref.keyClass != WC_ELSPKC_KEY_ECC_SIGN) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* ELS consumes a full 32-byte digest. Rather than guess whether a caller
     * wants left-padding or truncation, decline. */
    if (inlen != ELS_ECC_COORD_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    XMEMCPY(hash, in, ELS_ECC_COORD_SZ);

    opt.word.value    = 0u;
    opt.bits.echashchl = MCUXCLELS_ECC_HASHED;
    opt.bits.signrtf   = MCUXCLELS_ECC_NO_RTF;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ret = ElsCheckSlot(&ref, WC_ELSPKC_KEY_ECC_SIGN);
    if (ret == 0) {
        ret = ElsEccSignRun(opt, ref.slot, hash, sig);
    }

    ElsUnlock();

    if (ret == 0) {
        /* ELS returns raw R||S; the callback boundary is DER. */
        ret = StoreECC_DSA_Sig_Bin(out, outlen,
                                   sig, ELS_ECC_COORD_SZ,
                                   sig + ELS_ECC_COORD_SZ, ELS_ECC_COORD_SZ);
        if (ret == 0) {
            wc_ElsPkc_EccOffloadCount++;
        }
    }

    ForceZero(hash, sizeof(hash));
    ForceZero(sig, sizeof(sig));

    return ret;
}

/* Verification needs no slot - the public key is ordinary wolfCrypt material,
 * so this accelerates any P-256 verify, vaulted key or not. */
static int ElsEccVerify(const byte* sig, word32 siglen, const byte* hashIn,
                        word32 hashlen, int* res, ecc_key* key)
{
    mcuxClEls_EccVerifyOption_t opt;
    ALIGN32 byte sigAndPub[ELS_ECC_SIG_SZ + ELS_ECC_PUB_SZ];
    ALIGN32 byte hash[ELS_ECC_COORD_SZ];
    ALIGN32 byte rCalc[ELS_ECC_COORD_SZ];
    byte   x963[1 + ELS_ECC_PUB_SZ];
    word32 x963Sz = sizeof(x963);
    word32 rLen = ELS_ECC_COORD_SZ, sLen = ELS_ECC_COORD_SZ;
    int    ret;

    if (sig == NULL || hashIn == NULL || res == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (!ElsEccCurveOk(key) || hashlen != ELS_ECC_COORD_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    *res = 0;

    /* DER in, raw R||S out, both fixed 32-byte components. */
    ret = DecodeECC_DSA_Sig_Bin(sig, siglen, sigAndPub, &rLen,
                                sigAndPub + ELS_ECC_COORD_SZ, &sLen);
    if (ret != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (rLen != ELS_ECC_COORD_SZ || sLen != ELS_ECC_COORD_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* X9.62 uncompressed is 0x04 || X || Y; ELS wants the point without the
     * leading tag byte. */
    ret = wc_ecc_export_x963_ex(key, x963, &x963Sz, 0);
    if (ret != 0 || x963Sz != sizeof(x963) || x963[0] != 0x04) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    XMEMCPY(sigAndPub + ELS_ECC_SIG_SZ, x963 + 1, ELS_ECC_PUB_SZ);
    XMEMCPY(hash, hashIn, ELS_ECC_COORD_SZ);

    opt.word.value     = 0u;
    opt.bits.echashchl = MCUXCLELS_ECC_HASHED;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_EccVerify_Async(
        opt, hash, NULL, 0u, sigAndPub, rCalc));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccVerify_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        ElsUnlock();
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    ret = ElsWait();

    ElsUnlock();

    if (ret == 0) {
        /* THE RESULT IS THE COMPARISON, NOT THE STATUS. ELS does not report a
         * bad signature through the return code: it recomputes R, and the
         * verification succeeds only if that equals the caller's R. */
        *res = (ElsCtCompare(rCalc, sigAndPub, ELS_ECC_COORD_SZ) == 0);
        wc_ElsPkc_EccOffloadCount++;
    }

    ForceZero(hash, sizeof(hash));
    ForceZero(rCalc, sizeof(rCalc));

    return ret;
}

#endif /* HAVE_ECC */

/* ---------------------------------------------------------------------------
 * PKC tier
 * ------------------------------------------------------------------------ */

/* The PKC workarea is a FIXED HARDWARE REGION at PKC_RAM_ADDR, not memory the
 * caller chose, even though mcuxClSession_init() takes it as a pointer. That
 * shared region is why PKC work runs under the same lock as ELS. Nothing here
 * is vaulted: the PKC accelerates ordinary in-memory key material. */

/* Shared by every PKC consumer - RSA, ECDSA and X25519 - so guarded on the
 * union of them, not on RSA alone. */
#if !defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_CURVE25519)
#define ELS_PKC_HAVE_SESSION

#include <mcuxClSession.h>
#include <mcuxClPkc_Types.h>   /* MCUXCLPKC_PACKARGS4, used by the ECC
                                * domain-parameter packing macro */
#include <mcuxClRandom.h>
#include <mcuxClRandomModes.h>
#ifdef HAVE_ECC
    #include <mcuxClEcc.h>     /* here, not in the X25519 block below: the
                                * ECDSA code needs it whether or not the
                                * Montgomery curves are built */
#endif
#ifndef NO_RSA
    #include <mcuxClRsa.h>
#endif

/* Fixed PKC RAM window on rw61x, mirrored from the vendor platform header so a
 * build that does not export ip_platform.h still gets the right region. */
#ifndef WOLFSSL_ELS_PKC_RAM_ADDR
    #define WOLFSSL_ELS_PKC_RAM_ADDR 0x5015A000u
#endif
#ifndef WOLFSSL_ELS_PKC_RAM_SIZE
    #define WOLFSSL_ELS_PKC_RAM_SIZE 0x2000u
#endif

/* Large enough for every operation this port claims: RSA sign/verify tops out
 * at 536 bytes (4096-bit, NoEncode) and ECC at 504. */
#ifndef WOLFSSL_ELS_PKC_CPU_WA_SZ
    #define WOLFSSL_ELS_PKC_CPU_WA_SZ 1024
#endif

#ifndef NO_RSA
unsigned long wc_ElsPkc_RsaOffloadCount = 0;
#endif

static uint32_t elsPkcCpuWa[(WOLFSSL_ELS_PKC_CPU_WA_SZ + 3u) / 4u];
static uint32_t elsPkcRngCtx[64];

/* The DRBG the PKC operations draw from. Not the ELS one: its security
 * strength is 128 bits on this part, so mcuxClEcc_Sign returns RNG_ERROR for
 * P-384 and P-521 - a failure that names the random source, not the curve. The
 * CTR_DRBG at 256 bits covers every selectable curve. Caller holds the lock. */
static int ElsPkcRandomInit(mcuxClSession_Descriptor_t* sess)
{
    XMEMSET(elsPkcRngCtx, 0, sizeof(elsPkcRngCtx));

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(rr, rt, mcuxClRandom_init(
        sess, (mcuxClRandom_Context_t)elsPkcRngCtx,
        mcuxClRandomModes_Mode_CtrDrbg_AES256_DRG3));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != rt) ||
        (MCUXCLRANDOM_STATUS_OK != rr)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcRandomNcInit(mcuxClSession_Descriptor_t* sess)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(pr, pt, mcuxClRandom_ncInit(sess));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != pt) ||
        (MCUXCLRANDOM_STATUS_OK != pr)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcSessionInit(mcuxClSession_Descriptor_t* sess)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sr, st, mcuxClSession_init(
        sess, elsPkcCpuWa, WOLFSSL_ELS_PKC_CPU_WA_SZ,
        (uint32_t*)WOLFSSL_ELS_PKC_RAM_ADDR, WOLFSSL_ELS_PKC_RAM_SIZE));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_init) != st) ||
        (MCUXCLSESSION_STATUS_OK != sr)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* Bring up a session over the shared workareas. Caller holds the lock. */
static int ElsPkcSessionOpen(mcuxClSession_Descriptor_t* sess)
{
    int ret = ElsPkcSessionInit(sess);

    if (ret == 0) {
        ret = ElsPkcRandomInit(sess);
    }
    if (ret == 0) {
        ret = ElsPkcRandomNcInit(sess);
    }

    return ret;
}

#ifndef NO_RSA

/* Export an mp_int as a fixed-width big-endian string, which is the only form
 * the vendor key entries accept. */
static int ElsPkcMpToBin(mp_int* a, byte* out, word32 len)
{
    if (mp_unsigned_bin_size(a) > (int)len) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }

    return mp_to_unsigned_bin_len(a, out, (int)len);
}

/* RSAVP1: the raw public operation, out = in^e mod n. */
static int ElsPkcRsaPublic(mcuxClSession_Descriptor_t* sess,
                           mcuxClRsa_Key* k, const byte* in, word32 modLen,
                           byte* out)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClRsa_verify(
        sess, k, NULL, 0u, (mcuxCl_Buffer_t)(uintptr_t)in,
        (mcuxClRsa_SignVerifyMode)&mcuxClRsa_Mode_Verify_NoVerify,
        0u, 0u, out));
    /* RSAVP1 reports VERIFYPRIMITIVE_OK, not VERIFY_OK - the latter belongs to
     * the padded modes. */
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_verify) != t) ||
        ((MCUXCLRSA_STATUS_VERIFYPRIMITIVE_OK != r) &&
         (MCUXCLRSA_STATUS_VERIFY_OK != r))) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    (void)modLen;

    return 0;
}

/* RSASP1: the raw private operation, out = in^d mod n (by CRT when possible). */
static int ElsPkcRsaPrivate(mcuxClSession_Descriptor_t* sess,
                            mcuxClRsa_Key* k, const byte* in, word32 modLen,
                            byte* out)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClRsa_sign(
        sess, k, in, modLen,
        (mcuxClRsa_SignVerifyMode)&mcuxClRsa_Mode_Sign_NoEncode,
        0u, 0u, out));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRsa_sign) != t) ||
        (MCUXCLRSA_STATUS_SIGN_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* RSA at the raw primitive. wolfCrypt's callback sits in wc_RsaFunction_ex,
 * beneath all padding, so the matching vendor modes are NoVerify (RSAVP1) and
 * NoEncode (RSASP1) - also the only corner of this API that compiles, since
 * the rw61x encrypt/decrypt workarea macros carry unsubstituted placeholders. */
static int ElsPkcRsaFunction(const byte* in, word32 inLen, byte* out,
                             word32* outLen, int type, RsaKey* key)
{
    mcuxClSession_Descriptor_t sess;
    mcuxClRsa_Key      rsaKey;
    mcuxClRsa_KeyEntry_t e1, e2, e3, e4, e5;
    byte*  buf = NULL;
    word32 modLen;
    int    isPrivate;
    int    ret;

    if (in == NULL || out == NULL || outLen == NULL || key == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }

    modLen = (word32)mp_unsigned_bin_size(&key->n);
    /* The engine covers 512..4096-bit moduli in multiples of 8 bits. Anything
     * else, including a modulus wolfCrypt would accept, goes to software. */
    if (modLen < 64 || modLen > 512 || inLen != modLen) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (*outLen < modLen) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    isPrivate = (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT);

    /* One scratch block holds every key entry, sized for the CRT case: five
     * entries of at most half a modulus each, plus the modulus itself. */
    buf = (byte*)XMALLOC(modLen * 4u, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return WC_NO_ERR_TRACE(MEMORY_E);
    }
    XMEMSET(buf, 0, modLen * 4u);
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));

    if (!isPrivate) {
        /* public: N and E */
        e1.pKeyEntryData = buf;
        e1.keyEntryLength = modLen;
        ret = ElsPkcMpToBin(&key->n, e1.pKeyEntryData, modLen);

        if (ret == 0) {
            word32 eLen = (word32)mp_unsigned_bin_size(&key->e);
            e4.pKeyEntryData = buf + modLen;
            e4.keyEntryLength = eLen;
            ret = ElsPkcMpToBin(&key->e, e4.pKeyEntryData, eLen);
        }
        rsaKey.keytype = MCUXCLRSA_KEY_PUBLIC;
        rsaKey.pMod1 = &e1;
        rsaKey.pExp1 = &e4;
    }
    else {
        /* CRT is the whole point of offloading a private operation, so only
         * fall back when the key genuinely lacks the factors. */
        word32 half = (modLen + 1u) / 2u;

        if (mp_unsigned_bin_size(&key->p) > 0 &&
            mp_unsigned_bin_size(&key->q) > 0) {
            e1.pKeyEntryData = buf;              e1.keyEntryLength = half;
            e2.pKeyEntryData = buf + half;       e2.keyEntryLength = half;
            e3.pKeyEntryData = buf + 2u * half;  e3.keyEntryLength = half;
            e4.pKeyEntryData = buf + 3u * half;  e4.keyEntryLength = half;
            e5.pKeyEntryData = buf + 4u * half;  e5.keyEntryLength = half;

            ret = ElsPkcMpToBin(&key->p, e1.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->q,  e2.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->u,  e3.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->dP, e4.pKeyEntryData, half);
            if (ret == 0) ret = ElsPkcMpToBin(&key->dQ, e5.pKeyEntryData, half);

            rsaKey.keytype = MCUXCLRSA_KEY_PRIVATECRT;
            rsaKey.pMod1 = &e1;
            rsaKey.pMod2 = &e2;
            rsaKey.pQInv = &e3;
            rsaKey.pExp1 = &e4;
            rsaKey.pExp2 = &e5;
        }
        else {
            e1.pKeyEntryData = buf;           e1.keyEntryLength = modLen;
            e4.pKeyEntryData = buf + modLen;  e4.keyEntryLength = modLen;

            ret = ElsPkcMpToBin(&key->n, e1.pKeyEntryData, modLen);
            if (ret == 0) ret = ElsPkcMpToBin(&key->d, e4.pKeyEntryData, modLen);

            rsaKey.keytype = MCUXCLRSA_KEY_PRIVATEPLAIN;
            rsaKey.pMod1 = &e1;
            rsaKey.pExp1 = &e4;
        }
    }

    if (ret == 0) {
        ret = ElsLock();
    }
    if (ret == 0) {
        ret = ElsPkcSessionOpen(&sess);
        if (ret == 0) {
            ret = isPrivate
                ? ElsPkcRsaPrivate(&sess, &rsaKey, in, modLen, out)
                : ElsPkcRsaPublic(&sess, &rsaKey, in, modLen, out);
        }
        ElsUnlock();
    }

    if (ret == 0) {
        *outLen = modLen;
        wc_ElsPkc_RsaOffloadCount++;
    }

    ForceZero(buf, modLen * 4u);
    XFREE(buf, key->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif /* !NO_RSA */

#endif /* ELS_PKC_HAVE_SESSION */

/* ---------------------------------------------------------------------------
 * X25519
 * ------------------------------------------------------------------------ */

/* Only the shared secret is claimed; key generation stays in software. */

#ifdef HAVE_CURVE25519

#include <mcuxClKey.h>

unsigned long wc_ElsPkc_X25519OffloadCount = 0;

#define ELS_X25519_KEY_SZ MCUXCLECC_MONTDH_CURVE25519_SIZE_PRIVATEKEY

/* Wrap a raw key buffer in a vendor key descriptor. Caller holds the lock. */
static int ElsPkcKeyInit(mcuxClSession_Descriptor_t* sess,
                         mcuxClKey_Handle_t h, mcuxClKey_Type_t type,
                         byte* data)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClKey_init(
        sess, h, type, data, ELS_X25519_KEY_SZ));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != t) ||
        (MCUXCLKEY_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* The agreement itself, kept in its own scope so the flow-protection macro
 * pair - which expands to a do/while - stays balanced. */
static int ElsPkcMontDhRun(mcuxClSession_Descriptor_t* sess,
                           mcuxClKey_Handle_t priv, mcuxClKey_Handle_t pub,
                           byte* ss, uint32_t* len)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_MontDH_KeyAgreement(
        sess, priv, pub, ss, len));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_MontDH_KeyAgreement) != t) ||
        (MCUXCLECC_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcMontDh(mcuxClSession_Descriptor_t* sess,
                        const byte* priv, const byte* pub, byte* out,
                        word32* outLen)
{
    uint32_t privDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    uint32_t pubDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    ALIGN32 byte privBuf[ELS_X25519_KEY_SZ];
    ALIGN32 byte pubBuf[ELS_X25519_KEY_SZ];
    ALIGN32 byte ss[ELS_X25519_KEY_SZ];
    uint32_t len = 0u;
    int ret = 0;

    XMEMCPY(privBuf, priv, ELS_X25519_KEY_SZ);
    XMEMCPY(pubBuf, pub, ELS_X25519_KEY_SZ);

    ret = ElsPkcKeyInit(sess, (mcuxClKey_Handle_t)privDesc,
                        mcuxClKey_Type_Ecc_MontDH_Curve25519_PrivateKey,
                        privBuf);
    if (ret == 0) {
        ret = ElsPkcKeyInit(sess, (mcuxClKey_Handle_t)pubDesc,
                            mcuxClKey_Type_Ecc_MontDH_Curve25519_PublicKey,
                            pubBuf);
    }

    if (ret == 0) {
        ret = ElsPkcMontDhRun(sess, (mcuxClKey_Handle_t)privDesc,
                              (mcuxClKey_Handle_t)pubDesc, ss, &len);
    }

    if (ret == 0) {
        if (len != ELS_X25519_KEY_SZ || *outLen < len) {
            ret = WC_NO_ERR_TRACE(BUFFER_E);
        }
        else {
            XMEMCPY(out, ss, len);
            *outLen = len;
        }
    }

    ForceZero(privBuf, sizeof(privBuf));
    ForceZero(ss, sizeof(ss));

    return ret;
}

static int ElsPkcX25519(curve25519_key* privKey, curve25519_key* pubKey,
                        byte* out, word32* outLen, int endian)
{
    mcuxClSession_Descriptor_t sess;
    byte priv[ELS_X25519_KEY_SZ];
    byte pub[ELS_X25519_KEY_SZ];
    word32 privSz = sizeof(priv);
    word32 pubSz  = sizeof(pub);
    int ret;

    if (privKey == NULL || pubKey == NULL || out == NULL || outLen == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* The engine works little-endian, which is X25519's own wire order. A
     * big-endian request is wolfCrypt's legacy convention; decline it rather
     * than byte-swapping a shared secret behind the caller's back. */
    if (endian != EC25519_LITTLE_ENDIAN) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = wc_curve25519_export_private_raw_ex(privKey, priv, &privSz,
                                              EC25519_LITTLE_ENDIAN);
    if (ret == 0) {
        ret = wc_curve25519_export_public_ex(pubKey, pub, &pubSz,
                                             EC25519_LITTLE_ENDIAN);
    }
    if (ret != 0 || privSz != ELS_X25519_KEY_SZ ||
        pubSz != ELS_X25519_KEY_SZ) {
        ForceZero(priv, sizeof(priv));
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret == 0) {
        ret = ElsPkcSessionOpen(&sess);
        if (ret == 0) {
            ret = ElsPkcMontDh(&sess, priv, pub, out, outLen);
        }
        ElsUnlock();
    }

    if (ret == 0) {
        wc_ElsPkc_X25519OffloadCount++;
    }

    ForceZero(priv, sizeof(priv));

    return ret;
}

#endif /* HAVE_CURVE25519 */

/* ---------------------------------------------------------------------------
 * ECDSA on the PKC
 * ------------------------------------------------------------------------ */

/* Serves every curve but P-256, which the ELS tier answers first. The PKC has
 * no built-in curves: a, b, p, G and n are converted from wolfCrypt's hex into
 * shared scratch under the lock, keeping ~half a kilobyte off the stack. */

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)

#define ELS_PKC_ECC_MAX_P MCUXCLECC_WEIERECC_MAX_SIZE_PRIMEP
#define ELS_PKC_ECC_MAX_N MCUXCLECC_WEIERECC_MAX_SIZE_BASEPOINTORDER

unsigned long wc_ElsPkc_EccPkcOffloadCount = 0;

/* Curve constants for the operation in flight. Caller holds the lock. */
static struct {
    ALIGN32 byte a[ELS_PKC_ECC_MAX_P];
    ALIGN32 byte b[ELS_PKC_ECC_MAX_P];
    ALIGN32 byte p[ELS_PKC_ECC_MAX_P];
    ALIGN32 byte g[2 * ELS_PKC_ECC_MAX_P];
    ALIGN32 byte n[ELS_PKC_ECC_MAX_N];
} elsPkcCurve;

/* PrecG is (2^(byteLenN*4))*G, which an input verification needs and neither
 * wolfCrypt nor the vendor library ships. One entry: alternating curves
 * recomputes it, which is fine because P-256 never reaches here. */
static struct {
    ALIGN32 byte precG[2 * ELS_PKC_ECC_MAX_P];
    int    curveId;
    word32 lenP;
} elsPkcPrecG;

/* wolfCrypt stores curve constants as hex text; the engine wants fixed-width
 * big-endian octets with leading zeros. */
static int ElsPkcHexToBin(const char* hex, byte* out, word32 len)
{
    mp_int t;
    int ret;

    if (hex == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    ret = mp_init(&t);
    if (ret != 0) {
        return ret;
    }
    ret = mp_read_radix(&t, hex, MP_RADIX_HEX);
    if (ret == 0) {
        ret = mp_to_unsigned_bin_len(&t, out, (int)len);
    }
    mp_clear(&t);

    return ret;
}

/* Marshal a wolfCrypt curve into the engine's parameter block. */
static int ElsPkcLoadCurve(const ecc_key* key, mcuxClEcc_DomainParam_t* dp,
                           word32* lenPOut)
{
    const ecc_set_type* set;
    word32 lenP;
    int ret;

    if (key == NULL || key->dp == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    set  = key->dp;
    lenP = (word32)set->size;
    if (lenP == 0 || lenP > ELS_PKC_ECC_MAX_P) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsPkcHexToBin(set->Af, elsPkcCurve.a, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->Bf,    elsPkcCurve.b, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->prime, elsPkcCurve.p, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->Gx,    elsPkcCurve.g, lenP);
    if (ret == 0) ret = ElsPkcHexToBin(set->Gy,    elsPkcCurve.g + lenP, lenP);
    /* The order is carried at the same width as the prime, which holds for
     * every selectable curve; one needing more bytes would truncate here. */
    if (ret == 0) ret = ElsPkcHexToBin(set->order, elsPkcCurve.n, lenP);
    if (ret != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    /* Both leading bytes must be nonzero per the engine's contract. */
    if (elsPkcCurve.p[0] == 0 || elsPkcCurve.n[0] == 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    dp->pA = elsPkcCurve.a;
    dp->pB = elsPkcCurve.b;
    dp->pP = elsPkcCurve.p;
    dp->pG = elsPkcCurve.g;
    dp->pN = elsPkcCurve.n;
    dp->misc = mcuxClEcc_DomainParam_misc_Pack(lenP, lenP);

    *lenPOut = lenP;

    return 0;
}

static int ElsPkcEccSignRun(mcuxClSession_Descriptor_t* sess,
                            mcuxClEcc_Sign_Param_t* prm)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_Sign(sess, prm));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Sign) != t) ||
        (MCUXCLECC_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcEccSign(const byte* in, word32 inlen, byte* out,
                         word32* outlen, ecc_key* key)
{
    mcuxClSession_Descriptor_t sess;
    mcuxClEcc_Sign_Param_t prm;
    ALIGN32 byte priv[ELS_PKC_ECC_MAX_N];
    ALIGN32 byte sig[2 * ELS_PKC_ECC_MAX_N];
    ALIGN32 byte hash[ELS_PKC_ECC_MAX_N];
    word32 lenP = 0, privSz;
    int ret;

    if (in == NULL || out == NULL || outlen == NULL || key == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* The digest is copied into a fixed buffer, which bounds this more tightly
     * than the eight-bit byteLenHash field does. */
    if (inlen == 0 || inlen > 255 || inlen > sizeof(hash)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ret = ElsPkcLoadCurve(key, &prm.curveParam, &lenP);

    if (ret == 0) {
        privSz = lenP;
        if (wc_ecc_export_private_only(key, priv, &privSz) != 0 ||
            privSz != lenP) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }

    if (ret == 0) {
        XMEMCPY(hash, in, inlen);

        prm.pHash       = hash;
        prm.pPrivateKey = priv;
        prm.pSignature  = sig;
        prm.optLen      = mcuxClEcc_Sign_Param_optLen_Pack(inlen);
        prm.pMode       = &mcuxClEcc_ECDSA_ProtocolDescriptor;

        ret = ElsPkcSessionOpen(&sess);
        if (ret == 0) {
            ret = ElsPkcEccSignRun(&sess, &prm);
        }
    }

    ElsUnlock();

    if (ret == 0) {
        /* raw R||S out of the engine, DER at the callback boundary */
        ret = StoreECC_DSA_Sig_Bin(out, outlen, sig, lenP, sig + lenP, lenP);
        if (ret == 0) {
            wc_ElsPkc_EccPkcOffloadCount++;
        }
    }

    ForceZero(priv, sizeof(priv));
    ForceZero(hash, sizeof(hash));

    return ret;
}

#ifdef HAVE_ECC_VERIFY

static int ElsPkcPointMultRun(mcuxClSession_Descriptor_t* sess,
                              mcuxClEcc_PointMult_Param_t* prm)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_PointMult(sess, prm));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_PointMult) != t) ||
        (MCUXCLECC_STATUS_OK != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

/* Derive PrecG = (2^(byteLenN*4))*G for the loaded curve and keep it.
 * Caller holds the lock and has loaded the curve. */
static int ElsPkcPrecGet(mcuxClSession_Descriptor_t* sess,
                         const mcuxClEcc_DomainParam_t* dp, int curveId,
                         word32 lenP)
{
    mcuxClEcc_PointMult_Param_t prm;
    ALIGN32 byte scalar[ELS_PKC_ECC_MAX_N];
    int ret;

    if (elsPkcPrecG.curveId == curveId && elsPkcPrecG.lenP == lenP) {
        return 0;
    }
    /* The exponent byteLenN*4 is half the order's bit width, so the single set
     * bit lands halfway through the scalar. Even byte lengths only. */
    if ((lenP & 1u) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    XMEMSET(scalar, 0, sizeof(scalar));
    scalar[lenP / 2u - 1u] = 0x01;

    prm.curveParam = *dp;
    prm.pScalar    = scalar;
    prm.pPoint     = dp->pG;
    prm.pResult    = elsPkcPrecG.precG;
    prm.optLen     = 0u;

    ret = ElsPkcPointMultRun(sess, &prm);
    if (ret == 0) {
        elsPkcPrecG.curveId = curveId;
        elsPkcPrecG.lenP    = lenP;
    }
    else {
        elsPkcPrecG.curveId = ECC_CURVE_INVALID;
    }

    return ret;
}

static int ElsPkcEccVerifyRun(mcuxClSession_Descriptor_t* sess,
                              mcuxClEcc_Verify_Param_t* prm, int* res)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEcc_Verify(sess, prm));
    if (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEcc_Verify) != t) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    /* Unlike ELS, the PKC has a dedicated INVALID_SIGNATURE status, so here
     * the status is the answer and a wrong signature is not an error. */
    if (MCUXCLECC_STATUS_OK == r) {
        *res = 1;
    }
    else if (MCUXCLECC_STATUS_INVALID_SIGNATURE == r) {
        *res = 0;
    }
    else {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return 0;
}

static int ElsPkcEccVerify(const byte* sigDer, word32 sigLen,
                           const byte* hashIn, word32 hashLen, int* res,
                           ecc_key* key)
{
    mcuxClSession_Descriptor_t sess;
    mcuxClEcc_Verify_Param_t prm;
    ALIGN32 byte sig[2 * ELS_PKC_ECC_MAX_N];
    ALIGN32 byte hash[ELS_PKC_ECC_MAX_N];
    ALIGN32 byte pub[2 * ELS_PKC_ECC_MAX_P];
    ALIGN32 byte rOut[ELS_PKC_ECC_MAX_N];
    byte   x963[1 + 2 * ELS_PKC_ECC_MAX_P];
    word32 x963Sz = sizeof(x963);
    word32 lenP = 0, rLen, sLen;
    int    ret;

    if (sigDer == NULL || hashIn == NULL || res == NULL || key == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* As in the signer: the fixed buffer bounds this more tightly than the
     * eight-bit byteLenHash field does. */
    if (hashLen == 0 || hashLen > 255 || hashLen > sizeof(hash)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    *res = 0;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ret = ElsPkcLoadCurve(key, &prm.curveParam, &lenP);

    if (ret == 0) {
        rLen = lenP;
        sLen = lenP;
        if (DecodeECC_DSA_Sig_Bin(sigDer, sigLen, sig, &rLen,
                                  sig + lenP, &sLen) != 0 ||
            rLen != lenP || sLen != lenP) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
    }

    if (ret == 0) {
        if (wc_ecc_export_x963_ex(key, x963, &x963Sz, 0) != 0 ||
            x963Sz != (1u + 2u * lenP) || x963[0] != 0x04) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        else {
            XMEMCPY(pub, x963 + 1, 2u * lenP);
        }
    }

    if (ret == 0) {
        XMEMCPY(hash, hashIn, hashLen);
        ret = ElsPkcSessionOpen(&sess);
    }
    if (ret == 0) {
        ret = ElsPkcPrecGet(&sess, &prm.curveParam, key->dp->id, lenP);
    }
    if (ret == 0) {
        prm.pPrecG     = elsPkcPrecG.precG;
        prm.pHash      = hash;
        prm.pSignature = sig;
        prm.pPublicKey = pub;
        prm.pOutputR   = rOut;
        prm.optLen     = mcuxClEcc_Verify_Param_optLen_Pack(hashLen);

        ret = ElsPkcEccVerifyRun(&sess, &prm, res);
    }

    ElsUnlock();

    if (ret == 0) {
        wc_ElsPkc_EccPkcOffloadCount++;
    }

    ForceZero(hash, sizeof(hash));
    ForceZero(rOut, sizeof(rOut));

    return ret;
}

#endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC && HAVE_ECC_SIGN */

/* ---------------------------------------------------------------------------
 * Key store
 * ------------------------------------------------------------------------ */

/* These calls name two slots rather than one, and a permission mistake resets
 * the SoC, so both references are validated against the hardware first. */

#ifdef WOLF_CRYPTO_CB_KEYSTORE

unsigned long wc_ElsPkc_KeyStoreOffloadCount = 0;

/* The container is the key plus an 8-byte property/padding prefix, all inside
 * an RFC 3394 wrap that adds its own 8-byte integrity block. */
#define ELS_KS_BLOB_SZ(keySz) ((word32)(keySz) + 16u)

/* ELS derives with a fixed-width label/context block. */
#define ELS_KS_DERIV_SZ MCUXCLELS_CKDF_DERIVATIONDATA_SIZE

/* Map a stored key's ELS properties onto the facility's vocabulary. */
static word32 ElsKsTypeFromProp(const mcuxClEls_KeyProp_t* prop)
{
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_ECSGN) {
        return WC_KEYSTORE_KEY_ECC_SIGN;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_ECDH) {
        return WC_KEYSTORE_KEY_ECC_DH;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_HMAC) {
        return WC_KEYSTORE_KEY_HMAC;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_CMAC) {
        return WC_KEYSTORE_KEY_CMAC;
    }
    if (prop->word.value & MCUXCLELS_KEYPROPERTY_VALUE_AES) {
        return WC_KEYSTORE_KEY_AES;
    }

    return WC_KEYSTORE_KEY_NONE;
}

/* Key size in bits, from the two-bit size field. */
static word32 ElsKsBitsFromProp(const mcuxClEls_KeyProp_t* prop)
{
    /* The 512-bit encoding only exists on parts with an internal public-key
     * store; elsewhere the field holds 128 or 256 and nothing else. */
    switch (prop->word.value & 0x3u) {
        case MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_128: return 128;
        case MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_256: return 256;
#ifdef MCUXCL_FEATURE_ELS_PUK_INTERNAL
        case MCUXCLELS_KEYPROPERTY_VALUE_KEY_SIZE_512: return 512;
#endif
        default:                                       return 0;
    }
}

/* Find room for a key that does not exist yet, since PSA's generate has no way
 * for a caller to name a slot. The store is not empty on a fresh part, so the
 * only safe test is the hardware's active bit, and a 256-bit key needs a
 * consecutive pair. Advisory: reserve and generate together. */
int wc_ElsPkc_ReserveSlot(byte keyClass, wc_ElsPkc_KeyRef* ref)
{
    mcuxClEls_KeyProp_t prop;
    int need;
    int run = 0;
    int slot;
    int ret;

    if (ref == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (ElsClassUsageBit(keyClass) == 0) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    need = (keyClass == WC_ELSPKC_KEY_ECC_SIGN ||
            keyClass == WC_ELSPKC_KEY_ECC_DH) ? 2 : 1;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    for (slot = 0; slot <= WC_ELSPKC_MAX_SLOT; slot++) {
        ret = ElsKsProps((byte)slot, &prop);
        if (ret != 0) {
            break;
        }
        if (prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) {
            run = 0;
            continue;
        }
        if (++run == need) {
            XMEMSET(ref, 0, sizeof(*ref));
            ref->keyClass = keyClass;
            ref->slot     = (byte)(slot - (need - 1));
            ElsUnlock();
            return 0;
        }
    }

    ElsUnlock();

    return (ret == 0) ? WC_NO_ERR_TRACE(MEMORY_E) : ret;
}

/* Parse a reference and, when it must already exist, confirm the slot carries
 * the permission its class claims. */
static int ElsKsRef(const byte* ref, word32 refSz, byte expectClass,
                    int mustExist, wc_ElsPkc_KeyRef* out)
{
    int ret = wc_ElsPkc_ParseKeyRef(ref, refSz, out);

    if (ret != 0) {
        return ret;
    }
    if (out->keyClass != expectClass) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return mustExist ? ElsCheckSlot(out, expectClass) : 0;
}

/* ukwk both wraps and unwraps, ukuok only unwraps, so an export needs more
 * than an import does - the point of an unwrap-only key. */
static int ElsKsWrapRef(const byte* ref, word32 refSz, int needWrap,
                        wc_ElsPkc_KeyRef* out)
{
    mcuxClEls_KeyProp_t prop;
    int ret = wc_ElsPkc_ParseKeyRef(ref, refSz, out);

    if (ret != 0) {
        return ret;
    }
    if (out->keyClass != WC_ELSPKC_KEY_KWK) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    ret = ElsKsProps(out->slot, &prop);
    if (ret != 0) {
        return ret;
    }
    if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }
    if (needWrap) {
        if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_KWK) == 0) {
            return WC_NO_ERR_TRACE(BAD_STATE_E);
        }
    }
    else if ((prop.word.value & (MCUXCLELS_KEYPROPERTY_VALUE_KWK |
                                 MCUXCLELS_KEYPROPERTY_VALUE_KUOK)) == 0) {
        return WC_NO_ERR_TRACE(BAD_STATE_E);
    }

    return 0;
}

static int ElsKsImportRun(const byte* blob, word32 blobSz, byte wrapSlot,
                          byte targetSlot)
{
    mcuxClEls_KeyImportOption_t opt;

    opt.word.value = 0u;
    opt.bits.kfmt  = MCUXCLELS_KEYIMPORT_KFMT_RFC3394;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_KeyImport_Async(
        opt, blob, (size_t)blobSz, (mcuxClEls_KeyIndex_t)wrapSlot,
        (mcuxClEls_KeyIndex_t)targetSlot));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyImport_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsKsExportRun(byte wrapSlot, byte keySlot, byte* out)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_KeyExport_Async(
        (mcuxClEls_KeyIndex_t)wrapSlot, (mcuxClEls_KeyIndex_t)keySlot, out));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyExport_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsKsDeriveRun(byte srcSlot, byte targetSlot,
                          mcuxClEls_KeyProp_t prop, const byte* deriv)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t, mcuxClEls_Ckdf_Sp800108_Async(
        (mcuxClEls_KeyIndex_t)srcSlot, (mcuxClEls_KeyIndex_t)targetSlot,
        prop, deriv));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Ckdf_Sp800108_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsKsDeleteRun(byte slot)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_KeyDelete_Async((mcuxClEls_KeyIndex_t)slot));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyDelete_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsKsImport(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef target, wrap;
    int ret;

    if (info->keystore.op.importWrapped.blob == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    /* Only this container shape. A bare RFC 3394 blob has no property word,
     * so ELS would have nothing to set the imported key's permissions from. */
    if (info->keystore.op.importWrapped.format != WC_KEYWRAP_FORMAT_VENDOR) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (info->keystore.op.importWrapped.blobSz != ELS_KS_BLOB_SZ(16) &&
        info->keystore.op.importWrapped.blobSz != ELS_KS_BLOB_SZ(32)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* The target need not exist yet - that is the point of an import - so its
     * reference is parsed but not checked against the hardware. */
    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.importWrapped.keyRef,
                                info->keystore.op.importWrapped.keyRefSz,
                                &target);
    if (ret == 0) {
        ret = ElsKsWrapRef(info->keystore.op.importWrapped.wrapKeyRef,
                           info->keystore.op.importWrapped.wrapKeyRefSz,
                           0, &wrap);
    }
    if (ret == 0) {
        ret = ElsKsImportRun(info->keystore.op.importWrapped.blob,
                             info->keystore.op.importWrapped.blobSz,
                             wrap.slot, target.slot);
    }

    ElsUnlock();

    if (ret == 0) {
        wc_ElsPkc_KeyStoreOffloadCount++;
    }

    return ret;
}

static int ElsKsExport(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef key, wrap;
    mcuxClEls_KeyProp_t prop;
    word32 need = 0;
    int ret;

    if (info->keystore.op.exportWrapped.blobSz == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (info->keystore.op.exportWrapped.format != WC_KEYWRAP_FORMAT_VENDOR) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.exportWrapped.keyRef,
                                info->keystore.op.exportWrapped.keyRefSz,
                                &key);
    if (ret == 0) {
        ret = ElsKsProps(key.slot, &prop);
    }
    if (ret == 0) {
        word32 bits = ElsKsBitsFromProp(&prop);

        if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0) {
            ret = WC_NO_ERR_TRACE(BAD_STATE_E);
        }
        /* wrpok is set at creation and cannot be added later, so a key that
         * was not made exportable simply cannot leave. */
        else if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_WRPOK) == 0) {
            ret = WC_NO_ERR_TRACE(BAD_STATE_E);
        }
        else if (bits != 128 && bits != 256) {
            ret = WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
        }
        else {
            need = ELS_KS_BLOB_SZ(bits / 8u);

            /* Size query: the caller asks how big the container will be. */
            if (info->keystore.op.exportWrapped.blob == NULL) {
                *info->keystore.op.exportWrapped.blobSz = need;
                ElsUnlock();
                return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
            }
            if (*info->keystore.op.exportWrapped.blobSz < need) {
                ret = WC_NO_ERR_TRACE(BUFFER_E);
            }
        }
    }

    if (ret == 0) {
        ret = ElsKsWrapRef(info->keystore.op.exportWrapped.wrapKeyRef,
                           info->keystore.op.exportWrapped.wrapKeyRefSz,
                           1, &wrap);
    }
    if (ret == 0) {
        ret = ElsKsExportRun(wrap.slot, key.slot,
                             info->keystore.op.exportWrapped.blob);
    }

    ElsUnlock();

    if (ret == 0) {
        *info->keystore.op.exportWrapped.blobSz = need;
        wc_ElsPkc_KeyStoreOffloadCount++;
    }

    return ret;
}

static int ElsKsDerive(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef target, src;
    mcuxClEls_KeyProp_t prop;
    int ret;

    if (info->keystore.op.derive.deriv == NULL ||
        info->keystore.op.derive.derivSz != ELS_KS_DERIV_SZ) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    /* The source must already be a derivation key; the target is where the
     * result lands and does not exist yet. */
    ret = ElsKsRef(info->keystore.op.derive.srcKeyRef,
                   info->keystore.op.derive.srcKeyRefSz,
                   WC_ELSPKC_KEY_CKDF, 1, &src);
    if (ret == 0) {
        ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.derive.keyRef,
                                    info->keystore.op.derive.keyRefSz,
                                    &target);
    }
    if (ret == 0) {
        /* The derived key's permissions come from the target reference's
         * class - that is what the caller is asking to create. */
        prop.word.value = 0u;
        prop.bits.upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_FALSE;
        prop.bits.upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_FALSE;
        prop.word.value |= ElsClassUsageBit(target.keyClass);
        if (info->keystore.op.derive.attrs & WC_KEYSTORE_ATTR_EXPORTABLE) {
            prop.bits.wrpok = MCUXCLELS_KEYPROPERTY_WRAP_TRUE;
        }
        if (target.keyClass == WC_ELSPKC_KEY_KWK &&
            (info->keystore.op.derive.attrs & WC_KEYSTORE_ATTR_UNWRAP_ONLY)) {
            /* An unwrap-only wrapping key: it can bring keys in and never
             * take them out. */
            prop.word.value &= ~MCUXCLELS_KEYPROPERTY_VALUE_KWK;
            prop.word.value |= MCUXCLELS_KEYPROPERTY_VALUE_KUOK;
        }

        ret = ElsKsDeriveRun(src.slot, target.slot, prop,
                             info->keystore.op.derive.deriv);
    }

    ElsUnlock();

    if (ret == 0) {
        wc_ElsPkc_KeyStoreOffloadCount++;
    }

    return ret;
}

static int ElsKsDelete(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef key;
    int ret = ElsLock();

    if (ret != 0) {
        return ret;
    }

    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.deleteKey.keyRef,
                                info->keystore.op.deleteKey.keyRefSz, &key);
    if (ret == 0) {
        mcuxClEls_KeyProp_t prop;

        ret = ElsKsProps(key.slot, &prop);
        if (ret == 0) {
            /* Deleting an empty slot is a caller mistake, and this part does
             * not return errors for those. Nothing is destroyed either way. */
            if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0) {
                ElsUnlock();
                return 0;
            }
            ret = ElsKsDeleteRun(key.slot);
        }
    }

    ElsUnlock();

    if (ret == 0) {
        wc_ElsPkc_KeyStoreOffloadCount++;
    }

    return ret;
}

static int ElsKsGetInfo(wc_CryptoInfo* info)
{
    wc_ElsPkc_KeyRef key;
    mcuxClEls_KeyProp_t prop;
    int ret = ElsLock();

    if (ret != 0) {
        return ret;
    }

    ret = wc_ElsPkc_ParseKeyRef(info->keystore.op.getInfo.keyRef,
                                info->keystore.op.getInfo.keyRefSz, &key);
    if (ret == 0) {
        ret = ElsKsProps(key.slot, &prop);
    }

    ElsUnlock();

    if (ret == 0) {
        if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_ACTIVE) == 0) {
            return WC_NO_ERR_TRACE(BAD_STATE_E);
        }
        if (info->keystore.op.getInfo.keyType != NULL) {
            *info->keystore.op.getInfo.keyType = ElsKsTypeFromProp(&prop);
        }
        if (info->keystore.op.getInfo.keySz != NULL) {
            *info->keystore.op.getInfo.keySz = ElsKsBitsFromProp(&prop);
        }
        if (info->keystore.op.getInfo.attrs != NULL) {
            word32 a = 0;

            if (prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_WRPOK) {
                a |= WC_KEYSTORE_ATTR_EXPORTABLE;
            }
            if ((prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_KUOK) &&
                !(prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_KWK)) {
                a |= WC_KEYSTORE_ATTR_UNWRAP_ONLY;
            }
            if (prop.word.value & MCUXCLELS_KEYPROPERTY_VALUE_RETENTION_SLOT) {
                a |= WC_KEYSTORE_ATTR_PERSISTENT;
            }
            *info->keystore.op.getInfo.attrs = a;
        }
        wc_ElsPkc_KeyStoreOffloadCount++;
    }

    return ret;
}

#endif /* WOLF_CRYPTO_CB_KEYSTORE */

/* ---------------------------------------------------------------------------
 * Random
 * ------------------------------------------------------------------------ */

/* Serving WC_ALGO_TYPE_SEED as well as _RNG means wolfCrypt's own Hash-DRBG is
 * seeded from the hardware, not just the direct generate path. */

#ifndef WC_NO_RNG

unsigned long wc_ElsPkc_RngOffloadCount = 0;

/* Issue one DRBG request. Caller holds the lock, and len must already satisfy
 * the engine's contract. */
static int ElsRandomRun(byte* out, word32 len)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r, t,
        mcuxClEls_Rng_DrbgRequest_Async(out, (size_t)len));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Rng_DrbgRequest_Async) != t) ||
        (MCUXCLELS_STATUS_OK_WAIT != r)) {
        return WC_NO_ERR_TRACE(WC_HW_E);
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return ElsWait();
}

static int ElsRandom(byte* out, word32 sz)
{
    /* The DRBG takes at least four bytes and only whole words; with the
     * driver's parameter checks compiled out a sub-word length would program
     * the DMA past the end of the caller's buffer. Odd sizes are ordinary
     * (wc_RNG_GenerateByte), so the tail comes from a word-sized scratch. */
    ALIGN32 byte tail[MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MIN_SIZE];
    word32 whole;
    word32 rest;
    int ret;

    if (out == NULL) {
        return WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    }
    if (sz == 0) {
        return 0;
    }
    if (sz > MCUXCLELS_RNG_DRBG_TEST_EXTRACT_OUTPUT_MAX_SIZE) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    whole = sz & ~(word32)(sizeof(tail) - 1u);
    rest  = sz - whole;

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    if (whole > 0) {
        ret = ElsRandomRun(out, whole);
    }
    if (ret == 0 && rest > 0) {
        ret = ElsRandomRun(tail, (word32)sizeof(tail));
        if (ret == 0) {
            XMEMCPY(out + whole, tail, rest);
        }
    }

    ElsUnlock();

    if (ret == 0) {
        wc_ElsPkc_RngOffloadCount++;
    }

    ForceZero(tail, sizeof(tail));

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
    if (inSz == 0) {
        return 0;
    }

    ret = ElsLock();
    if (ret != 0) {
        return ret;
    }

    ctx = (ElsCmacCtx*)cmac->devCtx;

    /* CMAC uses a different subkey for the final chunk and only the final call
     * knows which that is, so a full buffer is flushed only once more data is
     * known to follow. */
    while (inSz > 0) {
        take = ELS_CMAC_BLOCK - ctx->buffered;
        if (take > inSz) {
            take = inSz;
        }
        XMEMCPY(ctx->buf + ctx->buffered, in, take);
        ctx->buffered += take;
        in += take;
        inSz -= take;

        if (ctx->buffered == ELS_CMAC_BLOCK && inSz > 0) {
            ret = ElsCmacChunk(ctx, ctx->buf, ELS_CMAC_BLOCK, 0);
            if (ret != 0) {
                goto out;
            }
            ctx->buffered = 0;
        }
    }

out:
    ElsUnlock();

    return ret;
}

static int ElsCmacFinal(Cmac* cmac, byte* out, word32* outSz)
{
    ElsCmacCtx* ctx;
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

    ctx = (ElsCmacCtx*)cmac->devCtx;

    /* ELS takes inputLength as the length *before* padding but expects the
     * block already padded per SP 800-38B. Getting this wrong is quiet: exact
     * block multiples come out correct and every other length is wrong. */
    if (ctx->buffered < ELS_CMAC_BLOCK) {
        ctx->buf[ctx->buffered] = 0x80;
        if (ctx->buffered + 1u < ELS_CMAC_BLOCK) {
            XMEMSET(ctx->buf + ctx->buffered + 1u, 0,
                    ELS_CMAC_BLOCK - ctx->buffered - 1u);
        }
    }

    ret = ElsCmacChunk(ctx, ctx->buf, ctx->buffered, 1);
    if (ret == 0) {
        XMEMCPY(out, ctx->state, *outSz);
        wc_ElsPkc_CmacOffloadCount++;
    }

    ForceZero(ctx, sizeof(*ctx));
    cmac->devCtx = NULL;

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
            else if (info->cmac.in != NULL && info->cmac.out == NULL) {
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

#if defined(HAVE_ECC) || !defined(NO_RSA) || defined(HAVE_CURVE25519)
        case WC_ALGO_TYPE_PK:
            switch (info->pk.type) {
    #ifdef HAVE_CURVE25519
                case WC_PK_TYPE_CURVE25519:
                    ret = ElsPkcX25519(info->pk.curve25519.private_key,
                            info->pk.curve25519.public_key,
                            info->pk.curve25519.out,
                            info->pk.curve25519.outlen,
                            info->pk.curve25519.endian);
                    break;
    #endif
    #ifndef NO_RSA
                case WC_PK_TYPE_RSA:
                    ret = ElsPkcRsaFunction(info->pk.rsa.in,
                            info->pk.rsa.inLen, info->pk.rsa.out,
                            info->pk.rsa.outLen, info->pk.rsa.type,
                            info->pk.rsa.key);
                    break;
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)
                case WC_PK_TYPE_EC_KEYGEN:
                    ret = ElsEccKeyGen(info->pk.eckg.key);
                    break;
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
                case WC_PK_TYPE_ECDSA_SIGN:
                    /* ELS first: it answers only for a P-256 key that names a
                     * slot, and declines everything else, which is exactly
                     * the set the PKC tier covers. */
                    ret = ElsEccSign(info->pk.eccsign.in,
                            info->pk.eccsign.inlen, info->pk.eccsign.out,
                            info->pk.eccsign.outlen, info->pk.eccsign.key);
                    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                        ret = ElsPkcEccSign(info->pk.eccsign.in,
                                info->pk.eccsign.inlen, info->pk.eccsign.out,
                                info->pk.eccsign.outlen, info->pk.eccsign.key);
                    }
                    break;
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
                case WC_PK_TYPE_ECDSA_VERIFY:
                    ret = ElsEccVerify(info->pk.eccverify.sig,
                            info->pk.eccverify.siglen,
                            info->pk.eccverify.hash,
                            info->pk.eccverify.hashlen,
                            info->pk.eccverify.res,
                            info->pk.eccverify.key);
                    if (ret == WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE)) {
                        ret = ElsPkcEccVerify(info->pk.eccverify.sig,
                                info->pk.eccverify.siglen,
                                info->pk.eccverify.hash,
                                info->pk.eccverify.hashlen,
                                info->pk.eccverify.res,
                                info->pk.eccverify.key);
                    }
                    break;
    #endif
                /* WC_PK_TYPE_ECDH is deliberately absent: ELS deposits the
                 * shared secret in a slot, which cannot be read back, while
                 * the ecdh callback must hand a buffer back. The keystore
                 * derive path covers an in-slot agreement. */
                default:
                    break;
            }
            break;
#endif /* HAVE_ECC || !NO_RSA || HAVE_CURVE25519 */

#ifdef WOLF_CRYPTO_CB_KEYSTORE
        case WC_ALGO_TYPE_KEYSTORE:
            switch (info->keystore.type) {
                case WC_KEYSTORE_IMPORT_WRAPPED:
                    ret = ElsKsImport(info);
                    break;
                case WC_KEYSTORE_EXPORT_WRAPPED:
                    ret = ElsKsExport(info);
                    break;
                case WC_KEYSTORE_DERIVE:
                    ret = ElsKsDerive(info);
                    break;
                case WC_KEYSTORE_DELETE:
                    ret = ElsKsDelete(info);
                    break;
                case WC_KEYSTORE_GET_INFO:
                    ret = ElsKsGetInfo(info);
                    break;
                default:
                    break;
            }
            break;
#endif /* WOLF_CRYPTO_CB_KEYSTORE */

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

#if !defined(NO_SHA256) || defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512)
        case WC_ALGO_TYPE_HASH:
            /* update passes (data, len, NULL) and final passes (NULL, 0,
             * digest), never both. Claim each separately. */
            switch (info->hash.type) {
    #if !defined(NO_SHA256)
                case WC_HASH_TYPE_SHA256:
                    if (info->hash.sha256 == NULL) {
                        break;
                    }
                    if (info->hash.digest != NULL) {
                        ret = ElsHashFinal(&info->hash.sha256->devCtx,
                                info->hash.digest, WC_SHA256_DIGEST_SIZE);
                    }
                    else if (info->hash.in != NULL) {
                        ret = ElsHashUpdate(&info->hash.sha256->devCtx,
                                MCUXCLELS_HASH_MODE_SHA_256,
                                info->hash.in, info->hash.inSz);
                    }
                    else {
                        /* update of zero bytes with no buffer */
                        ret = 0;
                        break;
                    }
                    if (ret == 0) {
                        wc_ElsPkc_HashOffloadCount++;
                    }
                    break;
    #endif
    #ifdef WOLFSSL_SHA384
                case WC_HASH_TYPE_SHA384:
                    if (info->hash.sha384 == NULL) {
                        break;
                    }
                    if (info->hash.digest != NULL) {
                        ret = ElsHashFinal(&info->hash.sha384->devCtx,
                                info->hash.digest, WC_SHA384_DIGEST_SIZE);
                    }
                    else if (info->hash.in != NULL) {
                        ret = ElsHashUpdate(&info->hash.sha384->devCtx,
                                MCUXCLELS_HASH_MODE_SHA_384,
                                info->hash.in, info->hash.inSz);
                    }
                    else {
                        ret = 0;
                        break;
                    }
                    if (ret == 0) {
                        wc_ElsPkc_HashOffloadCount++;
                    }
                    break;
    #endif
    #ifdef WOLFSSL_SHA512
                case WC_HASH_TYPE_SHA512:
                    if (info->hash.sha512 == NULL) {
                        break;
                    }
                    if (info->hash.digest != NULL) {
                        ret = ElsHashFinal(&info->hash.sha512->devCtx,
                                info->hash.digest, WC_SHA512_DIGEST_SIZE);
                    }
                    else if (info->hash.in != NULL) {
                        ret = ElsHashUpdate(&info->hash.sha512->devCtx,
                                MCUXCLELS_HASH_MODE_SHA_512,
                                info->hash.in, info->hash.inSz);
                    }
                    else {
                        ret = 0;
                        break;
                    }
                    if (ret == 0) {
                        wc_ElsPkc_HashOffloadCount++;
                    }
                    break;
    #endif
                default:
                    break;
            }
            break;
#endif

#if defined(WOLF_CRYPTO_CB_COPY) && (!defined(NO_SHA256) || \
    defined(WOLFSSL_SHA384) || defined(WOLFSSL_SHA512))
        case WC_ALGO_TYPE_COPY:
            if (info->copy.algo != WC_ALGO_TYPE_HASH) {
                break;
            }
    #if !defined(NO_SHA256)
            if (info->copy.type == WC_HASH_TYPE_SHA256) {
                ret = ElsSha256Copy((wc_Sha256*)info->copy.src,
                                    (wc_Sha256*)info->copy.dst);
            }
    #endif
    #ifdef WOLFSSL_SHA384
            if (info->copy.type == WC_HASH_TYPE_SHA384) {
                ret = ElsSha512Copy((wc_Sha384*)info->copy.src,
                                    (wc_Sha384*)info->copy.dst);
            }
    #endif
    #ifdef WOLFSSL_SHA512
            if (info->copy.type == WC_HASH_TYPE_SHA512) {
                ret = ElsSha512Copy((wc_Sha512*)info->copy.src,
                                    (wc_Sha512*)info->copy.dst);
            }
    #endif
            break;
#endif

#if defined(WOLF_CRYPTO_CB_FREE)
        case WC_ALGO_TYPE_FREE:
    #if !defined(NO_SHA256)
            if (info->free.algo == WC_ALGO_TYPE_HASH &&
                info->free.type == WC_HASH_TYPE_SHA256 &&
                info->free.obj != NULL) {
                ElsHashFreeCtx(&((wc_Sha256*)info->free.obj)->devCtx);
            }
    #endif
    #ifdef WOLFSSL_SHA384
            if (info->free.algo == WC_ALGO_TYPE_HASH &&
                info->free.type == WC_HASH_TYPE_SHA384 &&
                info->free.obj != NULL) {
                ElsHashFreeCtx(&((wc_Sha384*)info->free.obj)->devCtx);
            }
    #endif
    #ifdef WOLFSSL_SHA512
            if (info->free.algo == WC_ALGO_TYPE_HASH &&
                info->free.type == WC_HASH_TYPE_SHA512 &&
                info->free.obj != NULL) {
                ElsHashFreeCtx(&((wc_Sha512*)info->free.obj)->devCtx);
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
            /* Drop every claimed pool entry: once elsLockInit is clear the
             * free paths can no longer take the lock to release them, and the
             * CMAC pool holds plaintext keys. Free live objects first. */
#ifndef NO_SHA256
            ForceZero(elsHashPool, sizeof(elsHashPool));
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
            ForceZero(elsCmacPool, sizeof(elsCmacPool));
#endif
            (void)wc_UnLockMutex(&elsLock);
        }
        elsLockInit = 0;
        wc_FreeMutex(&elsLock);
    }

#ifdef ELS_PKC_HAVE_SESSION
    /* The DRBG context and the CPU workarea hold intermediate values from
     * whatever ran last - key material among them for a private-key
     * operation - and nothing else clears them, so a shutdown would leave
     * them in .bss. */
    ForceZero(elsPkcRngCtx, sizeof(elsPkcRngCtx));
    ForceZero(elsPkcCpuWa, sizeof(elsPkcCpuWa));
#endif

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
