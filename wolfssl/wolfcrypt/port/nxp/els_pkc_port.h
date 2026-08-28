/* els_pkc_port.h
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

#ifndef WOLF_CRYPT_ELS_PKC_PORT_H
#define WOLF_CRYPT_ELS_PKC_PORT_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ELS_PKC

/* The port IS a crypto callback: it hands back a wc_CryptoInfo* and registers
 * against the callback device table, neither of which exists without this. */
#ifndef WOLF_CRYPTO_CB
    #error WOLFSSL_ELS_PKC requires WOLF_CRYPTO_CB
#endif

/* The hash offload keeps per-hash state in a pool entry hung off devCtx, which
 * needs copy and free to be visible. Without them a copied hash silently
 * shares an entry and an abandoned one never gives its entry back. */
#if !defined(NO_SHA256) && !defined(WOLF_CRYPTO_CB_COPY)
    #error WOLFSSL_ELS_PKC SHA-256 offload requires WOLF_CRYPTO_CB_COPY
#endif
#if !defined(NO_SHA256) && !defined(WOLF_CRYPTO_CB_FREE)
    #error WOLFSSL_ELS_PKC SHA-256 offload requires WOLF_CRYPTO_CB_FREE
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Default device id for the EdgeLock port. 'EL' - an application may register
 * the callback under a different id and bind keys to that instead. */
#ifndef WOLFSSL_ELS_PKC_DEVID
    #define WOLFSSL_ELS_PKC_DEVID 0x454CU
#endif

/* Interrupt priority for the ELS completion interrupt. */
#ifndef WOLFSSL_ELS_PKC_IRQ_PRIO
    #define WOLFSSL_ELS_PKC_IRQ_PRIO 2
#endif

/* Instrumentation: how many times each hardware path actually ran, and which
 * completion route was taken.
 *
 * These exist so a test can assert the offload ran rather than only that its
 * result agrees with software - a handler that never fires produces a passing
 * comparison of software against itself. They are incremented without
 * atomics, some outside the ELS lock, so treat them as best-effort under
 * concurrency: fine for a counter that only has to be non-zero. */
WOLFSSL_API extern unsigned long wc_ElsPkc_HashOffloadCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_AesOffloadCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_GcmOffloadCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_CmacOffloadCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_RngOffloadCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_IrqWaitCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_PollWaitCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_TimeoutCount;

/* Bring the EdgeLock subsystem up and register the crypto callback.
 *
 * Must run after wolfCrypt_Init(), which calls wc_CryptoCb_Init() and zeroes
 * the device table - registering before that point is silently undone.
 *
 * Safe to call more than once; subsequent calls are no-ops. */
WOLFSSL_API int wc_ElsPkc_Init(void);

/* Unregister the callback and release the lock. */
WOLFSSL_API int wc_ElsPkc_Cleanup(void);

/* The crypto callback itself. Exposed so an application that wants a different
 * device id, or several devices, can register it by hand.
 *
 * Registering does not by itself route anything here: wolfCrypt selects a
 * device per key or per context. An application opts in by initialising with
 * this devId, e.g. wc_InitSha256_ex(&sha, NULL, WOLFSSL_ELS_PKC_DEVID) or
 * wc_AesInit(&aes, NULL, WOLFSSL_ELS_PKC_DEVID). Contexts initialised with
 * INVALID_DEVID keep using software. */
WOLFSSL_API int wc_ElsPkc_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_ELS_PKC */
#endif /* WOLF_CRYPT_ELS_PKC_PORT_H */
