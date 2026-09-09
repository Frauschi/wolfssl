/* els_pkc_port.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
    #error "WOLFSSL_ELS_PKC requires WOLF_CRYPTO_CB"
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* WOLFSSL_ELS_PKC_DEVID comes from settings.h, which the test and benchmark
 * reach without the vendor headers this file needs. An application may still
 * register the callback under a different id and bind keys to that instead. */

#ifndef WOLFSSL_ELS_PKC_IRQ_PRIO
    #define WOLFSSL_ELS_PKC_IRQ_PRIO 2
#endif

/* Bring the EdgeLock subsystem up and register the crypto callback.
 * wolfCrypt_Init() already does this; call it directly only to re-register
 * after a wolfCrypt_Cleanup(). Safe to call more than once. */
WOLFSSL_API int wc_ElsPkc_Init(void);

/* Unregister the callback and release the lock. */
WOLFSSL_API int wc_ElsPkc_Cleanup(void);

/* The crypto callback itself, exposed so an application can register it under
 * a different device id. Registering routes nothing by itself: a context opts
 * in by being initialised with this devId, e.g. wc_AesInit(&aes, NULL,
 * WOLFSSL_ELS_PKC_DEVID). */
WOLFSSL_API int wc_ElsPkc_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_ELS_PKC */
#endif /* WOLF_CRYPT_ELS_PKC_PORT_H */
