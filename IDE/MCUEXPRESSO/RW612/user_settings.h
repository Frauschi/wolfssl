/* user_settings.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* wolfSSL configuration for the NXP RW612 (frdm_rw612) with the EdgeLock
 * ELS + PKC crypto callback port, built from an MCUXpresso SDK project.
 *
 * See README.md in this directory for the SDK components to select and the
 * compiler flags this expects. The algorithm set here mirrors the "full"
 * configuration in .github/workflows/els-pkc.yml, so what a customer builds is
 * what CI compiles.
 *
 * Under Zephyr none of this applies: the module's Kconfig generates the
 * equivalent settings, and CONFIG_WOLFSSL_ELS_PKC=y turns the port on.
 */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Platform
 * ------------------------------------------------------------------------ */

#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED

/* wolfCrypt_Init() uses a __thread recursion guard when the toolchain reports
 * thread-local storage. Bare-metal startup never sets the thread pointer, so
 * the guard reads garbage and the call fails with DEADLOCK_AVERTED_E (-1000)
 * before doing any work. */
#define NO_THREAD_LS
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO
#define NO_DEV_RANDOM           /* entropy comes from the ELS DRBG, below */
#define WOLFCRYPT_ONLY          /* drop for TLS; then supply IO and time */

/* No RTC by default on this board. Supply a real time source and remove this
 * if certificate validity has to be checked. */
#define NO_ASN_TIME

/* ---------------------------------------------------------------------------
 * EdgeLock (ELS + PKC) offload
 * ------------------------------------------------------------------------ */

/* The single switch for the port. Everything in
 * wolfcrypt/src/port/nxp/els_pkc_port.c is gated on it, so without it that
 * file is an empty translation unit reaching no vendor header. */
#define WOLFSSL_ELS_PKC

/* The port IS a crypto callback, and it keeps per-operation state on devCtx:
 * the SHA-256 and CMAC offloads need COPY to hand a hash's pool entry to a
 * copy, and FREE to give the entry back when an operation is abandoned before
 * its Final. Without them the failures are silent and at run time, so
 * els_pkc_port.h makes them build errors. KEYSTORE adds the ELS key store
 * operations (generate, delete, import a wrapped key). */
#define WOLF_CRYPTO_CB
#define WOLF_CRYPTO_CB_COPY
#define WOLF_CRYPTO_CB_FREE
#define WOLF_CRYPTO_CB_KEYSTORE

/* Seed wolfCrypt's DRBG from the ELS hardware DRBG. */
#define HAVE_HASHDRBG

/* ---------------------------------------------------------------------------
 * Algorithms
 *
 * The port offloads SHA-256, AES (ECB/CBC/CTR), AES-GCM, CMAC, the DRBG, and
 * ECDSA/ECDH on P-256 to the ELS; RSA, X25519 and ECDSA on the larger curves
 * to the PKC coprocessor. Anything not listed here falls back to software
 * through the normal CRYPTOCB_UNAVAILABLE path.
 * ------------------------------------------------------------------------ */

#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_CMAC

#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_CURVE25519
/* Ed25519 is deliberately absent: the PKC does not serve EdDSA, so it would be
 * pure software here and imply an offload that does not exist. */

/* SP math with the curves this build uses. SP_MATH is per-curve: a curve the
 * SP backend was not built for fails at run time with WC_KEY_SIZE_E rather
 * than at compile time, so keep this in step with the curve list above. */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_384
#define WOLFSSL_HAVE_SP_RSA

#define WC_RSA_BLINDING
#define WOLFSSL_KEY_GEN

/* ---------------------------------------------------------------------------
 * Size
 * ------------------------------------------------------------------------ */

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_PSK
#define NO_OLD_TLS
#define WOLFSSL_SMALL_STACK

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
