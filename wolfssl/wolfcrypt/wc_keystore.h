/* wc_keystore.h
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

/*!
    \file wolfssl/wolfcrypt/wc_keystore.h
*/

#ifndef WOLF_CRYPT_KEYSTORE_H
#define WOLF_CRYPT_KEYSTORE_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLF_CRYPTO_CB_KEYSTORE

/* Every backing wc_CryptoCb_KeyStore* function, the wc_CryptoInfo.keystore
 * member and the related enums live inside WOLF_CRYPTO_CB. Without it this
 * header would advertise an API that does not link - fail loudly instead,
 * since a hand-written user_settings.h has no configure check to catch it. */
#ifndef WOLF_CRYPTO_CB
    #error WOLF_CRYPTO_CB_KEYSTORE requires WOLF_CRYPTO_CB
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Lifecycle operations on a key held inside a secure element.
 *
 * These exist because a hardware-held key never becomes plaintext on this side
 * of the boundary, so none of the algorithm-specific callbacks can express
 * them: WC_ALGO_TYPE_SETKEY and WC_ALGO_TYPE_EXPORT_KEY both carry plaintext
 * key material to or from a wolfCrypt key object.
 *
 * Key references are opaque byte strings, interpreted only by the device -
 * the same contract as the id[] blob on an ecc_key or Aes. wolfCrypt copies
 * them through without inspection.
 *
 * All return 0 on success, CRYPTOCB_UNAVAILABLE when no registered device
 * handles the operation, or a negative error code.
 */

/* Unwrap a key blob directly into the device's key store. Nothing is returned:
 * on success the key exists at keyRef and its material was never in memory. */
WOLFSSL_API int wc_KeyStore_ImportWrapped(int devId,
    const byte* keyRef, word32 keyRefSz,
    const byte* wrapKeyRef, word32 wrapKeyRefSz,
    const byte* blob, word32 blobSz, word32 format, const void* ctx);

/* Wrap a stored key under wrapKeyRef and emit the blob. blobSz is in/out:
 * capacity on entry, bytes written on return. Pass blob == NULL to query the
 * size the device would produce. Typically requires the key to have been
 * created exportable. */
WOLFSSL_API int wc_KeyStore_ExportWrapped(int devId,
    const byte* keyRef, word32 keyRefSz,
    const byte* wrapKeyRef, word32 wrapKeyRefSz,
    byte* blob, word32* blobSz, word32 format, const void* ctx);

/* Derive a new stored key from an existing one without either touching RAM.
 * derivSz is algorithm-specific and often fixed by the hardware. */
WOLFSSL_API int wc_KeyStore_Derive(int devId,
    const byte* keyRef, word32 keyRefSz,
    const byte* srcKeyRef, word32 srcKeyRefSz,
    word32 kdfType, const byte* deriv, word32 derivSz,
    word32 attrs, const void* ctx);

/* Destroy a stored key. Deliberately separate from WC_ALGO_TYPE_FREE: freeing
 * a wolfCrypt key object must never destroy the hardware key it refers to. */
WOLFSSL_API int wc_KeyStore_Delete(int devId,
    const byte* keyRef, word32 keyRefSz, const void* ctx);

/* Query a stored key. Any out parameter may be NULL if not wanted; those
 * that are supplied are cleared before the device is consulted, so a partial
 * answer never leaves stale caller state. keySz is in BITS - key sizes are a
 * property of the algorithm here, unlike the byte counts used for buffers. */
WOLFSSL_API int wc_KeyStore_GetInfo(int devId,
    const byte* keyRef, word32 keyRefSz,
    word32* keyType, word32* keySz, word32* attrs, const void* ctx);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPTO_CB_KEYSTORE */
#endif /* WOLF_CRYPT_KEYSTORE_H */
