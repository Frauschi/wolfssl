/* els_pkc_keyblob.h
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

#ifndef WOLF_CRYPT_ELS_PKC_KEYBLOB_H
#define WOLF_CRYPT_ELS_PKC_KEYBLOB_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ELS_PKC_KEYBLOB

#include <wolfssl/wolfcrypt/types.h>

/* Both: HAVE_AES_KEYWRAP can be defined in a build with no AES at all. */
#if defined(NO_AES) || !defined(HAVE_AES_KEYWRAP)
    #error WOLFSSL_ELS_PKC_KEYBLOB requires AES with HAVE_AES_KEYWRAP
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Builds the wrapped-key container the NXP EdgeLock (ELS) key store accepts:
 *
 *     container = AES-KW(KEK, properties_be32 || 0x00000000 || key)
 *
 * The properties travel inside the wrap, so whoever wraps a key decides what
 * it may be used for. Plain wolfCrypt, so an off-device provisioning tool
 * needs no NXP code. */

/* 8-byte prefix (properties + padding) plus the 8-byte AES-KW integrity block */
#define WC_ELSPKC_BLOB_OVERHEAD  16

/* container size for a key of keySz bytes */
#define WC_ELSPKC_BLOB_SIZE(keySz) ((keySz) + WC_ELSPKC_BLOB_OVERHEAD)

/* ELS accepts only 128- and 256-bit keys; 192 has no representation. */

/* Build a container.
 *
 *   kek/kekSz   the key wrapping key (16 or 32 bytes)
 *   props       ELS key-property word, host byte order; stored big-endian
 *   key/keySz   the key to wrap; keySz must be 16 or 32
 *   out/outSz   receives the container; outSz >= keySz + 16
 *
 * Returns the number of bytes written (a positive count), or a negative error
 * code. Note this mirrors wc_AesKeyWrap(): success is > 0, not 0.
 */
WOLFSSL_API int wc_ElsPkc_BuildWrappedBlob(const byte* kek, word32 kekSz,
    word32 props, const byte* key, word32 keySz, byte* out, word32 outSz);

/* Inverse, for tests and for a provisioning tool that wants to verify what it
 * just produced. Recovers both the property word and the key.
 *
 *   key/keyBufSz  where to put the key, and the capacity of that buffer;
 *                 pass key == NULL (keyBufSz ignored) to query the size only
 *   props/keySz   outputs; either may be NULL if not wanted
 *
 * The buffer capacity is a separate input from the recovered size so there is
 * no in/out parameter to leave uninitialised.
 *
 * Returns the number of key bytes recovered (a positive count), or a negative
 * error code - the same convention as wc_ElsPkc_BuildWrappedBlob.
 *
 * Two failures are worth telling apart. A wrong KEK fails the AES-KW integrity
 * check and returns whatever wc_AesKeyUnWrap reports. BAD_STATE_E means the
 * unwrap succeeded but the plaintext is not an ELS container - the reserved
 * padding after the property word was non-zero - so the KEK was right and the
 * content was not.
 */
WOLFSSL_API int wc_ElsPkc_ParseWrappedBlob(const byte* kek, word32 kekSz,
    const byte* blob, word32 blobSz, word32* props,
    byte* key, word32 keyBufSz, word32* keySz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_ELS_PKC_KEYBLOB */
#endif /* WOLF_CRYPT_ELS_PKC_KEYBLOB_H */
