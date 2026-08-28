/* els_pkc_keyblob.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFSSL_ELS_PKC_KEYBLOB

#include <wolfssl/wolfcrypt/port/nxp/els_pkc_keyblob.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* plaintext staged before wrapping: properties(4) || pad(4) || key */
#define ELSPKC_PREFIX_SZ  8

/* ELS stores only 128- and 256-bit keys */
static int ElsPkcKeySizeOk(word32 keySz)
{
    return (keySz == 16 || keySz == 32);
}

int wc_ElsPkc_BuildWrappedBlob(const byte* kek, word32 kekSz,
    word32 props, const byte* key, word32 keySz, byte* out, word32 outSz)
{
    byte plain[ELSPKC_PREFIX_SZ + 32];
    int ret;

    if (kek == NULL || key == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!ElsPkcKeySizeOk(keySz)) {
        return BAD_FUNC_ARG;
    }
    if (kekSz != 16 && kekSz != 32) {
        return BAD_FUNC_ARG;
    }
    if (outSz < WC_ELSPKC_BLOB_SIZE(keySz)) {
        return BUFFER_E;
    }

    /* properties big-endian, then four zero bytes of ELS padding */
    plain[0] = (byte)(props >> 24);
    plain[1] = (byte)(props >> 16);
    plain[2] = (byte)(props >>  8);
    plain[3] = (byte)(props);
    XMEMSET(plain + 4, 0, 4);
    XMEMCPY(plain + ELSPKC_PREFIX_SZ, key, keySz);

    ret = wc_AesKeyWrap(kek, kekSz, plain, ELSPKC_PREFIX_SZ + keySz,
                        out, outSz, NULL);

    ForceZero(plain, sizeof(plain));

    return ret;
}

int wc_ElsPkc_ParseWrappedBlob(const byte* kek, word32 kekSz,
    const byte* blob, word32 blobSz, word32* props,
    byte* key, word32 keyBufSz, word32* keySz)
{
    byte plain[ELSPKC_PREFIX_SZ + 32];
    word32 recovered;
    int ret;

    if (kek == NULL || blob == NULL) {
        return BAD_FUNC_ARG;
    }
    if (kekSz != 16 && kekSz != 32) {
        return BAD_FUNC_ARG;
    }
    /* only the two container sizes wc_ElsPkc_BuildWrappedBlob can produce;
     * expressed through the same predicate the builder uses so the two cannot
     * drift apart */
    if (blobSz < WC_ELSPKC_BLOB_OVERHEAD ||
        !ElsPkcKeySizeOk(blobSz - WC_ELSPKC_BLOB_OVERHEAD)) {
        return BAD_FUNC_ARG;
    }

    /* validated just above: blobSz == WC_ELSPKC_BLOB_SIZE(recovered) */
    recovered = blobSz - WC_ELSPKC_BLOB_OVERHEAD;

    /* capacity is a separate input, so there is no in/out value that could be
     * left uninitialised and silently pass this check */
    if (key != NULL && keyBufSz < recovered) {
        return BUFFER_E;
    }

    ret = wc_AesKeyUnWrap(kek, kekSz, blob, blobSz, plain, sizeof(plain), NULL);
    if (ret < 0) {
        ForceZero(plain, sizeof(plain));
        return ret;
    }

    /* ELS defines the four bytes after the property word as zero padding; a
     * mismatch means the AES-KW integrity check passed but this is not an ELS
     * container. That is rejected content rather than a caller mistake, so it
     * is not BAD_FUNC_ARG - but there is no ASN.1 anywhere in this container
     * either, so an ASN error code would read as the wrong layer and would
     * collide with real ASN.1 failures in a caller that aggregates them. */
    if (plain[4] != 0 || plain[5] != 0 || plain[6] != 0 || plain[7] != 0) {
        ForceZero(plain, sizeof(plain));
        return BAD_STATE_E;
    }

    if (props != NULL) {
        *props = ((word32)plain[0] << 24) | ((word32)plain[1] << 16) |
                 ((word32)plain[2] <<  8) |  (word32)plain[3];
    }
    if (keySz != NULL) {
        *keySz = recovered;
    }
    if (key != NULL) {
        XMEMCPY(key, plain + ELSPKC_PREFIX_SZ, recovered);
    }

    ForceZero(plain, sizeof(plain));

    return (int)recovered;
}

#endif /* WOLFSSL_ELS_PKC_KEYBLOB */
