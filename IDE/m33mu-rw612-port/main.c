/* main.c
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

/* Bare-metal checks for the EdgeLock port, run under m33mu --cpu rw612.
 *
 * See README.md for what this does and does not cover. In short: the key
 * reference codec and the wrapped-key container are pure software and are
 * tested for real here, and the offload arms are driven against failing CLNS
 * stubs to prove the software fallback. No ELS command is executed.
 *
 * Result is signalled by BKPT immediate:
 *   0x7f  every check passed
 *   0x70  setup failed
 *   0x71  key reference codec
 *   0x72  wrapped-key container
 *   0x73  the port did not fail closed when the hardware failed
 *   0x74  an engine counter moved for something we never asked for
 *   0x75  the software path was disturbed by the port being registered
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>
#ifdef WOLFSSL_ELS_PKC_KEYBLOB
    #include <wolfssl/wolfcrypt/port/nxp/els_pkc_keyblob.h>
#endif

#include <string.h>
#include <stdint.h>

#define BKPT(imm) __asm volatile("bkpt %0" :: "I"(imm))

static void spin_forever(void)
{
    while (1) {
    }
}

static int failures = 0;

#define CHECK(cond) do { if (!(cond)) { failures++; return -1; } } while (0)

/* ---------------------------------------------------------------------------
 * 1. Key reference codec
 *
 * The blob is attacker-reachable in the wolfPSA flow, so what matters is that
 * every malformed shape is rejected as content (BAD_STATE_E) before anything
 * treats the slot number as real.
 * ------------------------------------------------------------------------ */
static int check_keyref(void)
{
    wc_ElsPkc_KeyRef ref;
    wc_ElsPkc_KeyRef out;
    byte blob[WC_ELSPKC_KEYREF_SZ + 65];
    word32 sz;
    int i;

    XMEMSET(&ref, 0, sizeof(ref));
    ref.keyClass = WC_ELSPKC_KEY_ECC_SIGN;
    ref.slot     = 4;
    ref.flags    = WC_ELSPKC_REF_FLAG_BIND | WC_ELSPKC_REF_FLAG_EXPORTABLE;
    for (i = 0; i < WC_ELSPKC_BIND_SZ; i++) {
        ref.bind[i] = (byte)(0xA0 + i);
    }

    /* size query */
    sz = 0;
    CHECK(wc_ElsPkc_MakeKeyRef(&ref, NULL, &sz) == WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    CHECK(sz == WC_ELSPKC_KEYREF_SZ);

    /* round trip */
    sz = sizeof(blob);
    CHECK(wc_ElsPkc_MakeKeyRef(&ref, blob, &sz) == 0);
    CHECK(sz == WC_ELSPKC_KEYREF_SZ);

    XMEMSET(&out, 0, sizeof(out));
    CHECK(wc_ElsPkc_ParseKeyRef(blob, sz, &out) == 0);
    CHECK(out.keyClass == ref.keyClass);
    CHECK(out.slot == ref.slot);
    CHECK(out.flags == ref.flags);
    CHECK(XMEMCMP(out.bind, ref.bind, WC_ELSPKC_BIND_SZ) == 0);

    /* a longer buffer is accepted: wolfPSA stores the public point after it */
    XMEMSET(blob + WC_ELSPKC_KEYREF_SZ, 0x5A, 65);
    CHECK(wc_ElsPkc_ParseKeyRef(blob, WC_ELSPKC_KEYREF_SZ + 65, &out) == 0);
    CHECK(out.slot == ref.slot);

    /* truncated */
    CHECK(wc_ElsPkc_ParseKeyRef(blob, WC_ELSPKC_KEYREF_SZ - 1, &out) != 0);

    /* wrong magic */
    sz = sizeof(blob);
    CHECK(wc_ElsPkc_MakeKeyRef(&ref, blob, &sz) == 0);
    blob[0] ^= 0xFF;
    CHECK(wc_ElsPkc_ParseKeyRef(blob, sz, &out) == WC_NO_ERR_TRACE(BAD_STATE_E));

    /* unknown version */
    sz = sizeof(blob);
    CHECK(wc_ElsPkc_MakeKeyRef(&ref, blob, &sz) == 0);
    blob[2] = WC_ELSPKC_KEYREF_VER + 7;
    CHECK(wc_ElsPkc_ParseKeyRef(blob, sz, &out) == WC_NO_ERR_TRACE(BAD_STATE_E));

    /* slot past the end of the key store */
    ref.slot = WC_ELSPKC_MAX_SLOT + 1;
    sz = sizeof(blob);
    CHECK(wc_ElsPkc_MakeKeyRef(&ref, blob, &sz) != 0 ||
          wc_ElsPkc_ParseKeyRef(blob, sz, &out) == WC_NO_ERR_TRACE(BAD_STATE_E));
    ref.slot = 4;

    /* unassigned key class */
    ref.keyClass = WC_ELSPKC_KEY_NONE;
    sz = sizeof(blob);
    CHECK(wc_ElsPkc_MakeKeyRef(&ref, blob, &sz) != 0 ||
          wc_ElsPkc_ParseKeyRef(blob, sz, &out) == WC_NO_ERR_TRACE(BAD_STATE_E));

    ref.keyClass = 0x7E;
    sz = sizeof(blob);
    CHECK(wc_ElsPkc_MakeKeyRef(&ref, blob, &sz) != 0 ||
          wc_ElsPkc_ParseKeyRef(blob, sz, &out) == WC_NO_ERR_TRACE(BAD_STATE_E));

    return 0;
}

/* ---------------------------------------------------------------------------
 * 2. Wrapped-key container
 *
 * The design rests on the container being exactly an AES key wrap of
 * props||pad||key, so a provisioning tool needs no vendor code. Check the
 * round trip, that a wrong KEK is rejected, and the equivalence itself.
 * ------------------------------------------------------------------------ */
static int check_keyblob(void)
{
#ifdef WOLFSSL_ELS_PKC_KEYBLOB
    static const byte kek[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    static const byte key[16] = {
        0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,
        0x78,0x69,0x5A,0x4B,0x3C,0x2D,0x1E,0x0F
    };
    const word32 props = 0x00000021u;
    byte blob[64];
    byte recovered[32];
    byte wrongKek[16];
    word32 gotProps = 0;
    word32 gotSz = 0;
    int blobSz;

    blobSz = wc_ElsPkc_BuildWrappedBlob(kek, sizeof(kek), props,
                                        key, sizeof(key),
                                        blob, sizeof(blob));
    CHECK(blobSz > 0);

    CHECK(wc_ElsPkc_ParseWrappedBlob(kek, sizeof(kek), blob, (word32)blobSz,
                                     &gotProps, recovered, sizeof(recovered),
                                     &gotSz) > 0);
    CHECK(gotProps == props);
    CHECK(gotSz == sizeof(key));
    CHECK(XMEMCMP(recovered, key, sizeof(key)) == 0);

    /* a wrong KEK must fail the key wrap integrity check, not return garbage */
    XMEMCPY(wrongKek, kek, sizeof(kek));
    wrongKek[0] ^= 0x01;
    CHECK(wc_ElsPkc_ParseWrappedBlob(wrongKek, sizeof(wrongKek), blob,
                                     (word32)blobSz, &gotProps, recovered,
                                     sizeof(recovered), &gotSz) < 0);

#ifdef HAVE_AES_KEYWRAP
    {
        /* The equivalence the design depends on: build the same plaintext by
         * hand - the property word big-endian, the reserved padding, then the
         * key - wrap it with plain wc_AesKeyWrap, and require the same bytes.
         */
        /* props big-endian, four reserved zero bytes, then the key */
        const word32 prefixSz = 8;
        byte plain[8 + 32];
        byte reference[64];
        int refSz;

        XMEMSET(plain, 0, sizeof(plain));
        plain[0] = (byte)(props >> 24);
        plain[1] = (byte)(props >> 16);
        plain[2] = (byte)(props >> 8);
        plain[3] = (byte)(props);
        XMEMCPY(plain + prefixSz, key, sizeof(key));

        refSz = wc_AesKeyWrap(kek, sizeof(kek), plain,
                              prefixSz + (word32)sizeof(key),
                              reference, sizeof(reference), NULL);
        CHECK(refSz == blobSz);
        CHECK(XMEMCMP(reference, blob, (size_t)blobSz) == 0);
    }
#endif

#endif /* WOLFSSL_ELS_PKC_KEYBLOB */
    return 0;
}

/* ---------------------------------------------------------------------------
 * 3. The port fails closed, and leaves the software path alone
 *
 * Two different promises, and it is worth being precise about which is which.
 * CRYPTOCB_UNAVAILABLE means the port DECLINED an operation, and wolfCrypt
 * then does it in software. A hardware FAILURE is not a decline: the port
 * reports the error rather than quietly finishing in software, because a
 * caller that ignores the return would otherwise get a confident bad digest.
 *
 * The CLNS stubs make every hardware call fail, so this checks the second
 * promise: an operation issued through the port's devId returns an error
 * instead of a wrong answer, and the very same operation on the default devId
 * still produces the right answer with the port registered.
 * ------------------------------------------------------------------------ */

/* NIST FIPS 180-4, SHA-256 of "abc" */
static const byte abc[3] = { 'a', 'b', 'c' };
static const byte abcDigest[WC_SHA256_DIGEST_SIZE] = {
    0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,
    0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
    0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,
    0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
};

static int sha256_once(int devId, byte* digest)
{
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256_ex(&sha, NULL, devId);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Sha256Update(&sha, abc, sizeof(abc));
    if (ret == 0) {
        ret = wc_Sha256Final(&sha, digest);
    }
    wc_Sha256Free(&sha);

    return ret;
}

static int check_fails_closed(void)
{
    byte digest[WC_SHA256_DIGEST_SIZE];

    /* through the port, with the hardware failing: an error, not a digest */
    XMEMSET(digest, 0, sizeof(digest));
    CHECK(sha256_once(WOLFSSL_ELS_PKC_DEVID, digest) != 0);

    /* and it must not have produced the right answer by accident either, or
     * the check above would be passing for the wrong reason */
    CHECK(XMEMCMP(digest, abcDigest, sizeof(abcDigest)) != 0);

    return 0;
}

static int check_software_path(void)
{
    byte digest[WC_SHA256_DIGEST_SIZE];

    /* the port is registered, but this operation never asked for it */
    XMEMSET(digest, 0, sizeof(digest));
    CHECK(sha256_once(INVALID_DEVID, digest) == 0);
    CHECK(XMEMCMP(digest, abcDigest, sizeof(abcDigest)) == 0);

#ifdef WOLFSSL_CMAC
    {
        /* NIST SP 800-38B, AES-128 CMAC of the empty message */
        static const byte cmacKey[16] = {
            0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
            0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
        };
        static const byte cmacEmpty[16] = {
            0xBB,0x1D,0x69,0x29,0xE9,0x59,0x37,0x28,
            0x7F,0xA3,0x7D,0x12,0x9B,0x75,0x67,0x46
        };
        Cmac cmac;
        byte mac[16];
        word32 macSz = sizeof(mac);

        CHECK(wc_InitCmac_ex(&cmac, cmacKey, sizeof(cmacKey), WC_CMAC_AES,
                             NULL, NULL, INVALID_DEVID) == 0);
        CHECK(wc_CmacFinal(&cmac, mac, &macSz) == 0);
        CHECK(macSz == sizeof(cmacEmpty));
        CHECK(XMEMCMP(mac, cmacEmpty, sizeof(cmacEmpty)) == 0);
    }
#endif

#ifdef HAVE_AESGCM
    {
        /* NIST GCM test case 2: 128-bit zero key, zero IV, 16 zero bytes */
        static const byte gcmKey[16] = { 0 };
        static const byte gcmIv[12]  = { 0 };
        static const byte gcmPlain[16] = { 0 };
        static const byte gcmCipher[16] = {
            0x03,0x88,0xDA,0xCE,0x60,0xB6,0xA3,0x92,
            0xF3,0x28,0xC2,0xB9,0x71,0xB2,0xFE,0x78
        };
        static const byte gcmTag[16] = {
            0xAB,0x6E,0x47,0xD4,0x2C,0xEC,0x13,0xBD,
            0xF5,0x3A,0x67,0xB2,0x12,0x57,0xBD,0xDF
        };
        Aes aes;
        byte ct[16];
        byte tag[16];

        CHECK(wc_AesInit(&aes, NULL, INVALID_DEVID) == 0);
        CHECK(wc_AesGcmSetKey(&aes, gcmKey, sizeof(gcmKey)) == 0);
        CHECK(wc_AesGcmEncrypt(&aes, ct, gcmPlain, sizeof(gcmPlain),
                               gcmIv, sizeof(gcmIv), tag, sizeof(tag),
                               NULL, 0) == 0);
        wc_AesFree(&aes);
        CHECK(XMEMCMP(ct, gcmCipher, sizeof(gcmCipher)) == 0);
        CHECK(XMEMCMP(tag, gcmTag, sizeof(gcmTag)) == 0);
    }
#endif

    return 0;
}

/* ---------------------------------------------------------------------------
 * 4. Nothing ran behind our back
 *
 * Only SHA-256 was ever issued through the port. Every other engine counter
 * must therefore still read zero: if one moved, the port acted on an operation
 * this firmware never asked it to handle.
 *
 * The hash counter is deliberately excluded. It advances whenever an update is
 * accepted, and an update smaller than a block is only buffered, so it moves
 * without the engine running. That the hash produced no result is already
 * established by check_fails_closed(), which is the stronger statement anyway.
 * ------------------------------------------------------------------------ */
static int check_nothing_else_ran(void)
{
    CHECK(wc_ElsPkc_TimeoutCount == 0);
#ifndef NO_AES
    CHECK(wc_ElsPkc_AesOffloadCount == 0);
#ifdef HAVE_AESGCM
    CHECK(wc_ElsPkc_GcmOffloadCount == 0);
#endif
#ifdef WOLFSSL_CMAC
    CHECK(wc_ElsPkc_CmacOffloadCount == 0);
#endif
#endif
#ifdef HAVE_ECC
    CHECK(wc_ElsPkc_EccOffloadCount == 0);
    CHECK(wc_ElsPkc_EccPkcOffloadCount == 0);
#endif
    CHECK(wc_ElsPkc_RngOffloadCount == 0);
#ifdef WOLF_CRYPTO_CB_KEYSTORE
    CHECK(wc_ElsPkc_KeyStoreOffloadCount == 0);
#endif
    return 0;
}

int main(void)
{
    if (wolfCrypt_Init() != 0) {
        BKPT(0x70);
        spin_forever();
    }

    /* Expected to succeed: the bring-up stub reports the peripheral is up, so
     * the callback registers and dispatches. The crypto stubs are what fail. */
    if (wc_ElsPkc_Init() != 0) {
        BKPT(0x70);
        spin_forever();
    }

    if (check_keyref() != 0) {
        BKPT(0x71);
        spin_forever();
    }
    if (check_keyblob() != 0) {
        BKPT(0x72);
        spin_forever();
    }
    if (check_fails_closed() != 0) {
        BKPT(0x73);
        spin_forever();
    }
    if (check_software_path() != 0) {
        BKPT(0x75);
        spin_forever();
    }
    if (check_nothing_else_ran() != 0) {
        BKPT(0x74);
        spin_forever();
    }

    (void)wc_ElsPkc_Cleanup();
    (void)wolfCrypt_Cleanup();

    if (failures == 0) {
        BKPT(0x7f);
    }
    else {
        BKPT(0x70);
    }
    spin_forever();
    return 0;
}

extern unsigned long _sidata;
extern unsigned long _sdata;
extern unsigned long _edata;
extern unsigned long _sbss;
extern unsigned long _ebss;
extern void __libc_init_array(void);

void Reset_Handler(void);
void Reset_Handler(void)
{
    uint32_t* src;
    uint32_t* dst;

    src = (uint32_t*)&_sidata;
    for (dst = (uint32_t*)&_sdata; dst < (uint32_t*)&_edata; ++dst) {
        *dst = *src++;
    }
    for (dst = (uint32_t*)&_sbss; dst < (uint32_t*)&_ebss; ++dst) {
        *dst = 0;
    }
    __libc_init_array();
    (void)main();
    BKPT(0x70);
    spin_forever();
}
