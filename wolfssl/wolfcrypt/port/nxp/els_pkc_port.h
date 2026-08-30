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

/* The SHA-256 offload keeps its per-hash state in a pool entry hung off
 * devCtx, which only works if the port sees copy and free.
 *
 * Without WOLF_CRYPTO_CB_COPY, wc_Sha256Copy() falls through to a struct-wide
 * XMEMCPY that duplicates devCtx verbatim, leaving two hashes driving one
 * pool entry - and that is the path wc_Sha256GetHash() takes to snapshot a
 * TLS 1.3 transcript on every handshake. Without WOLF_CRYPTO_CB_FREE, a hash
 * or CMAC abandoned before its Final never gives its entry back. Both fail
 * silently and at runtime, so they are build errors here instead. */
#if !defined(NO_SHA256) && !defined(WOLF_CRYPTO_CB_COPY)
    #error WOLFSSL_ELS_PKC SHA-256 offload requires WOLF_CRYPTO_CB_COPY
#endif
#if !defined(WOLF_CRYPTO_CB_FREE) && \
    (!defined(NO_SHA256) || (defined(WOLFSSL_CMAC) && !defined(NO_AES)))
    #error WOLFSSL_ELS_PKC hash and CMAC offload require WOLF_CRYPTO_CB_FREE
#endif

/* The slot reference travels as a key's id blob, which is what wc_ecc_init_id()
 * and wc_AesInit_Id() exist to set. WOLF_CRYPTO_CB implies WOLF_PRIVATE_KEY_ID
 * in settings.h today, so this is normally satisfied for free - but the
 * dependency is real, and NO_WOLF_PRIVATE_KEY_ID would otherwise remove those
 * functions and leave a link error instead of a diagnosis. */
#ifndef WOLF_PRIVATE_KEY_ID
    #error WOLFSSL_ELS_PKC key slot references require WOLF_PRIVATE_KEY_ID
#endif

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#ifdef WOLF_CRYPTO_CB_KEYSTORE
    #include <wolfssl/wolfcrypt/wc_keystore.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Default device id for the EdgeLock port. 'EL' - an application may register
 * the callback under a different id and bind keys to that instead. */
#ifndef WOLFSSL_ELS_PKC_DEVID
    #define WOLFSSL_ELS_PKC_DEVID 0x454C  /* int: devId is int throughout */
#endif

/* Interrupt priority for the ELS completion interrupt. */
#ifndef WOLFSSL_ELS_PKC_IRQ_PRIO
    #define WOLFSSL_ELS_PKC_IRQ_PRIO 2
#endif

/* ---------------------------------------------------------------------------
 * Slot references
 *
 * wolfCrypt has no notion of a key that lives inside a peripheral: a callback
 * sees only key->id[], its length, and the devId. So a reference to an ELS key
 * slot has to be self-describing, and it travels as the key's id blob. The
 * same 16 bytes are what wolfPSA stores for a vendor-location key, followed
 * there by the public point - ELS cannot hand a slot key's public part back
 * after generation, so whoever wants it later has to have kept it.
 *
 * Never redefine a field; bump ver and append. 16 of the 32 bytes id[] allows
 * are used, and the rest is deliberate headroom.
 *
 *   off  size  field
 *   0    2     magic 'E','L'
 *   2    1     ver
 *   3    1     keyClass
 *   4    1     slot
 *   5    1     flags
 *   6    2     reserved, zero
 *   8    8     bind - first 8 bytes of SHA-256 over the X9.62 public point,
 *              zero for symmetric keys
 * ------------------------------------------------------------------------ */

/* Highest slot index a reference may name. The ELS key store has a fixed
 * number of slots; this mirrors the vendor header's MCUXCLELS_KEY_SLOTS so a
 * caller can range-check a slot without including the NXP SDK, and the port
 * asserts the two agree. */
#define WC_ELSPKC_MAX_SLOT       19

#define WC_ELSPKC_KEYREF_SZ      16
#define WC_ELSPKC_KEYREF_MAGIC_0 0x45  /* 'E' */
#define WC_ELSPKC_KEYREF_MAGIC_1 0x4C  /* 'L' */
#define WC_ELSPKC_KEYREF_VER     1
#define WC_ELSPKC_BIND_SZ        8

/* Each class maps 1:1 onto one ELS permission bit and one ELS entry point, so
 * a reference cannot be used for an operation it was not created for.
 *
 * RSA and the Ed curves are absent on purpose, not by oversight: the ELS key
 * property word has no bit for either, and uecsg/uecdh are P-256 only, so the
 * hardware has no slot that could hold them. They are accelerated through the
 * PKC tier with ordinary wolfCrypt key material - never vaulted - and use the
 * plain devId path with no reference at all. */
enum wc_ElsPkc_KeyClass {
    WC_ELSPKC_KEY_NONE     = 0,
    WC_ELSPKC_KEY_ECC_SIGN = 1,   /* ELS uecsg */
    WC_ELSPKC_KEY_ECC_DH   = 2,   /* ELS uecdh */
    WC_ELSPKC_KEY_AES      = 3,   /* ELS uaes  */
    WC_ELSPKC_KEY_HMAC     = 4,   /* ELS uhmac */
    WC_ELSPKC_KEY_CMAC     = 5,   /* ELS ucmac */
    WC_ELSPKC_KEY_KWK      = 6,   /* ELS ukwk / ukuok */
    WC_ELSPKC_KEY_CKDF     = 7,   /* ELS uckdf */
    WC_ELSPKC_KEY_HKDF     = 8    /* ELS uhkdf */
};

/* bit0 is set when bind[] carries a real value rather than zeros; bits 1-2 are
 * creation-time attributes, meaningful only on a key generation, where the
 * reference names a slot the key does not occupy yet. */
#define WC_ELSPKC_REF_FLAG_BIND       0x01
#define WC_ELSPKC_REF_FLAG_EXPORTABLE 0x02  /* ELS wrpok */
#define WC_ELSPKC_REF_FLAG_PERSISTENT 0x04  /* ELS frtn  */

typedef struct wc_ElsPkc_KeyRef {
    byte keyClass;
    byte slot;
    byte flags;
    byte bind[WC_ELSPKC_BIND_SZ];
} wc_ElsPkc_KeyRef;

/* Serialise the reference into out, which must hold WC_ELSPKC_KEYREF_SZ bytes.
 * outSz is in/out: on entry the capacity of out, on return the number of bytes
 * written. Passing out == NULL is a size query - outSz receives the required
 * size and the call returns LENGTH_ONLY_E, matching the convention used across
 * wolfCrypt.
 *
 * Parse rejects a wrong magic, an unknown version, an unassigned class and an
 * out-of-range slot, returning BAD_STATE_E for each - the blob is rejected
 * content rather than a caller mistake. A blob longer than the reference is
 * accepted and only its prefix read, because wolfPSA stores the public point
 * immediately after it. Parsing touches no hardware, so a reference that
 * parses is still only a claim; ElsCheckSlot() is what tests it. */
WOLFSSL_API int wc_ElsPkc_MakeKeyRef(const wc_ElsPkc_KeyRef* ref, byte* out,
                                     word32* outSz);
WOLFSSL_API int wc_ElsPkc_ParseKeyRef(const byte* in, word32 inSz,
                                      wc_ElsPkc_KeyRef* ref);

#ifdef HAVE_ECC
/* Initialise an ecc_key that names an ELS slot instead of holding a private
 * key, and bind it to the port's devId and to P-256.
 *
 * For a sign or ECDH operation the slot must already hold a key. For a key
 * generation the reference is a *request*: slot and the exportable/persistent
 * flags say where the key should land and what it should be allowed to do,
 * and the key does not exist until wc_ecc_make_key() returns. */
WOLFSSL_API int wc_ElsPkc_EccUseSlot(ecc_key* key, const wc_ElsPkc_KeyRef* ref,
                                     void* heap, int devId);
#endif

#ifndef NO_AES
/* Same, for an Aes that names a slot rather than carrying key material.
 *
 * The key store can now put an AES key into a slot, but the cipher path still
 * does not consume the reference - an encrypt under a slot-resident AES key
 * needs the ELS internal-key option, which is separate work. Until then this
 * builds the reference and binds the Aes to it, and an encrypt against it
 * fails rather than silently using an empty key, because wc_AesInit_Id()
 * deliberately leaves keyInstalled clear. */
WOLFSSL_API int wc_ElsPkc_AesUseSlot(Aes* aes, const wc_ElsPkc_KeyRef* ref,
                                     void* heap, int devId);
#endif

/* Instrumentation: how many times each hardware path actually ran, and which
 * completion route was taken.
 *
 * These exist so a test can assert the offload ran rather than only that its
 * result agrees with software - a handler that never fires produces a passing
 * comparison of software against itself. They are incremented without
 * atomics, some outside the ELS lock, so treat them as best-effort under
 * concurrency: fine for a counter that only has to be non-zero. */
WOLFSSL_API extern unsigned long wc_ElsPkc_IrqWaitCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_PollWaitCount;
WOLFSSL_API extern unsigned long wc_ElsPkc_TimeoutCount;
#ifndef NO_SHA256
WOLFSSL_API extern unsigned long wc_ElsPkc_HashOffloadCount;
#endif
#ifndef NO_AES
WOLFSSL_API extern unsigned long wc_ElsPkc_AesOffloadCount;
#endif
#if defined(HAVE_AESGCM) && !defined(NO_AES)
WOLFSSL_API extern unsigned long wc_ElsPkc_GcmOffloadCount;
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
WOLFSSL_API extern unsigned long wc_ElsPkc_CmacOffloadCount;
#endif
#ifndef WC_NO_RNG
WOLFSSL_API extern unsigned long wc_ElsPkc_RngOffloadCount;
#endif
#ifdef WOLF_CRYPTO_CB_KEYSTORE
WOLFSSL_API extern unsigned long wc_ElsPkc_KeyStoreOffloadCount;
#endif
#ifdef HAVE_ECC
WOLFSSL_API extern unsigned long wc_ElsPkc_EccOffloadCount;
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
WOLFSSL_API extern unsigned long wc_ElsPkc_EccPkcOffloadCount;
#endif
#ifndef NO_RSA
WOLFSSL_API extern unsigned long wc_ElsPkc_RsaOffloadCount;
#endif
#ifdef HAVE_CURVE25519
WOLFSSL_API extern unsigned long wc_ElsPkc_X25519OffloadCount;
#endif

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
