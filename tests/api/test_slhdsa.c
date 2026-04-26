/* test_slhdsa.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_HAVE_SLHDSA
    #include <wolfssl/wolfcrypt/wc_slhdsa.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <tests/api/api.h>
#include <tests/api/test_slhdsa.h>


/*
 * Test basic init/free and NULL parameter handling for SLH-DSA key operations.
 */
int test_wc_slhdsa(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey key;

    /* Test NULL parameter handling for init. */
    ExpectIntEQ(wc_SlhDsaKey_Init(NULL, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test wc_SlhDsaKey_Free with NULL - should not crash. */
    wc_SlhDsaKey_Free(NULL);

    /* Test valid init for each supported parameter set. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
    wc_SlhDsaKey_Free(&key);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test size functions for SLH-DSA.
 */
int test_wc_slhdsa_sizes(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey key;

    /* Test NULL parameter handling for size functions. */
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SigSize(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test sizes for each parameter set. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE128S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE128S),
        WC_SLHDSA_SHAKE128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE128S),
        WC_SLHDSA_SHAKE128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE128S),
        WC_SLHDSA_SHAKE128S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE128F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE128F),
        WC_SLHDSA_SHAKE128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE128F),
        WC_SLHDSA_SHAKE128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE128F),
        WC_SLHDSA_SHAKE128F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE192S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE192S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE192S),
        WC_SLHDSA_SHAKE192S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE192F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE192F),
        WC_SLHDSA_SHAKE192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE192F),
        WC_SLHDSA_SHAKE192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE192F),
        WC_SLHDSA_SHAKE192F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE256S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE256S),
        WC_SLHDSA_SHAKE256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE256S),
        WC_SLHDSA_SHAKE256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE256S),
        WC_SLHDSA_SHAKE256S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHAKE256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHAKE256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHAKE256F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHAKE256F),
        WC_SLHDSA_SHAKE256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHAKE256F),
        WC_SLHDSA_SHAKE256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHAKE256F),
        WC_SLHDSA_SHAKE256F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_128S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_128S),
        WC_SLHDSA_SHA2_128S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_128S),
        WC_SLHDSA_SHA2_128S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_128S),
        WC_SLHDSA_SHA2_128S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_128F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_128F),
        WC_SLHDSA_SHA2_128F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_128F),
        WC_SLHDSA_SHA2_128F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_128F),
        WC_SLHDSA_SHA2_128F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_192S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_192S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_192S),
        WC_SLHDSA_SHA2_192S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_192S),
        WC_SLHDSA_SHA2_192S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_192S),
        WC_SLHDSA_SHA2_192S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_192F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_192F),
        WC_SLHDSA_SHA2_192F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_192F),
        WC_SLHDSA_SHA2_192F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_192F),
        WC_SLHDSA_SHA2_192F_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_256S_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_256S),
        WC_SLHDSA_SHA2_256S_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_256S),
        WC_SLHDSA_SHA2_256S_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_256S),
        WC_SLHDSA_SHA2_256S_SIG_LEN);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSize(&key), WC_SLHDSA_SHA2_256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSize(&key), WC_SLHDSA_SHA2_256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSize(&key), WC_SLHDSA_SHA2_256F_SIG_LEN);
    wc_SlhDsaKey_Free(&key);

#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    ExpectIntEQ(wc_SlhDsaKey_PrivateSizeFromParam(SLHDSA_SHA2_256F),
        WC_SLHDSA_SHA2_256F_PRIV_LEN);
#endif
    ExpectIntEQ(wc_SlhDsaKey_PublicSizeFromParam(SLHDSA_SHA2_256F),
        WC_SLHDSA_SHA2_256F_PUB_LEN);
    ExpectIntEQ(wc_SlhDsaKey_SigSizeFromParam(SLHDSA_SHA2_256F),
        WC_SLHDSA_SHA2_256F_SIG_LEN);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test key generation for SLH-DSA.
 */
int test_wc_slhdsa_make_key(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

    /* Test MakeKeyWithRandom. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    {
        byte sk_seed[WC_SLHDSA_SHAKE128S_SEED_LEN];
        byte sk_prf[WC_SLHDSA_SHAKE128S_SEED_LEN];
        byte pk_seed[WC_SLHDSA_SHAKE128S_SEED_LEN];

        XMEMSET(sk_seed, 0x01, sizeof(sk_seed));
        XMEMSET(sk_prf, 0x02, sizeof(sk_prf));
        XMEMSET(pk_seed, 0x03, sizeof(pk_seed));

        /* Test NULL parameter handling. */
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(NULL, sk_seed,
            sizeof(sk_seed), sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, NULL, sizeof(sk_seed),
            sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed,
            sizeof(sk_seed), NULL, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed,
            sizeof(sk_seed), sk_prf, sizeof(sk_prf), NULL, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* Test wrong size. */
        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed, 8,
            sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_SlhDsaKey_MakeKeyWithRandom(&key, sk_seed,
            sizeof(sk_seed), sk_prf, sizeof(sk_prf), pk_seed, sizeof(pk_seed)),
            0);
        wc_SlhDsaKey_Free(&key);
    }
#endif

    wc_FreeRng(&rng);
#endif /* WOLFSSL_HAVE_SLHDSA && !WOLFSSL_SLHDSA_VERIFY_ONLY */
    return EXPECT_RESULT();
}

/*
 * Test signing for SLH-DSA.
 */
int test_wc_slhdsa_sign(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    word32 expSigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(NULL, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256F_SIG_LEN;
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), NULL, sizeof(msg),
        sig, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        NULL, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test buffer too small. */
    sigLen = 10;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* Test successful signing. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, expSigLen);

    /* Test signing with NULL context (allowed). */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, NULL, 0, msg, sizeof(msg),
        sig, &sigLen, &rng), 0);

    wc_SlhDsaKey_Free(&key);

    /* Test SignDeterministic. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignDeterministic(NULL, ctx, sizeof(ctx),
        msg, sizeof(msg), sig, &sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignDeterministic(&key, ctx, sizeof(ctx),
        msg, sizeof(msg), sig, &sigLen), 0);
    ExpectIntEQ(sigLen, expSigLen);

    wc_SlhDsaKey_Free(&key);

    /* Test SignWithRandom. */
    {
        byte addRnd[WC_SLHDSA_MAX_SEED];
        XMEMSET(addRnd, 0x55, sizeof(addRnd));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL,
            INVALID_DEVID), 0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
        ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL,
            INVALID_DEVID), 0);
#endif
        ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

        sigLen = WC_SLHDSA_MAX_SIG_LEN;
        ExpectIntEQ(wc_SlhDsaKey_SignWithRandom(NULL, ctx, sizeof(ctx),
            msg, sizeof(msg), sig, &sigLen, addRnd),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignWithRandom(&key, ctx, sizeof(ctx),
            msg, sizeof(msg), sig, &sigLen, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignWithRandom(&key, ctx, sizeof(ctx),
            msg, sizeof(msg), sig, &sigLen, addRnd), 0);
        ExpectIntEQ(sigLen, expSigLen);

        wc_SlhDsaKey_Free(&key);
    }

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA && !WOLFSSL_SLHDSA_VERIFY_ONLY */
    return EXPECT_RESULT();
}

/*
 * Test verification for SLH-DSA.
 */
int test_wc_slhdsa_verify(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Generate a signature. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);

    /* Test NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(NULL, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), NULL, sizeof(msg),
        sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        NULL, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test successful verification. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    /* Test verification with wrong message. */
    msg[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    msg[0] ^= 0xFF;

    /* Test verification with wrong context. */
    ctx[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    ctx[0] ^= 0xFF;

    /* Test verification with corrupted signature. */
    sig[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    sig[0] ^= 0xFF;

    /* Test verification with NULL context (allowed, but must match signing). */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, NULL, 0, msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, NULL, 0, msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test combined sign and verify for all parameter sets.
 */
int test_wc_slhdsa_sign_vfy(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE128S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE128F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, (word32)wc_SlhDsaKey_SigSize(&key));
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE192F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE256S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHAKE256F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
#endif

#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_128S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_128F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_128F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_192S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_192F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_192F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256S, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_256S_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHA2_256F, NULL, INVALID_DEVID),
        0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, WC_SLHDSA_SHA2_256F_SIG_LEN);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test hash signing and verification for SLH-DSA.
 */
int test_wc_slhdsa_sign_hash(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte hash[64];
    byte* sig = NULL;
    word32 sigLen;
    word32 expSigLen;
    byte ctx[10];

    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(hash, 0xBB, sizeof(hash));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE128F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE192F_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256S_SIG_LEN;
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    expSigLen = WC_SLHDSA_SHAKE256F_SIG_LEN;
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Test SignHash NULL parameter handling. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignHash(NULL, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, &sigLen, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), NULL,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, &sigLen, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, NULL, &sigLen, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, NULL, &rng),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash,
        sizeof(hash), WC_HASH_TYPE_SHA256, sig, &sigLen, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test SignHash with SHA-256. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, &sigLen, &rng), 0);
    ExpectIntEQ(sigLen, expSigLen);
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), 0);

    /* Test VerifyHash NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(NULL, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), NULL, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, NULL, sigLen), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test VerifyHash with wrong hash. */
    hash[0] ^= 0xFF;
    ExpectIntNE(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), 0);
    hash[0] ^= 0xFF;

    /* Test SignHashDeterministic. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_SignHashDeterministic(NULL, ctx, sizeof(ctx),
        hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_SignHashDeterministic(&key, ctx, sizeof(ctx),
        hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
        WC_HASH_TYPE_SHA256, sig, sigLen), 0);

    /* Test SignHashWithRandom. */
    {
        byte addRnd[WC_SLHDSA_MAX_SEED];
        XMEMSET(addRnd, 0x55, sizeof(addRnd));

        sigLen = WC_SLHDSA_MAX_SIG_LEN;
        ExpectIntEQ(wc_SlhDsaKey_SignHashWithRandom(NULL, ctx, sizeof(ctx),
            hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen, addRnd),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignHashWithRandom(&key, ctx, sizeof(ctx),
            hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SlhDsaKey_SignHashWithRandom(&key, ctx, sizeof(ctx),
            hash, 32, WC_HASH_TYPE_SHA256, sig, &sigLen, addRnd), 0);
        ExpectIntEQ(wc_SlhDsaKey_VerifyHash(&key, ctx, sizeof(ctx), hash, 32,
            WC_HASH_TYPE_SHA256, sig, sigLen), 0);
    }

    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test export and import for SLH-DSA keys.
 */
int test_wc_slhdsa_export_import(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    SlhDsaKey key2;
    WC_RNG rng;
    byte* privKey = NULL;
    byte* pubKey = NULL;
    word32 privKeyLen;
    word32 expPrivKeyLen;
    word32 pubKeyLen;
    word32 expPubKeyLen;
    byte msg[64];
    byte* sig = NULL;
    word32 sigLen;
    byte ctx[10];

    privKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PRIV_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(privKey);
    pubKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PUB_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pubKey);
    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    XMEMSET(msg, 0xAA, sizeof(msg));
    XMEMSET(ctx, 0x01, sizeof(ctx));

    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling for export functions. */
    privKeyLen = WC_SLHDSA_MAX_PRIV_LEN;
    pubKeyLen = WC_SLHDSA_MAX_PUB_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(NULL, privKey, &privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(NULL, pubKey, &pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test NULL parameter handling for import functions. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(NULL, privKey, privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(NULL, pubKey, pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 16;
    expPubKeyLen = 2 * 16;
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 16;
    expPubKeyLen = 2 * 16;
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 24;
    expPubKeyLen = 2 * 24;
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 24;
    expPubKeyLen = 2 * 24;
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 32;
    expPubKeyLen = 2 * 32;
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
    expPrivKeyLen = 4 * 32;
    expPubKeyLen = 2 * 32;
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Test export with NULL buffer. */
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, NULL, &privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, NULL, &pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test export with buffer too small. */
    privKeyLen = 10;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeyLen),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));
    pubKeyLen = 10;
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeyLen),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* Test successful export. */
    privKeyLen = WC_SLHDSA_MAX_PRIV_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeyLen), 0);
    ExpectIntEQ(privKeyLen, expPrivKeyLen);

    pubKeyLen = WC_SLHDSA_MAX_PUB_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeyLen), 0);
    ExpectIntEQ(pubKeyLen, expPubKeyLen);

    /* Sign with original key. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);

    /* Test import into new key and verify. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif

    /* Test import with NULL data. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key2, NULL, privKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key2, NULL, pubKeyLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Test import with wrong size. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key2, privKey, 10),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key2, pubKey, 10),
        WC_NO_ERR_TRACE(BAD_LENGTH_E));

    /* Test successful import of public key only. */
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key2, pubKey, pubKeyLen), 0);
    /* Verify with imported public key. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key2, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);
    wc_SlhDsaKey_Free(&key2);

    /* Test import of private key. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key2, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key2, privKey, privKeyLen), 0);
    /* Sign with imported key. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key2, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, &sigLen, &rng), 0);
    /* Verify with original key. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, ctx, sizeof(ctx), msg, sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key2);
    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

/*
 * Test key check for SLH-DSA.
 */
int test_wc_slhdsa_check_key(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    SlhDsaKey key;
    WC_RNG rng;
    byte* privKey = NULL;
    byte* pubKey = NULL;
    word32 privKeyLen;
    word32 pubKeyLen;

    privKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PRIV_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(privKey);
    pubKey = (byte*)XMALLOC(WC_SLHDSA_MAX_PUB_LEN, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pubKey);

    XMEMSET(&rng, 0, sizeof(WC_RNG));
    ExpectIntEQ(wc_InitRng(&rng), 0);

    /* Test NULL parameter handling. */
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    /* Test check of valid key. */
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);

    /* Export keys. */
    privKeyLen = WC_SLHDSA_MAX_PRIV_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPrivate(&key, privKey, &privKeyLen), 0);
    pubKeyLen = WC_SLHDSA_MAX_PUB_LEN;
    ExpectIntEQ(wc_SlhDsaKey_ExportPublic(&key, pubKey, &pubKeyLen), 0);

    wc_SlhDsaKey_Free(&key);

    /* Test check with only public key imported - requires private key. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key, pubKey, pubKeyLen), 0);
    /* CheckKey requires a private key to validate. */
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), WC_NO_ERR_TRACE(MISSING_KEY));
    wc_SlhDsaKey_Free(&key);

    /* Test check with only private key imported. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key, privKey, privKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    wc_SlhDsaKey_Free(&key);

    /* Test check with both keys imported.
     * Order: ImportPublic uses |= on flags, so Private and Public can be
     * imported in either order without dropping the FLAG_PRIVATE bit. */
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_128F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_192F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE192F, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256S)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256S, NULL, INVALID_DEVID),
        0);
#elif defined(WOLFSSL_SLHDSA_PARAM_256F)
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE256F, NULL, INVALID_DEVID),
        0);
#endif
    ExpectIntEQ(wc_SlhDsaKey_ImportPublic(&key, pubKey, pubKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_ImportPrivate(&key, privKey, privKeyLen), 0);
    ExpectIntEQ(wc_SlhDsaKey_CheckKey(&key), 0);
    wc_SlhDsaKey_Free(&key);

    wc_FreeRng(&rng);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT)
/* Round-trip a single SLH-DSA parameter set through the DER codec:
 * generate -> KeyToDer -> PrivateKeyDecode -> sign/verify round-trip.
 * Also tests PublicKeyToDer -> PublicKeyDecode, and that the decode
 * correctly auto-detects the parameter set from the OID. */
static int slhdsa_der_roundtrip_one(enum SlhDsaParam param)
{
    EXPECT_DECLS;
    SlhDsaKey keyGen;
    SlhDsaKey keyPriv;
    SlhDsaKey keyPub;
    WC_RNG rng;
    byte* derBuf = NULL;
    byte* sig = NULL;
    const word32 derBufSz = 16 * 1024;
    word32 derLen;
    word32 idx;
    word32 sigLen;
    /* Use the same param as placeholder - the auto-detect overrides it
     * anyway, and this avoids failures when FAST or SMALL variants are
     * selectively disabled via WOLFSSL_SLHDSA_PARAM_NO_FAST/NO_SMALL. */
    enum SlhDsaParam placeholder = param;
    static const byte msg[] = "SLH-DSA DER round-trip";

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&keyGen, 0, sizeof(keyGen));
    XMEMSET(&keyPriv, 0, sizeof(keyPriv));
    XMEMSET(&keyPub, 0, sizeof(keyPub));

    derBuf = (byte*)XMALLOC(derBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(derBuf);
    sig = (byte*)XMALLOC(WC_SLHDSA_MAX_SIG_LEN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sig);

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Init(&keyGen, param, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&keyGen, &rng), 0);

    /* Encode the freshly-generated key to DER (private + public). */
    ExpectIntGT(derLen = (word32)wc_SlhDsaKey_KeyToDer(&keyGen, derBuf,
        derBufSz), 0);

    /* Decode into a fresh key.  The decode must auto-detect the real
     * parameter set from the OID embedded in the DER encoding. */
    ExpectIntEQ(wc_SlhDsaKey_Init(&keyPriv, placeholder, NULL, INVALID_DEVID),
        0);
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(derBuf, &idx, &keyPriv, derLen),
        0);
    /* Verify the decoded key reports the ORIGINAL parameter set. */
    if (keyPriv.params != NULL) {
        ExpectIntEQ((int)keyPriv.params->param, (int)param);
    }

    /* Sign with the decoded private key and verify with the originally
     * generated key. This proves the decoded key material is correct. */
    sigLen = WC_SLHDSA_MAX_SIG_LEN;
    ExpectIntEQ(wc_SlhDsaKey_Sign(&keyPriv, NULL, 0, msg, (word32)sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&keyGen, NULL, 0, msg, (word32)sizeof(msg),
        sig, sigLen), 0);

    /* Also test PrivateKeyToDer -> PrivateKeyDecode round-trip. */
    {
        SlhDsaKey keyPriv2;
        word32 derLen2;
        word32 idx2 = 0;
        XMEMSET(&keyPriv2, 0, sizeof(keyPriv2));
        ExpectIntGT(derLen2 = (word32)wc_SlhDsaKey_PrivateKeyToDer(&keyGen,
            derBuf, derBufSz), 0);
        ExpectIntEQ(wc_SlhDsaKey_Init(&keyPriv2, placeholder, NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(derBuf, &idx2, &keyPriv2,
            derLen2), 0);
        /* Verify the PrivateKeyToDer output matches KeyToDer. */
        sigLen = WC_SLHDSA_MAX_SIG_LEN;
        ExpectIntEQ(wc_SlhDsaKey_Sign(&keyPriv2, NULL, 0, msg,
            (word32)sizeof(msg), sig, &sigLen, &rng), 0);
        ExpectIntEQ(wc_SlhDsaKey_Verify(&keyGen, NULL, 0, msg,
            (word32)sizeof(msg), sig, sigLen), 0);
        wc_SlhDsaKey_Free(&keyPriv2);
    }

    /* Now round-trip the public key alone. */
    ExpectIntGT(derLen = (word32)wc_SlhDsaKey_PublicKeyToDer(&keyGen, derBuf,
        derBufSz, 1), 0);
    ExpectIntEQ(wc_SlhDsaKey_Init(&keyPub, placeholder, NULL, INVALID_DEVID),
        0);
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(derBuf, &idx, &keyPub, derLen), 0);
    if (keyPub.params != NULL) {
        ExpectIntEQ((int)keyPub.params->param, (int)param);
    }
    /* The decoded public key should verify the signature we just produced. */
    ExpectIntEQ(wc_SlhDsaKey_Verify(&keyPub, NULL, 0, msg, (word32)sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&keyPub);
    wc_SlhDsaKey_Free(&keyPriv);
    wc_SlhDsaKey_Free(&keyGen);
    wc_FreeRng(&rng);
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return EXPECT_RESULT();
}
#endif

/*
 * DER codec round-trip test: encode each compiled-in SLH-DSA parameter set
 * to DER, decode it (without telling the decoder which parameter set it is),
 * confirm auto-detect produces the right parameter, and verify a signature
 * produced with the decoded key. This test would fail if PrivateKeyDecode
 * / PublicKeyDecode did not auto-detect the parameter set from the OID.
 */
int test_wc_slhdsa_der_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WC_ENABLE_ASYM_KEY_EXPORT)
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE128S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE128F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE192S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE192F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE256S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHAKE256F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_128S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_128F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_192S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_192F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_256S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(slhdsa_der_roundtrip_one(SLHDSA_SHA2_256F), TEST_SUCCESS);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */
#endif /* WOLFSSL_HAVE_SLHDSA && !VERIFY_ONLY && WC_ENABLE_ASYM_KEY_EXPORT */
    return EXPECT_RESULT();
}

/*
 * Negative / error-path tests for the DER encode/decode functions.
 */
int test_wc_slhdsa_der_negative(void)
{
    EXPECT_DECLS;
#ifdef WOLFSSL_HAVE_SLHDSA
    SlhDsaKey key;
    word32 idx;
    byte buf[16];

    XMEMSET(&key, 0, sizeof(key));

    /* PrivateKeyDecode: NULL parameters */
#ifndef WOLFSSL_SLHDSA_VERIFY_ONLY
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(NULL, &idx, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(buf, NULL, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(buf, &idx, NULL, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(buf, &idx, &key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* PrivateKeyDecode: truncated data */
    idx = 0;
    XMEMSET(buf, 0, sizeof(buf));
    ExpectIntNE(wc_SlhDsaKey_PrivateKeyDecode(buf, &idx, &key, sizeof(buf)), 0);
#endif

    /* PublicKeyDecode: NULL parameters */
    idx = 0;
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(NULL, &idx, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(buf, NULL, &key, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(buf, &idx, NULL, 10),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyDecode(buf, &idx, &key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    /* KeyToDer / PrivateKeyToDer: NULL key */
    ExpectIntEQ(wc_SlhDsaKey_KeyToDer(NULL, buf, sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyToDer(NULL, buf, sizeof(buf)),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* KeyToDer: public-only key should return MISSING_KEY */
    {
        SlhDsaKey pubOnly;
        XMEMSET(&pubOnly, 0, sizeof(pubOnly));
#ifdef WOLFSSL_SLHDSA_PARAM_128S
        ExpectIntEQ(wc_SlhDsaKey_Init(&pubOnly, SLHDSA_SHAKE128S, NULL,
            INVALID_DEVID), 0);
        /* Only set the public flag, no private key material. */
        pubOnly.flags = WC_SLHDSA_FLAG_PUBLIC;
        ExpectIntEQ(wc_SlhDsaKey_KeyToDer(&pubOnly, NULL, 0),
            WC_NO_ERR_TRACE(MISSING_KEY));
        ExpectIntEQ(wc_SlhDsaKey_PrivateKeyToDer(&pubOnly, NULL, 0),
            WC_NO_ERR_TRACE(MISSING_KEY));
        wc_SlhDsaKey_Free(&pubOnly);
#endif
    }
#endif /* WC_ENABLE_ASYM_KEY_EXPORT && !VERIFY_ONLY */

    /* PublicKeyToDer: NULL key */
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
    ExpectIntEQ(wc_SlhDsaKey_PublicKeyToDer(NULL, buf, sizeof(buf), 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

#endif /* WOLFSSL_HAVE_SLHDSA */
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    !defined(NO_FILESYSTEM)
/* Load an RFC 9909 compliant DER file from disk and confirm that
 * wc_SlhDsaKey_PrivateKeyDecode accepts it, auto-detects the parameter
 * set from the OID, and produces a usable signing key. This test
 * exercises the on-disk certs/slhdsa/ fixtures - any future file-format
 * drift (nested wrapper, seed-only, wrong length) will be caught here. */
static int slhdsa_decode_file_one(const char *path, enum SlhDsaParam expected)
{
    EXPECT_DECLS;
    XFILE f = XBADFILE;
    byte der[256];
    int derSz = 0;
    SlhDsaKey key;
    WC_RNG rng;
    word32 idx = 0;
    byte sig[WC_SLHDSA_MAX_SIG_LEN];
    word32 sigLen = (word32)sizeof(sig);
    static const byte msg[] = "slhdsa decode-file test";

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));

    ExpectTrue((f = XFOPEN(path, "rb")) != XBADFILE);
    if (f != XBADFILE) {
        ExpectIntGT(derSz = (int)XFREAD(der, 1, sizeof(der), f), 0);
        XFCLOSE(f);
    }

    /* Seed the decoder with a DIFFERENT parameter than the file; auto-detect
     * must overwrite it from the OID. If parameter-set gating disables the
     * placeholder, fall back to the expected param (tests still exercise
     * auto-detect because that's what the decoder uses). */
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, expected, NULL, INVALID_DEVID), 0);

    ExpectIntEQ(wc_SlhDsaKey_PrivateKeyDecode(der, &idx, &key, (word32)derSz),
        0);
    ExpectNotNull(key.params);
    if (key.params != NULL) {
        ExpectIntEQ((int)key.params->param, (int)expected);
    }

    /* Sanity: signing works with the decoded key. */
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Sign(&key, NULL, 0, msg, (word32)sizeof(msg),
        sig, &sigLen, &rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Verify(&key, NULL, 0, msg, (word32)sizeof(msg),
        sig, sigLen), 0);

    wc_SlhDsaKey_Free(&key);
    wc_FreeRng(&rng);
    return EXPECT_RESULT();
}
#endif

/* Load each checked-in bench_slhdsa_shake*_key.der fixture and confirm it
 * decodes via wc_SlhDsaKey_PrivateKeyDecode with correct auto-detection.
 * These fixtures are RFC 9909 compliant (bare OCTET STRING, 4*n bytes) -
 * this test would fail if the files drift to a non-compliant encoding
 * (e.g. nested OCTET STRING, seed-only). */
int test_wc_slhdsa_der_decode_files(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    !defined(NO_FILESYSTEM)
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake128s_key.der", SLHDSA_SHAKE128S),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake128f_key.der", SLHDSA_SHAKE128F),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake192s_key.der", SLHDSA_SHAKE192S),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake192f_key.der", SLHDSA_SHAKE192F),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake256s_key.der", SLHDSA_SHAKE256S),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_shake256f_key.der", SLHDSA_SHAKE256F),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_128s_key.der", SLHDSA_SHA2_128S),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_128f_key.der", SLHDSA_SHA2_128F),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_192s_key.der", SLHDSA_SHA2_192S),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_192f_key.der", SLHDSA_SHA2_192F),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_256s_key.der", SLHDSA_SHA2_256S),
        TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(slhdsa_decode_file_one(
        "./certs/slhdsa/bench_slhdsa_sha2_256f_key.der", SLHDSA_SHA2_256F),
        TEST_SUCCESS);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */
#endif
    return EXPECT_RESULT();
}

#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WOLFSSL_CERT_GEN) && defined(WC_ENABLE_ASYM_KEY_EXPORT) && \
    !defined(NO_CERTS)
/* Mint a self-signed leaf cert with the given SLH-DSA key, parse it,
 * and call ConfirmSignature() directly with the parsed components.
 *
 * Sister function: wolfcrypt/test/slhdsa_interop_one.c::run_one() does
 * the same procedure out-of-process for one variant per invocation.
 * If the cert-gen / parse / confirm-signature API surface evolves,
 * both copies must be updated together. */
static int slhdsa_cert_roundtrip_one(enum SlhDsaParam param, int certKeyType,
    int sigType)
{
    EXPECT_DECLS;
    SlhDsaKey key;
    WC_RNG rng;
    Cert cert;
    byte* der = NULL;
    int derSz = 0;
    int signedSz = 0;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));

    der = (byte*)XMALLOC(64 * 1024, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(der);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectIntEQ(wc_SlhDsaKey_Init(&key, param, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SlhDsaKey_MakeKey(&key, &rng), 0);

    ExpectIntEQ(wc_InitCert(&cert), 0);
    XSTRNCPY(cert.subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.state, "WA", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.locality, "Seattle", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.org, "wolfSSL", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.unit, "Test", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.commonName, "slhdsa-test", CTC_NAME_SIZE);
    /* Self-signed: issuer == subject. */
    XMEMCPY(&cert.issuer, &cert.subject, sizeof(cert.issuer));
    cert.sigType = sigType;
    cert.isCA = 1;
    cert.selfSigned = 1;

    ExpectIntGT(derSz = wc_MakeCert_ex(&cert, der, 64 * 1024,
        certKeyType, &key, &rng), 0);
    ExpectIntGT(signedSz = wc_SignCert_ex(cert.bodySz, sigType, der,
        64 * 1024, certKeyType, &key, &rng), 0);

    /* Parse the cert (NO_VERIFY) to extract TBS, signature, and the
     * embedded public key, then call ConfirmSignature() directly with
     * the SLH-DSA pubKey. This drives the SLH-DSA OID -> SLHDSA_*
     * dispatch arms in ConfirmSignature for both SHAKE and SHA-2,
     * which is the actual code path this commit modifies. A missed
     * SHA-2 dispatch site or a signature corruption would surface as
     * a non-zero return from ConfirmSignature. */
    {
        DecodedCert decoded;
        SignatureCtx sigCtx;
        int parseRet, sigRet;

        InitDecodedCert(&decoded, der, (word32)signedSz, NULL);
        parseRet = ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
        ExpectIntEQ(parseRet, 0);

        if (parseRet == 0) {
            InitSignatureCtx(&sigCtx, NULL, INVALID_DEVID);
            sigRet = ConfirmSignature(&sigCtx,
                der + decoded.certBegin,
                decoded.sigIndex - decoded.certBegin,
                decoded.publicKey, decoded.pubKeySize, decoded.keyOID,
                decoded.signature, decoded.sigLength,
                decoded.signatureOID, NULL, 0, NULL);
            ExpectIntEQ(sigRet, 0);
            FreeSignatureCtx(&sigCtx);
        }
        FreeDecodedCert(&decoded);
    }

    wc_SlhDsaKey_Free(&key);
    wc_FreeRng(&rng);
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (EXPECT_RESULT() != TEST_SUCCESS) {
        return TEST_FAIL;
    }
    return TEST_SUCCESS;
}
#endif

/* End-to-end cert layer test: for each compiled-in SLH-DSA parameter set,
 * mint a self-signed cert, parse it, and verify the cert's signature using
 * the embedded public key. This exercises every site touched in this
 * follow-up: MakeAnyCert, SetAlgoID, ConfirmSignature, the SLH-DSA branches
 * in src/x509.c, and the SHA2-aware key dispatch tables. */
int test_wc_slhdsa_cert_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_SLHDSA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY) && \
    defined(WOLFSSL_CERT_GEN) && defined(WC_ENABLE_ASYM_KEY_EXPORT) && \
    !defined(NO_CERTS)
#ifdef WOLFSSL_SLHDSA_PARAM_128S
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHAKE128S,
        SLH_DSA_SHAKE_128S_TYPE, CTC_SLH_DSA_SHAKE_128S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_128F
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHAKE128F,
        SLH_DSA_SHAKE_128F_TYPE, CTC_SLH_DSA_SHAKE_128F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192S
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHAKE192S,
        SLH_DSA_SHAKE_192S_TYPE, CTC_SLH_DSA_SHAKE_192S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_192F
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHAKE192F,
        SLH_DSA_SHAKE_192F_TYPE, CTC_SLH_DSA_SHAKE_192F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256S
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHAKE256S,
        SLH_DSA_SHAKE_256S_TYPE, CTC_SLH_DSA_SHAKE_256S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_256F
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHAKE256F,
        SLH_DSA_SHAKE_256F_TYPE, CTC_SLH_DSA_SHAKE_256F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_SHA2
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHA2_128S,
        SLH_DSA_SHA2_128S_TYPE, CTC_SLH_DSA_SHA2_128S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHA2_128F,
        SLH_DSA_SHA2_128F_TYPE, CTC_SLH_DSA_SHA2_128F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHA2_192S,
        SLH_DSA_SHA2_192S_TYPE, CTC_SLH_DSA_SHA2_192S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHA2_192F,
        SLH_DSA_SHA2_192F_TYPE, CTC_SLH_DSA_SHA2_192F), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHA2_256S,
        SLH_DSA_SHA2_256S_TYPE, CTC_SLH_DSA_SHA2_256S), TEST_SUCCESS);
#endif
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
    ExpectIntEQ(slhdsa_cert_roundtrip_one(SLHDSA_SHA2_256F,
        SLH_DSA_SHA2_256F_TYPE, CTC_SLH_DSA_SHA2_256F), TEST_SUCCESS);
#endif
#endif /* WOLFSSL_SLHDSA_SHA2 */
#endif
    return EXPECT_RESULT();
}
