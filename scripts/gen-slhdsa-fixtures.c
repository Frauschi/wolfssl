/* gen-slhdsa-fixtures.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * Deterministic generator for the bench_slhdsa_*_key.der fixture files
 * under certs/slhdsa/, used by tests/api/test_slhdsa.c::
 * test_wc_slhdsa_der_decode_files.
 *
 * Each fixture is produced by wc_SlhDsaKey_MakeKeyWithRandom() using
 * fixed per-variant byte patterns for SK.seed, SK.prf, and PK.seed,
 * so re-running this generator is byte-stable and reviewers can
 * reproduce the committed .der bytes exactly.
 *
 * This program is built as part of the wolfSSL noinst test programs
 * when --enable-slhdsa --enable-keygen --enable-certgen are set.
 * Run from the source root:
 *
 *   ./scripts/gen-slhdsa-fixtures
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_HAVE_SLHDSA) || defined(WOLFSSL_SLHDSA_VERIFY_ONLY) || \
    !defined(WC_ENABLE_ASYM_KEY_EXPORT)
#include <stdio.h>
int main(void)
{
    fprintf(stderr,
        "gen-slhdsa-fixtures: build needs --enable-slhdsa --enable-keygen "
        "--enable-certgen with wc_SlhDsaKey_PrivateKeyToDer enabled.\n");
    return 77;
}
#else

#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct fixture {
    const char*      path;
    enum SlhDsaParam param;
    byte             seed_byte;   /* fill byte for SK.seed */
    byte             prf_byte;    /* fill byte for SK.prf */
    byte             pk_byte;     /* fill byte for PK.seed */
    int              enabled;
};

/* Per-variant fill-bytes are arbitrary but distinct so each fixture
 * gets a unique key. They are part of the on-disk fixture contract:
 * changing them changes the committed .der bytes. */
static const struct fixture FIXTURES[] = {
    { "certs/slhdsa/bench_slhdsa_shake128s_key.der", SLHDSA_SHAKE128S,
      0x01, 0x02, 0x03,
#ifdef WOLFSSL_SLHDSA_PARAM_128S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake128f_key.der", SLHDSA_SHAKE128F,
      0x11, 0x12, 0x13,
#ifdef WOLFSSL_SLHDSA_PARAM_128F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake192s_key.der", SLHDSA_SHAKE192S,
      0x21, 0x22, 0x23,
#ifdef WOLFSSL_SLHDSA_PARAM_192S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake192f_key.der", SLHDSA_SHAKE192F,
      0x31, 0x32, 0x33,
#ifdef WOLFSSL_SLHDSA_PARAM_192F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake256s_key.der", SLHDSA_SHAKE256S,
      0x41, 0x42, 0x43,
#ifdef WOLFSSL_SLHDSA_PARAM_256S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake256f_key.der", SLHDSA_SHAKE256F,
      0x51, 0x52, 0x53,
#ifdef WOLFSSL_SLHDSA_PARAM_256F
      1
#else
      0
#endif
    },
#ifdef WOLFSSL_SLHDSA_SHA2
    { "certs/slhdsa/bench_slhdsa_sha2_128s_key.der", SLHDSA_SHA2_128S,
      0x61, 0x62, 0x63,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_128f_key.der", SLHDSA_SHA2_128F,
      0x71, 0x72, 0x73,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_192s_key.der", SLHDSA_SHA2_192S,
      0x81, 0x82, 0x83,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_192f_key.der", SLHDSA_SHA2_192F,
      0x91, 0x92, 0x93,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_256s_key.der", SLHDSA_SHA2_256S,
      0xa1, 0xa2, 0xa3,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_256f_key.der", SLHDSA_SHA2_256F,
      0xb1, 0xb2, 0xb3,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
      1
#else
      0
#endif
    },
#endif
};

/* SLH-DSA seed length n bytes per variant; SK.seed, SK.prf, PK.seed
 * are each n bytes. Categories 1/3/5 have n = 16 / 24 / 32. */
static word32 seed_len_for(enum SlhDsaParam p)
{
    switch (p) {
        case SLHDSA_SHAKE128S:
        case SLHDSA_SHAKE128F:
            return 16;
        case SLHDSA_SHAKE192S:
        case SLHDSA_SHAKE192F:
            return 24;
        case SLHDSA_SHAKE256S:
        case SLHDSA_SHAKE256F:
            return 32;
#ifdef WOLFSSL_SLHDSA_SHA2
        case SLHDSA_SHA2_128S:
        case SLHDSA_SHA2_128F:
            return 16;
        case SLHDSA_SHA2_192S:
        case SLHDSA_SHA2_192F:
            return 24;
        case SLHDSA_SHA2_256S:
        case SLHDSA_SHA2_256F:
            return 32;
#endif
    }
    return 0;
}

static int gen_one(const struct fixture* f)
{
    SlhDsaKey key;
    byte sk_seed[WC_SLHDSA_MAX_SEED];
    byte sk_prf[WC_SLHDSA_MAX_SEED];
    byte pk_seed[WC_SLHDSA_MAX_SEED];
    byte der[64 * 1024];
    word32 n;
    int derSz;
    int ret;
    FILE* fp;

    if (!f->enabled) {
        fprintf(stdout, "skip   %s (variant not compiled in)\n", f->path);
        return 0;
    }

    n = seed_len_for(f->param);
    if (n == 0) {
        fprintf(stderr, "%s: unknown param %d\n", f->path, (int)f->param);
        return -1;
    }
    XMEMSET(sk_seed, f->seed_byte, n);
    XMEMSET(sk_prf,  f->prf_byte,  n);
    XMEMSET(pk_seed, f->pk_byte,   n);

    if ((ret = wc_SlhDsaKey_Init(&key, f->param, NULL, INVALID_DEVID)) != 0) {
        fprintf(stderr, "%s: wc_SlhDsaKey_Init=%d\n", f->path, ret);
        return ret;
    }
    if ((ret = wc_SlhDsaKey_MakeKeyWithRandom(&key,
            sk_seed, n, sk_prf, n, pk_seed, n)) != 0) {
        fprintf(stderr, "%s: wc_SlhDsaKey_MakeKeyWithRandom=%d\n",
                f->path, ret);
        goto out;
    }
    derSz = wc_SlhDsaKey_PrivateKeyToDer(&key, der, (word32)sizeof(der));
    if (derSz < 0) {
        fprintf(stderr, "%s: wc_SlhDsaKey_PrivateKeyToDer=%d\n",
                f->path, derSz);
        ret = derSz;
        goto out;
    }
    fp = fopen(f->path, "wb");
    if (fp == NULL) {
        perror(f->path);
        ret = -1;
        goto out;
    }
    if (fwrite(der, 1, (size_t)derSz, fp) != (size_t)derSz) {
        fprintf(stderr, "%s: short write\n", f->path);
        ret = -1;
    }
    else {
        fprintf(stdout, "wrote  %s (%d bytes)\n", f->path, derSz);
    }
    fclose(fp);
out:
    wc_SlhDsaKey_Free(&key);
    return ret;
}

int main(void)
{
    size_t i;
    int rc = 0;

    for (i = 0; i < sizeof(FIXTURES) / sizeof(FIXTURES[0]); i++) {
        if (gen_one(&FIXTURES[i]) != 0) {
            rc = 1;
        }
    }
    return rc;
}

#endif
