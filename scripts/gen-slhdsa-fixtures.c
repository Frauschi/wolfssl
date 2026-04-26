/* gen-slhdsa-fixtures.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * Generator for the bench_slhdsa_*_key.der fixture files under
 * certs/slhdsa/ used by tests/api/test_slhdsa.c::
 * test_wc_slhdsa_der_decode_files.
 *
 * The fixtures contain raw RFC 9909 PKCS#8 OneAsymmetricKey encodings
 * of newly-generated SLH-DSA keys. The keys themselves are random, so
 * each invocation of this generator produces different bytes; the
 * tests only check that auto-detect parses each fixture back into the
 * expected parameter set, so the actual key bits do not matter.
 *
 * Build (from the wolfSSL source root, after ./configure --enable-slhdsa
 * --enable-keygen --enable-certgen and make):
 *
 *   gcc -DWOLFSSL_USE_OPTIONS_H -I. \
 *       scripts/gen-slhdsa-fixtures.c src/.libs/libwolfssl.a \
 *       -lpthread -lm -o scripts/gen-slhdsa-fixtures
 *
 * Run from the source root:
 *
 *   ./scripts/gen-slhdsa-fixtures
 *
 * Re-running overwrites the fixtures with fresh random keys; commit
 * the resulting .der files. The generator is not built by `make` --
 * it is a one-shot tool kept under scripts/ so reviewers can always
 * regenerate the fixtures.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct fixture {
    const char*      path;
    enum SlhDsaParam param;
    int              enabled;
};

static const struct fixture FIXTURES[] = {
    { "certs/slhdsa/bench_slhdsa_shake128s_key.der", SLHDSA_SHAKE128S,
#ifdef WOLFSSL_SLHDSA_PARAM_128S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake128f_key.der", SLHDSA_SHAKE128F,
#ifdef WOLFSSL_SLHDSA_PARAM_128F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake192s_key.der", SLHDSA_SHAKE192S,
#ifdef WOLFSSL_SLHDSA_PARAM_192S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake192f_key.der", SLHDSA_SHAKE192F,
#ifdef WOLFSSL_SLHDSA_PARAM_192F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake256s_key.der", SLHDSA_SHAKE256S,
#ifdef WOLFSSL_SLHDSA_PARAM_256S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_shake256f_key.der", SLHDSA_SHAKE256F,
#ifdef WOLFSSL_SLHDSA_PARAM_256F
      1
#else
      0
#endif
    },
#ifdef WOLFSSL_SLHDSA_SHA2
    { "certs/slhdsa/bench_slhdsa_sha2_128s_key.der", SLHDSA_SHA2_128S,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_128f_key.der", SLHDSA_SHA2_128F,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_192s_key.der", SLHDSA_SHA2_192S,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_192f_key.der", SLHDSA_SHA2_192F,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_256s_key.der", SLHDSA_SHA2_256S,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
      1
#else
      0
#endif
    },
    { "certs/slhdsa/bench_slhdsa_sha2_256f_key.der", SLHDSA_SHA2_256F,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
      1
#else
      0
#endif
    },
#endif
};

static int gen_one(const struct fixture* f)
{
    SlhDsaKey key;
    WC_RNG rng;
    byte der[64 * 1024];
    int derSz;
    int ret;
    FILE* fp;

    if (!f->enabled) {
        fprintf(stdout, "skip   %s (variant not compiled in)\n", f->path);
        return 0;
    }

    if ((ret = wc_InitRng(&rng)) != 0) {
        fprintf(stderr, "%s: wc_InitRng=%d\n", f->path, ret);
        return ret;
    }
    if ((ret = wc_SlhDsaKey_Init(&key, f->param, NULL, INVALID_DEVID)) != 0) {
        fprintf(stderr, "%s: wc_SlhDsaKey_Init=%d\n", f->path, ret);
        wc_FreeRng(&rng);
        return ret;
    }
    if ((ret = wc_SlhDsaKey_MakeKey(&key, &rng)) != 0) {
        fprintf(stderr, "%s: wc_SlhDsaKey_MakeKey=%d\n", f->path, ret);
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
    wc_FreeRng(&rng);
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
