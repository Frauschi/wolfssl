/* slhdsa_interop_one.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * Per-variant standalone driver invoked by scripts/slhdsa-interop.test.
 * Takes one SLH-DSA variant name on argv[1] (e.g. "shake_128s",
 * "sha2_192f"), mints a self-signed cert with that variant via the
 * wolfCrypt cert-gen API, then verifies the cert's signature via the
 * cert-layer ConfirmSignature() path. Exits 0 on success, 1 on failure
 * (with a one-line reason on stderr). The script invokes this once per
 * variant so PASS/FAIL is genuinely per-variant.
 *
 * Build is gated by BUILD_WC_SLHDSA in wolfcrypt/test/include.am.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#if !defined(WOLFSSL_HAVE_SLHDSA) || defined(WOLFSSL_SLHDSA_VERIFY_ONLY) || \
    !defined(WOLFSSL_CERT_GEN) || !defined(WC_ENABLE_ASYM_KEY_EXPORT)

#include <stdio.h>
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "slhdsa_interop_one: SLH-DSA cert-gen build not enabled\n");
    return 77; /* automake "skip" */
}

#else

#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct variant_map {
    const char*        name;
    enum SlhDsaParam   param;
    int                certKeyType;
    int                sigType;
    int                enabled;
};

static const struct variant_map variants[] = {
    { "shake_128s", SLHDSA_SHAKE128S, SLH_DSA_SHAKE_128S_TYPE,
      CTC_SLH_DSA_SHAKE_128S,
#ifdef WOLFSSL_SLHDSA_PARAM_128S
      1
#else
      0
#endif
    },
    { "shake_128f", SLHDSA_SHAKE128F, SLH_DSA_SHAKE_128F_TYPE,
      CTC_SLH_DSA_SHAKE_128F,
#ifdef WOLFSSL_SLHDSA_PARAM_128F
      1
#else
      0
#endif
    },
    { "shake_192s", SLHDSA_SHAKE192S, SLH_DSA_SHAKE_192S_TYPE,
      CTC_SLH_DSA_SHAKE_192S,
#ifdef WOLFSSL_SLHDSA_PARAM_192S
      1
#else
      0
#endif
    },
    { "shake_192f", SLHDSA_SHAKE192F, SLH_DSA_SHAKE_192F_TYPE,
      CTC_SLH_DSA_SHAKE_192F,
#ifdef WOLFSSL_SLHDSA_PARAM_192F
      1
#else
      0
#endif
    },
    { "shake_256s", SLHDSA_SHAKE256S, SLH_DSA_SHAKE_256S_TYPE,
      CTC_SLH_DSA_SHAKE_256S,
#ifdef WOLFSSL_SLHDSA_PARAM_256S
      1
#else
      0
#endif
    },
    { "shake_256f", SLHDSA_SHAKE256F, SLH_DSA_SHAKE_256F_TYPE,
      CTC_SLH_DSA_SHAKE_256F,
#ifdef WOLFSSL_SLHDSA_PARAM_256F
      1
#else
      0
#endif
    },
#ifdef WOLFSSL_SLHDSA_SHA2
    { "sha2_128s", SLHDSA_SHA2_128S, SLH_DSA_SHA2_128S_TYPE,
      CTC_SLH_DSA_SHA2_128S,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128S
      1
#else
      0
#endif
    },
    { "sha2_128f", SLHDSA_SHA2_128F, SLH_DSA_SHA2_128F_TYPE,
      CTC_SLH_DSA_SHA2_128F,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_128F
      1
#else
      0
#endif
    },
    { "sha2_192s", SLHDSA_SHA2_192S, SLH_DSA_SHA2_192S_TYPE,
      CTC_SLH_DSA_SHA2_192S,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192S
      1
#else
      0
#endif
    },
    { "sha2_192f", SLHDSA_SHA2_192F, SLH_DSA_SHA2_192F_TYPE,
      CTC_SLH_DSA_SHA2_192F,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_192F
      1
#else
      0
#endif
    },
    { "sha2_256s", SLHDSA_SHA2_256S, SLH_DSA_SHA2_256S_TYPE,
      CTC_SLH_DSA_SHA2_256S,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256S
      1
#else
      0
#endif
    },
    { "sha2_256f", SLHDSA_SHA2_256F, SLH_DSA_SHA2_256F_TYPE,
      CTC_SLH_DSA_SHA2_256F,
#ifdef WOLFSSL_SLHDSA_PARAM_SHA2_256F
      1
#else
      0
#endif
    },
#endif
    { NULL, (enum SlhDsaParam)0, 0, 0, 0 }
};

static int run_one(const struct variant_map* v)
{
    SlhDsaKey key;
    WC_RNG rng;
    Cert cert;
    DecodedCert decoded;
    SignatureCtx sigCtx;
    byte* der;
    int derSz;
    int signedSz;
    int ret;

    der = (byte*)XMALLOC(64 * 1024, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (der == NULL) {
        fprintf(stderr, "%s: malloc\n", v->name);
        return 1;
    }
    if ((ret = wc_InitRng(&rng)) != 0) {
        fprintf(stderr, "%s: wc_InitRng=%d\n", v->name, ret);
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return 1;
    }
    if ((ret = wc_SlhDsaKey_Init(&key, v->param, NULL, INVALID_DEVID)) != 0) {
        fprintf(stderr, "%s: wc_SlhDsaKey_Init=%d\n", v->name, ret);
        wc_FreeRng(&rng);
        XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return 1;
    }
    if ((ret = wc_SlhDsaKey_MakeKey(&key, &rng)) != 0) {
        fprintf(stderr, "%s: wc_SlhDsaKey_MakeKey=%d\n", v->name, ret);
        goto fail;
    }

    if ((ret = wc_InitCert(&cert)) != 0) {
        fprintf(stderr, "%s: wc_InitCert=%d\n", v->name, ret);
        goto fail;
    }
    /* Use sizeof - 1 + explicit NUL terminator to avoid the
     * -Wstringop-truncation false positive on bound-equals-dest. */
    XSTRNCPY(cert.subject.country, "US", sizeof(cert.subject.country) - 1);
    cert.subject.country[sizeof(cert.subject.country) - 1] = '\0';
    XSTRNCPY(cert.subject.commonName, v->name,
             sizeof(cert.subject.commonName) - 1);
    cert.subject.commonName[sizeof(cert.subject.commonName) - 1] = '\0';
    XMEMCPY(&cert.issuer, &cert.subject, sizeof(cert.issuer));
    cert.sigType = v->sigType;
    cert.isCA = 1;
    cert.selfSigned = 1;

    derSz = wc_MakeCert_ex(&cert, der, 64 * 1024, v->certKeyType, &key, &rng);
    if (derSz <= 0) {
        fprintf(stderr, "%s: wc_MakeCert_ex=%d\n", v->name, derSz);
        ret = derSz;
        goto fail;
    }
    signedSz = wc_SignCert_ex(cert.bodySz, v->sigType, der, 64 * 1024,
        v->certKeyType, &key, &rng);
    if (signedSz <= 0) {
        fprintf(stderr, "%s: wc_SignCert_ex=%d\n", v->name, signedSz);
        ret = signedSz;
        goto fail;
    }

    InitDecodedCert(&decoded, der, (word32)signedSz, NULL);
    ret = ParseCert(&decoded, CERT_TYPE, NO_VERIFY, NULL);
    if (ret != 0) {
        fprintf(stderr, "%s: ParseCert=%d\n", v->name, ret);
        FreeDecodedCert(&decoded);
        goto fail;
    }

    InitSignatureCtx(&sigCtx, NULL, INVALID_DEVID);
    ret = ConfirmSignature(&sigCtx,
        der + decoded.certBegin,
        decoded.sigIndex - decoded.certBegin,
        decoded.publicKey, decoded.pubKeySize, decoded.keyOID,
        decoded.signature, decoded.sigLength,
        decoded.signatureOID, NULL, 0, NULL);
    FreeSignatureCtx(&sigCtx);
    FreeDecodedCert(&decoded);

    if (ret != 0) {
        fprintf(stderr, "%s: ConfirmSignature=%d\n", v->name, ret);
        goto fail;
    }

    wc_SlhDsaKey_Free(&key);
    wc_FreeRng(&rng);
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;

fail:
    wc_SlhDsaKey_Free(&key);
    wc_FreeRng(&rng);
    XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 1;
}

int main(int argc, char** argv)
{
    const struct variant_map* v;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <variant>\n", argv[0]);
        fprintf(stderr, "variants: ");
        for (v = variants; v->name != NULL; v++) {
            fprintf(stderr, "%s%s", v->name, (v + 1)->name ? " " : "\n");
        }
        return 2;
    }

    for (v = variants; v->name != NULL; v++) {
        if (strcmp(argv[1], v->name) == 0) {
            if (!v->enabled) {
                /* Variant is recognised but not compiled in - report as
                 * skip via automake's exit-77 convention. */
                printf("%s: skipped (not compiled in)\n", argv[1]);
                return 77;
            }
            return run_one(v);
        }
    }
    fprintf(stderr, "%s: unknown variant\n", argv[1]);
    return 2;
}

#endif
