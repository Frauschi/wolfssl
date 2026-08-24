/* gen_mlkem.c
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

/* Generator for the ML-KEM test key material in this directory.
 *
 * ML-KEM certificate issuance is not available in OpenSSL before 3.5, so this
 * material is produced by wolfSSL itself. A KEM cannot sign, so nothing here
 * is self-signed: each certificate is issued by the ML-DSA-87 test key in
 * certs/mldsa, per RFC 9935 and the CNSA 2.0 PKIX profile.
 *
 * The certificates follow the CNSA 2.0 profile for a key establishment
 * certificate: keyUsage is critical and asserts keyEncipherment alone.
 *
 * Build against an installed wolfSSL configured with (at least):
 *   --enable-mlkem --enable-mldsa --enable-keygen --enable-certgen
 *   --enable-certreq --enable-certext  (and HAVE_PKCS8)
 *
 *   cc gen_mlkem.c -lwolfssl -o gen_mlkem && (cd certs/mlkem && ./gen_mlkem)
 *
 * Run it from this directory; it reads ../mldsa/mldsa87-cert.der and
 * ../mldsa/mldsa87-key.der and writes mlkem<N>-cert.der / mlkem<N>-key.der.
 */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <string.h>

#if !defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_MLKEM_NO_ASN1) || \
    !defined(WOLFSSL_HAVE_MLDSA) || !defined(WOLFSSL_CERT_GEN) || \
    !defined(WOLFSSL_CERT_EXT) || defined(WOLFSSL_MLKEM_NO_MAKE_KEY)
int main(void)
{
    fprintf(stderr, "wolfSSL not built with the features needed to generate "
                    "the ML-KEM certificates (see the header comment).\n");
    return 1;
}
#else

static byte der[16000];
static byte caCert[16000];
static byte caKey[16000];

static int readFile(const char* name, byte* buf, word32 bufSz, word32* outSz)
{
    FILE* f = fopen(name, "rb");
    size_t n;

    if (f == NULL) {
        fprintf(stderr, "  cannot open %s\n", name);
        return -1;
    }
    n = fread(buf, 1, bufSz, f);
    fclose(f);
    if (n == 0) {
        fprintf(stderr, "  %s is empty\n", name);
        return -1;
    }
    *outSz = (word32)n;
    return 0;
}

static int writeFile(const char* name, const byte* data, int len)
{
    FILE* f;

    if (len <= 0) {
        fprintf(stderr, "  %s: nothing to write (%d)\n", name, len);
        return -1;
    }
    f = fopen(name, "wb");
    if (f == NULL) {
        fprintf(stderr, "  cannot open %s\n", name);
        return -1;
    }
    (void)fwrite(data, 1, (size_t)len, f);
    fclose(f);
    printf("  wrote %s (%d bytes)\n", name, len);
    return 0;
}

/* Only set the string fields; wc_InitCert() already zeroed the struct and set
 * the per-field ASN encoding types, which must be preserved. */
static void setName(CertName* n, const char* cn)
{
    XSTRNCPY(n->country, "US", CTC_NAME_SIZE);
    n->countryEnc = CTC_PRINTABLE;
    XSTRNCPY(n->state, "Montana", CTC_NAME_SIZE);
    n->stateEnc = CTC_UTF8;
    XSTRNCPY(n->locality, "Bozeman", CTC_NAME_SIZE);
    n->localityEnc = CTC_UTF8;
    XSTRNCPY(n->org, "wolfSSL", CTC_NAME_SIZE);
    n->orgEnc = CTC_UTF8;
    XSTRNCPY(n->commonName, cn, CTC_NAME_SIZE);
    n->commonNameEnc = CTC_UTF8;
}

/* Key, PKCS#8 private key and ML-DSA-87-signed certificate for one ML-KEM
 * parameter set. */
static int genVariant(WC_RNG* rng, wc_MlDsaKey* ca, const byte* caCertDer,
                      word32 caCertSz, int type, const char* prefix,
                      const char* cn)
{
    MlKemKey* kem;
    Cert cert;
    char fn[128];
    int len, body, ret = -1;

    kem = (MlKemKey*)XMALLOC(sizeof(MlKemKey), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (kem == NULL) {
        fprintf(stderr, "out of memory for %s\n", prefix);
        return -1;
    }
    if (wc_MlKemKey_Init(kem, type, NULL, INVALID_DEVID) != 0) {
        fprintf(stderr, "ML-KEM key init failed for %s\n", prefix);
        goto out;
    }
    if (wc_MlKemKey_MakeKey(kem, rng) != 0) {
        fprintf(stderr, "ML-KEM key generation failed for %s\n", prefix);
        goto out_free;
    }

    len = wc_MlKemKey_PrivateKeyToDer(kem, der, sizeof(der));
    XSNPRINTF(fn, sizeof(fn), "%s-key.der", prefix);
    if (writeFile(fn, der, len) != 0)
        goto out_free;

    wc_InitCert(&cert);
    setName(&cert.subject, cn);
    cert.sigType = CTC_ML_DSA_LEVEL5;
    cert.selfSigned = 0;          /* a KEM cannot sign for itself */
    cert.daysValid = 7300;
    /* CNSA 2.0 key establishment certificate: keyEncipherment alone. */
    if (wc_SetKeyUsage(&cert, "keyEncipherment") != 0) {
        fprintf(stderr, "setting keyUsage failed for %s\n", prefix);
        goto out_free;
    }
    if (wc_SetIssuerBuffer(&cert, caCertDer, (int)caCertSz) != 0) {
        fprintf(stderr, "setting issuer failed for %s\n", prefix);
        goto out_free;
    }
    (void)wc_SetSubjectKeyIdFromPublicKey_ex(&cert, MLKEM_TYPE, kem);

    body = wc_MakeCert_ex(&cert, der, sizeof(der), MLKEM_TYPE, kem, rng);
    if (body <= 0) {
        fprintf(stderr, "wc_MakeCert_ex failed for %s (%d)\n", prefix, body);
        goto out_free;
    }
    len = wc_SignCert_ex(body, CTC_ML_DSA_LEVEL5, der, sizeof(der),
                         ML_DSA_LEVEL5_TYPE, ca, rng);
    if (len <= 0) {
        fprintf(stderr, "wc_SignCert_ex failed for %s (%d)\n", prefix, len);
        goto out_free;
    }
    XSNPRINTF(fn, sizeof(fn), "%s-cert.der", prefix);
    if (writeFile(fn, der, len) != 0)
        goto out_free;

    ret = 0;

out_free:
    wc_MlKemKey_Free(kem);
out:
    XFREE(kem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int main(void)
{
    WC_RNG rng;
    wc_MlDsaKey* ca = NULL;
    word32 caCertSz = 0, caKeySz = 0, idx = 0;
    int ret = 1;

    if (readFile("../mldsa/mldsa87-cert.der", caCert, sizeof(caCert),
                 &caCertSz) != 0)
        return 1;
    if (readFile("../mldsa/mldsa87-key.der", caKey, sizeof(caKey),
                 &caKeySz) != 0)
        return 1;

    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "RNG init failed\n");
        return 1;
    }

    ca = (wc_MlDsaKey*)XMALLOC(sizeof(wc_MlDsaKey), NULL,
                               DYNAMIC_TYPE_TMP_BUFFER);
    if (ca == NULL) {
        fprintf(stderr, "out of memory for the issuer key\n");
        goto out_rng;
    }
    if (wc_MlDsaKey_Init(ca, NULL, INVALID_DEVID) != 0) {
        fprintf(stderr, "ML-DSA key init failed\n");
        goto out_key;
    }
    if (wc_MlDsaKey_SetParams(ca, WC_ML_DSA_87) != 0) {
        fprintf(stderr, "ML-DSA parameter selection failed\n");
        goto out_free;
    }
    if (wc_MlDsaKey_PrivateKeyDecode(ca, caKey, caKeySz, &idx) != 0) {
        fprintf(stderr, "decoding the ML-DSA-87 issuer key failed\n");
        goto out_free;
    }

#if defined(WOLFSSL_WC_ML_KEM_512) && !defined(WOLFSSL_NO_ML_KEM)
    (void)genVariant(&rng, ca, caCert, caCertSz, WC_ML_KEM_512, "mlkem512",
                     "ML-KEM-512");
#endif
#if defined(WOLFSSL_WC_ML_KEM_768) && !defined(WOLFSSL_NO_ML_KEM)
    (void)genVariant(&rng, ca, caCert, caCertSz, WC_ML_KEM_768, "mlkem768",
                     "ML-KEM-768");
#endif
#if defined(WOLFSSL_WC_ML_KEM_1024) && !defined(WOLFSSL_NO_ML_KEM)
    (void)genVariant(&rng, ca, caCert, caCertSz, WC_ML_KEM_1024, "mlkem1024",
                     "ML-KEM-1024");
#endif
    ret = 0;

out_free:
    wc_MlDsaKey_Free(ca);
out_key:
    XFREE(ca, NULL, DYNAMIC_TYPE_TMP_BUFFER);
out_rng:
    wc_FreeRng(&rng);
    return ret;
}

#endif
