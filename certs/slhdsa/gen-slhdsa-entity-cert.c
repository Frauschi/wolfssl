/* gen-slhdsa-entity-cert.c
 *
 * Regenerate the self-signed SLH-DSA-SHAKE-128f entity certificate and key
 * used by tests/test-tls13-slhdsa-entity.conf.
 *
 * OpenSSL < 3.5 cannot emit SLH-DSA certificates, so wolfSSL's own certificate
 * generation is used here instead. SLH-DSA-SHAKE-128f is chosen because its
 * ~17KB signature makes the TLS 1.3 CertificateVerify message exceed a single
 * record, exercising fragmented CertificateVerify send + reassembly.
 *
 * Build (from the wolfSSL source root, after configuring with SLH-DSA + cert
 * generation, e.g. ./configure --enable-slhdsa --enable-certgen --enable-keygen
 * --enable-certext):
 *
 *   gcc certs/slhdsa/gen-slhdsa-entity-cert.c -I. \
 *       -L./src/.libs -lwolfssl -lm -o gen-slhdsa-entity-cert
 *   LD_LIBRARY_PATH=./src/.libs ./gen-slhdsa-entity-cert
 *
 * The committed PEM/DER fixtures under this directory are authoritative; this
 * program is for renewal only.
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GEN_BUF_SZ 70000

static int save(const char* path, const byte* buf, int sz)
{
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        printf("Unable to open %s for writing\n", path);
        return -1;
    }
    fwrite(buf, 1, (size_t)sz, f);
    fclose(f);
    return 0;
}

int main(void)
{
    WC_RNG    rng;
    SlhDsaKey key;
    Cert      cert;
    byte*     der    = NULL;
    byte*     keyder = NULL;
    byte*     pem    = NULL;
    int       ret, certSz, keySz, pemSz;

    wolfCrypt_Init();

    if (wc_InitRng(&rng) != 0) {
        printf("RNG init failed\n");
        return 1;
    }
    if ((ret = wc_SlhDsaKey_Init(&key, SLHDSA_SHAKE128F, NULL,
                                 INVALID_DEVID)) != 0) {
        printf("wc_SlhDsaKey_Init failed: %d\n", ret);
        return 1;
    }
    if ((ret = wc_SlhDsaKey_MakeKey(&key, &rng)) != 0) {
        printf("wc_SlhDsaKey_MakeKey failed: %d\n", ret);
        return 1;
    }

    der    = (byte*)malloc(GEN_BUF_SZ);
    keyder = (byte*)malloc(GEN_BUF_SZ);
    pem    = (byte*)malloc(GEN_BUF_SZ);
    if (der == NULL || keyder == NULL || pem == NULL) {
        printf("Out of memory\n");
        return 1;
    }

    /* PKCS#8 private key (DER + PEM). */
    keySz = wc_SlhDsaKey_PrivateKeyToDer(&key, keyder, GEN_BUF_SZ);
    if (keySz < 0) {
        printf("wc_SlhDsaKey_PrivateKeyToDer failed: %d\n", keySz);
        return 1;
    }
    save("certs/slhdsa/entity-slhdsa-shake-128f-priv.der", keyder, keySz);

    /* Self-signed certificate (DER + PEM). */
    wc_InitCert(&cert);
    strncpy(cert.subject.country, "US", CTC_NAME_SIZE);
    strncpy(cert.subject.state, "Montana", CTC_NAME_SIZE);
    strncpy(cert.subject.locality, "Bozeman", CTC_NAME_SIZE);
    strncpy(cert.subject.org, "wolfSSL_SLH-DSA", CTC_NAME_SIZE);
    strncpy(cert.subject.unit, "Entity-SLHDSA-shake-128f", CTC_NAME_SIZE);
    strncpy(cert.subject.commonName, "www.wolfssl.com", CTC_NAME_SIZE);
    strncpy(cert.subject.email, "facts@wolfssl.com", CTC_NAME_SIZE);
    cert.daysValid = 1000;
    cert.selfSigned = 1;
    cert.isCA = 1; /* self-signed, also usable as its own trust anchor */
    cert.sigType = CTC_SLH_DSA_SHAKE_128F;

    if ((ret = wc_SetSubjectKeyIdFromPublicKey_ex(&cert,
                    SLH_DSA_SHAKE_128F_TYPE, &key)) < 0) {
        printf("wc_SetSubjectKeyIdFromPublicKey_ex failed: %d\n", ret);
        return 1;
    }
    if ((ret = wc_SetAuthKeyIdFromPublicKey_ex(&cert,
                    SLH_DSA_SHAKE_128F_TYPE, &key)) < 0) {
        printf("wc_SetAuthKeyIdFromPublicKey_ex failed: %d\n", ret);
        return 1;
    }

    ret = wc_MakeCert_ex(&cert, der, GEN_BUF_SZ, SLH_DSA_SHAKE_128F_TYPE,
                         &key, &rng);
    if (ret < 0) {
        printf("wc_MakeCert_ex failed: %d\n", ret);
        return 1;
    }
    ret = wc_SignCert_ex(cert.bodySz, cert.sigType, der, GEN_BUF_SZ,
                         SLH_DSA_SHAKE_128F_TYPE, &key, &rng);
    if (ret < 0) {
        printf("wc_SignCert_ex failed: %d\n", ret);
        return 1;
    }
    certSz = ret;
    save("certs/slhdsa/entity-slhdsa-shake-128f.der", der, certSz);

    pemSz = wc_DerToPem(der, certSz, pem, GEN_BUF_SZ, CERT_TYPE);
    if (pemSz > 0)
        save("certs/slhdsa/entity-slhdsa-shake-128f.pem", pem, pemSz);
    pemSz = wc_DerToPem(keyder, keySz, pem, GEN_BUF_SZ, PKCS8_PRIVATEKEY_TYPE);
    if (pemSz > 0)
        save("certs/slhdsa/entity-slhdsa-shake-128f-priv.pem", pem, pemSz);

    printf("Generated SLH-DSA-SHAKE-128f entity cert (certSz=%d keySz=%d)\n",
           certSz, keySz);

    free(der);
    free(keyder);
    free(pem);
    wc_SlhDsaKey_Free(&key);
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();
    return 0;
}
