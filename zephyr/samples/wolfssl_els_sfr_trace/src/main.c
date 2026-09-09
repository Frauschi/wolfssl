/* Drive three ELS operations and record every register access CLNS makes, so
 * the sequence can be diffed against the emulator's for the same work. */
#include <zephyr/kernel.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>

#include "els_trace.h"

static const byte key16[16] = {
    0x2B,0x7E,0x15,0x16,0x28,0xAE,0xD2,0xA6,
    0xAB,0xF7,0x15,0x88,0x09,0xCF,0x4F,0x3C
};
static const byte iv16[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
static byte msg[32];
static byte out[32];
static byte digest[WC_SHA256_DIGEST_SIZE];
static byte tag[16];

int main(void)
{
    wc_Sha256 sha;
    Aes aes;
    Cmac cmac;
    word32 tagSz = sizeof(tag);
    int i;

    for (i = 0; i < (int)sizeof(msg); ++i) {
        msg[i] = (byte)(0xF0 ^ i);
    }

    if (wolfCrypt_Init() != 0) {
        printk("wolfCrypt_Init failed\n");
        return 0;
    }
    if (wc_ElsPkc_Init() != 0) {
        printk("wc_ElsPkc_Init failed\n");
        return 0;
    }

    els_trace_arm(1);

    els_trace_mark("sha256-abc");
    if (wc_InitSha256_ex(&sha, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
        (void)wc_Sha256Update(&sha, (const byte *)"abc", 3);
        (void)wc_Sha256Final(&sha, digest);
        wc_Sha256Free(&sha);
    }

    els_trace_mark("aes128-cbc-encrypt-32");
    if (wc_AesInit(&aes, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
        if (wc_AesSetKey(&aes, key16, 16, iv16, AES_ENCRYPTION) == 0) {
            (void)wc_AesCbcEncrypt(&aes, out, msg, sizeof(msg));
        }
        wc_AesFree(&aes);
    }

    els_trace_mark("cmac-aes128-32");
    if (wc_InitCmac_ex(&cmac, key16, 16, WC_CMAC_AES, NULL, NULL,
                       WOLFSSL_ELS_PKC_DEVID) == 0) {
        (void)wc_CmacUpdate(&cmac, msg, sizeof(msg));
        (void)wc_CmacFinal(&cmac, tag, &tagSz);
    }

    /* X25519 runs on the PKC, which has its own register file and its own
     * unpublished calculation modes. */
    {
        WC_RNG rng;
        static curve25519_key ka, kb;
        static byte shared[32];
        word32 sharedSz = sizeof(shared);

        if (wc_InitRng_ex(&rng, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
            els_trace_mark("x25519-keygen");
            if (wc_curve25519_init_ex(&ka, NULL, WOLFSSL_ELS_PKC_DEVID) == 0 &&
                wc_curve25519_init_ex(&kb, NULL, WOLFSSL_ELS_PKC_DEVID) == 0 &&
                wc_curve25519_make_key(&rng, 32, &ka) == 0 &&
                wc_curve25519_make_key(&rng, 32, &kb) == 0) {

                /* the agreement is the step this port offloads */
                els_trace_mark("x25519-agree");
                (void)wc_curve25519_shared_secret(&ka, &kb, shared, &sharedSz);
                wc_curve25519_free(&ka);
                wc_curve25519_free(&kb);
            }
            (void)wc_FreeRng(&rng);
        }
    }

    els_trace_mark("done");
    els_trace_arm(0);

    els_trace_dump();
    return 0;
}
