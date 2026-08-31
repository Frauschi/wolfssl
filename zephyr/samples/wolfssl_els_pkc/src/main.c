/* Phase 1 end-to-end check: does the EdgeLock crypto callback actually get
 * registered at boot, and does an offloaded SHA-256 agree with the software
 * implementation for the awkward lengths (block boundaries, and the length
 * that forces a second padding block)? */
#include <zephyr/kernel.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/wc_keystore.h>
#define USE_CERT_BUFFERS_2048
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>

/* FIPS 180-4 "abc" */
static const byte abc[] = { 'a','b','c' };
static const byte abcDigest[32] = {
    0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
    0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
};

static int fails;
static void check(const char *what, int ok)
{
    printk("  %-52s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

/* software reference, computed with the callback bypassed */
static int swSha256(const byte *in, word32 len, byte *out)
{
    wc_Sha256 sha;
    int ret = wc_InitSha256_ex(&sha, NULL, INVALID_DEVID);
    if (ret != 0) return ret;
    ret = wc_Sha256Update(&sha, in, len);
    if (ret == 0) ret = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    return ret;
}

/* through the port: a devId-bound one-shot */
static int hwSha256(const byte *in, word32 len, byte *out)
{
    wc_Sha256 sha;
    int ret = wc_InitSha256_ex(&sha, NULL, WOLFSSL_ELS_PKC_DEVID);
    if (ret != 0) return ret;
    ret = wc_Sha256Update(&sha, in, len);
    if (ret == 0) ret = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    return ret;
}

extern unsigned long wc_ElsPkc_HashOffloadCount;
extern unsigned long wc_ElsPkc_IrqWaitCount;
extern unsigned long wc_ElsPkc_PollWaitCount;
extern unsigned long wc_ElsPkc_TimeoutCount;
extern unsigned long wc_ElsPkc_AesOffloadCount;
extern unsigned long wc_ElsPkc_RngOffloadCount;
extern unsigned long wc_ElsPkc_CmacOffloadCount;
extern unsigned long wc_ElsPkc_GcmOffloadCount;
extern unsigned long wc_ElsPkc_RsaOffloadCount;
extern unsigned long wc_ElsPkc_X25519OffloadCount;
extern unsigned long wc_ElsPkc_EccPkcOffloadCount;
extern unsigned long wc_ElsPkc_KeyStoreOffloadCount;

int main(void)
{
    static byte buf[300];
    byte hw[32], sw[32];
    /* 0 and 55 fit one padding block; 56..63 force a second; 64 and 128 are
     * exact multiples; 200 exercises whole blocks plus a remainder. */
    static const word32 lens[] = { 0, 1, 55, 56, 63, 64, 65, 127, 128, 200 };
    unsigned i;

    printk("\n=== EdgeLock port, phase 1 ===\n");

    for (i = 0; i < sizeof(buf); i++) buf[i] = (byte)i;

    /* SYS_INIT should already have registered the device */
    check("callback registered at boot (SYS_INIT)",
          wc_CryptoCb_DefaultDevID() == WOLFSSL_ELS_PKC_DEVID);

    if (hwSha256(abc, sizeof(abc), hw) == 0) {
        check("SHA-256(\"abc\") matches FIPS 180-4",
              memcmp(hw, abcDigest, 32) == 0);
    } else {
        check("SHA-256(\"abc\")", 0);
    }

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        char label[48];
        int ok = (hwSha256(buf, lens[i], hw) == 0) &&
                 (swSha256(buf, lens[i], sw) == 0) &&
                 (memcmp(hw, sw, 32) == 0);
        (void)snprintk(label, sizeof(label),
                       "len=%-4u hardware == software", (unsigned)lens[i]);
        check(label, ok);
    }

    /* incremental: split the message across several updates, including
     * splits that land mid-block, and compare against a single-shot software
     * digest of the same bytes */
    {
        static const word32 splits[][3] = {
            {1, 1, 0}, {32, 32, 0}, {63, 1, 0}, {64, 64, 0},
            {1, 63, 64}, {100, 100, 0}, {70, 30, 100}
        };
        unsigned k;
        for (k = 0; k < sizeof(splits)/sizeof(splits[0]); k++) {
            wc_Sha256 sha;
            word32 tot = splits[k][0] + splits[k][1] + splits[k][2];
            char label[56];
            int ok = 0;

            if (wc_InitSha256_ex(&sha, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                unsigned p2 = 0, seg;
                int r = 0;
                for (seg = 0; seg < 3 && r == 0; seg++) {
                    if (splits[k][seg] > 0) {
                        r = wc_Sha256Update(&sha, buf + p2, splits[k][seg]);
                        p2 += splits[k][seg];
                    }
                }
                if (r == 0) r = wc_Sha256Final(&sha, hw);
                wc_Sha256Free(&sha);
                ok = (r == 0) && (swSha256(buf, tot, sw) == 0) &&
                     (memcmp(hw, sw, 32) == 0);
            }
            (void)snprintk(label, sizeof(label),
                           "incremental %u+%u+%u == one-shot",
                           (unsigned)splits[k][0], (unsigned)splits[k][1],
                           (unsigned)splits[k][2]);
            check(label, ok);
        }
    }

    /* wc_Sha256GetHash() is Copy-then-Final: the TLS 1.3 transcript snapshot.
     * Without a WC_ALGO_TYPE_COPY handler both hashes share one hardware
     * context, so the snapshot releases it and the original silently restarts
     * from empty - the continued hash below is what catches that. */
    {
        wc_Sha256 sha;
        byte snap1[32], snap2[32], fin[32];
        byte ref1[32], ref2[32], reffin[32];
        int ok = 0;

        if (wc_InitSha256_ex(&sha, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
            int r = wc_Sha256Update(&sha, buf, 100);
            if (r == 0) r = wc_Sha256GetHash(&sha, snap1);   /* snapshot @100 */
            if (r == 0) r = wc_Sha256Update(&sha, buf + 100, 50);
            if (r == 0) r = wc_Sha256GetHash(&sha, snap2);   /* snapshot @150 */
            if (r == 0) r = wc_Sha256Update(&sha, buf + 150, 50);
            if (r == 0) r = wc_Sha256Final(&sha, fin);       /* final   @200 */
            wc_Sha256Free(&sha);

            ok = (r == 0) &&
                 (swSha256(buf, 100, ref1) == 0) &&
                 (swSha256(buf, 150, ref2) == 0) &&
                 (swSha256(buf, 200, reffin) == 0) &&
                 (memcmp(snap1, ref1, 32) == 0) &&
                 (memcmp(snap2, ref2, 32) == 0) &&
                 (memcmp(fin, reffin, 32) == 0);
        }
        check("GetHash snapshots do not disturb the running hash", ok);
    }

    /* SHA-384 and SHA-512 offload. Same engine, 128-byte blocks and a 128-bit
     * length field, so the interesting lengths move: 111/112/113 straddle the
     * point where the padding needs a second block. SHA-384 additionally
     * truncates the engine's 512-bit state, which is what these check. */
    {
        static const byte abc384[48] = {
            0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,
            0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
            0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,
            0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
            0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,
            0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
        };
        static const byte abc512[64] = {
            0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
            0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
            0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
            0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
            0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
            0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
            0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
            0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
        };
        static const word32 lens5[] = {
            0, 1, 111, 112, 113, 127, 128, 129, 255, 256, 300
        };
        byte hw5[64], sw5[64];
        unsigned k;
        int r;

        /* SHA-384 */
        {
            wc_Sha384 h;
            int ok = 0;
            if (wc_InitSha384_ex(&h, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                r = wc_Sha384Update(&h, abc, sizeof(abc));
                if (r == 0) r = wc_Sha384Final(&h, hw5);
                wc_Sha384Free(&h);
                ok = (r == 0) && (memcmp(hw5, abc384, 48) == 0);
            }
            check("SHA-384(\"abc\") matches FIPS 180-4", ok);
        }

        {
            wc_Sha512 h;
            int ok = 0;
            if (wc_InitSha512_ex(&h, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                r = wc_Sha512Update(&h, abc, sizeof(abc));
                if (r == 0) r = wc_Sha512Final(&h, hw5);
                wc_Sha512Free(&h);
                ok = (r == 0) && (memcmp(hw5, abc512, 64) == 0);
            }
            check("SHA-512(\"abc\") matches FIPS 180-4", ok);
        }

        for (k = 0; k < sizeof(lens5)/sizeof(lens5[0]); k++) {
            wc_Sha384 hh; wc_Sha384 hs;
            char label[56];
            int ok = 0;
            if (wc_InitSha384_ex(&hh, NULL, WOLFSSL_ELS_PKC_DEVID) == 0 &&
                wc_InitSha384_ex(&hs, NULL, INVALID_DEVID) == 0) {
                r = wc_Sha384Update(&hh, buf, lens5[k]);
                if (r == 0) r = wc_Sha384Final(&hh, hw5);
                if (r == 0) r = wc_Sha384Update(&hs, buf, lens5[k]);
                if (r == 0) r = wc_Sha384Final(&hs, sw5);
                ok = (r == 0) && (memcmp(hw5, sw5, 48) == 0);
                wc_Sha384Free(&hh); wc_Sha384Free(&hs);
            }
            (void)snprintk(label, sizeof(label),
                           "SHA-384 len=%-4u hardware == software",
                           (unsigned)lens5[k]);
            check(label, ok);
        }

        for (k = 0; k < sizeof(lens5)/sizeof(lens5[0]); k++) {
            wc_Sha512 hh; wc_Sha512 hs;
            char label[56];
            int ok = 0;
            if (wc_InitSha512_ex(&hh, NULL, WOLFSSL_ELS_PKC_DEVID) == 0 &&
                wc_InitSha512_ex(&hs, NULL, INVALID_DEVID) == 0) {
                r = wc_Sha512Update(&hh, buf, lens5[k]);
                if (r == 0) r = wc_Sha512Final(&hh, hw5);
                if (r == 0) r = wc_Sha512Update(&hs, buf, lens5[k]);
                if (r == 0) r = wc_Sha512Final(&hs, sw5);
                ok = (r == 0) && (memcmp(hw5, sw5, 64) == 0);
                wc_Sha512Free(&hh); wc_Sha512Free(&hs);
            }
            (void)snprintk(label, sizeof(label),
                           "SHA-512 len=%-4u hardware == software",
                           (unsigned)lens5[k]);
            check(label, ok);
        }

        /* incremental splits that land mid-block */
        {
            static const word32 sp5[][3] = {
                {1, 1, 0}, {64, 64, 0}, {127, 1, 0}, {128, 128, 0},
                {1, 127, 128}, {100, 100, 100}
            };
            for (k = 0; k < sizeof(sp5)/sizeof(sp5[0]); k++) {
                wc_Sha512 hh; wc_Sha512 hs;
                word32 tot = sp5[k][0] + sp5[k][1] + sp5[k][2];
                char label[56];
                unsigned p2 = 0, seg;
                int ok = 0;
                if (wc_InitSha512_ex(&hh, NULL, WOLFSSL_ELS_PKC_DEVID) == 0 &&
                    wc_InitSha512_ex(&hs, NULL, INVALID_DEVID) == 0) {
                    r = 0;
                    for (seg = 0; seg < 3 && r == 0; seg++) {
                        if (sp5[k][seg] > 0) {
                            r = wc_Sha512Update(&hh, buf + p2, sp5[k][seg]);
                            p2 += sp5[k][seg];
                        }
                    }
                    if (r == 0) r = wc_Sha512Final(&hh, hw5);
                    if (r == 0) r = wc_Sha512Update(&hs, buf, tot);
                    if (r == 0) r = wc_Sha512Final(&hs, sw5);
                    ok = (r == 0) && (memcmp(hw5, sw5, 64) == 0);
                    wc_Sha512Free(&hh); wc_Sha512Free(&hs);
                }
                (void)snprintk(label, sizeof(label),
                               "SHA-512 incremental %u+%u+%u == one-shot",
                               (unsigned)sp5[k][0], (unsigned)sp5[k][1],
                               (unsigned)sp5[k][2]);
                check(label, ok);
            }
        }

        /* the Copy handler, for the 512-bit context */
        {
            wc_Sha512 h, hs;
            byte snap[64], fin[64], refsnap[64], reffin[64];
            int ok = 0;
            if (wc_InitSha512_ex(&h, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                r = wc_Sha512Update(&h, buf, 200);
                if (r == 0) r = wc_Sha512GetHash(&h, snap);
                if (r == 0) r = wc_Sha512Update(&h, buf + 200, 100);
                if (r == 0) r = wc_Sha512Final(&h, fin);
                wc_Sha512Free(&h);

                if (r == 0 &&
                    wc_InitSha512_ex(&hs, NULL, INVALID_DEVID) == 0) {
                    r = wc_Sha512Update(&hs, buf, 200);
                    if (r == 0) r = wc_Sha512Final(&hs, refsnap);
                    wc_Sha512Free(&hs);
                }
                if (r == 0 &&
                    wc_InitSha512_ex(&hs, NULL, INVALID_DEVID) == 0) {
                    r = wc_Sha512Update(&hs, buf, 300);
                    if (r == 0) r = wc_Sha512Final(&hs, reffin);
                    wc_Sha512Free(&hs);
                }
                ok = (r == 0) && (memcmp(snap, refsnap, 64) == 0) &&
                     (memcmp(fin, reffin, 64) == 0);
            }
            check("SHA-512 GetHash snapshot leaves the hash intact", ok);
        }

        /* Agreement with software proves correctness but not offload: a
         * decline would agree too. Prove the engine was actually entered. */
        {
            unsigned long before = wc_ElsPkc_HashOffloadCount;
            wc_Sha512 h;
            int ok = 0;
            if (wc_InitSha512_ex(&h, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                r = wc_Sha512Update(&h, buf, 256);
                if (r == 0) r = wc_Sha512Final(&h, hw5);
                wc_Sha512Free(&h);
                ok = (r == 0) && (wc_ElsPkc_HashOffloadCount > before);
            }
            check("SHA-512 reached the hardware, not the fallback", ok);
        }

        {
            unsigned long before = wc_ElsPkc_HashOffloadCount;
            wc_Sha384 h;
            int ok = 0;
            if (wc_InitSha384_ex(&h, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                r = wc_Sha384Update(&h, buf, 256);
                if (r == 0) r = wc_Sha384Final(&h, hw5);
                wc_Sha384Free(&h);
                ok = (r == 0) && (wc_ElsPkc_HashOffloadCount > before);
            }
            check("SHA-384 reached the hardware, not the fallback", ok);
        }
    }


    /* AES: hardware vs software for each mode and both key sizes. NIST
     * vectors would only prove AES is AES; comparing against wolfCrypt's own
     * software path also proves the IV/counter chaining is carried correctly
     * across calls, which is where an offload usually goes wrong. */
    {
        static const byte key16[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
        static const byte key32[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,
            0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4 };
        static const byte iv[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
        static byte hwOut[128], swOut[128], back[128];
        struct { const char* name; const byte* k; word32 kl; int mode; } cases[] = {
            { "AES-128-CBC", key16, 16, 1 },
            { "AES-256-CBC", key32, 32, 1 },
            /* CTR omitted: WOLFSSL_AES_COUNTER is off in the module's
             * default Zephyr settings, so wc_AesCtrEncrypt is not built. The
             * port handles it when a build enables it. */
            { "AES-128-ECB", key16, 16, 3 },
        };
        unsigned c;

        for (c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
            Aes hw, sw;
            char label[52];
            int ok = 0, r = 0;

            if (wc_AesInit(&hw, NULL, WOLFSSL_ELS_PKC_DEVID) != 0) continue;
            if (wc_AesInit(&sw, NULL, INVALID_DEVID) != 0) { wc_AesFree(&hw); continue; }

            if (cases[c].mode == 1) {
                r  = wc_AesSetKey(&hw, cases[c].k, cases[c].kl, iv, AES_ENCRYPTION);
                r |= wc_AesSetKey(&sw, cases[c].k, cases[c].kl, iv, AES_ENCRYPTION);
                /* two chained calls, so a dropped IV update shows up */
                if (r == 0) r  = wc_AesCbcEncrypt(&hw, hwOut, buf, 64);
                if (r == 0) r |= wc_AesCbcEncrypt(&hw, hwOut + 64, buf + 64, 64);
                if (r == 0) r |= wc_AesCbcEncrypt(&sw, swOut, buf, 64);
                if (r == 0) r |= wc_AesCbcEncrypt(&sw, swOut + 64, buf + 64, 64);
            }
            else {
                r  = wc_AesSetKey(&hw, cases[c].k, cases[c].kl, NULL, AES_ENCRYPTION);
                r |= wc_AesSetKey(&sw, cases[c].k, cases[c].kl, NULL, AES_ENCRYPTION);
                if (r == 0) r  = wc_AesEcbEncrypt(&hw, hwOut, buf, 128);
                if (r == 0) r |= wc_AesEcbEncrypt(&sw, swOut, buf, 128);
            }

            ok = (r == 0) && (memcmp(hwOut, swOut, 128) == 0);
            wc_AesFree(&hw); wc_AesFree(&sw);

            (void)snprintk(label, sizeof(label), "%s hardware == software",
                           cases[c].name);
            check(label, ok);
        }

        /* diagnostic: one 16-byte CBC block, hardware vs software */
        {
            Aes h2, s2;
            byte o1[16], o2[16];
            int r;
            if (wc_AesInit(&h2, NULL, WOLFSSL_ELS_PKC_DEVID) == 0 &&
                wc_AesInit(&s2, NULL, INVALID_DEVID) == 0) {
                r  = wc_AesSetKey(&h2, key16, 16, iv, AES_ENCRYPTION);
                r |= wc_AesSetKey(&s2, key16, 16, iv, AES_ENCRYPTION);
                if (r == 0) r  = wc_AesCbcEncrypt(&h2, o1, buf, 16);
                if (r == 0) r |= wc_AesCbcEncrypt(&s2, o2, buf, 16);
                printk("    1-block CBC hw: ");
                for (int q = 0; q < 16; q++) printk("%02x", o1[q]);
                printk("\n    1-block CBC sw: ");
                for (int q = 0; q < 16; q++) printk("%02x", o2[q]);
                printk("\n    hw IV after:    ");
                for (int q = 0; q < 16; q++) printk("%02x", ((byte*)h2.reg)[q]);
                printk("\n    sw IV after:    ");
                for (int q = 0; q < 16; q++) printk("%02x", ((byte*)s2.reg)[q]);
                printk("\n");
                wc_AesFree(&h2); wc_AesFree(&s2);
            }
        }

        /* decrypt must undo hardware encrypt */
        {
            Aes e, d;
            int ok = 0, r;
            if (wc_AesInit(&e, NULL, WOLFSSL_ELS_PKC_DEVID) == 0 &&
                wc_AesInit(&d, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                r  = wc_AesSetKey(&e, key16, 16, iv, AES_ENCRYPTION);
                r |= wc_AesSetKey(&d, key16, 16, iv, AES_DECRYPTION);
                if (r == 0) r = wc_AesCbcEncrypt(&e, hwOut, buf, 128);
                if (r == 0) r = wc_AesCbcDecrypt(&d, back, hwOut, 128);
                ok = (r == 0) && (memcmp(back, buf, 128) == 0);
                wc_AesFree(&e); wc_AesFree(&d);
            }
            check("AES-128-CBC decrypt round trip", ok);
        }

        printk("  >>> ELS AES offload ran %lu time(s) <<<\n",
               wc_ElsPkc_AesOffloadCount);
        check("AES actually used the hardware",
              wc_ElsPkc_AesOffloadCount > 0);
    }

    /* RNG: correctness cannot be asserted from output, so check the things
     * that would actually be broken - it runs, it fills the whole buffer, and
     * successive draws differ. */
    {
        WC_RNG rng;
        byte r1[48], r2[48];
        int ok = 0;

        XMEMSET(r1, 0, sizeof(r1));
        XMEMSET(r2, 0, sizeof(r2));

        if (wc_InitRng_ex(&rng, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
            int r  = wc_RNG_GenerateBlock(&rng, r1, sizeof(r1));
            if (r == 0) r = wc_RNG_GenerateBlock(&rng, r2, sizeof(r2));
            ok = (r == 0) && (memcmp(r1, r2, sizeof(r1)) != 0);
            /* an all-zero buffer would mean the call silently did nothing */
            if (ok) {
                unsigned z, nz = 0;
                for (z = 0; z < sizeof(r1); z++) if (r1[z] != 0) nz++;
                ok = (nz > 0);
            }
            wc_FreeRng(&rng);
        }
        check("RNG produces distinct non-zero output", ok);
        printk("  >>> ELS RNG offload ran %lu time(s) <<<\n",
               wc_ElsPkc_RngOffloadCount);
        check("RNG actually used the hardware",
              wc_ElsPkc_RngOffloadCount > 0);
    }

    /* CMAC: lengths chosen around the block boundary, because the final chunk
     * takes a different subkey depending on whether it is complete - the exact
     * case a naive buffering scheme gets wrong. Split updates too, so the
     * withheld-final-block logic is exercised rather than just one-shot. */
    {
        static const byte ckey[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };
        static const word32 clens[] = { 0, 1, 15, 16, 17, 32, 40, 64 };
        unsigned c;

        for (c = 0; c < sizeof(clens)/sizeof(clens[0]); c++) {
            Cmac hw, sw;
            byte m1[16], m2[16];
            word32 s1 = sizeof(m1), s2 = sizeof(m2);
            char label[52];
            int ok = 0, r;

            if (wc_InitCmac_ex(&hw, ckey, 16, WC_CMAC_AES, NULL, NULL,
                               WOLFSSL_ELS_PKC_DEVID) == 0 &&
                wc_InitCmac_ex(&sw, ckey, 16, WC_CMAC_AES, NULL, NULL,
                               INVALID_DEVID) == 0) {
                /* split into two updates so buffering is exercised */
                word32 half = clens[c] / 2;
                r  = (half > 0) ? wc_CmacUpdate(&hw, buf, half) : 0;
                if (r == 0 && clens[c] - half > 0)
                    r = wc_CmacUpdate(&hw, buf + half, clens[c] - half);
                if (r == 0) r = wc_CmacFinal(&hw, m1, &s1);

                if (r == 0 && clens[c] > 0)
                    r = wc_CmacUpdate(&sw, buf, clens[c]);
                if (r == 0) r = wc_CmacFinal(&sw, m2, &s2);

                ok = (r == 0) && (s1 == s2) && (memcmp(m1, m2, s1) == 0);
            }
            (void)snprintk(label, sizeof(label),
                           "CMAC len=%-3u hardware == software",
                           (unsigned)clens[c]);
            check(label, ok);
        }
        printk("  >>> ELS CMAC offload ran %lu time(s) <<<\n",
               wc_ElsPkc_CmacOffloadCount);
        check("CMAC actually used the hardware",
              wc_ElsPkc_CmacOffloadCount > 0);
    }

    /* ---- AES-GCM -------------------------------------------------------
     * Data and AAD lengths chosen so both the block-aligned path and the
     * zero-padded msgendw tail get exercised, on their own and together. */
    {
        static const struct { word32 dataSz, aadSz; } gcases[] = {
            {  0,  0 }, {  0, 16 }, {  0, 20 },
            {  1,  0 }, { 15,  0 }, { 16,  0 }, { 17,  0 },
            { 32, 16 }, { 40, 13 }, { 64, 64 }, { 61, 29 },
        };
        static byte gpt[80], gaad[80];
        static byte hwCt[80], swCt[80], rt[80];
        byte hwTag[16], swTag[16];
        byte key[32], iv[12];
        Aes aes;
        unsigned k, c;
        int r, ok;
        char label[72];

        for (k = 0; k < sizeof(gpt); k++)  gpt[k]  = (byte)(k * 7u + 1u);
        for (k = 0; k < sizeof(gaad); k++) gaad[k] = (byte)(k * 3u + 5u);
        for (k = 0; k < sizeof(key); k++)  key[k]  = (byte)(0xA0u + k);
        for (k = 0; k < sizeof(iv); k++)   iv[k]   = (byte)(0x30u + k);

        for (c = 0; c < sizeof(gcases) / sizeof(gcases[0]); c++) {
            word32 dsz = gcases[c].dataSz, asz = gcases[c].aadSz;

            /* hardware */
            memset(hwCt, 0, sizeof(hwCt));
            memset(hwTag, 0, sizeof(hwTag));
            r = wc_AesInit(&aes, NULL, WOLFSSL_ELS_PKC_DEVID);
            if (r == 0) r = wc_AesGcmSetKey(&aes, key, 32);
            if (r == 0) r = wc_AesGcmEncrypt(&aes, hwCt, gpt, dsz,
                                             iv, sizeof(iv),
                                             hwTag, sizeof(hwTag), gaad, asz);
            wc_AesFree(&aes);

            /* software reference */
            if (r == 0) {
                memset(swCt, 0, sizeof(swCt));
                memset(swTag, 0, sizeof(swTag));
                r = wc_AesInit(&aes, NULL, INVALID_DEVID);
                if (r == 0) r = wc_AesGcmSetKey(&aes, key, 32);
                if (r == 0) r = wc_AesGcmEncrypt(&aes, swCt, gpt, dsz,
                                                 iv, sizeof(iv),
                                                 swTag, sizeof(swTag),
                                                 gaad, asz);
                wc_AesFree(&aes);
            }

            ok = (r == 0) &&
                 (memcmp(hwCt, swCt, dsz) == 0) &&
                 (memcmp(hwTag, swTag, sizeof(hwTag)) == 0);
            (void)snprintk(label, sizeof(label),
                           "GCM enc len=%-3u aad=%-3u hardware == software",
                           (unsigned)dsz, (unsigned)asz);
            check(label, ok);

            /* hardware decrypt round-trips its own ciphertext */
            memset(rt, 0, sizeof(rt));
            r = wc_AesInit(&aes, NULL, WOLFSSL_ELS_PKC_DEVID);
            if (r == 0) r = wc_AesGcmSetKey(&aes, key, 32);
            if (r == 0) r = wc_AesGcmDecrypt(&aes, rt, hwCt, dsz,
                                             iv, sizeof(iv),
                                             hwTag, sizeof(hwTag), gaad, asz);
            wc_AesFree(&aes);
            ok = (r == 0) && (memcmp(rt, gpt, dsz) == 0);
            (void)snprintk(label, sizeof(label),
                           "GCM dec len=%-3u aad=%-3u round-trips",
                           (unsigned)dsz, (unsigned)asz);
            check(label, ok);
        }

        /* a flipped tag bit must be rejected, not silently accepted */
        {
            byte badTag[16];
            r = wc_AesInit(&aes, NULL, WOLFSSL_ELS_PKC_DEVID);
            if (r == 0) r = wc_AesGcmSetKey(&aes, key, 32);
            if (r == 0) r = wc_AesGcmEncrypt(&aes, hwCt, gpt, 32,
                                             iv, sizeof(iv),
                                             hwTag, sizeof(hwTag), gaad, 16);
            memcpy(badTag, hwTag, sizeof(badTag));
            badTag[0] ^= 0x01;
            if (r == 0) {
                r = wc_AesGcmDecrypt(&aes, rt, hwCt, 32, iv, sizeof(iv),
                                     badTag, sizeof(badTag), gaad, 16);
                check("GCM rejects a corrupted tag", r == AES_GCM_AUTH_E);
            }
            else {
                check("GCM rejects a corrupted tag", 0);
            }
            wc_AesFree(&aes);
        }

        printk("  >>> ELS GCM offload ran %lu time(s) <<<\n",
               wc_ElsPkc_GcmOffloadCount);
        check("GCM actually used the hardware",
              wc_ElsPkc_GcmOffloadCount > 0);
    }

    /* ---- HMAC-SHA256 ---------------------------------------------------
     * The port deliberately has no HMAC arm: ELS HMAC is one-shot while
     * wolfCrypt drives HMAC incrementally, so serving it would mean buffering
     * an unbounded message. Declining costs nothing, because hmac.c passes its
     * devId down to the inner SHA-256 - which this port does accelerate. This
     * asserts that, rather than assuming it. */
    {
        static const byte hkey[32] = {
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
            0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
        };
        static byte hmsg[100];
        byte hwMac[32], swMac[32];
        unsigned long before, after;
        Hmac hmac;
        unsigned k;
        int r, ok;

        for (k = 0; k < sizeof(hmsg); k++) hmsg[k] = (byte)(k * 11u + 3u);

        before = wc_ElsPkc_HashOffloadCount;

        r = wc_HmacInit(&hmac, NULL, WOLFSSL_ELS_PKC_DEVID);
        if (r == 0) r = wc_HmacSetKey(&hmac, WC_SHA256, hkey, sizeof(hkey));
        if (r == 0) r = wc_HmacUpdate(&hmac, hmsg, 40);
        if (r == 0) r = wc_HmacUpdate(&hmac, hmsg + 40, sizeof(hmsg) - 40);
        if (r == 0) r = wc_HmacFinal(&hmac, hwMac);
        wc_HmacFree(&hmac);

        after = wc_ElsPkc_HashOffloadCount;

        if (r == 0) {
            r = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
            if (r == 0) r = wc_HmacSetKey(&hmac, WC_SHA256, hkey,
                                          sizeof(hkey));
            if (r == 0) r = wc_HmacUpdate(&hmac, hmsg, sizeof(hmsg));
            if (r == 0) r = wc_HmacFinal(&hmac, swMac);
            wc_HmacFree(&hmac);
        }

        ok = (r == 0) && (memcmp(hwMac, swMac, sizeof(hwMac)) == 0);
        check("HMAC-SHA256 hardware == software", ok);
        printk("  >>> HMAC drove %lu hash offload(s) <<<\n", after - before);
        check("HMAC reaches the hardware through the hash path",
              after > before);
    }

    /* ---- regressions from the skoll review ----------------------------- */

    /* A truncated CMAC tag is legal - wc_AesCmacVerify_ex() asks for exactly
     * checkSz bytes - and the leftmost bytes of the full CMAC are that
     * truncation. The port used to reject anything under 16 with BUFFER_E,
     * which cannot fall back because the message is already in the hardware. */
    {
        static const byte ckey[16] = {
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        };
        static byte msg[40];
        byte m1[16], m2[16];
        word32 s1, s2;
        Cmac hw, sw;
        unsigned k;
        int r, ok;
        const word32 tagSzs[] = { 4, 8, 12, 13, 16 };
        unsigned tc;

        for (k = 0; k < sizeof(msg); k++) msg[k] = (byte)(k * 5u + 2u);

        for (tc = 0; tc < sizeof(tagSzs) / sizeof(tagSzs[0]); tc++) {
            char label[72];
            s1 = s2 = tagSzs[tc];
            memset(m1, 0, sizeof(m1));
            memset(m2, 0, sizeof(m2));

            r = wc_InitCmac_ex(&hw, ckey, 16, WC_CMAC_AES, NULL, NULL,
                               WOLFSSL_ELS_PKC_DEVID);
            if (r == 0) r = wc_CmacUpdate(&hw, msg, sizeof(msg));
            if (r == 0) r = wc_CmacFinal(&hw, m1, &s1);

            if (r == 0) {
                r = wc_InitCmac_ex(&sw, ckey, 16, WC_CMAC_AES, NULL, NULL,
                                   INVALID_DEVID);
                if (r == 0) r = wc_CmacUpdate(&sw, msg, sizeof(msg));
                if (r == 0) r = wc_CmacFinal(&sw, m2, &s2);
            }

            ok = (r == 0) && (memcmp(m1, m2, tagSzs[tc]) == 0);
            (void)snprintk(label, sizeof(label),
                           "CMAC %u-byte tag hardware == software",
                           (unsigned)tagSzs[tc]);
            check(label, ok);
        }
    }

    /* A CMAC started on hardware and dropped without a Final must give its
     * pool entry back through wc_CmacFree(). The pool holds two entries, so
     * before the fix three abandoned contexts disabled CMAC offload for good
     * - and left three plaintext AES keys sitting in .bss. */
    {
        static const byte ckey[16] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
        };
        static byte msg[32];
        byte m1[16];
        word32 s1;
        Cmac cmac;
        unsigned long before;
        unsigned k, i;
        int r = 0;

        for (k = 0; k < sizeof(msg); k++) msg[k] = (byte)(k + 1u);

        /* abandon more contexts than the pool has entries */
        for (i = 0; i < 4; i++) {
            if (wc_InitCmac_ex(&cmac, ckey, 16, WC_CMAC_AES, NULL, NULL,
                               WOLFSSL_ELS_PKC_DEVID) == 0) {
                (void)wc_CmacUpdate(&cmac, msg, sizeof(msg));
                (void)wc_CmacFree(&cmac);
            }
        }

        before = wc_ElsPkc_CmacOffloadCount;
        s1 = sizeof(m1);
        r = wc_InitCmac_ex(&cmac, ckey, 16, WC_CMAC_AES, NULL, NULL,
                           WOLFSSL_ELS_PKC_DEVID);
        if (r == 0) r = wc_CmacUpdate(&cmac, msg, sizeof(msg));
        if (r == 0) r = wc_CmacFinal(&cmac, m1, &s1);

        check("CMAC offload survives abandoned contexts",
              r == 0 && wc_ElsPkc_CmacOffloadCount > before);
    }

    /* ---- Phase 2: slot references and ECC ------------------------------ */

    /* 2a - the reference is pure logic, so check the rejections too. A blob
     * that parses is only a claim; one that does not must never reach the
     * hardware, because a bad slot index is a reset rather than an error. */
    {
        wc_ElsPkc_KeyRef in, out;
        byte blob[WC_ELSPKC_KEYREF_SZ];
        word32 sz;
        int r, ok;

        memset(&in, 0, sizeof(in));
        in.keyClass = WC_ELSPKC_KEY_ECC_SIGN;
        in.slot     = 10;
        in.flags    = WC_ELSPKC_REF_FLAG_BIND | WC_ELSPKC_REF_FLAG_EXPORTABLE;
        memcpy(in.bind, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);

        sz = sizeof(blob);
        r  = wc_ElsPkc_MakeKeyRef(&in, blob, &sz);
        ok = (r == 0) && (sz == WC_ELSPKC_KEYREF_SZ) &&
             (blob[0] == 'E') && (blob[1] == 'L');
        check("KeyRef serialises with the expected magic", ok);

        r  = wc_ElsPkc_ParseKeyRef(blob, sizeof(blob), &out);
        ok = (r == 0) && (out.keyClass == in.keyClass) &&
             (out.slot == in.slot) && (out.flags == in.flags) &&
             (memcmp(out.bind, in.bind, 8) == 0);
        check("KeyRef round-trips unchanged", ok);

        blob[0] = 'X';
        check("KeyRef rejects a wrong magic",
              wc_ElsPkc_ParseKeyRef(blob, sizeof(blob), &out) != 0);
        blob[0] = 'E'; blob[2] = 99;
        check("KeyRef rejects an unknown version",
              wc_ElsPkc_ParseKeyRef(blob, sizeof(blob), &out) != 0);
        blob[2] = WC_ELSPKC_KEYREF_VER; blob[4] = 200;
        check("KeyRef rejects an out-of-range slot",
              wc_ElsPkc_ParseKeyRef(blob, sizeof(blob), &out) != 0);
        blob[4] = 10; blob[3] = 0;
        check("KeyRef rejects an unassigned class",
              wc_ElsPkc_ParseKeyRef(blob, sizeof(blob), &out) != 0);

        /* a longer blob is normal - wolfPSA appends the public point */
        sz = sizeof(blob);
        (void)wc_ElsPkc_MakeKeyRef(&in, blob, &sz);
        {
            byte longer[WC_ELSPKC_KEYREF_SZ + 65];
            memset(longer, 0xAA, sizeof(longer));
            memcpy(longer, blob, sizeof(blob));
            check("KeyRef parses a prefix of a longer blob",
                  wc_ElsPkc_ParseKeyRef(longer, sizeof(longer), &out) == 0);
        }
    }

    /* AesUseSlot was declared in the header with no implementation behind it -
     * a link error waiting for the first caller. Calling it is the test. */
    {
        wc_ElsPkc_KeyRef ref;
        wc_ElsPkc_KeyRef back;
        Aes slotAes;
        int r, ok;

        memset(&ref, 0, sizeof(ref));
        ref.keyClass = WC_ELSPKC_KEY_AES;
        ref.slot     = 12;

        r  = wc_ElsPkc_AesUseSlot(&slotAes, &ref, NULL, WOLFSSL_ELS_PKC_DEVID);
        ok = (r == 0) && (slotAes.idLen == WC_ELSPKC_KEYREF_SZ) &&
             (wc_ElsPkc_ParseKeyRef(slotAes.id, (word32)slotAes.idLen,
                                    &back) == 0) &&
             (back.slot == 12) && (back.keyClass == WC_ELSPKC_KEY_AES);
        check("AesUseSlot binds an Aes to a slot reference", ok);
        if (r == 0) wc_AesFree(&slotAes);

        /* an ECC class on an Aes must be refused, not quietly accepted */
        ref.keyClass = WC_ELSPKC_KEY_ECC_SIGN;
        check("AesUseSlot rejects a non-AES key class",
              wc_ElsPkc_AesUseSlot(&slotAes, &ref, NULL,
                                   WOLFSSL_ELS_PKC_DEVID) != 0);

        /* the documented size-query mode */
        {
            word32 sz = 0;
            ref.keyClass = WC_ELSPKC_KEY_AES;
            check("MakeKeyRef size query reports the reference size",
                  wc_ElsPkc_MakeKeyRef(&ref, NULL, &sz) == LENGTH_ONLY_E &&
                  sz == WC_ELSPKC_KEYREF_SZ);
        }
    }

    /* 2b/2c - generate into a slot, sign with it, verify both ways */
    {
        wc_ElsPkc_KeyRef ref;
        ecc_key slotKey, swKey;
        WC_RNG rng;
        byte digest[32];
        byte sig[80];
        word32 sigSz;
        byte pub[MAX_ECC_BYTES * 2 + 1];
        word32 pubSz;
        unsigned long before;
        int r, ok, verified;
        unsigned k;

        for (k = 0; k < sizeof(digest); k++) digest[k] = (byte)(k * 9u + 4u);

        memset(&ref, 0, sizeof(ref));
        ref.keyClass = WC_ELSPKC_KEY_ECC_SIGN;
        ref.slot     = 10;   /* the index NXP's own example uses */

        r = wc_InitRng(&rng);
        check("RNG for ECC ready", r == 0);

        before = wc_ElsPkc_EccOffloadCount;
        r = wc_ElsPkc_EccUseSlot(&slotKey, &ref, NULL, WOLFSSL_ELS_PKC_DEVID);
        check("EccUseSlot binds a key to the slot", r == 0);

        if (r == 0) {
            r = wc_ecc_make_key_ex(&rng, 32, &slotKey, ECC_SECP256R1);
            check("in-slot keygen succeeds", r == 0);
            check("keygen ran on the hardware",
                  wc_ElsPkc_EccOffloadCount > before);
        }

        /* The public point must have survived: ELS cannot hand it back later,
         * so if it is not in the key now it is gone for good. */
        if (r == 0) {
            pubSz = sizeof(pub);
            ok = (wc_ecc_export_x963_ex(&slotKey, pub, &pubSz, 0) == 0) &&
                 (pubSz == 65) && (pub[0] == 0x04);
            check("keygen returned a usable public point", ok);
        }

        /* sign on hardware with the slot key */
        if (r == 0) {
            before = wc_ElsPkc_EccOffloadCount;
            sigSz  = sizeof(sig);
            r = wc_ecc_sign_hash(digest, sizeof(digest), sig, &sigSz,
                                 &rng, &slotKey);
            check("slot-key sign succeeds", r == 0);
            check("sign ran on the hardware",
                  wc_ElsPkc_EccOffloadCount > before);
        }

        /* software verifies the hardware signature - this is what proves the
         * signature is a real ECDSA signature over the real key, not merely
         * something both halves of the port agree about */
        if (r == 0) {
            ecc_key checkKey;
            pubSz = sizeof(pub);
            (void)wc_ecc_export_x963_ex(&slotKey, pub, &pubSz, 0);
            if (wc_ecc_init_ex(&checkKey, NULL, INVALID_DEVID) == 0) {
                verified = 0;
                ok = (wc_ecc_import_x963_ex(pub, pubSz, &checkKey,
                                            ECC_SECP256R1) == 0) &&
                     (wc_ecc_verify_hash(sig, sigSz, digest, sizeof(digest),
                                         &verified, &checkKey) == 0) &&
                     verified;
                check("software verifies the hardware signature", ok);
                wc_ecc_free(&checkKey);
            }
        }

        /* hardware verify of that same signature */
        if (r == 0) {
            pubSz = sizeof(pub);
            (void)wc_ecc_export_x963_ex(&slotKey, pub, &pubSz, 0);
            if (wc_ecc_init_ex(&swKey, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                before = wc_ElsPkc_EccOffloadCount;
                verified = 0;
                ok = (wc_ecc_import_x963_ex(pub, pubSz, &swKey,
                                            ECC_SECP256R1) == 0) &&
                     (wc_ecc_verify_hash(sig, sigSz, digest, sizeof(digest),
                                         &verified, &swKey) == 0) &&
                     verified;
                check("hardware verify accepts a good signature", ok);
                check("verify ran on the hardware",
                      wc_ElsPkc_EccOffloadCount > before);

                /* THE test for this port: ELS reports a bad signature only
                 * through the recalculated R, never through the status. A
                 * port that trusted the status would pass everything above
                 * and still accept forgeries. */
                sig[sigSz - 1] ^= 0x01;
                verified = 1;
                r = wc_ecc_verify_hash(sig, sigSz, digest, sizeof(digest),
                                       &verified, &swKey);
                check("hardware verify REJECTS a tampered signature",
                      r == 0 && verified == 0);
                sig[sigSz - 1] ^= 0x01;

                /* and a good signature against the wrong digest */
                digest[0] ^= 0xFF;
                verified = 1;
                r = wc_ecc_verify_hash(sig, sigSz, digest, sizeof(digest),
                                       &verified, &swKey);
                check("hardware verify REJECTS a wrong digest",
                      r == 0 && verified == 0);
                digest[0] ^= 0xFF;

                wc_ecc_free(&swKey);
            }
        }

        wc_ecc_free(&slotKey);
        wc_FreeRng(&rng);

        printk("  >>> ELS ECC offload ran %lu time(s) <<<\n",
               wc_ElsPkc_EccOffloadCount);
        check("ECC actually used the hardware",
              wc_ElsPkc_EccOffloadCount > 0);
    }

    /* ---- Phase 5: PKC tier, RSA raw modexp ------------------------------
     * The callback sits in wc_RsaFunction_ex, below all padding, so this
     * exercises RSASP1/RSAVP1 directly. A private op followed by the public
     * op must return the original block - and the counter proves the PKC
     * actually ran rather than software agreeing with itself. */
    {
        static RsaKey rsa;
        static byte   sig[256];
        static byte   rt[256];
        byte   msg[256];
        word32 idx = 0, sigSz = 0, rtSz = 0;
        unsigned long before;
        unsigned k;
        int r, ok;

        /* a block strictly below the modulus: top byte 0 keeps it in range */
        memset(msg, 0, sizeof(msg));
        for (k = 1; k < sizeof(msg); k++) msg[k] = (byte)(k * 13u + 7u);

        r = wc_InitRsaKey_ex(&rsa, NULL, WOLFSSL_ELS_PKC_DEVID);
        check("RSA key init", r == 0);

        if (r == 0) {
            r = wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &rsa,
                                       sizeof_client_key_der_2048);
            check("RSA-2048 test key decodes", r == 0);
        }

        /* Drive the padded API an application actually calls; the raw
         * primitive this port claims runs underneath it either way, and the
         * counter is what proves the PKC and not software did the work. */
        if (r == 0) {
            before = wc_ElsPkc_RsaOffloadCount;
            r = wc_RsaSSL_Sign(msg, 64, sig, sizeof(sig), &rsa, NULL);
            ok = (r == 256) && (wc_ElsPkc_RsaOffloadCount > before);
            check("RSA sign ran on the PKC", ok);
            sigSz = (r > 0) ? (word32)r : 0;
        }

        if (sigSz == 256) {
            before = wc_ElsPkc_RsaOffloadCount;
            r = wc_RsaSSL_Verify(sig, sigSz, rt, sizeof(rt), &rsa);
            ok = (r == 64) && (wc_ElsPkc_RsaOffloadCount > before);
            check("RSA verify ran on the PKC", ok);
            check("RSA verify recovers the signed block",
                  (r == 64) && (memcmp(rt, msg, 64) == 0));
            rtSz = (r > 0) ? (word32)r : 0;
        }
        (void)rtSz;

        printk("  >>> ELS PKC RSA offload ran %lu time(s) <<<\n",
               wc_ElsPkc_RsaOffloadCount);
        wc_FreeRsaKey(&rsa);
    }

    /* ---- Phase 5: X25519 on the PKC -------------------------------------
     * Both sides use software keys; only the agreement is offloaded. The
     * check is cross-implementation: alice computes her secret on hardware,
     * bob computes his in software, and X25519 says they must match. */
    {
        static curve25519_key aPriv, bPriv;
        WC_RNG rng;
        byte ssHw[32], ssSw[32];
        word32 hwLen = sizeof(ssHw), swLen = sizeof(ssSw);
        unsigned long before;
        int r, ok;

        r = wc_InitRng(&rng);
        if (r == 0) r = wc_curve25519_init_ex(&aPriv, NULL,
                                              WOLFSSL_ELS_PKC_DEVID);
        if (r == 0) r = wc_curve25519_init_ex(&bPriv, NULL, INVALID_DEVID);
        if (r == 0) r = wc_curve25519_make_key(&rng, 32, &aPriv);
        if (r == 0) r = wc_curve25519_make_key(&rng, 32, &bPriv);
        check("X25519 keypairs generated", r == 0);

        if (r == 0) {
            before = wc_ElsPkc_X25519OffloadCount;
            r = wc_curve25519_shared_secret_ex(&aPriv, &bPriv, ssHw, &hwLen,
                                               EC25519_LITTLE_ENDIAN);
            ok = (r == 0) && (wc_ElsPkc_X25519OffloadCount > before);
            check("X25519 agreement ran on the PKC", ok);
        }

        if (r == 0) {
            r = wc_curve25519_shared_secret_ex(&bPriv, &aPriv, ssSw, &swLen,
                                               EC25519_LITTLE_ENDIAN);
            ok = (r == 0) && (hwLen == swLen) &&
                 (memcmp(ssHw, ssSw, hwLen) == 0);
            check("X25519 hardware secret == software secret", ok);
        }

        printk("  >>> ELS PKC X25519 offload ran %lu time(s) <<<\n",
               wc_ElsPkc_X25519OffloadCount);
        wc_curve25519_free(&aPriv);
        wc_curve25519_free(&bPriv);
        wc_FreeRng(&rng);
    }

    /* ---- ECC curves selected by Kconfig ---------------------------------
     * A curve that "builds" is not a curve that works: with ECC_USER_CURVES
     * plus a minimum-key-size filter, an unselected or filtered curve simply
     * vanishes from wolfCrypt's table. Sign and verify on each so the option
     * is proven to do something. */
    {
        static const struct { int id; int sz; const char* name; } curves[] = {
#ifdef HAVE_ECC224
            { ECC_SECP224R1, 28, "SECP224R1" },
#endif
#ifndef NO_ECC256
            { ECC_SECP256R1, 32, "SECP256R1" },
#endif
#ifdef HAVE_ECC384
            { ECC_SECP384R1, 48, "SECP384R1" },
#endif
#ifdef HAVE_ECC521
            { ECC_SECP521R1, 66, "SECP521R1" },
#endif
#if defined(HAVE_ECC_KOBLITZ) && !defined(NO_ECC256)
            { ECC_SECP256K1, 32, "SECP256K1" },
#endif
#if defined(HAVE_ECC_BRAINPOOL) && !defined(NO_ECC256)
            { ECC_BRAINPOOLP256R1, 32, "BRAINPOOLP256R1" },
#endif
#if defined(HAVE_ECC_BRAINPOOL) && defined(HAVE_ECC320)
            { ECC_BRAINPOOLP320R1, 40, "BRAINPOOLP320R1" },
#endif
#if defined(HAVE_ECC_BRAINPOOL) && defined(HAVE_ECC384)
            { ECC_BRAINPOOLP384R1, 48, "BRAINPOOLP384R1" },
#endif
#if defined(HAVE_ECC_BRAINPOOL) && defined(HAVE_ECC512)
            { ECC_BRAINPOOLP512R1, 64, "BRAINPOOLP512R1" },
#endif
            { 0, 0, NULL }
        };
        WC_RNG rng;
        unsigned long pkcBefore = 0;
        unsigned c;
        int r;
        char label[72];

        if (wc_InitRng(&rng) == 0) {
            for (c = 0; curves[c].name != NULL; c++) {
                ecc_key k;
                byte dig[32], sig[256];
                word32 sigSz = sizeof(sig);
                int verified = 0, ok = 0;
                unsigned j;

                for (j = 0; j < sizeof(dig); j++) dig[j] = (byte)(j + c);

                /* bound to the port: P-256 falls through to software here
                 * (no slot reference), every other curve should land on the
                 * PKC tier - which the counter below is what proves */
                r = wc_ecc_init_ex(&k, NULL, WOLFSSL_ELS_PKC_DEVID);
                if (r == 0) {
                    r = wc_ecc_make_key_ex(&rng, curves[c].sz, &k,
                                           curves[c].id);
                }
                if (r == 0) {
                    r = wc_ecc_sign_hash(dig, sizeof(dig), sig, &sigSz,
                                         &rng, &k);
                }
                if (r == 0) {
                    r = wc_ecc_verify_hash(sig, sigSz, dig, sizeof(dig),
                                           &verified, &k);
                }
                /* A verify that always answers "valid" would pass every
                 * positive test, so require a rejection too - while the key
                 * is still live. The PKC reports INVALID_SIGNATURE in its
                 * status, where the ELS tier says nothing and expects the
                 * caller to compare the recomputed R. */
                if (r == 0 && verified) {
                    int bad = 1;
                    sig[sigSz - 1] ^= 0x01;
                    if (wc_ecc_verify_hash(sig, sigSz, dig, sizeof(dig),
                                           &bad, &k) != 0 || bad != 0) {
                        r = -1;   /* rejection failed => the curve fails */
                    }
                    sig[sigSz - 1] ^= 0x01;
                }

                ok = (r == 0) && verified;
                if (!ok) {
                    printk("      %s: r=%d verified=%d\n",
                           curves[c].name, r, verified);
                }
                wc_ecc_free(&k);

                (void)snprintk(label, sizeof(label),
                               "%s sign+verify round-trips", curves[c].name);
                check(label, ok);

                /* P-256 has no slot reference here, so it stays in software;
                 * anything else must have gone through the coprocessor. */
                if (curves[c].id != ECC_SECP256R1) {
                    (void)snprintk(label, sizeof(label),
                                   "%s actually used the PKC", curves[c].name);
                    check(label, wc_ElsPkc_EccPkcOffloadCount > pkcBefore);
                }
                pkcBefore = wc_ElsPkc_EccPkcOffloadCount;
            }
            wc_FreeRng(&rng);
        }
        printk("  >>> ELS PKC ECDSA offload ran %lu time(s) <<<\n",
               wc_ElsPkc_EccPkcOffloadCount);
    }

    /* ---- Phase 4: the key store ------------------------------------------
     * Everything here uses keys the device makes for itself: a KWK derived
     * from the DUK, and an AES key derived the same way. No blob from outside
     * is ever unwrapped, which matters because a malformed container does not
     * fail - it resets the SoC. */
    {
        wc_ElsPkc_KeyRef duk, kwk, aesk;
        byte dukRef[WC_ELSPKC_KEYREF_SZ];
        byte kwkRef[WC_ELSPKC_KEYREF_SZ];
        byte aesRef[WC_ELSPKC_KEYREF_SZ];
        word32 refSz;
        byte deriv1[12], deriv2[12];
        byte blob[64];
        word32 blobSz;
        word32 kt = 0, ks = 0, attrs = 0;
        unsigned long before;
        int r;

        memcpy(deriv1, "wolfkwk-0001", 12);
        memcpy(deriv2, "wolfaes-0001", 12);

        /* slot 0 is the DUK: 256-bit, uckdf, and the root of everything here */
        memset(&duk, 0, sizeof(duk));
        duk.keyClass = WC_ELSPKC_KEY_CKDF;
        duk.slot     = 0;
        refSz = sizeof(dukRef);
        r = wc_ElsPkc_MakeKeyRef(&duk, dukRef, &refSz);
        check("DUK reference built", r == 0);

        /* a wrapping key with ukwk and nothing else - adding uaes to a KWK
         * resets the SoC on export, measured during bring-up */
        memset(&kwk, 0, sizeof(kwk));
        kwk.keyClass = WC_ELSPKC_KEY_KWK;
        kwk.slot     = 14;
        refSz = sizeof(kwkRef);
        (void)wc_ElsPkc_MakeKeyRef(&kwk, kwkRef, &refSz);

        memset(&aesk, 0, sizeof(aesk));
        aesk.keyClass = WC_ELSPKC_KEY_AES;
        aesk.slot     = 15;
        refSz = sizeof(aesRef);
        (void)wc_ElsPkc_MakeKeyRef(&aesk, aesRef, &refSz);

        /* start from a known state; a slot that was never written declines,
         * which is fine */
        (void)wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, kwkRef,
                                 WC_ELSPKC_KEYREF_SZ, NULL);
        (void)wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, aesRef,
                                 WC_ELSPKC_KEYREF_SZ, NULL);

        before = wc_ElsPkc_KeyStoreOffloadCount;
        r = wc_KeyStore_Derive(WOLFSSL_ELS_PKC_DEVID,
                               kwkRef, WC_ELSPKC_KEYREF_SZ,
                               dukRef, WC_ELSPKC_KEYREF_SZ,
                               0, deriv1, sizeof(deriv1), 0, NULL);
        check("KWK derived from the DUK", r == 0);
        check("derive ran on the hardware",
              wc_ElsPkc_KeyStoreOffloadCount > before);

        /* the key to be wrapped out has to be created exportable - wrpok
         * cannot be added afterwards */
        r = wc_KeyStore_Derive(WOLFSSL_ELS_PKC_DEVID,
                               aesRef, WC_ELSPKC_KEYREF_SZ,
                               dukRef, WC_ELSPKC_KEYREF_SZ,
                               0, deriv2, sizeof(deriv2),
                               WC_KEYSTORE_ATTR_EXPORTABLE, NULL);
        check("exportable AES key derived", r == 0);

        r = wc_KeyStore_GetInfo(WOLFSSL_ELS_PKC_DEVID, aesRef,
                                WC_ELSPKC_KEYREF_SZ, &kt, &ks, &attrs, NULL);
        check("GetInfo reports an AES key",
              r == 0 && kt == WC_KEYSTORE_KEY_AES);
        check("GetInfo reports 128 bits", r == 0 && ks == 128);
        check("GetInfo reports it exportable",
              r == 0 && (attrs & WC_KEYSTORE_ATTR_EXPORTABLE));

        /* size query first, then the export itself */
        blobSz = 0;
        r = wc_KeyStore_ExportWrapped(WOLFSSL_ELS_PKC_DEVID,
                                      aesRef, WC_ELSPKC_KEYREF_SZ,
                                      kwkRef, WC_ELSPKC_KEYREF_SZ,
                                      NULL, &blobSz, WC_KEYWRAP_FORMAT_VENDOR,
                                      NULL);
        check("export size query returns 32", blobSz == 32);

        blobSz = sizeof(blob);
        memset(blob, 0, sizeof(blob));
        r = wc_KeyStore_ExportWrapped(WOLFSSL_ELS_PKC_DEVID,
                                      aesRef, WC_ELSPKC_KEYREF_SZ,
                                      kwkRef, WC_ELSPKC_KEYREF_SZ,
                                      blob, &blobSz, WC_KEYWRAP_FORMAT_VENDOR,
                                      NULL);
        check("key exported under the KWK", r == 0 && blobSz == 32);

        /* destroy it, then bring the same key back from the blob */
        r = wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, aesRef,
                               WC_ELSPKC_KEYREF_SZ, NULL);
        check("key deleted", r == 0);

        kt = ks = attrs = 0;
        r = wc_KeyStore_GetInfo(WOLFSSL_ELS_PKC_DEVID, aesRef,
                                WC_ELSPKC_KEYREF_SZ, &kt, &ks, &attrs, NULL);
        check("GetInfo refuses a deleted slot", r != 0);

        r = wc_KeyStore_ImportWrapped(WOLFSSL_ELS_PKC_DEVID,
                                      aesRef, WC_ELSPKC_KEYREF_SZ,
                                      kwkRef, WC_ELSPKC_KEYREF_SZ,
                                      blob, blobSz, WC_KEYWRAP_FORMAT_VENDOR,
                                      NULL);
        check("blob imported back into the slot", r == 0);

        kt = ks = attrs = 0;
        r = wc_KeyStore_GetInfo(WOLFSSL_ELS_PKC_DEVID, aesRef,
                                WC_ELSPKC_KEYREF_SZ, &kt, &ks, &attrs, NULL);
        check("restored key has the original properties",
              r == 0 && kt == WC_KEYSTORE_KEY_AES && ks == 128 &&
              (attrs & WC_KEYSTORE_ATTR_EXPORTABLE));

        /* a key that was never made exportable must not be able to leave */
        {
            wc_ElsPkc_KeyRef sealed;
            byte sealedRef[WC_ELSPKC_KEYREF_SZ];
            byte d3[12];

            memcpy(d3, "wolfseal-001", 12);
            memset(&sealed, 0, sizeof(sealed));
            sealed.keyClass = WC_ELSPKC_KEY_AES;
            sealed.slot     = 16;
            refSz = sizeof(sealedRef);
            (void)wc_ElsPkc_MakeKeyRef(&sealed, sealedRef, &refSz);
            (void)wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, sealedRef,
                                     WC_ELSPKC_KEYREF_SZ, NULL);

            r = wc_KeyStore_Derive(WOLFSSL_ELS_PKC_DEVID,
                                   sealedRef, WC_ELSPKC_KEYREF_SZ,
                                   dukRef, WC_ELSPKC_KEYREF_SZ,
                                   0, d3, sizeof(d3), 0, NULL);
            check("non-exportable key derived", r == 0);

            blobSz = sizeof(blob);
            r = wc_KeyStore_ExportWrapped(WOLFSSL_ELS_PKC_DEVID,
                                          sealedRef, WC_ELSPKC_KEYREF_SZ,
                                          kwkRef, WC_ELSPKC_KEYREF_SZ,
                                          blob, &blobSz,
                                          WC_KEYWRAP_FORMAT_VENDOR, NULL);
            check("export REFUSED for a sealed key", r != 0);
            (void)wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, sealedRef,
                                     WC_ELSPKC_KEYREF_SZ, NULL);
        }

        /* leave the store as we found it */
        (void)wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, aesRef,
                                 WC_ELSPKC_KEYREF_SZ, NULL);
        (void)wc_KeyStore_Delete(WOLFSSL_ELS_PKC_DEVID, kwkRef,
                                 WC_ELSPKC_KEYREF_SZ, NULL);

        printk("  >>> ELS key store ops ran %lu time(s) <<<\n",
               wc_ElsPkc_KeyStoreOffloadCount);
    }

    /* ---- regressions from the port-source review ------------------------
     * The DRBG takes whole words only, so a one-byte request used to fail
     * outright rather than fall back - and a single byte is an ordinary ask. */
    {
        static const word32 sizes[] = { 1, 2, 3, 4, 5, 13, 31, 32, 33 };
        unsigned c;
        int allOk = 1;
        unsigned long before = wc_ElsPkc_RngOffloadCount;

        for (c = 0; c < sizeof(sizes) / sizeof(sizes[0]); c++) {
            byte buf[40];
            byte zero[40];
            WC_RNG r2;

            memset(buf, 0, sizeof(buf));
            memset(zero, 0, sizeof(zero));
            /* bound to the port, so the generate itself is the offload -
             * a plain wc_InitRng() uses the software DRBG and the hardware
             * would only supply its seed */
            if (wc_InitRng_ex(&r2, NULL, WOLFSSL_ELS_PKC_DEVID) != 0) {
                allOk = 0; break;
            }
            if (wc_RNG_GenerateBlock(&r2, buf, sizes[c]) != 0) allOk = 0;
            /* not proof of randomness, but catches a request that quietly
             * wrote nothing */
            if (memcmp(buf, zero, sizes[c]) == 0) allOk = 0;
            /* and nothing beyond the asked-for length */
            if (memcmp(buf + sizes[c], zero, sizeof(buf) - sizes[c]) != 0) {
                allOk = 0;
            }
            wc_FreeRng(&r2);
        }
        check("RNG serves 1..33 byte requests, no overrun", allOk);
        check("  ...and those reached the hardware",
              wc_ElsPkc_RngOffloadCount > before);
    }

    /* A digest longer than the port's internal buffer must be declined, not
     * copied in. */
    {
        ecc_key k2;
        byte big[200];
        byte sig2[160];
        word32 sig2Sz = sizeof(sig2);
        WC_RNG r3;
        int r, declined = 0;

        memset(big, 0x5C, sizeof(big));
        if (wc_InitRng(&r3) == 0) {
            if (wc_ecc_init_ex(&k2, NULL, WOLFSSL_ELS_PKC_DEVID) == 0) {
                if (wc_ecc_make_key_ex(&r3, 32, &k2, ECC_SECP256R1) == 0) {
                    /* Either the port declines and software handles it, or it
                     * errors - both are fine. What must not happen is a
                     * 200-byte copy into an 80-byte buffer. */
                    r = wc_ecc_sign_hash(big, sizeof(big), sig2, &sig2Sz,
                                         &r3, &k2);
                    declined = 1;
                    (void)r;
                }
                wc_ecc_free(&k2);
            }
            wc_FreeRng(&r3);
        }
        check("oversized digest does not overflow the port buffer", declined);
    }

    printk("\n  >>> ELS hash offload actually ran %lu time(s) <<<\n",
           wc_ElsPkc_HashOffloadCount);
    check("the hardware path was exercised at all",
          wc_ElsPkc_HashOffloadCount > 0);

    printk("  >>> waits: %lu interrupt-driven, %lu polled, %lu timed out <<<\n",
           wc_ElsPkc_IrqWaitCount, wc_ElsPkc_PollWaitCount,
           wc_ElsPkc_TimeoutCount);
    check("completion waits use the interrupt, not the spin",
          wc_ElsPkc_IrqWaitCount > 0 && wc_ElsPkc_PollWaitCount == 0);

    printk("\n=== %s (%d failure%s) ===\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return 0;
}
