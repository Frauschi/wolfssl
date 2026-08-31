# wolfSSL NXP Hardware Acceleration Ports

wolfSSL supports hardware acceleration on NXP DCP, LTC (KSDK), LPC55S69, and SE050.

## NXP LPC55S69

The LPC55S69 is a general purpose edge computing device, with dual ARM
Cortex-M33 cores running up to 150 MHz, 640/320 KB internal flash/ram,
TrustZone-M, a DSP accelerator, and extensive cryptographic acceleration.

wolfSSL supports the following hardware acceleration on the LPC55S69:
- TRNG
- HashCrypt (Hash/AES Crypto Engine)
  - AES (128, 192, 256) encrypt/decrypt
    - AES-CBC, AES-ECB, AES-CTR, AES-OFB, AES-CFB
  - SHA-1, SHA-256
- CASPER (Asymmetric Crypto Accelerator)
  - RSA verify/encrypt/decrypt (up to 4096-bit, public key only)

### LPC55S69 Hardware Acceleration Caveats

The following caveats should be noted about the LPC55S69 hardware acceleration:
- AES-CTR mode fails when the counter wraps from all FF's to 0.  User should
ensure this never happens, by properly managing the iv/counter in use.
- AES-CFB and AES-OFB only support full 16-byte blocks and multiples thereof.
Encrypt/Decrypt requests of other sizes will fail.
- RSA acceleration is only supported for public keys.  Private key operations
will use a fully software implementation.
- When the HashCrypt engine is in use for SHA-1 or SHA-256, it must not be
interrupted with another hash request or an AES request.  The hash must be
completed before another operation is requested.

### wolfSSL LPC55S69 Hardware Acceleration Enable

To enable only the TRNG, define the following symbol:

**`WOLFSSL_NXP_RNG_1`**

To enable all LPC55S69 hardware acceleration, including the TRNG,
define the following symbol:

**`WOLFSSL_NXP_LPC55S6X`**

NOTE: Both can be defined with no problem.

## NXP SE050

For details on wolfSSL integration with NXP SE050,
see [README_SE050.md](./README_SE050.md).

## NXP EdgeLock (ELS + PKC)

`els_pkc_port.c` offloads wolfCrypt to the EdgeLock subsystem found on the
RW612 and related parts, through the crypto callback interface. The ELS
peripheral serves SHA-256, AES (ECB/CBC/CTR), AES-GCM, CMAC, the DRBG, and
ECDSA/ECDH on P-256; the PKC coprocessor serves RSA, X25519, and ECDSA on the
larger curves. Five key store operations cover generating, deleting, and
importing wrapped keys held in ELS slots.

Anything the hardware does not serve is declined with `CRYPTOCB_UNAVAILABLE`
and completed in software, so an unsupported algorithm or key size costs
performance, never correctness. A hardware failure is deliberately not treated
as a decline: it is reported, so a caller that ignores the return cannot walk
away with a confident bad result.

Keys that live in the ELS key store are referenced rather than exported.
`wc_ElsPkc_MakeKeyRef()` builds a slot reference, and `wc_ecc_init_id()` or
`wc_AesInit_Id()` attaches it to a key, so the private key never leaves the
hardware.

### Hardware behaviour worth knowing

**A rejected request resets the SoC.** ELS answers an invalid key permission or
a failed unwrap by signalling the Intrusion and Tamper Response Controller,
which drives a chip reset - it does not return an error. The port validates
every slot reference against the hardware in software before issuing a command,
and never cancels an operation already in flight, because
`mcuxClEls_Reset_Async(MCUXCLELS_RESET_CANCEL)` is itself a tamper event. Do not
probe the hardware with deliberately malformed references.

**ELS is a system-wide peripheral, and the port's lock covers only wolfSSL.**
Every operation is an `_Async` call followed by `mcuxClEls_WaitForOperation()`,
serialized under one mutex. NXP's PSA driver, an application calling `mcuxClEls`
directly, or a second OS task can all drive the peripheral behind wolfSSL's
back. An integration that mixes wolfSSL with another ELS user has to arbitrate
above both.

**Completion is interrupt-driven where a kernel is available**, with the vendor
busy-spin as the fallback for ISR context and pre-IRQ bring-up. On timeout the
wait degrades to the vendor's synchronous wait rather than aborting the
operation. Tune it with `WOLFSSL_ELS_PKC_TIMEOUT_MS` and
`WOLFSSL_ELS_PKC_IRQ_PRIO`.

**Hash and CMAC contexts come from fixed pools**, sized by
`WOLFSSL_ELS_PKC_HASH_CTX_COUNT` and `WOLFSSL_ELS_PKC_CMAC_CTX_COUNT`, because
these parts are routinely built with `WOLFSSL_NO_MALLOC`. An empty pool is not
an error: that hash runs in software.

**What the hardware declines**, so it runs in software instead: AES-192 (no ELS
key size), any trailing partial block, an AES-GCM IV other than 12 bytes, an
ECDSA digest that is not a full 32 bytes, and ECDH through the wolfCrypt
callback - ELS deposits an agreement result in a key slot, which cannot be read
back, so an in-slot agreement is reached through `wc_KeyStore_Derive()` instead.

**The PKC tier uses a CTR_DRBG, not the ELS DRBG.** The ELS DRBG's security
strength is 128 bits on this part, so `mcuxClEcc_Sign` refuses P-384 and P-521
with `RNG_ERROR` - a failure that names the random source rather than the curve.
The PKC workarea is a fixed hardware region shared by every PKC consumer, which
is why PKC work runs under the same lock as ELS.

**Key store permissions are per-purpose.** `uaes` and `ucmac` are separate
permission bits, so a slot holding both needs one reference per class, and
`wrpok` is set at creation and cannot be added later - a key not made
exportable can never leave. A generated key's public point is available only at
the moment of generation; the hardware will not hand it back afterwards.


### Vendor library

The port depends on NXP's CLNS library, `els_pkc`, which ships as an
MCUXpresso SDK component and is published at <https://github.com/NXP/els_pkc>.
wolfSSL neither builds nor vendors it: the port calls into CLNS and the
application links it, the same arrangement the SE050 port uses. A library built
with this port therefore carries unresolved `mcuxCl*` references by design.

`els_pkc` is under NXP's proprietary `LA_OPT_Online Code Hosting` license, not
an open source license, and its clause 3.7 forbids subjecting it to a license
requiring source disclosure. Fetch it at build time; do not copy it into a
wolfSSL tree.

### Building

Two supported routes, both compiling the same source:

- **Zephyr.** The wolfSSL Zephyr module compiles the port like every other
  wolfCrypt port and turns it on with `CONFIG_WOLFSSL_ELS_PKC=y`. The vendor
  headers arrive with the `els_pkc` Zephyr module, so `CONFIG_MCUX_ELS_PKC=y`
  is required alongside it. When a settings file is supplied through
  `CONFIG_WOLFSSL_SETTINGS_FILE`, the feature Kconfigs do not apply and
  `WOLFSSL_ELS_PKC` has to be defined in that file instead.
- **MCUXpresso SDK / autoconf.** Point configure at an `els_pkc` checkout and
  at a tree carrying the SoC device headers:

```sh
./configure --host=arm-none-eabi --enable-cryptonly --enable-cryptocb \
    --with-els-pkc=/path/to/els_pkc --with-mcux-sdk=/path/to/mcux-sdk-ng \
    CFLAGS="-mcpu=cortex-m33+nodsp -mthumb --specs=nosys.specs"
```

  `--with-els-pkc-platform` selects the els_pkc platform layer and defaults to
  `rw61x`. Note `+nodsp`: without it the vendor CMSIS headers reject the build.

See [IDE/MCUEXPRESSO/RW612](../../../IDE/MCUEXPRESSO/RW612) for a worked
MCUXpresso setup, a known-good `user_settings.h`, and the run-time API.

Everything in the port is gated on `WOLFSSL_ELS_PKC`. Without that macro the
file compiles to an empty translation unit and reaches no vendor header, which
is why it can sit in the build unconditionally. It also means a mis-wired build
succeeds with the port silently absent, so verify by symbol rather than by
object file:

```sh
nm src/.libs/libwolfssl.a | grep wc_ElsPkc
```

## Support

For questions please email support@wolfssl.com

