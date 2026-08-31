# wolfSSL on NXP RW612 with EdgeLock (ELS + PKC)

This directory configures wolfSSL for the NXP RW612 with the EdgeLock crypto callback port, `wolfcrypt/src/port/nxp/els_pkc_port.c`, built from an MCUXpresso SDK project. It offloads SHA-256, AES, AES-GCM, CMAC and the DRBG to the ELS peripheral, and RSA, X25519 and ECDSA to the PKC coprocessor.

Zephyr users do not need any of this: the wolfSSL Zephyr module supplies the same port through `CONFIG_WOLFSSL_ELS_PKC=y`, and the `els_pkc` Zephyr module supplies the vendor headers. This is the path for a project that uses the MCUXpresso SDK directly.

## What els_pkc is

`els_pkc` is NXP's CLNS (Crypto Library NXP Secure) middleware. It ships as an MCUXpresso SDK component under `components/els_pkc/` and is also published at <https://github.com/NXP/els_pkc>. The Zephyr module it carries is an add-on; the SDK component is the primary form.

wolfSSL never builds or vendors CLNS. The port calls into it and the application links it, exactly as the SE050 port does. Take either route:

- build `els_pkc/src/comps` as part of your project, or
- link the prebuilt `els_pkc/static_library/rw61x/libclns.a`.

**Licensing.** els_pkc is distributed under NXP's proprietary `LA_OPT_Online Code Hosting` license, not an open source license. Clause 3.7 forbids subjecting it to a license that would require source disclosure. Fetching it at build time is fine and is what both this setup and the Zephyr module do; copying it into a wolfSSL tree is not.

## MCUXpresso IDE setup

1. Create a project for your RW612 board (for example `frdm_rw612`).
2. In the SDK component selector, add **els_pkc**. That brings in `src/comps`, the `rw61x` platform layer, and the bundled CMSIS.
3. Add the wolfSSL sources to the project. `wolfcrypt/src/port/nxp/els_pkc_port.c` is compiled like every other wolfCrypt port and gates itself on `WOLFSSL_ELS_PKC`, so it costs nothing when the port is off.
4. Copy `user_settings.h` from this directory into your project and define `WOLFSSL_USER_SETTINGS` for the build.
5. Add these include paths, all inside the els_pkc component: `src/inc`, `src/compiler`, `src/comps/*/inc`, `src/comps/*/inc/internal`, `src/platforms/rw61x`, `src/platforms/rw61x/inc`, `src/platforms/rw61x/cmsis_cortex_m_5_5_1/inc`, `includes/platform/rw61x`.

### Compiler flags that matter

| Flag | Why |
| --- | --- |
| `-mcpu=cortex-m33+nodsp` | Without `+nodsp` the vendor CMSIS `core_cm33.h` aborts the build with "Compiler generates DSP (SIMD) instructions for a device without DSP extensions". `-D__DSP_PRESENT=1` does **not** work around it. |
| `-DCPU_RW612ETA2I` | `fsl_device_registers.h` selects the register map from the part number. Use the macro matching your part; only the A2 parts appear in its selector. |
| `-mcmse` | Matches how NXP builds CLNS. |
| `-DNO_THREAD_LS` | Required on bare metal. See below. |

### wolfCrypt_Init() returning -1000

`wolfCrypt_Init()` guards against recursive entry with a `__thread` variable whenever the toolchain advertises thread-local storage. On bare metal nothing sets the thread pointer, so that read returns garbage, the guard fires, and the call returns `DEADLOCK_AVERTED_E` (-1000) before initialising anything. Define `NO_THREAD_LS` unless your runtime really does set up TLS.

## Building with autoconf instead

The same result from a source tarball or checkout, which is also what CI compiles:

```sh
./autogen.sh
./configure --host=arm-none-eabi --disable-shared --enable-static \
    --enable-cryptonly --enable-cryptocb \
    --enable-cryptocbutils=keystore \
    --enable-ecc --enable-aesgcm --enable-cmac --enable-curve25519 --enable-rsa \
    --with-els-pkc=/path/to/els_pkc \
    --with-mcux-sdk=/path/to/mcux-sdk-ng \
    --disable-filesystem --enable-singlethreaded \
    CFLAGS="-mcpu=cortex-m33+nodsp -mthumb -Os --specs=nosys.specs" \
    CPPFLAGS="-DWOLFSSL_NO_SOCK -DWOLFSSL_USER_IO -DNO_WRITEV -DNO_DEV_RANDOM -DNO_THREAD_LS"
make
```

`--with-mcux-sdk` wants a tree holding `devices/Wireless/RW/RW612` and `drivers/common`: your MCUXpresso SDK install, or a checkout of NXP's `mcux-sdk-ng`. The els_pkc platform layer includes `fsl_common.h`, `fsl_device_registers.h` and `fsl_ocotp.h` from it.

The resulting `libwolfssl.a` carries unresolved `mcuxCl*` references. That is correct: the application links CLNS.

To confirm the port really made it into the archive, check for its symbols rather than for the object file. The port compiles to an empty translation unit when `WOLFSSL_ELS_PKC` is missing, so a build can succeed with the port silently absent:

```sh
arm-none-eabi-nm src/.libs/libwolfssl.a | grep wc_ElsPkc
```

## Using it

`wolfCrypt_Init()` brings the port up and registers its crypto callback, so there is nothing to call by hand, and `wc_CryptoCb_DefaultDevID()` answers `WOLFSSL_ELS_PKC_DEVID`, so a context created without an explicit device is offloaded too:

```c
#include <wolfssl/wolfcrypt/port/nxp/els_pkc_port.h>

wolfCrypt_Init();

wc_Sha256 sha;
wc_InitSha256(&sha);                                  /* offloaded */
wc_InitSha256_ex(&sha, NULL, WOLFSSL_ELS_PKC_DEVID);  /* the same, explicitly */
wc_InitSha256_ex(&sha, NULL, INVALID_DEVID);          /* kept in software */
```

Define `WC_NO_DEFAULT_DEVID` to switch the automatic routing off and require every context to name the device. Note it only reaches code that asks `wc_CryptoCb_DefaultDevID()` for a device: `wc_AesInit()` takes a `devId` argument directly, so pass `WOLFSSL_ELS_PKC_DEVID` there yourself.

Anything the hardware does not serve is *declined* with `CRYPTOCB_UNAVAILABLE` and completed in software, so an unsupported algorithm or key size is a performance question, never a failure.

A hardware *failure* is treated differently on purpose: the port reports the error rather than quietly finishing in software, because a caller that ignores the return would otherwise receive a confident bad result. Declining and failing are not the same thing.

`wolfCrypt_Cleanup()` unregisters the callback and releases the lock; `wc_ElsPkc_Init()` re-registers it if you need the port back afterwards.

Keys resident in the ELS key store are referenced rather than exported: build a reference with `wc_ElsPkc_MakeKeyRef()` and attach it with `wc_ecc_init_id()` or `wc_AesInit_Id()`. See the port header for the key store operations and the reference format.
