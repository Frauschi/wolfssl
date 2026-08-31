# m33mu-rw612-port

Bare-metal checks for the NXP EdgeLock port (`wolfcrypt/src/port/nxp/els_pkc_port.c`), run on an emulated RW612 under [m33mu](https://github.com/danielinux/m33mu).

## What this covers, and what it does not

**It does not run the EdgeLock offload.** m33mu emulates an ELS whose register map was invented for m33mu's own test firmware: a 4KB scratch buffer at `0x22040000` with offset registers, and commands for AES, SHA-256, HMAC and RNG. Real RW612 silicon uses DMA descriptors pointing into system memory (`ELS_DMA_SRC0..2`, `ELS_DMA_RES0`, `ELS_KIDX0..2`, `ELS_KPROPIN`), has a 20-slot key store, and puts the PKC RAM at `0x5015A000`, which m33mu does not map at all. Since this port reaches the ELS only through NXP's CLNS library, and CLNS drives the real interface, CLNS cannot run here.

So the offload paths stay hardware-validated on a frdm_rw612. What this firmware covers instead:

| Check | BKPT on failure |
| --- | --- |
| Key reference codec: round trip, size query, and rejection of a bad magic, an unknown version, an out-of-range slot, an unassigned class and a truncated blob | `0x71` |
| Wrapped-key container: round trip, a wrong KEK rejected, and byte-for-byte equivalence with a plain `wc_AesKeyWrap` of `props \|\| pad \|\| key` | `0x72` |
| The port fails closed: with the hardware failing, an operation on the port's devId returns an error rather than a wrong answer | `0x73` |
| Nothing ran behind our back: engine counters for algorithms never issued are still zero | `0x74` |
| The software path is undisturbed while the port is registered: SHA-256, CMAC and AES-GCM KATs on the default devId | `0x75` |

`0x7f` means everything passed; `0x70` means setup failed.

The first two are real tests of real code, and both are worth running on a target rather than a host: they are the parsers a malformed blob reaches first, and bare metal is where an alignment or endianness assumption shows up.

`els_stubs.c` supplies every CLNS symbol the port references, each returning a failure status. They are not a simulation and compute nothing; they exist so the firmware can link, and so the failure behaviour above can be tested at all. One stub deliberately succeeds - `ELS_PowerDownWakeupInit` - because `wc_ElsPkc_Init()` returns before registering the callback if bring-up fails, and then there would be no port to test.

## Building

Cross-build wolfSSL first, from the repository root:

```sh
./autogen.sh
./configure --host=arm-none-eabi --disable-shared --enable-static \
    --enable-cryptonly --enable-cryptocb \
    --enable-cryptocbutils=copy,free,keystore --enable-elspkckeyblob \
    --enable-ecc --enable-aesgcm --enable-cmac \
    --with-els-pkc=/path/to/els_pkc --with-mcux-sdk=/path/to/mcux-sdk-ng \
    --disable-filesystem --enable-singlethreaded \
    --disable-examples --disable-crypttests \
    CFLAGS="-mcpu=cortex-m33+nodsp -mthumb -Os -ffreestanding" \
    CPPFLAGS="-DWOLFSSL_NO_SOCK -DWOLFSSL_USER_IO -DNO_WRITEV -DNO_DEV_RANDOM -DNO_THREAD_LS"
make
```

Then here:

```sh
make ELS_PKC=/path/to/els_pkc MCUX_SDK=/path/to/mcux-sdk-ng
m33mu --cpu rw612 --expect-bkpt 0x7f --timeout 30 app.bin
```

`m33mu` exits 0 when the expected breakpoint is reached, 1 when execution ends without it, and 127 on timeout.

## Two things that will bite

**`-DNO_THREAD_LS` is required on bare metal.** `wolfCrypt_Init()` guards against recursion with a `__thread` variable when the toolchain reports thread-local storage. Bare-metal startup never sets the thread pointer, so that read returns garbage, the guard fires, and `wolfCrypt_Init()` returns `DEADLOCK_AVERTED_E` (-1000) before doing anything. It looks like a wolfSSL fault and is not one.

**The application must use the library's `wolfssl/options.h`, not a `user_settings.h` of its own.** This Makefile passes `-DWOLFSSL_USE_OPTIONS_H` for that reason. A mismatch in feature defines changes struct layouts and corrupts memory at run time instead of failing to compile.

## If a check fails

`--gdb-symbols app.elf` plus `--call-trace` shows the call that returned the error, and `arm-none-eabi-addr2line -f -e app.elf <pc>` resolves the reported PC. The BKPT immediate narrows it to one group first.
