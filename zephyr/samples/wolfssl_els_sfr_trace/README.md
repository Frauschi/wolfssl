# wolfssl_els_sfr_trace

Records every ELS register access the vendor library makes while three
operations run, so the sequence can be compared against another
implementation of the same interface.

It exists because the EdgeLock command numbering is not published: the device
header names the commands but assigns them no values, and the values live in
NXP headers that a reimplementation cannot use. Reading them off the hardware
instead is what this produces.

## What it does

Runs SHA-256, AES-128-CBC and AES-CMAC on the ELS, one after another, and
prints the register trace afterwards:

```
M sha256-abc
W ELS_DMA_SRC0 10055d98
W ELS_DMA_SRC0_LEN 00000040
W ELS_CMDCFG0 00000044
W ELS_CTRL 000001a3
...
```

`ELS_CTRL` bits 7:3 are the command, so `0x1a3` is command `0x14` with the
enable, start and byte-order bits set.

## How the interposition works

`src/els_sfr_trace.h` redefines the six macros in the vendor library's
`mcuxClEls_SfrAccess.h`, and `CMakeLists.txt` injects it with `-include` on the
`McuxElsPkc` target. No vendor file is edited.

`MCUXCLELS_SFR_READ` is deliberately left alone. The library takes its address
to walk the key store as an array, so it has to stay an lvalue naming the
register; wrapping it fails to compile. Register reads still appear through the
bit-field accessor.

Records are buffered in RAM and printed after the crypto has finished. Printing
as it goes would put a UART between the driver and the engine and change the
timing being measured.

## Running it

```sh
west build -p always -b frdm_rw612 -d build-sfrtrace \
    modules/crypto/wolfssl/zephyr/samples/wolfssl_els_sfr_trace
west flash -d build-sfrtrace -r jlink
```

Then capture the console across a reset. Addresses differ between builds, so
mask the four DMA descriptor registers before diffing two traces; the command
numbers, configuration words and lengths are the part that has to match.
