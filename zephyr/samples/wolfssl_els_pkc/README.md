# wolfCrypt EdgeLock (ELS + PKC) port checks

End to end checks for `wolfcrypt/src/port/nxp/els_pkc_port.c` on real NXP
RW612 silicon. Every check runs an operation through the crypto callback on
`WOLFSSL_ELS_PKC_DEVID` and compares it against the same operation with the
callback bypassed.

## Why this needs hardware

The ELS is reached only through NXP's CLNS library, which drives a register
interface no emulator implements, so there is no software platform this can
run on. `IDE/m33mu-rw612-port` covers the parts of the port that never touch
the hardware; this covers the offload itself.

## Running it

```sh
west build -p always -b frdm_rw612 -d build-els \
    modules/crypto/wolfssl/zephyr/samples/wolfssl_els_pkc
west flash -d build-els -r jlink
```

The console is the on-board MCU-Link virtual COM port at 115200 8N1.
`--reset-after-load` runs the image at flash time, so attach the terminal and
reset the part again if the banner has already gone by.

## What it covers

SHA-256, SHA-384 and SHA-512 against the FIPS 180-4 vectors and against the
software path, at lengths that straddle each digest's padding boundaries and
split across updates; the Copy handler that TLS 1.3 transcript snapshots
depend on; AES-ECB/CBC/CTR and AES-GCM; CMAC; the DRBG; ECDSA and ECDH across
the curves the ELS and the PKC each serve; RSA; X25519; and the key store
operations, including a DUK-rooted wrap and unwrap round trip and the refusal
to export a key that was not created exportable.

Agreement with software proves correctness but not offload: a declined
operation agrees too. So the suite also asserts that the engine counters
moved, and that completions arrived by interrupt rather than by the polling
fallback.

The run ends with `=== ALL PASS (0 failures) ===`, which is what the Twister
harness matches on.
