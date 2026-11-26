# pkcs11dev: wolfCrypt tests through a PKCS#11 module

`pkcs11dev` runs `testwolfcrypt` and `unit.test` with their crypto routed
through a PKCS#11 module, to exercise the PKCS#11 client in
`wolfcrypt/src/wc_pkcs11.c` against a real token. It is test-only code and is
linked into the test programs, not the library.

At start-up the loader opens the module named by `WOLFSSL_PKCS11DEV_MODULE`,
re-initializes the token in its first slot, sets a user PIN and registers
`wc_Pkcs11_CryptoDevCb()`. A `WOLF_CRYPTO_CB_FIND` callback then sends every
operation that names no device to that token. Operations the token declines
fall back to software as usual.

## Running it with wolfPKCS11

1. Build a static wolfSSL for wolfPKCS11 and build wolfPKCS11 with
   `--with-static-wolfssl`, so the module carries its own wolfCrypt and
   exports only the `C_*` functions. `.github/workflows/pkcs11-wolfpkcs11.yml`
   has the full configure lines.
2. Build this tree with `--enable-pkcs11 --enable-pkcs11dev`.
3. Run the tests with a scratch token directory:

```sh
mkdir -p /tmp/token
export WOLFPKCS11_TOKEN_PATH=/tmp/token
export WOLFSSL_PKCS11DEV_MODULE=/path/to/libwolfpkcs11.so
./wolfcrypt/test/testwolfcrypt
./tests/unit.test
```

The token is wiped on every start, so do not point it at a token you need.
