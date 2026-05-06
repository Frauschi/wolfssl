# Dilithium → ML-DSA migration guide

## Background

The post-quantum signature algorithm originally implemented in wolfSSL
under the pre-standardization name *Dilithium* was standardized by NIST
as **ML-DSA (Module-Lattice-based Digital Signature Algorithm) — FIPS
204** in 2024. This release renames the wolfSSL implementation of that
algorithm to its standardized name, mirroring the earlier Kyber → ML-KEM
migration in `wc_mlkem.{h,c}`.

For application code written against the legacy `dilithium_key` /
`wc_dilithium_*` / `wc_Dilithium_*` API there is **no immediate change
required**: a temporary compatibility shim translates the legacy names
into the canonical ones at compile time. The shim will be removed in a
future release; new code should adopt the canonical names directly.

## What changed

### File renames

| Old path                              | New path                                |
|---------------------------------------|-----------------------------------------|
| `wolfcrypt/src/dilithium.c`           | `wolfcrypt/src/wc_mldsa.c`              |
| `wolfssl/wolfcrypt/dilithium.h`       | `wolfssl/wolfcrypt/wc_mldsa.h`          |

The legacy `<wolfssl/wolfcrypt/dilithium.h>` path is now a thin shim
that `#include`s `wc_mldsa.h` and provides macro / inline aliases for
the legacy API.

### Symbol renames

| Old                                       | New                                          |
|-------------------------------------------|----------------------------------------------|
| `dilithium_key`                           | `MlDsaKey`                                   |
| `wc_dilithium_params`                     | `MlDsaParams`                                |
| `wc_dilithium_*` (lifecycle / sizing)     | `wc_MlDsaKey_*`                              |
| `wc_Dilithium_*` (DER encode / decode)    | `wc_MlDsaKey_*`                              |
| internal lower-case `dilithium_*` helpers | `mldsa_*`                                    |

The 16 sign / verify / import / DER-decode entry points were also
re-ordered to put the `MlDsaKey*` first (matching the FIPS 204 / ML-KEM
convention used by `wc_MlKemKey_*`). The legacy parameter order is
preserved through static-inline wrapper functions in the shim header,
so legacy call sites compile unchanged.

`wc_MlDsaKey_Init` is a 3-argument function (`MlDsaKey*`, `void* heap`,
`int devId`) matching `wc_MlKemKey_Init`. The legacy 1-argument
`wc_dilithium_init(key)` is mapped through the shim to
`wc_MlDsaKey_Init(key, NULL, INVALID_DEVID)`.

### Build-gate renames

| Old                            | New                          |
|--------------------------------|------------------------------|
| `HAVE_DILITHIUM`               | `WOLFSSL_HAVE_MLDSA`         |
| `WOLFSSL_DILITHIUM_*` (~25)    | `WOLFSSL_MLDSA_*`            |
| `WC_DILITHIUM_CACHE_*`         | `WC_MLDSA_CACHE_*`           |
| `WC_DILITHIUM_FIXED_ARRAY`     | `WC_MLDSA_FIXED_ARRAY`       |
| `WC_DILITHIUMKEY_TYPE_DEFINED` | `WC_MLDSAKEY_TYPE_DEFINED`   |

The Autotools / CMake configure switches gain canonical aliases:

| Legacy                  | Canonical             |
|-------------------------|-----------------------|
| `--enable-dilithium`    | `--enable-mldsa`      |
| `WOLFSSL_DILITHIUM`     | `WOLFSSL_MLDSA`       |

Both spellings remain valid; the canonical form is recommended for new
projects.

The configure summary echoes `ML-DSA: yes` rather than `DILITHIUM: yes`.

### OpenSSL compatibility

The OpenSSL-compat enum value `WC_EVP_PKEY_DILITHIUM` and macro
`EVP_PKEY_DILITHIUM` are unchanged in this release. Aligning them with
OpenSSL 3.5+'s actual `NID_ML_DSA_*` values is planned for a follow-up
commit.

## How to migrate (when you are ready)

The temporary shim accepts both legacy and canonical names indefinitely
until it is removed. To migrate a consumer to canonical:

1. Replace `#include <wolfssl/wolfcrypt/dilithium.h>` with
   `#include <wolfssl/wolfcrypt/wc_mldsa.h>`.
2. Replace `dilithium_key` with `MlDsaKey`.
3. Replace each `wc_dilithium_*` / `wc_Dilithium_*` call with the
   `wc_MlDsaKey_*` form, swapping arguments to put the key first
   for the 16 affected entry points.
4. Replace `HAVE_DILITHIUM` / `WOLFSSL_DILITHIUM_*` / `WC_DILITHIUM_*`
   build-gate references with the canonical names.

Migration can be done file by file; the two spellings interoperate at
the link level (the shim's static-inline wrappers call into the
canonical exported symbols).

To suppress the legacy aliases (e.g. to surface stale references during
migration), define one or both of:

- `WOLFSSL_NO_DILITHIUM_LEGACY_NAMES` — suppresses the legacy
  `dilithium_key` / `wc_dilithium_*` / `wc_Dilithium_*` macro / inline
  aliases.
- `WOLFSSL_NO_DILITHIUM_LEGACY_GATES` — suppresses the bidirectional
  sub-config gate translations (legacy `WOLFSSL_DILITHIUM_*` /
  `WC_DILITHIUM_*` ↔ canonical `WOLFSSL_MLDSA_*` / `WC_MLDSA_*`). The
  parent gate (`HAVE_DILITHIUM` ↔ `WOLFSSL_HAVE_MLDSA`) forward arm is
  always active so that builds using only the legacy parent name still
  compile the canonical implementation file; the reverse arm honors
  this opt-out.

> **Note on `WOLFSSL_NO_DILITHIUM_LEGACY_NAMES`:** in this release the
> opt-out is only useful for builds whose consumer code (TLS, ASN.1,
> EVP, tests, benchmark, examples, ...) has already been migrated to
> the canonical names. The standard wolfSSL distribution still uses
> `wc_dilithium_*` and `dilithium_key` in `wolfcrypt/src/asn.c`,
> `src/ssl_load.c`, `src/internal.c`, `wolfcrypt/test/test.c`, and
> elsewhere; suppressing the macro / inline aliases breaks those
> translation units (e.g. `wc_dilithium_verify_ctx_msg` becomes an
> implicit declaration). The flag is intended primarily for downstream
> projects that have completed their own migration; in-tree consumers
> will be migrated in a follow-up PR.

## Internal infrastructure files migrated to canonical sub-gates

Two wolfSSL-internal files had their `WOLFSSL_DILITHIUM_NO_SIGN` /
`WOLFSSL_DILITHIUM_NO_VERIFY` / `WOLFSSL_DILITHIUM_*_SMALL_MEM` /
`WOLFSSL_DILITHIUM_VERIFY_ONLY` sub-gate references migrated to their
canonical `WOLFSSL_MLDSA_*` spellings:

- `wolfssl/wolfcrypt/memory.h` — read by `<types.h>` (which is included
  before any TU has a chance to pull in `dilithium.h`), so the
  bidirectional shim cannot reach it. Reads 4 sub-gates for
  `LARGEST_MEM_BUCKET` sizing.
- `wolfssl/certs_test.h` — auto-generated cert-data buffers, has zero
  `#include` directives. Reachable from external TUs (examples,
  embedded apps) that pull in only `<wolfssl/ssl.h>` and do not
  transitively include `dilithium.h`. Reads 11 sub-gate references
  (`_NO_SIGN` / `_NO_VERIFY`).

Both files now read the canonical names directly so `--enable-mldsa`-
configure-driven builds (which emit `-DWOLFSSL_MLDSA_*`) reach them
without a translation step. The corresponding generator script
(`gencertbuf.pl`) was updated correspondingly.

Both files are wolfSSL-internal infrastructure (the allocator and an
auto-generated cert-buffer data file), not consumer-facing API; this
migration does not require downstream code changes.

## ABI note

The library's exported linkage symbols are renamed: the `.so` /
`.dylib` / `.dll` now exports `wc_MlDsaKey_*` instead of
`wc_dilithium_*`. Applications that linked dynamically against the
legacy symbol names need to either recompile against the legacy header
path (the shim's static-inline wrappers resolve to the new symbols at
compile time) or switch their sources to the canonical names. Source
code that includes `<wolfssl/wolfcrypt/dilithium.h>` continues to build
without modification.
