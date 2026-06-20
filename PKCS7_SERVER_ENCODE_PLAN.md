# Implementation plan: PKCS#7 server-side encode helpers for wolfSSL

This is the concrete wolfSSL-repo implementation plan derived from the
wolfCert agent's request. It covers the three additive/relaxing changes that
let a downstream EST/SCEP enrollment library drop its hand-rolled ASN.1 and
call wolfSSL instead.

Branch: `claude/pkcs7-server-encode-plan-mid2qu`
(parallel and conflict-light with the ML-DSA decode branch).

All work is gated under the existing `HAVE_PKCS7`; no new build options.

---

## Codebase findings (what already exists vs. what's missing)

Before the per-item plans, the relevant facts established by reading the code:

1. **A degenerate (certs-only) encode path already exists.** `PKCS7_EncodeSigned()`
   (`wolfcrypt/src/pkcs7.c:3018`) fully handles `pkcs7->sidType == DEGENERATE_SID`:
   - no SignerInfo emitted (`pkcs7.c:3216`, `3583`),
   - empty `signerInfos` SET (`signerInfoSetSz = SetSet(0,...)`),
   - empty `digestAlgorithms` SET (`singleDigAlgoIdSz` stays 0 → `digAlgoIdSet` is an empty SET, `pkcs7.c:3333-3337`),
   - `version` INTEGER 1 (`pkcs7.c:3343-3345`),
   - certificates `[0] IMPLICIT` emitted from `pkcs7->certList` (`pkcs7.c:3319-3331`, `3524-3537`).
   - `wc_PKCS7_SetSignerIdentifierType()` already accepts `DEGENERATE_SID` (`pkcs7.c:9528`).
   - The two-pass size probe already works through this path (`pkcs7.c:3414-3440`).

   **Gap:** `PKCS7_EncodeSigned()` rejects `pkcs7->hashOID == 0` unconditionally
   at `pkcs7.c:3057`, even though `hashOID` is unused in the degenerate case.
   And there is no clearly-named entry point, so consumers don't discover this.

2. **`MAX_SIGNED_ATTRIBS_SZ` has a latent buffer bug.** The macro defaults to 7
   (`pkcs7.h:66-68`) and the bound check uses it (`pkcs7.c:2332`), **but the
   backing array is hardcoded** `EncodedAttrib signedAttribs[7];` at
   `pkcs7.c:1621` — it does *not* reference the macro. Bumping the macro alone
   would let the bound check pass while writing past a 7-element array
   (stack/heap overflow). The auth/unauth equivalents are correct
   (`authAttribs[MAX_AUTH_ATTRIBS_SZ]` at `pkcs7.c:14166`), so this is a
   `signedAttribs`-only inconsistency.

3. **Decoded-attribute value shape is already the preferred one.**
   `wc_PKCS7_ParseAttribs()` (`pkcs7.c:5417`) does `GetSet(...)` which strips the
   outer `SET` (`0x31`) tag, then copies the **contents inside the SET** into
   `attrib->value` with `attrib->valueSz` = SET-contents length
   (`pkcs7.c:5457-5478`). For a single-valued attribute that is
   `<value-tag><len><content>` (e.g. `0x13 ...` / `0x04 ...`), with the SET
   removed. This already matches the plan's *preferred* convention ("raw
   `SET OF AttributeValue` contents"). The work is to **lock it in** with
   documentation + a regression test, and optionally add a typed accessor.
   `wc_PKCS7_GetAttributeValue()` (`pkcs7.c:1510`) already copies this value out.

Net effect: the request is smaller than it looks. Items 1 and 3 are mostly
"expose + document + test" rather than new ASN.1; Item 2 is a 2-line fix plus
the overflow correction.

---

## Item 1 — Certs-only (degenerate) SignedData encoder  ★ highest value

### Approach
Add a thin, clearly-named convenience wrapper that drives the existing
`DEGENERATE_SID` path, and relax the single `hashOID` precondition so the
degenerate case does not require a hash algorithm.

### Changes

**`wolfcrypt/src/pkcs7.c`**
1. Relax the precondition at `pkcs7.c:3057`:
   ```c
   if (pkcs7 == NULL ||
       (pkcs7->hashOID == 0 && pkcs7->sidType != DEGENERATE_SID) ||
       outputSz == NULL) {
   ```
   Rationale: `hashOID` is never read on the degenerate path (all uses are
   guarded by `sidType != DEGENERATE_SID`). No behavior change for signers.

2. Add new public function (place near `wc_PKCS7_EncodeSignedData`, ~`pkcs7.c:3905`):
   ```c
   /* Encode a certs-only (degenerate) SignedData around the certificate(s)
    * already loaded via wc_PKCS7_InitWithCert()/wc_PKCS7_AddCertificate().
    * No signer, no signed attributes, no eContent.
    * If output == NULL (or outputSz == 0) returns the required size. */
   int wc_PKCS7_EncodeCertsOnlySignedData(wc_PKCS7* pkcs7,
                                          byte* output, word32 outputSz)
   ```
   Implementation:
   - `if (pkcs7 == NULL || pkcs7->certList == NULL) return BAD_FUNC_ARG;`
     (require ≥1 certificate).
   - Save prior `sidType`, `detached`, `contentOID`, `contentSz`, `content`.
   - Force the degenerate, no-content shape:
     - `pkcs7->sidType  = DEGENERATE_SID;`
     - `pkcs7->detached = 1;` (suppresses the `[0] eContent`, so
       `encapContentInfo` is just `{ eContentType }` — matches the target and
       the consumer's current bytes).
     - `pkcs7->contentOID = DATA;` (→ `eContentType` = id-data) if unset.
     - `pkcs7->content = NULL; pkcs7->contentSz = 0;`
   - `ret = wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz);`
   - Restore the saved fields (so the call is non-destructive to caller state).
   - Return `ret`.

   Note: `wc_PKCS7_EncodeSignedData` already pre-validates `content==NULL`
   only when `contentSz>0`, so the `contentSz=0` path is accepted
   (`pkcs7.c:3851`). The size-probe (`output==NULL`/`outputSz==0`) propagates
   through unchanged.

**`wolfssl/wolfcrypt/pkcs7.h`**
3. Add the prototype next to the other SignedData encoders (~`pkcs7.h:432`):
   ```c
   WOLFSSL_API int wc_PKCS7_EncodeCertsOnlySignedData(wc_PKCS7* pkcs7,
                                                      byte* output,
                                                      word32 outputSz);
   ```
   with a doc comment describing the emitted structure and the size-probe
   convention.

### Resulting DER (verified against the target)
```
SEQUENCE {                              -- ContentInfo
  OID signedData (1.2.840.113549.1.7.2)
  [0] EXPLICIT SEQUENCE {               -- SignedData
    INTEGER 1                           -- version
    SET {}                              -- digestAlgorithms (empty)
    SEQUENCE { OID id-data }            -- encapContentInfo, no eContent
    [0] IMPLICIT <cert DERs...>         -- certificates, input order
    SET {}                              -- signerInfos (empty)
  }
}
```

### Tests (`wolfcrypt/test/test.c`, `pkcs7signed_test`)
- Encode certs-only with **1 cert**; assert `ret > 0`.
- Encode with **3 certs** (e.g. client + intermediate + CA already available in
  the test cert set); assert all three round-trip via
  `wc_PKCS7_VerifySignedData()` → `pkcs7->cert[0..2]`/`certSz[]` repopulated in
  input order.
- **Size probe**: call with `output==NULL`/`outputSz==0`, get `needed`, alloc
  `needed`, re-encode into the buffer, assert returned length `<= needed` and
  re-verify.
- Honor the heap hint: construct via `wc_PKCS7_New(HEAP_HINT, devId)` like the
  surrounding tests so static-memory builds are covered.
- (Manual/CI-doc, not a unit assert) interop note: output also parses with
  `openssl pkcs7 -inform DER -print_certs` and `openssl cms -inform DER -cmsout`.

---

## Item 2 — Raise / relax `MAX_SIGNED_ATTRIBS_SZ`

### Approach
Take the plan's option (2) (raise the default) **plus** fix the latent overflow
by making the backing array track the macro. This is the minimal, low-risk
change; the fully-dynamic option (1) is noted as a follow-up but is more
invasive given `ESD` is one large struct allocated as a unit.

### Changes

**`wolfssl/wolfcrypt/pkcs7.h`** (`pkcs7.h:66-68`)
```c
/* Max number of signed attributes (user-supplied + up to 3 CMS auto-defaults:
 * contentType, messageDigest, signingTime). Override with -DMAX_SIGNED_ATTRIBS_SZ.
 * Default raised to 12 to accommodate profiles such as SCEP CertRep
 * (RFC 8894) which carry up to 6 user attributes alongside the auto-defaults. */
#ifndef MAX_SIGNED_ATTRIBS_SZ
    #define MAX_SIGNED_ATTRIBS_SZ 12
#endif
```

**`wolfcrypt/src/pkcs7.c`** (`pkcs7.c:1621`)
```c
EncodedAttrib signedAttribs[MAX_SIGNED_ATTRIBS_SZ];   /* was [7] */
```
This is the required correctness fix: the existing bound check at
`pkcs7.c:2332` (`MAX_SIGNED_ATTRIBS_SZ - atrIdx`) already accounts for the
auto-default count via `atrIdx`, but only the array-size fix prevents an
overflow once the macro grows.

No other call sites change; existing callers under the old cap are unaffected.

### Tests (`wolfcrypt/test/test.c`)
- Extend the signed-attributes coverage with a case supplying **6 user signed
  attributes**; with the 3 auto-defaults that is 9 total. Assert
  `wc_PKCS7_EncodeSignedData()` succeeds (previously `BUFFER_E`) and the result
  verifies via `wc_PKCS7_VerifySignedData()`.
- Keep an existing small-attrib case to prove no regression under the cap.

---

## Item 3 — Stabilize & document `PKCS7DecodedAttrib.value` shape

### Approach
The current decode output is already the plan's preferred shape (raw
`SET OF AttributeValue` *contents*, outer `SET` tag stripped). So: (a) make the
guarantee explicit in the header, (b) add a regression test pinning the shape
for two value types, and (c) optionally add a typed accessor that returns the
first `AttributeValue` (tag+len+content) without a copy, which is what the
consumer actually wants.

### Changes

**`wolfssl/wolfcrypt/pkcs7.h`** (`pkcs7.h:178-184`)
Document the contract next to `PKCS7DecodedAttrib`:
```c
/* Decoded signed/unsigned attribute.
 *   oid/oidSz   : the attribute OID (tag+len+content as parsed by GetObjectId).
 *   value/valueSz: the *contents of the SET OF AttributeValue* — i.e. the bytes
 *                  inside the attribute's SET, with the outer SET (0x31) tag and
 *                  length removed. For a single-valued attribute this is one
 *                  AttributeValue as <tag><len><content> (e.g. 0x13 PrintableString,
 *                  0x04 OCTET STRING). This shape is stable and guaranteed. */
```

**(Optional, recommended) `wolfcrypt/src/pkcs7.c` + `pkcs7.h`** — typed accessor:
```c
/* Locate a decoded signed attribute by OID; on success set *out/*outSz to point
 * at the first AttributeValue (tag+len+content) inside the SET, no copy.
 * Returns 0 on success, ASN_PARSE_E if absent, BAD_FUNC_ARG on bad args. */
int wc_PKCS7_GetSignedAttribValue(wc_PKCS7* pkcs7, const byte* oid,
                                  word32 oidSz, const byte** out, word32* outSz);
```
Implementation reuses `findAttrib()` (`pkcs7.c:1455`); since `value` is already
the SET contents, the first AttributeValue is just `attrib->value` parsed for
its own tag+len (validate the inner TLV stays within `valueSz`). This is a
non-copy convenience layer over the documented shape, distinct from the
existing copy-out `wc_PKCS7_GetAttributeValue()`.

### Tests (`wolfcrypt/test/test.c`)
- Build/decode a SignedData carrying signed attributes whose values are a
  **PrintableString (0x13)** and an **OCTET STRING (0x04)**.
- Assert `attrib->value[0]` is the value tag (not `0x31`) and that
  `valueSz`/content match — pinning the shape so a future change is caught.
- If the accessor is added, assert it returns the same pointer/len.

### Changelog note
Because downstream parsers depend on this, add a one-line note (e.g.
`ChangeLog.md`) stating the decoded-attribute `value` shape is now documented
and guaranteed (no behavior change vs. current release — it documents existing
behavior).

---

## PR shape & ordering

Three small, independent, additive/relaxing PRs (preferred over one):
1. **Item 1** (certs-only encoder) — biggest value, self-contained.
2. **Item 2** (attrib cap + array-size fix) — small; the array fix is a latent
   bug fix worth calling out in the PR description.
3. **Item 3** (decoded-attrib documentation + test, optional accessor) — isolate
   it and note it documents (does not change) current behavior.

All three touch different functions in `pkcs7.c`, so they should merge
conflict-light with the ML-DSA decode branch.

## Acceptance bar
- Item 1 output round-trips through `wc_PKCS7_VerifySignedData` and OpenSSL
  `pkcs7 -print_certs` / `cms -cmsout`.
- Item 2: 6 user + 3 default signed attributes encode and verify; no regression
  under the cap.
- Item 3: PrintableString and OCTET STRING attribute values decode to the
  documented, stable shape; regression test asserts it.
- `./configure --enable-pkcs7` build + `./wolfcrypt/test/testwolfcrypt` (or
  `make check`) pass.
