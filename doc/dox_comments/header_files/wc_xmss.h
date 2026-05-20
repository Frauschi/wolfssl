/*!
    \file wolfssl/wolfcrypt/wc_xmss.h
*/

/*!
    \ingroup XMSS

    \brief Initializes an XMSS / XMSS^MT key object. Must be called before
    setting parameters or performing any other XMSS operation. Use
    wc_XmssKey_Free() to release resources when done.

    XMSS (eXtended Merkle Signature Scheme) and the multi-tree variant
    XMSS^MT are stateful hash-based signature schemes standardized in
    RFC 8391 and approved by NIST SP 800-208. After initialization the
    key is in the INITED state, ready for parameter selection via
    wc_XmssKey_SetParamStr().

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key   XmssKey to initialize.
    \param [in]     heap  Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in]     devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    XmssKey key;
    int ret;

    ret = wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    // ... configure params, generate or reload key, sign/verify ...
    wc_XmssKey_Free(&key);
    \endcode

    \sa wc_XmssKey_Free
    \sa wc_XmssKey_SetParamStr
    \sa wc_XmssKey_MakeKey
*/
int  wc_XmssKey_Init(XmssKey* key, void* heap, int devId);

/*!
    \ingroup XMSS

    \brief Configures an initialized XMSS / XMSS^MT key with the parameter
    set named by str. The string must match one of the supported names
    listed in wc_xmss.h, for example "XMSS-SHA2_10_256" or
    "XMSSMT-SHA2_20/4_256". The key must be in the INITED state.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or str is NULL, or the string is not
    recognized.
    \return BAD_STATE_E if the key is not in the INITED state.
    \return NOT_COMPILED_IN if the named parameter set is not built in.

    \param [in,out] key  XmssKey previously initialized with
    wc_XmssKey_Init().
    \param [in]     str  XMSS / XMSS^MT parameter set name string.

    _Example_
    \code
    XmssKey key;
    int ret;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    if (ret != 0) {
        // error setting parameters
    }
    \endcode

    \sa wc_XmssKey_GetParamStr
    \sa wc_XmssKey_MakeKey
*/
int  wc_XmssKey_SetParamStr(XmssKey* key, const char* str);

/*!
    \ingroup XMSS

    \brief Returns the parameter set name string corresponding to the OID
    currently configured on the key. The string is a pointer into a static
    table and remains valid for the lifetime of the program. The key must
    already have its parameter set configured.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or str is NULL.
    \return BAD_STATE_E if the key's parameter set is not configured.
    \return NOT_COMPILED_IN if the configured OID is not in the supported
    tables.

    \param [in]  key  XmssKey with parameters set.
    \param [out] str  On success, set to the parameter set name string.

    _Example_
    \code
    XmssKey key;
    const char* name = NULL;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    if (wc_XmssKey_GetParamStr(&key, &name) == 0) {
        printf("XMSS params: %s\n", name);
    }
    \endcode

    \sa wc_XmssKey_SetParamStr
*/
int  wc_XmssKey_GetParamStr(const XmssKey* key, const char** str);

/*!
    \ingroup XMSS

    \brief Stores a caller-supplied opaque context pointer on the XMSS key.
    The context is forwarded unchanged to the read and write private-key
    callbacks; a typical use is to pass a filename or file handle for
    persistence. The context may be NULL when read/write callbacks are
    stubs (for example because a device owns the private state).

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.
    \return BAD_STATE_E if the key is already in use.

    \param [in,out] key      XmssKey to update.
    \param [in]     context  Caller-defined context pointer. May be NULL.

    _Example_
    \code
    XmssKey key;
    const char* path = "xmss_priv.bin";

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_SetContext(&key, (void*)path);
    \endcode

    \sa wc_XmssKey_MakeKey
    \sa wc_XmssKey_Reload
*/
int  wc_XmssKey_SetContext(XmssKey* key, void* context);

/*!
    \ingroup XMSS

    \brief Generates a new XMSS / XMSS^MT private/public key pair using
    the supplied RNG. The key must already have its parameter set
    configured (via wc_XmssKey_SetParamStr()) and a write private-key
    callback plus context configured so the freshly generated private
    state can be persisted before any signatures are issued — XMSS is
    stateful and state loss leads to catastrophic key reuse.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL, or if the write callback
    has not been set.
    \return BAD_STATE_E if the key state is not ready for generation.
    \return IO_FAILED_E if persisting the private key via the write
    callback fails.
    \return MEMORY_E on allocation failure.

    \param [in,out] key  XmssKey with parameters and callbacks configured.
    \param [in]     rng  Pointer to an initialized WC_RNG.

    _Example_
    \code
    XmssKey key;
    WC_RNG rng;
    int ret;

    wc_InitRng(&rng);
    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_SetWriteCb(&key, my_write_cb);
    wc_XmssKey_SetReadCb(&key, my_read_cb);
    wc_XmssKey_SetContext(&key, my_ctx);
    ret = wc_XmssKey_MakeKey(&key, &rng);
    \endcode

    \sa wc_XmssKey_Reload
    \sa wc_XmssKey_SetContext
    \sa wc_XmssKey_SigsLeft
*/
int  wc_XmssKey_MakeKey(XmssKey* key, WC_RNG* rng);

/*!
    \ingroup XMSS

    \brief Loads private-key state from persistent storage (via the
    previously configured read callback) so signing can resume with an
    existing XMSS / XMSS^MT key. The key must already have its parameter
    set configured and read/write callbacks plus context configured. Use
    this instead of wc_XmssKey_MakeKey() when continuing to use a key
    generated in an earlier session.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or callbacks are not set.
    \return BAD_STATE_E if the key state is not ready for reload.
    \return IO_FAILED_E if reading the private key via the read callback
    fails.
    \return MEMORY_E on allocation failure.

    \param [in,out] key  XmssKey with parameters and callbacks configured.

    _Example_
    \code
    XmssKey key;
    int ret;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_SetReadCb(&key, my_read_cb);
    wc_XmssKey_SetWriteCb(&key, my_write_cb);
    wc_XmssKey_SetContext(&key, my_ctx);
    ret = wc_XmssKey_Reload(&key);
    \endcode

    \sa wc_XmssKey_MakeKey
    \sa wc_XmssKey_SetContext
*/
int  wc_XmssKey_Reload(XmssKey* key);

/*!
    \ingroup XMSS

    \brief Returns the length in bytes of the persisted XMSS / XMSS^MT
    private key for the configured parameter set. The parameter set must
    already be configured on the key. Use this to size buffers used by
    the read/write private-key callbacks.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or parameters not set.

    \param [in]  key  XmssKey with parameters configured.
    \param [out] len  On success, receives the private key length in bytes.

    _Example_
    \code
    XmssKey key;
    word32 privLen = 0;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_GetPrivLen(&key, &privLen);
    \endcode

    \sa wc_XmssKey_GetPubLen
    \sa wc_XmssKey_GetSigLen
*/
int  wc_XmssKey_GetPrivLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief Reports whether the XMSS / XMSS^MT key still has one-time
    signatures available. Because XMSS is stateful, each signature consumes
    part of a finite budget fixed by the parameter set; once exhausted the
    key must not be used again.

    \return 1 if at least one signature can still be produced.
    \return 0 if signatures are exhausted or key is NULL.

    \param [in] key  XmssKey to query.

    _Example_
    \code
    if (wc_XmssKey_SigsLeft(&key) == 0) {
        // do not sign — key is exhausted
    }
    \endcode

    \sa wc_XmssKey_MakeKey
*/
int  wc_XmssKey_SigsLeft(XmssKey* key);

/*!
    \ingroup XMSS

    \brief Releases all resources held by an XMSS / XMSS^MT key, scrubbing
    private-key material as appropriate. Safe to call on a key that was
    initialized but never further populated.

    \param [in,out] key  XmssKey to free. May be NULL.

    _Example_
    \code
    XmssKey key;
    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    // ... use key ...
    wc_XmssKey_Free(&key);
    \endcode

    \sa wc_XmssKey_Init
*/
void wc_XmssKey_Free(XmssKey* key);

/*!
    \ingroup XMSS

    \brief Returns the length in bytes of an XMSS / XMSS^MT signature for
    the key's configured parameter set. Use this to size the signature
    buffer before calling the signing operation.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or parameters not set.

    \param [in]  key  XmssKey with parameters configured.
    \param [out] len  On success, receives the signature length in bytes.

    _Example_
    \code
    XmssKey key;
    word32 sigLen = 0;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_GetSigLen(&key, &sigLen);
    // allocate a sigLen-byte signature buffer
    \endcode

    \sa wc_XmssKey_GetPubLen
    \sa wc_XmssKey_GetPrivLen
*/
int  wc_XmssKey_GetSigLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief Returns the length in bytes of the encoded XMSS / XMSS^MT
    public key for the key's configured parameter set. Use this to size
    buffers passed to wc_XmssKey_ExportPubRaw().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or parameters not set.

    \param [in]  key  XmssKey with parameters configured.
    \param [out] len  On success, receives the public key length in bytes.

    _Example_
    \code
    XmssKey key;
    word32 pubLen = 0;

    wc_XmssKey_Init(&key, NULL, INVALID_DEVID);
    wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_10_256");
    wc_XmssKey_GetPubLen(&key, &pubLen);
    \endcode

    \sa wc_XmssKey_GetPrivLen
    \sa wc_XmssKey_GetSigLen
*/
int  wc_XmssKey_GetPubLen(const XmssKey* key, word32* len);

/*!
    \ingroup XMSS

    \brief Copies the public key and parameter set from one XMSS key to
    another, producing a verify-only key suitable for distribution to
    verifiers. The destination key is fully initialized; it inherits the
    source key's heap hint and is given INVALID_DEVID. Use
    wc_XmssKey_ExportPub_ex() if explicit heap or devId values are
    required.

    \return 0 on success.
    \return BAD_FUNC_ARG if keyDst or keySrc is NULL.
    \return BAD_STATE_E if the source key is not in a state with a usable
    public key.

    \param [out] keyDst  XmssKey to populate.
    \param [in]  keySrc  XmssKey to copy the public key and parameters from.

    _Example_
    \code
    XmssKey signer, verifier;

    // signer is already generated/loaded
    wc_XmssKey_ExportPub(&verifier, &signer);
    // verifier can now be used with wc_XmssKey_Verify(...)
    \endcode

    \sa wc_XmssKey_ExportPubRaw
    \sa wc_XmssKey_ImportPubRaw
*/
int  wc_XmssKey_ExportPub(XmssKey* keyDst, const XmssKey* keySrc);
