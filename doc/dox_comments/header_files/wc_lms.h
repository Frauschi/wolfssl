/*!
    \file wolfssl/wolfcrypt/wc_lms.h
*/

/*!
    \ingroup LMS

    \brief Initializes an LMS / HSS key object. Must be called before
    setting parameters or performing any other LMS operation. Use
    wc_LmsKey_Free() to release resources when done.

    LMS (Leighton-Micali Signatures) and the multi-tree variant HSS are
    stateful hash-based signature schemes standardized in RFC 8554 and
    approved by NIST SP 800-208. After initialization the key is in the
    INITED state, ready for parameter selection via wc_LmsKey_SetLmsParm()
    or wc_LmsKey_SetParameters().

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key   LmsKey to initialize.
    \param [in]     heap  Heap hint for dynamic memory allocation. May be
    NULL.
    \param [in]     devId Device identifier for hardware crypto callbacks.
    Use INVALID_DEVID for software-only.

    _Example_
    \code
    LmsKey key;
    int ret;

    ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (ret != 0) {
        // error initializing key
    }
    // ... configure params, generate or reload key, sign/verify ...
    wc_LmsKey_Free(&key);
    \endcode

    \sa wc_LmsKey_Free
    \sa wc_LmsKey_SetLmsParm
    \sa wc_LmsKey_MakeKey
*/
int  wc_LmsKey_Init(LmsKey* key, void* heap, int devId);

/*!
    \ingroup LMS

    \brief Configures an initialized LMS key with one of the predefined
    parameter sets identified by the wc_LmsParm enumeration (for example
    WC_LMS_PARM_L2_H10_W8). The parameter set fixes the number of HSS
    tree levels, the height of each tree and the Winternitz width. The
    key must be in the INITED state.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL, or lmsParm is not supported.
    \return BAD_STATE_E if the key is not in the INITED state.

    \param [in,out] key      LmsKey previously initialized with
    wc_LmsKey_Init().
    \param [in]     lmsParm  Predefined LMS parameter set identifier.

    _Example_
    \code
    LmsKey key;
    int ret;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    ret = wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    if (ret != 0) {
        // error setting parameters
    }
    \endcode

    \sa wc_LmsKey_Init
    \sa wc_LmsKey_ParmToStr
    \sa wc_LmsKey_MakeKey
*/
int  wc_LmsKey_SetLmsParm(LmsKey* key, enum wc_LmsParm lmsParm);

/*!
    \ingroup LMS

    \brief Returns a human-readable string for the given LMS parameter set
    identifier (for example "L2_H10_W8"). Useful for logging and debug
    output. Returns NULL when the parameter set is not recognized.

    \return Non-NULL pointer to a static string on success.
    \return NULL when the parameter set is not supported.

    \param [in] lmsParm  LMS parameter set identifier.

    _Example_
    \code
    const char* name = wc_LmsKey_ParmToStr(WC_LMS_PARM_L2_H10_W8);
    if (name != NULL) {
        printf("LMS params: %s\n", name);
    }
    \endcode

    \sa wc_LmsKey_SetLmsParm
*/
const char* wc_LmsKey_ParmToStr(enum wc_LmsParm lmsParm);

/*!
    \ingroup LMS

    \brief Stores a caller-supplied opaque context pointer on the LMS key.
    The context is forwarded unchanged to the read and write private-key
    callbacks; a typical use is to pass a filename or file handle for
    persistence. The context may be NULL (for example when read/write
    callbacks are stubs because the device owns the private state).

    The key must not already be in the WC_LMS_STATE_OK (in-use) state.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.
    \return BAD_STATE_E if the key is already in use.

    \param [in,out] key      LmsKey to update.
    \param [in]     context  Caller-defined context pointer forwarded to
    the read/write callbacks. May be NULL.

    _Example_
    \code
    LmsKey key;
    const char* path = "lms_priv.bin";

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_SetContext(&key, (void*)path);
    \endcode

    \sa wc_LmsKey_MakeKey
    \sa wc_LmsKey_Reload
*/
int  wc_LmsKey_SetContext(LmsKey* key, void* context);

/*!
    \ingroup LMS

    \brief Generates a new LMS / HSS private/public key pair using the
    supplied RNG. The key must already have its parameter set selected
    (via wc_LmsKey_SetLmsParm() or wc_LmsKey_SetParameters()) and a write
    private-key callback plus context configured so the freshly generated
    private state can be persisted before any signatures are issued — LMS
    is stateful and state loss leads to catastrophic key reuse.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL, or if the write callback
    has not been set.
    \return BAD_STATE_E if the key state is not ready for generation, or
    if the freshly generated key has zero signatures remaining.
    \return IO_FAILED_E if persisting the private key via the write callback
    fails.
    \return MEMORY_E on allocation failure.

    \param [in,out] key  LmsKey with parameters and callbacks configured.
    \param [in]     rng  Pointer to an initialized WC_RNG.

    _Example_
    \code
    LmsKey key;
    WC_RNG rng;
    int ret;

    wc_InitRng(&rng);
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_SetWriteCb(&key, my_write_cb);
    wc_LmsKey_SetReadCb(&key, my_read_cb);
    wc_LmsKey_SetContext(&key, my_ctx);
    ret = wc_LmsKey_MakeKey(&key, &rng);
    \endcode

    \sa wc_LmsKey_Reload
    \sa wc_LmsKey_SetContext
    \sa wc_LmsKey_SigsLeft
*/
int  wc_LmsKey_MakeKey(LmsKey* key, WC_RNG* rng);

/*!
    \ingroup LMS

    \brief Loads private-key state from persistent storage (via the
    previously configured read callback) so signing can resume with an
    existing LMS / HSS key. The key must already have its parameter set
    selected and read/write callbacks plus context configured. Use this
    instead of wc_LmsKey_MakeKey() when continuing to use a key generated
    in an earlier session.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or callbacks are not set.
    \return BAD_STATE_E if the key state is not ready for reload or if
    no signatures remain.
    \return IO_FAILED_E if reading the private key via the read callback
    fails.
    \return MEMORY_E on allocation failure.

    \param [in,out] key  LmsKey with parameters and callbacks configured.

    _Example_
    \code
    LmsKey key;
    int ret;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_SetReadCb(&key, my_read_cb);
    wc_LmsKey_SetWriteCb(&key, my_write_cb);
    wc_LmsKey_SetContext(&key, my_ctx);
    ret = wc_LmsKey_Reload(&key);
    \endcode

    \sa wc_LmsKey_MakeKey
    \sa wc_LmsKey_SetContext
*/
int  wc_LmsKey_Reload(LmsKey* key);

/*!
    \ingroup LMS

    \brief Returns the length in bytes of the persisted LMS / HSS private
    key (the HSS_PRIVATE_KEY_LEN for the configured hash). The parameter
    set must already be configured on the key. Use this to size buffers
    used by the read/write private-key callbacks.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or if parameters have not
    been configured on the key.

    \param [in]  key  LmsKey with parameters configured.
    \param [out] len  On success, receives the private key length in bytes.

    _Example_
    \code
    LmsKey key;
    word32 privLen = 0;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_GetPrivLen(&key, &privLen);
    \endcode

    \sa wc_LmsKey_GetPubLen
    \sa wc_LmsKey_GetSigLen
*/
int  wc_LmsKey_GetPrivLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief Reports whether the LMS / HSS key still has one-time signatures
    available. Because LMS is stateful, each signature consumes part of a
    finite budget fixed by the parameter set; once exhausted the key must
    not be used again.

    \return 1 if at least one signature can still be produced.
    \return 0 if signatures are exhausted or key is NULL.

    \param [in] key  LmsKey to query.

    _Example_
    \code
    if (wc_LmsKey_SigsLeft(&key) == 0) {
        // do not sign — key is exhausted
    }
    \endcode

    \sa wc_LmsKey_MakeKey
*/
int  wc_LmsKey_SigsLeft(LmsKey* key);

/*!
    \ingroup LMS

    \brief Releases all resources held by an LMS / HSS key, scrubbing
    private-key material as appropriate. Safe to call on a key that was
    initialized but never further populated.

    \param [in,out] key  LmsKey to free. May be NULL.

    _Example_
    \code
    LmsKey key;
    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    // ... use key ...
    wc_LmsKey_Free(&key);
    \endcode

    \sa wc_LmsKey_Init
*/
void wc_LmsKey_Free(LmsKey* key);

/*!
    \ingroup LMS

    \brief Returns the length in bytes of an LMS / HSS signature for the
    key's configured parameter set. Use this to size the signature buffer
    before calling the signing operation.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or if parameters have not
    been configured on the key.

    \param [in]  key  LmsKey with parameters configured.
    \param [out] len  On success, receives the signature length in bytes.

    _Example_
    \code
    LmsKey key;
    word32 sigLen = 0;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_GetSigLen(&key, &sigLen);
    // allocate a sigLen-byte signature buffer
    \endcode

    \sa wc_LmsKey_GetPubLen
    \sa wc_LmsKey_GetPrivLen
*/
int  wc_LmsKey_GetSigLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief Returns the length in bytes of the encoded LMS / HSS public key
    for the key's configured parameter set. Use this to size buffers passed
    to wc_LmsKey_ExportPubRaw().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL, or if parameters have not
    been configured on the key.

    \param [in]  key  LmsKey with parameters configured.
    \param [out] len  On success, receives the public key length in bytes.

    _Example_
    \code
    LmsKey key;
    word32 pubLen = 0;

    wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    wc_LmsKey_SetLmsParm(&key, WC_LMS_PARM_L2_H10_W8);
    wc_LmsKey_GetPubLen(&key, &pubLen);
    \endcode

    \sa wc_LmsKey_GetPrivLen
    \sa wc_LmsKey_GetSigLen
*/
int  wc_LmsKey_GetPubLen(const LmsKey* key, word32* len);

/*!
    \ingroup LMS

    \brief Copies the public key and parameter set from one LMS key to
    another, producing a verify-only key suitable for distribution to
    verifiers. The destination key is fully initialized; it inherits the
    source key's heap hint and is given INVALID_DEVID. Use
    wc_LmsKey_ExportPub_ex() if explicit heap or devId values are required.

    \return 0 on success.
    \return BAD_FUNC_ARG if keyDst or keySrc is NULL.
    \return BAD_STATE_E if the source key is not in a state with a usable
    public key.

    \param [out] keyDst  LmsKey to populate.
    \param [in]  keySrc  LmsKey to copy the public key and parameters from.

    _Example_
    \code
    LmsKey signer, verifier;

    // signer is already generated/loaded
    wc_LmsKey_ExportPub(&verifier, &signer);
    // verifier can now be used with wc_LmsKey_Verify(...)
    \endcode

    \sa wc_LmsKey_ExportPubRaw
    \sa wc_LmsKey_ImportPubRaw
*/
int  wc_LmsKey_ExportPub(LmsKey* keyDst, const LmsKey* keySrc);
