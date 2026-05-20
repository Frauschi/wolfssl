/*!
    \file wolfssl/wolfcrypt/wc_mlkem.h
*/

/*!
    \ingroup ML_KEM

    \brief Allocates and initializes a new ML-KEM (FIPS 203) key object on
    the heap and configures it for the requested parameter set. The returned
    pointer must later be released with wc_MlKemKey_Delete(). This is the
    constructor-style counterpart to wc_MlKemKey_Init() for callers that
    prefer dynamic allocation.

    \return Pointer to the new MlKemKey on success.
    \return NULL on allocation failure, or when type is not supported
    in this build.

    \param [in] type  Key type. One of WC_ML_KEM_512, WC_ML_KEM_768,
    WC_ML_KEM_1024 (or the legacy KYBER512/KYBER768/KYBER1024 aliases).
    \param [in] heap  Pointer to heap hint for dynamic memory allocation.
    May be NULL.
    \param [in] devId Device identifier for hardware crypto callbacks. Use
    INVALID_DEVID for software-only.

    _Example_
    \code
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_768, NULL, INVALID_DEVID);
    if (key == NULL) {
        // allocation or unsupported type
    }
    // ... use key ...
    wc_MlKemKey_Delete(key, &key);
    \endcode

    \sa wc_MlKemKey_Init
    \sa wc_MlKemKey_Delete
    \sa wc_MlKemKey_Free
*/
MlKemKey* wc_MlKemKey_New(int type, void* heap, int devId);

/*!
    \ingroup ML_KEM

    \brief Frees the resources held by an ML-KEM key object that was
    allocated with wc_MlKemKey_New() and releases the key object itself.
    If key_p is non-NULL the caller's pointer is set to NULL to help avoid
    use-after-free.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in]     key    MlKemKey to delete (previously returned by
    wc_MlKemKey_New()).
    \param [in,out] key_p  Optional caller-held pointer to key. When non-NULL,
    set to NULL on success.

    _Example_
    \code
    MlKemKey* key = wc_MlKemKey_New(WC_ML_KEM_768, NULL, INVALID_DEVID);
    // ... use key ...
    wc_MlKemKey_Delete(key, &key);
    // key is now NULL
    \endcode

    \sa wc_MlKemKey_New
    \sa wc_MlKemKey_Free
*/
int wc_MlKemKey_Delete(MlKemKey* key, MlKemKey** key_p);

/*!
    \ingroup ML_KEM

    \brief Releases the resources held by a caller-allocated ML-KEM key
    object without freeing the key object itself. Use this for keys
    initialized with wc_MlKemKey_Init(); for keys allocated with
    wc_MlKemKey_New() use wc_MlKemKey_Delete() instead.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL.

    \param [in,out] key  MlKemKey to release.

    _Example_
    \code
    MlKemKey key;
    wc_MlKemKey_Init(&key, WC_ML_KEM_512, NULL, INVALID_DEVID);
    // ... use key ...
    wc_MlKemKey_Free(&key);
    \endcode

    \sa wc_MlKemKey_Init
    \sa wc_MlKemKey_Delete
*/
int wc_MlKemKey_Free(MlKemKey* key);

/*!
    \ingroup ML_KEM

    \brief Generates an ML-KEM (FIPS 203) key pair from random material
    obtained via the supplied RNG. The key must have been configured with
    a parameter set via wc_MlKemKey_Init() or wc_MlKemKey_New() first.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or rng is NULL.
    \return NOT_COMPILED_IN if the key's parameter set is not built in.
    \return Other negative error codes from the RNG or KEM internals.

    \param [in,out] key  Initialized MlKemKey to populate.
    \param [in]     rng  Pointer to an initialized WC_RNG.

    _Example_
    \code
    MlKemKey key;
    WC_RNG   rng;
    int ret;

    wc_InitRng(&rng);
    wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    ret = wc_MlKemKey_MakeKey(&key, &rng);
    if (ret != 0) {
        // key generation failed
    }
    wc_MlKemKey_Free(&key);
    wc_FreeRng(&rng);
    \endcode

    \sa wc_MlKemKey_Init
    \sa wc_MlKemKey_Free
*/
int wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng);

/*!
    \ingroup ML_KEM

    \brief Returns the size in bytes of the ciphertext produced by ML-KEM
    encapsulation for the key's parameter set. Use this to size the
    ciphertext buffer before calling the ML-KEM encapsulation/decapsulation
    operations.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.
    \return NOT_COMPILED_IN if the key's parameter set is not built in.

    \param [in]  key  Initialized MlKemKey.
    \param [out] len  On success, receives the ciphertext size in bytes.

    _Example_
    \code
    MlKemKey key;
    word32 ctSz = 0;

    wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    wc_MlKemKey_CipherTextSize(&key, &ctSz);
    // allocate a ciphertext buffer of ctSz bytes
    \endcode

    \sa wc_MlKemKey_SharedSecretSize
    \sa wc_MlKemKey_PublicKeySize
    \sa wc_MlKemKey_PrivateKeySize
*/
int wc_MlKemKey_CipherTextSize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief Returns the size in bytes of the shared secret produced by ML-KEM
    encapsulation or decapsulation. The size is fixed at WC_ML_KEM_SS_SZ
    (32 bytes) regardless of parameter set, but the function form is
    provided for API symmetry.

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.

    \param [in]  key  ML-KEM key (not inspected beyond NULL check).
    \param [out] len  On success, receives the shared secret size in bytes.

    _Example_
    \code
    MlKemKey key;
    word32 ssSz = 0;

    wc_MlKemKey_Init(&key, WC_ML_KEM_512, NULL, INVALID_DEVID);
    wc_MlKemKey_SharedSecretSize(&key, &ssSz);
    // ssSz == 32
    \endcode

    \sa wc_MlKemKey_CipherTextSize
*/
int wc_MlKemKey_SharedSecretSize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief Returns the size in bytes of an ML-KEM private (decapsulation)
    key for the key's parameter set. Use this to size the buffer passed to
    wc_MlKemKey_EncodePrivateKey().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.
    \return NOT_COMPILED_IN if the key's parameter set is not built in.

    \param [in]  key  Initialized MlKemKey.
    \param [out] len  On success, receives the private key size in bytes.

    _Example_
    \code
    MlKemKey key;
    word32 privSz = 0;

    wc_MlKemKey_Init(&key, WC_ML_KEM_1024, NULL, INVALID_DEVID);
    wc_MlKemKey_PrivateKeySize(&key, &privSz);
    \endcode

    \sa wc_MlKemKey_PublicKeySize
    \sa wc_MlKemKey_CipherTextSize
*/
int wc_MlKemKey_PrivateKeySize(MlKemKey* key, word32* len);

/*!
    \ingroup ML_KEM

    \brief Returns the size in bytes of an ML-KEM public (encapsulation)
    key for the key's parameter set. Use this to size the buffer passed to
    wc_MlKemKey_EncodePublicKey().

    \return 0 on success.
    \return BAD_FUNC_ARG if key or len is NULL.
    \return NOT_COMPILED_IN if the key's parameter set is not built in.

    \param [in]  key  Initialized MlKemKey.
    \param [out] len  On success, receives the public key size in bytes.

    _Example_
    \code
    MlKemKey key;
    word32 pubSz = 0;

    wc_MlKemKey_Init(&key, WC_ML_KEM_768, NULL, INVALID_DEVID);
    wc_MlKemKey_PublicKeySize(&key, &pubSz);
    \endcode

    \sa wc_MlKemKey_PrivateKeySize
    \sa wc_MlKemKey_CipherTextSize
*/
int wc_MlKemKey_PublicKeySize(MlKemKey* key, word32* len);
