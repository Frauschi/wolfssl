/*!
    \file wolfssl/wolfcrypt/dilithium.h
*/

/*!
    \ingroup Dilithium

    \brief Returns the private key size in bytes for the configured ML-DSA
    (FIPS 204) / Dilithium parameter set on the key. The size depends on the
    security level previously selected on the key (ML-DSA-44, ML-DSA-65 or
    ML-DSA-87).

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or the parameter set / security level
    has not been configured on the key.

    \param [in]  key  Pointer to an initialized MlDsaKey.
    \param [out] len  On success, receives the private key size in bytes.

    _Example_
    \code
    MlDsaKey key;
    int privLen = 0;
    int ret;

    wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    wc_MlDsaKey_SetParams(&key, WC_ML_DSA_44);
    ret = wc_MlDsaKey_GetPrivLen(&key, &privLen);
    if (ret == 0) {
        // privLen now holds the private key size for ML-DSA-44
    }
    \endcode

    \sa wc_MlDsaKey_GetPubLen
    \sa wc_MlDsaKey_GetSigLen
*/
int wc_MlDsaKey_GetPrivLen(MlDsaKey* key, int* len);

/*!
    \ingroup Dilithium

    \brief Returns the public key size in bytes for the configured ML-DSA
    (FIPS 204) / Dilithium parameter set on the key. The size depends on the
    security level previously selected on the key (ML-DSA-44, ML-DSA-65 or
    ML-DSA-87).

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or the parameter set / security level
    has not been configured on the key.

    \param [in]  key  Pointer to an initialized MlDsaKey.
    \param [out] len  On success, receives the public key size in bytes.

    _Example_
    \code
    MlDsaKey key;
    int pubLen = 0;
    int ret;

    wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65);
    ret = wc_MlDsaKey_GetPubLen(&key, &pubLen);
    if (ret == 0) {
        // pubLen now holds the public key size for ML-DSA-65
    }
    \endcode

    \sa wc_MlDsaKey_GetPrivLen
    \sa wc_MlDsaKey_GetSigLen
*/
int wc_MlDsaKey_GetPubLen(MlDsaKey* key, int* len);

/*!
    \ingroup Dilithium

    \brief Returns the signature size in bytes for the configured ML-DSA
    (FIPS 204) / Dilithium parameter set on the key. Use this to size the
    output buffer before calling the ML-DSA sign operation.

    \return 0 on success.
    \return BAD_FUNC_ARG if key is NULL or the parameter set / security level
    has not been configured on the key.

    \param [in]  key  Pointer to an initialized MlDsaKey.
    \param [out] len  On success, receives the signature size in bytes.

    _Example_
    \code
    MlDsaKey key;
    int sigLen = 0;
    int ret;

    wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID);
    wc_MlDsaKey_SetParams(&key, WC_ML_DSA_87);
    ret = wc_MlDsaKey_GetSigLen(&key, &sigLen);
    if (ret == 0) {
        // allocate a signature buffer of sigLen bytes
    }
    \endcode

    \sa wc_MlDsaKey_GetPrivLen
    \sa wc_MlDsaKey_GetPubLen
*/
int wc_MlDsaKey_GetSigLen(MlDsaKey* key, int* len);
