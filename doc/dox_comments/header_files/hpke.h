/*!
    \file wolfssl/wolfcrypt/hpke.h
*/

/*!
    \ingroup HPKE

    \brief This function initializes an Hpke context with the desired KEM,
    KDF, and AEAD ciphersuite identifiers as specified by Hybrid Public Key
    Encryption (HPKE), RFC 9180. The supplied KEM, KDF, and AEAD identifiers
    are validated against the implementations available in this build, the
    associated parameter sizes (Nh, Nk, Nn, Nt, Ndh, Npk, Nsecret) are
    populated, and the KEM and HPKE suite IDs are constructed for later use
    by the seal/open routines. The provided heap hint is stored in the
    context for use by subsequent allocations.

    \return 0 on success.
    \return BAD_FUNC_ARG if hpke is NULL or any of kem, kdf, or aead is 0
    or unsupported.

    \param hpke pointer to the Hpke structure to initialize.
    \param kem the KEM identifier (e.g. DHKEM_P256_HKDF_SHA256,
    DHKEM_X25519_HKDF_SHA256).
    \param kdf the KDF identifier (e.g. HKDF_SHA256, HKDF_SHA512).
    \param aead the AEAD identifier (e.g. HPKE_AES_128_GCM,
    HPKE_AES_256_GCM).
    \param heap pointer to a heap hint used for memory allocations
    (may be NULL).

    _Example_
    \code
    Hpke hpke;
    int ret = wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL);
    if (ret != 0) {
        // failed to initialize Hpke
    }
    \endcode

    \sa wc_HpkeGenerateKeyPair
    \sa wc_HpkeSealBase
    \sa wc_HpkeOpenBase
*/
int wc_HpkeInit(Hpke* hpke, int kem, int kdf, int aead, void* heap);

/*!
    \ingroup HPKE

    \brief This function generates an ephemeral key pair for use with the
    KEM previously configured in the Hpke structure (RFC 9180). The newly
    allocated key pair is returned through keypair and must later be
    released with wc_HpkeFreeKey. The supplied random number generator
    must already be initialized.

    \return 0 on success.
    \return BAD_FUNC_ARG if hpke, keypair, or rng is NULL.
    \return MEMORY_E on allocation failure.
    \return other negative error codes on key generation failure.

    \param hpke pointer to an initialized Hpke structure.
    \param keypair output pointer that receives the address of the newly
    allocated key pair (type depends on the configured KEM, e.g.
    ecc_key* or curve25519_key*).
    \param rng pointer to an initialized WC_RNG used to generate the key.

    _Example_
    \code
    Hpke hpke;
    WC_RNG rng;
    void* ephemeralKey = NULL;

    wc_InitRng(&rng);
    wc_HpkeInit(&hpke, DHKEM_X25519_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL);

    if (wc_HpkeGenerateKeyPair(&hpke, &ephemeralKey, &rng) != 0) {
        // key generation failed
    }
    // ... use ephemeralKey ...
    wc_HpkeFreeKey(&hpke, hpke.kem, ephemeralKey, NULL);
    \endcode

    \sa wc_HpkeInit
    \sa wc_HpkeFreeKey
    \sa wc_HpkeSerializePublicKey
*/
int wc_HpkeGenerateKeyPair(Hpke* hpke, void** keypair, WC_RNG* rng);
