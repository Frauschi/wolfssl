/*!
    \ingroup PKCS11
*/
int wc_Pkcs11_Initialize(Pkcs11Dev* dev, const char* library,
                                     void* heap);

/*!
    \ingroup PKCS11
*/
void wc_Pkcs11_Finalize(Pkcs11Dev* dev);

/*!
    \ingroup PKCS11
*/
int wc_Pkcs11Token_Init(Pkcs11Token* token, Pkcs11Dev* dev,
    int slotId, const char* tokenName, const unsigned char *userPin,
    int userPinSz);

/*!
    \ingroup PKCS11
*/
void wc_Pkcs11Token_Final(Pkcs11Token* token);

/*!
    \ingroup PKCS11
 */
int wc_Pkcs11Token_Open(Pkcs11Token* token, int readWrite);

/*!
    \ingroup PKCS11
 */
void wc_Pkcs11Token_Close(Pkcs11Token* token);

/*!
    \ingroup PKCS11

    \brief Makes the crypto callback generate RSA, ECC, ML-DSA and ML-KEM
    keys that have an id or label as token objects (CKA_TOKEN set).

    Use it for tokens that cannot make a session key persistent later with
    wc_Pkcs11PersistKey. The public key is kept as a token object too. Key
    generation fails with BAD_STATE_E when a token key of the type already
    has the id or label. A key without a name, such as a TLS ephemeral key,
    stays a session object, or is generated in software when no session
    from wc_Pkcs11Token_Open is open.

    The private key gets CKA_PRIVATE, so the session must be logged in, and
    a session from wc_Pkcs11Token_Open must be read/write. Without such a
    session a token key is later found by its id or label.

    \return 0 on success.
    \return BAD_FUNC_ARG when token is NULL.

    \param token Token used by the crypto callback.
    \param persistent Generate token objects when non-zero.

    \sa wc_Pkcs11PersistKey
    \sa wc_Pkcs11DeleteKey
*/
int wc_Pkcs11Token_SetKeyGenPersistent(Pkcs11Token* token, int persistent);

/*!
    \ingroup PKCS11
 */
int wc_Pkcs11StoreKey(Pkcs11Token* token, int type, int clear,
    void* key);

/*!
    \ingroup PKCS11

    \brief Stores a private key on the token like wc_Pkcs11StoreKey. With
    persistent set, the objects are created with CKA_TOKEN set and stay on
    the token after the session closes; this needs a read/write session and
    a logged in token. A persistent private or secret key also gets
    CKA_PRIVATE and CKA_SENSITIVE set and CKA_EXTRACTABLE cleared, and needs
    an id or label that no token key of the type has, or the call fails
    with BAD_FUNC_ARG or BAD_STATE_E.

    \return 0 on success.
    \return BAD_FUNC_ARG when token or key is NULL.
    \return NOT_COMPILED_IN when the key type or mechanism is not available.
    \return WC_HW_E when a PKCS#11 call fails.

    \param token Token to store the key on.
    \param type One of the PKCS11_KEY_TYPE_* values.
    \param clear Clear the private key data from the software key.
    \param key Key object of the type.
    \param persistent Store the key as token objects when non-zero.

    \sa wc_Pkcs11StoreKey
*/
int wc_Pkcs11StoreKey_ex(Pkcs11Token* token, int type, int clear,
    void* key, int persistent);

/*!
    \ingroup PKCS11

    \brief Makes a private or secret key that lives in a session object
    persistent. The session object, from key generation or
    wc_Pkcs11StoreKey, is copied with C_CopyObject to a token object with
    the key's id and label and then destroyed. For RSA, ECC, ML-DSA and
    ML-KEM keys that hold their public key, a token object with the public
    key replaces any session public key with the same names. RSA, ECC,
    ML-DSA and ML-KEM keys refer to the new private object through devCtx.
    Freeing the key does not remove token objects. The token session must
    be read/write and logged in, and stay open from key generation until
    this call.

    \return 0 on success.
    \return BAD_FUNC_ARG when token or key is NULL, the key has neither an
    id nor a label, or an Hmac has no hash type.
    \return BAD_STATE_E when the token already holds a key with the same id
    or label, or the key already refers to a token object.
    \return NOT_COMPILED_IN when the key type is not supported.
    \return WC_HW_E when no session object is found or a PKCS#11 call fails.

    \param token Token holding the key.
    \param type PKCS11_KEY_TYPE_RSA, PKCS11_KEY_TYPE_EC, PKCS11_KEY_TYPE_MLDSA,
    PKCS11_KEY_TYPE_MLKEM, PKCS11_KEY_TYPE_AES_GCM, PKCS11_KEY_TYPE_AES_CBC
    or PKCS11_KEY_TYPE_HMAC.
    \param key RsaKey, ecc_key, wc_MlDsaKey, MlKemKey, Aes or Hmac with an id
    or label. An Hmac needs its hash type (macType), as wc_HmacSetKey sets.

    _Example_
    \code
    ecc_key key;
    wc_ecc_init_id(&key, id, idLen, NULL, devId);
    wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
    // use the key, for example to sign a CSR, then keep it
    wc_Pkcs11PersistKey(&token, PKCS11_KEY_TYPE_EC, &key);
    \endcode

    \sa wc_Pkcs11StoreKey_ex
*/
int wc_Pkcs11PersistKey(Pkcs11Token* token, int type, void* key);

/*!
    \ingroup PKCS11

    \brief Removes a key from the token: every token object of the key type
    with the key's id and label is destroyed. The user must be logged in to
    see private objects. For RSA, ECC, ML-DSA and ML-KEM keys a session
    object in devCtx is destroyed as well and devCtx is cleared; when a
    PKCS#11 call fails part way, devCtx is kept only while its object still
    exists. An HMAC key is removed under its HMAC key type and as a generic
    secret. Finding nothing to remove is not an error. A token key with only
    the same id or only the same label is kept, and still keeps a new key
    from using that id or label.

    \return 0 on success.
    \return BAD_FUNC_ARG when token or key is NULL, the key has neither an
    id nor a label, or an Hmac has no hash type.
    \return BAD_STATE_E when the user is not logged in.
    \return NOT_COMPILED_IN when the key type is not supported.
    \return WC_HW_E when a PKCS#11 call fails.

    \param token Token holding the key.
    \param type PKCS11_KEY_TYPE_RSA, PKCS11_KEY_TYPE_EC, PKCS11_KEY_TYPE_MLDSA,
    PKCS11_KEY_TYPE_MLKEM, PKCS11_KEY_TYPE_AES_GCM, PKCS11_KEY_TYPE_AES_CBC
    or PKCS11_KEY_TYPE_HMAC.
    \param key RsaKey, ecc_key, wc_MlDsaKey, MlKemKey, Aes or Hmac with an id
    or label. An Hmac needs its hash type (macType), as wc_HmacSetKey sets.

    \sa wc_Pkcs11PersistKey
*/
int wc_Pkcs11DeleteKey(Pkcs11Token* token, int type, void* key);

/*!
    \ingroup PKCS11
 */
int wc_Pkcs11_CryptoDevCb(int devId, wc_CryptoInfo* info,
    void* ctx);
