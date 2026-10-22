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
 */
int wc_Pkcs11_CryptoDevCb(int devId, wc_CryptoInfo* info,
    void* ctx);
