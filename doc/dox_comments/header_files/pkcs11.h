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
 */
int wc_Pkcs11_CryptoDevCb(int devId, wc_CryptoInfo* info,
    void* ctx);
