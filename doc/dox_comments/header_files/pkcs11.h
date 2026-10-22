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

    \brief Sets up a token by slot id or name. A user PIN is copied into
    memory the token owns. Call wc_Pkcs11Token_Final before initializing the
    same token again, so that the copy is zeroized and freed.
*/
int wc_Pkcs11Token_Init(Pkcs11Token* token, Pkcs11Dev* dev,
    int slotId, const char* tokenName, const unsigned char *userPin,
    int userPinSz);

/*!
    \ingroup PKCS11

    \brief Sets up a token by name. A user PIN is copied as by
    wc_Pkcs11Token_Init.
*/
int wc_Pkcs11Token_InitName(Pkcs11Token* token, Pkcs11Dev* dev,
    const char* tokenName, int tokenNameSz,
    const unsigned char* userPin, int userPinSz);

/*!
    \ingroup PKCS11
*/
void wc_Pkcs11Token_Final(Pkcs11Token* token);

/*!
    \ingroup PKCS11

    \brief Opens a session on the token that is used for all operations until
    wc_Pkcs11Token_Close.

    Once this session is logged in, by its own login with the user PIN or
    because another token already logged the application in, the token's
    copy of the PIN is zeroized and freed, as the login lasts while the
    session is open. A later session then needs wc_Pkcs11Token_Final and a
    new init with the PIN. Calling this again while the session is open
    does nothing and keeps the session's read/write mode. Open the session
    before the token is used from other threads.

    \return 0 on success.
    \return BAD_FUNC_ARG when token is NULL.
    \return BAD_STATE_E when the PIN was discarded by an earlier open.
    \return WC_HW_E when opening the session or logging in fails. A session
    whose login failed is closed again.

    \param token Token object.
    \param readWrite Open a read/write session when non-zero.

    \sa wc_Pkcs11Token_Close
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
 */
int wc_Pkcs11_CryptoDevCb(int devId, wc_CryptoInfo* info,
    void* ctx);
