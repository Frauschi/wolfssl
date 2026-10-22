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
