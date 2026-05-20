/*!
    \file wolfssl/wolfcrypt/wc_pkcs11.h
*/

/*!
    \ingroup PKCS11

    \brief Tears down a Pkcs11Dev previously initialized with
    wc_Pkcs11_Initialize() (or its \c _ex/\c _v3 variants). This calls
    the PKCS#11 \c C_Finalize entry of the underlying provider and
    releases any dynamic library handle held by the device. After this
    call the Pkcs11Dev structure must not be used unless reinitialized.
    This API is only available when wolfSSL is built with HAVE_PKCS11.

    \return none No return value.

    \param dev pointer to a Pkcs11Dev structure previously initialized
    with wc_Pkcs11_Initialize().

    _Example_
    \code
    Pkcs11Dev dev;
    if (wc_Pkcs11_Initialize(&dev, "/usr/lib/softhsm/libsofthsm2.so",
                             NULL) == 0) {
        // ... use the device ...
        wc_Pkcs11_Finalize(&dev);
    }
    \endcode

    \sa wc_Pkcs11_Initialize
    \sa wc_Pkcs11Token_Init
*/
void wc_Pkcs11_Finalize(Pkcs11Dev* dev);

/*!
    \ingroup PKCS11

    \brief Releases the resources held by a Pkcs11Token. Any open
    session is closed and the user PIN (if cached for login) is zeroed
    and freed. This is the counterpart to wc_Pkcs11Token_Init() /
    wc_Pkcs11Token_InitName() and must be called before the underlying
    Pkcs11Dev is finalized. This API is only available when wolfSSL is
    built with HAVE_PKCS11.

    \return none No return value.

    \param token pointer to the Pkcs11Token to finalize.

    _Example_
    \code
    Pkcs11Token token;
    wc_Pkcs11Token_Init(&token, &dev, slotId, "tokenName",
                        (const unsigned char*)"1234", 4);
    // ... use the token ...
    wc_Pkcs11Token_Final(&token);
    \endcode

    \sa wc_Pkcs11Token_Init
    \sa wc_Pkcs11Token_Open
    \sa wc_Pkcs11Token_Close
*/
void wc_Pkcs11Token_Final(Pkcs11Token* token);

/*!
    \ingroup PKCS11

    \brief Opens a PKCS#11 session against the slot associated with the
    supplied Pkcs11Token. If the token was initialized with a user PIN,
    the session is logged in as the normal user. The \c readWrite flag
    selects between a read-only and a read-write session. This API is
    only available when wolfSSL is built with HAVE_PKCS11.

    \return 0 on success.
    \return BAD_FUNC_ARG if \c token is NULL.
    \return WC_HW_E if the PKCS#11 provider returns an error while
    opening the session or performing login.

    \param token pointer to an initialized Pkcs11Token.
    \param readWrite non-zero to open a read-write session, zero for a
    read-only session.

    _Example_
    \code
    if (wc_Pkcs11Token_Open(&token, 1) != 0) {
        // failed to open a R/W session against the token
    }
    // ... perform operations ...
    wc_Pkcs11Token_Close(&token);
    \endcode

    \sa wc_Pkcs11Token_Close
    \sa wc_Pkcs11Token_Init
    \sa wc_Pkcs11Token_Final
*/
int wc_Pkcs11Token_Open(Pkcs11Token* token, int readWrite);

/*!
    \ingroup PKCS11

    \brief Closes a PKCS#11 session previously opened with
    wc_Pkcs11Token_Open(). If the session was logged in, this also
    performs a \c C_Logout before closing. Passing a token with no open
    session is safe. This API is only available when wolfSSL is built
    with HAVE_PKCS11.

    \return none No return value.

    \param token pointer to a Pkcs11Token with an open session.

    _Example_
    \code
    wc_Pkcs11Token_Open(&token, 1);
    // ... perform operations ...
    wc_Pkcs11Token_Close(&token);
    \endcode

    \sa wc_Pkcs11Token_Open
    \sa wc_Pkcs11Token_Final
*/
void wc_Pkcs11Token_Close(Pkcs11Token* token);
