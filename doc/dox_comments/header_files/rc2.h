/*!
    \file wolfssl/wolfcrypt/rc2.h
*/

/*!
    \ingroup RC2

    \brief This function sets the initialization vector (IV) in an Rc2
    structure for use with RC2-CBC mode. If the supplied iv pointer is NULL
    the internal IV register is cleared to zero. The IV is RC2_BLOCK_SIZE
    octets long. The RC2 key must have already been set with wc_Rc2SetKey
    before performing CBC encryption/decryption operations.

    \return 0 on success.
    \return BAD_FUNC_ARG if rc2 is NULL.

    \param rc2 pointer to the Rc2 structure on which to set the IV.
    \param iv pointer to a buffer holding the IV. Must be RC2_BLOCK_SIZE
    bytes. If NULL, the IV register is zeroed.

    _Example_
    \code
    Rc2 rc2;
    byte key[]    = { initialize with key };
    byte iv[RC2_BLOCK_SIZE] = { initialize with IV };

    if (wc_Rc2SetKey(&rc2, key, sizeof(key), NULL, 8 * sizeof(key)) != 0) {
        // error setting key
    }
    if (wc_Rc2SetIV(&rc2, iv) != 0) {
        // error setting IV
    }
    \endcode

    \sa wc_Rc2SetKey
    \sa wc_Rc2CbcEncrypt
    \sa wc_Rc2CbcDecrypt
*/
int wc_Rc2SetIV(Rc2* rc2, const byte* iv);

/*!
    \ingroup RC2

    \brief This function frees an Rc2 structure. It releases any resources
    that may have been allocated and zeroizes sensitive data held by the
    structure. It should be called when the Rc2 structure is no longer
    needed.

    \return none No return value.

    \param rc2 pointer to the Rc2 structure to free.

    _Example_
    \code
    Rc2 rc2;
    byte key[] = { initialize with key };
    wc_Rc2SetKey(&rc2, key, sizeof(key), NULL, 8 * sizeof(key));
    // use rc2 for encryption / decryption
    wc_Rc2Free(&rc2);
    \endcode

    \sa wc_Rc2SetKey
    \sa wc_Rc2SetIV
*/
void wc_Rc2Free(Rc2* rc2);
