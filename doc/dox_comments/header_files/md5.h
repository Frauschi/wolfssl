/*!
    \ingroup MD5

    \brief This function initializes md5. This is automatically
    called by wc_Md5Hash.

    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned if the Md5 structure is passed
    as a NULL value.

    \param md5 pointer to the md5 structure to use for encryption

    _Example_
    \code
    Md5 md5;
    byte* hash;
    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Update Failure Case.
       }
       ret = wc_Md5Final(&md5, hash);
      if (ret != 0) {
    	// Md5 Final Failure Case.
      }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
int wc_InitMd5(wc_Md5* md5);

/*!
    \ingroup MD5

    \brief This function initializes an Md5 structure and accepts a heap
    hint and device identifier so the object can take advantage of crypto
    callbacks or async hardware. wc_InitMd5 is a convenience wrapper that
    calls wc_InitMd5_ex with a NULL heap and INVALID_DEVID.

    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned if the Md5 structure is passed as a
    NULL value.

    \param md5 pointer to the md5 structure to initialize
    \param heap heap hint to use for any dynamic allocations made by the
    object. May be NULL.
    \param devId device identifier used to associate the Md5 object with
    a crypto callback or async device. Use INVALID_DEVID (-2) when none.

    _Example_
    \code
    wc_Md5 md5;
    if (wc_InitMd5_ex(&md5, NULL, INVALID_DEVID) != 0) {
        // initialization failure
    }
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
    \sa wc_Md5Free
*/
int wc_InitMd5_ex(wc_Md5* md5, void* heap, int devId);

/*!
    \ingroup MD5

    \brief Can be called to continually hash the provided byte array of
    length len.

    \return 0 Returned upon successfully adding the data to the digest.
    \return BAD_FUNC_ARG Returned if the Md5 structure is NULL or if
    data is NULL and len is greater than zero. The function should
    not return an error if the data parameter is NULL and len is zero.

    \param md5 pointer to the md5 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed

    _Example_
    \code
    Md5 md5;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Update Error Case.
       }
       ret = wc_Md5Final(&md5, hash);
       if (ret != 0) {
    	// Md5 Final Error Case.
       }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int wc_Md5Update(wc_Md5* md5, const byte* data, word32 len);

/*!
    \ingroup MD5

    \brief Finalizes hashing of data. Result is placed into hash. Md5
    Struct is reset. Note: This function will also return the result
    of calling IntelQaSymMd5() in the case that HAVE_INTEL_QA is defined.

    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned if the Md5 structure or hash pointer
    is passed in NULL.

    \param md5 pointer to the md5 structure to use for encryption
    \param hash Byte array to hold hash value.

    _Example_
    \code
    md5 md5[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(md5, data, len);
       if (ret != 0) {
    	// Md5 Update Failure Case.
       }
      ret = wc_Md5Final(md5, hash);
       if (ret != 0) {
	    // Md5 Final Failure Case.
       }
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_InitMd5
    \sa wc_Md5GetHash
*/
int wc_Md5Final(wc_Md5* md5, byte* hash);

/*!
    \ingroup MD5

    \brief Resets the Md5 structure.  Note: this is only supported if
    you have WOLFSSL_TI_HASH defined.

    \return none No returns.

    \param md5 Pointer to the Md5 structure to be reset.

    _Example_
    \code
    Md5 md5;
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
        WOLFSSL_MSG("wc_InitMd5 failed");
    }
    else {
        wc_Md5Update(&md5, data, len);
        wc_Md5Final(&md5, hash);
        wc_Md5Free(&md5);
    }
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
void wc_Md5Free(wc_Md5* md5);

/*!
    \ingroup MD5

    \brief Gets hash data. Result is placed into hash.  Md5 struct
    is not reset.

    \return none No returns

    \param md5 pointer to the md5 structure to use for encryption.
    \param hash Byte array to hold hash value.

    _Example_
    \code
    md5 md5[1];
    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       wc_Md5Update(md5, data, len);
       wc_Md5GetHash(md5, hash);
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int  wc_Md5GetHash(wc_Md5* md5, byte* hash);

/*!
    \ingroup MD5

    \brief Copies the state of one Md5 hashing context into another so the
    second context can continue hashing independently from the source. This
    is useful when the same prefix needs to be hashed with several different
    suffixes.

    \return 0 Returned upon successfully copying the state.
    \return BAD_FUNC_ARG Returned if either src or dst is NULL.
    \return MEMORY_E Returned if memory allocation fails (when applicable).

    \param src pointer to the source Md5 structure to copy from
    \param dst pointer to the destination Md5 structure to copy into

    _Example_
    \code
    wc_Md5 md5, md5Copy;
    wc_InitMd5(&md5);
    wc_Md5Update(&md5, data, sizeof(data));
    if (wc_Md5Copy(&md5, &md5Copy) != 0) {
        // copy failed
    }
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
int  wc_Md5Copy(wc_Md5* src, wc_Md5* dst);

/*!
    \ingroup MD5

    \brief Sets the final hash length used by hardware-accelerated MD5
    implementations (for example, the PIC32MZ port). On platforms that do
    not require a pre-set length the call has no effect.

    \return none No returns.

    \param md5 pointer to the Md5 structure to update
    \param len length, in bytes, of the data that will be hashed

    _Example_
    \code
    wc_Md5 md5;
    wc_InitMd5(&md5);
    wc_Md5SizeSet(&md5, totalLen);
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
void wc_Md5SizeSet(wc_Md5* md5, word32 len);

/*!
    \ingroup MD5

    \brief Performs a single MD5 compression round on the provided 64-byte
    data block. This is primarily intended for internal use and for testing
    of the MD5 implementation.

    \return 0 Returned upon successfully transforming the data block.
    \return BAD_FUNC_ARG Returned if md5 or data is NULL.

    \param md5 pointer to the Md5 structure whose state will be updated
    \param data pointer to a 64-byte block to compress

    _Example_
    \code
    wc_Md5 md5;
    byte block[WC_MD5_BLOCK_SIZE];
    wc_InitMd5(&md5);
    if (wc_Md5Transform(&md5, block) != 0) {
        // transform failed
    }
    \endcode

    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
int wc_Md5Transform(wc_Md5* md5, const byte* data);

/*!
    \ingroup MD5

    \brief Sets implementation specific flags on an Md5 context. The set of
    valid flag values depends on the build configuration; this API is only
    available when wolfSSL is built with WOLFSSL_HASH_FLAGS or
    WOLF_CRYPTO_CB defined.

    \return 0 Returned upon successfully setting the flags.
    \return BAD_FUNC_ARG Returned if md5 is NULL.

    \param md5 pointer to the Md5 structure to modify
    \param flags bit-field of implementation specific flags to apply

    _Example_
    \code
    wc_Md5 md5;
    wc_InitMd5(&md5);
    wc_Md5SetFlags(&md5, WC_HASH_FLAG_WILLCOPY);
    \endcode

    \sa wc_Md5GetFlags
    \sa wc_InitMd5
*/
int wc_Md5SetFlags(wc_Md5* md5, word32 flags);

/*!
    \ingroup MD5

    \brief Retrieves the currently configured implementation specific flags
    on an Md5 context. This API is only available when wolfSSL is built
    with WOLFSSL_HASH_FLAGS or WOLF_CRYPTO_CB defined.

    \return 0 Returned upon successfully retrieving the flags.
    \return BAD_FUNC_ARG Returned if md5 or flags is NULL.

    \param md5 pointer to the Md5 structure to query
    \param flags pointer to a word32 that receives the current flag bits

    _Example_
    \code
    wc_Md5 md5;
    word32 flags = 0;
    wc_InitMd5(&md5);
    wc_Md5GetFlags(&md5, &flags);
    \endcode

    \sa wc_Md5SetFlags
    \sa wc_InitMd5
*/
int wc_Md5GetFlags(wc_Md5* md5, word32* flags);
