/*!
    \ingroup wolfCrypt

    \brief This function maps an ASN.1 hash OID value to its corresponding
    wc_HashType enumeration value. It is the inverse of wc_HashGetOID.

    \return wc_HashType A value from the wc_HashType enumeration on success.
    \return WC_HASH_TYPE_NONE if the OID is not recognized.

    \param oid The ASN.1 OID sum value identifying a hash algorithm
    (e.g. SHA256h, SHA384h).

    _Example_
    \code
    enum wc_HashType ht = wc_OidGetHash(SHA256h);
    if (ht != WC_HASH_TYPE_NONE) {
        // Found matching hash type
    }
    \endcode

    \sa wc_HashGetOID
    \sa wc_HashTypeConvert
*/
enum wc_HashType wc_OidGetHash(int oid);

/*!
    \ingroup wolfCrypt

    \brief This function converts an integer hash identifier (such as the
    legacy WC_SHA, WC_SHA256, etc.) into the corresponding wc_HashType
    enumeration value. It is most useful for code that needs to bridge older
    hash identifiers with the modern wc_HashType-based wrapper API.

    \return wc_HashType A value from the wc_HashType enumeration on success.
    \return WC_HASH_TYPE_NONE if hashType is not a recognized value.

    \param hashType Integer hash identifier to convert.

    _Example_
    \code
    enum wc_HashType ht = wc_HashTypeConvert(WC_SHA256);
    if (ht != WC_HASH_TYPE_NONE) {
        // use ht with wc_Hash, wc_HashInit, etc.
    }
    \endcode

    \sa wc_HashGetOID
    \sa wc_OidGetHash
*/
enum wc_HashType wc_HashTypeConvert(int hashType);

/*!
    \ingroup wolfCrypt

    \brief This function will return the OID for the wc_HashType provided.

    \return OID returns value greater than 0
    \return HASH_TYPE_E hash type not supported.
    \return BAD_FUNC_ARG one of the provided arguments is incorrect.

    \param hash_type A hash type from the “enum  wc_HashType” such
    as “WC_HASH_TYPE_SHA256”.

    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int oid = wc_HashGetOID(hash_type);
    if (oid > 0) {
    	// Success
    }
    \endcode

    \sa wc_HashGetDigestSize
    \sa wc_Hash
*/
int wc_HashGetOID(enum wc_HashType hash_type);

/*!
    \ingroup wolfCrypt

    \brief This function returns the size of the digest (output) for a
    hash_type. The returns size is used to make sure the output buffer
    provided to wc_Hash is large enough.

    \return Success A positive return value indicates the digest size
    for the hash.
    \return Error Returns HASH_TYPE_E if hash_type is not supported.
    \return Failure Returns BAD_FUNC_ARG if an invalid hash_type was used.

    \param hash_type A hash type from the “enum  wc_HashType” such as
    “WC_HASH_TYPE_SHA256”.

    _Example_
    \code
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len <= 0) {
    WOLFSSL_MSG("Invalid hash type/len");
    return BAD_FUNC_ARG;
    }
    \endcode

    \sa wc_Hash
*/
int wc_HashGetDigestSize(enum wc_HashType hash_type);

/*!
    \ingroup wolfCrypt

    \brief This function performs a hash on the provided data buffer
    and returns it in the hash buffer provided.

    \return 0 Success, else error (such as BAD_FUNC_ARG or BUFFER_E).

    \param hash_type A hash type from the “enum  wc_HashType”
    such as “WC_HASH_TYPE_SHA256”.
    \param data Pointer to buffer containing the data to hash.
    \param data_len Length of the data buffer.
    \param hash Pointer to buffer used to output the final hash to.
    \param hash_len Length of the hash buffer.

    _Example_
    \code
    enum wc_HashType hash_type = WC_HASH_TYPE_SHA256;
    int hash_len = wc_HashGetDigestSize(hash_type);
    if (hash_len > 0) {
        int ret = wc_Hash(hash_type, data, data_len, hash_data, hash_len);
        if(ret == 0) {
		    // Success
        }
    }
    \endcode

    \sa wc_HashGetDigestSize
*/
int wc_Hash(enum wc_HashType hash_type,
    const byte* data, word32 data_len,
    byte* hash, word32 hash_len);

/*!
    \ingroup wolfCrypt

    \brief This function returns the block size, in bytes, of the underlying
    hash algorithm identified by hash_type. The block size is the input
    block length used by the compression function (e.g. 64 bytes for SHA-256,
    128 bytes for SHA-512).

    \return Success A positive value indicating the block size in bytes.
    \return HASH_TYPE_E if hash_type is not supported by the build.
    \return BAD_FUNC_ARG if hash_type is an invalid value.

    \param hash_type A hash type from the wc_HashType enumeration such as
    WC_HASH_TYPE_SHA256.

    _Example_
    \code
    int block_size = wc_HashGetBlockSize(WC_HASH_TYPE_SHA256);
    if (block_size > 0) {
        // block_size is the SHA-256 block size in bytes
    }
    \endcode

    \sa wc_HashGetDigestSize
    \sa wc_Hash
*/
int wc_HashGetBlockSize(enum wc_HashType hash_type);

/*!
    \ingroup wolfCrypt

    \brief This function initializes a wc_HashAlg generic hash context for
    the requested hash algorithm. After successful initialization the context
    can be used with wc_HashUpdate() and wc_HashFinal() to compute a digest.
    Once finished the context must be released with wc_HashFree().

    \return 0 Success.
    \return BAD_FUNC_ARG if hash is NULL or type is not supported.
    \return Other negative error codes on internal initialization failure.

    \param hash Pointer to the wc_HashAlg context to initialize.
    \param type A hash type from the wc_HashType enumeration such as
    WC_HASH_TYPE_SHA256.

    _Example_
    \code
    wc_HashAlg hash;
    int ret = wc_HashInit(&hash, WC_HASH_TYPE_SHA256);
    if (ret == 0) {
        wc_HashUpdate(&hash, WC_HASH_TYPE_SHA256, data, dataSz);
        wc_HashFinal(&hash, WC_HASH_TYPE_SHA256, out);
        wc_HashFree(&hash, WC_HASH_TYPE_SHA256);
    }
    \endcode

    \sa wc_HashInit_ex
    \sa wc_HashUpdate
    \sa wc_HashFinal
    \sa wc_HashFree
*/
int wc_HashInit(wc_HashAlg* hash, enum wc_HashType type);

/*!
    \ingroup wolfCrypt

    \brief This function releases any resources held by a wc_HashAlg context
    that was previously initialized with wc_HashInit() or wc_HashInit_ex().
    After this call the context must not be used unless re-initialized.

    \return 0 Success.
    \return BAD_FUNC_ARG if hash is NULL or type is not supported.

    \param hash Pointer to the wc_HashAlg context to free.
    \param type The hash type that was used to initialize the context.

    _Example_
    \code
    wc_HashAlg hash;
    wc_HashInit(&hash, WC_HASH_TYPE_SHA256);
    // ... use hash ...
    wc_HashFree(&hash, WC_HASH_TYPE_SHA256);
    \endcode

    \sa wc_HashInit
    \sa wc_HashInit_ex
    \sa wc_HashDelete
*/
int wc_HashFree(wc_HashAlg* hash, enum wc_HashType type);

/*!
    \ingroup wolfCrypt

    \brief This function frees a wc_HashAlg that was allocated with
    wc_HashNew(). It internally calls wc_HashFree() to release algorithm
    resources, frees the memory of the wc_HashAlg structure itself, and
    optionally clears the caller's pointer to it.

    \return 0 Success.
    \return BAD_FUNC_ARG if hash is NULL.
    \return Negative error codes on internal hash teardown failure.

    \param hash Pointer to the wc_HashAlg to delete.
    \param hash_p Optional pointer to the caller's wc_HashAlg pointer; if
    non-NULL it will be set to NULL after the structure is freed.

    _Example_
    \code
    int rc;
    wc_HashAlg* hash = wc_HashNew(WC_HASH_TYPE_SHA256, NULL,
                                  INVALID_DEVID, &rc);
    if (hash != NULL) {
        // ... use hash ...
        wc_HashDelete(hash, &hash);
    }
    \endcode

    \sa wc_HashNew
    \sa wc_HashFree
*/
int wc_HashDelete(wc_HashAlg *hash, wc_HashAlg **hash_p);

/*!
    \ingroup MD5

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data.
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    \param hashLen Number of bytes to write to hash.

    _Example_
    \code
    const byte* data;
    word32 data_len;
    byte* hash;
    int ret;
    ...
    ret = wc_Md5Hash(data, data_len, hash);
    if (ret != 0) {
         // Md5 Hash Failure Case.
    }
    \endcode

    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
int wc_Md5Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully ….
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
int wc_ShaHash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Success
    \return <0 Error

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha224
    \sa wc_Sha224Update
    \sa wc_Sha224Final
*/
int wc_Sha224Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully …
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha256Hash
    \sa wc_Sha256Final
    \sa wc_InitSha256
*/
int wc_Sha256Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha384Hash
    \sa wc_Sha384Final
    \sa wc_InitSha384
*/
int wc_Sha384Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_Sha512Hash
    \sa wc_Sha512Final
    \sa wc_InitSha512
*/
int wc_Sha512Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash. Computes the SHA-512/224 digest of the supplied data.

    \return 0 Returned upon successfully hashing the data.
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value. Must be at least
    WC_SHA512_224_DIGEST_SIZE (28) bytes.

    _Example_
    \code
    const byte* data;
    word32 data_len;
    byte hash[WC_SHA512_224_DIGEST_SIZE];
    int ret = wc_Sha512_224Hash(data, data_len, hash);
    if (ret != 0) {
        // SHA-512/224 hash failure
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_InitSha512_224
    \sa wc_Sha512_224Update
    \sa wc_Sha512_224Final
*/
int wc_Sha512_224Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash. Computes the SHA-512/256 digest of the supplied data.

    \return 0 Returned upon successfully hashing the data.
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value. Must be at least
    WC_SHA512_256_DIGEST_SIZE (32) bytes.

    _Example_
    \code
    const byte* data;
    word32 data_len;
    byte hash[WC_SHA512_256_DIGEST_SIZE];
    int ret = wc_Sha512_256Hash(data, data_len, hash);
    if (ret != 0) {
        // SHA-512/256 hash failure
    }
    \endcode

    \sa wc_Sha512Hash
    \sa wc_InitSha512_256
    \sa wc_Sha512_256Update
    \sa wc_Sha512_256Final
*/
int wc_Sha512_256Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_224
    \sa wc_Sha3_224_Update
    \sa wc_Sha3_224_Final
*/
int wc_Sha3_224Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_256
    \sa wc_Sha3_256_Update
    \sa wc_Sha3_256_Final
*/
int wc_Sha3_256Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_384
    \sa wc_Sha3_384_Update
    \sa wc_Sha3_384_Final
*/
int wc_Sha3_384Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitSha3_512
    \sa wc_Sha3_512_Update
    \sa wc_Sha3_512_Final
*/
int wc_Sha3_512Hash(const byte* data, word32 len, byte* hash);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitShake128
    \sa wc_Shake128_Update
    \sa wc_Shake128_Final
*/
int wc_Shake128Hash(const byte* data, word32 len, byte* hash,
                    word32 hashLen);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash.

    \return 0 Returned upon successfully hashing the inputted data
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value.
    \param hashLen Number of bytes to write to hash.

    _Example_
    \code
    none
    \endcode

    \sa wc_InitShake256
    \sa wc_Shake256_Update
    \sa wc_Shake256_Final
*/
int wc_Shake256Hash(const byte* data, word32 len, byte* hash,
                    word32 hashLen);

/*!
    \ingroup SHA

    \brief Convenience function, handles all the hashing and places the
    result into hash. Computes the SM3 digest of the supplied data.

    \return 0 Returned upon successfully hashing the data.
    \return Memory_E memory error, unable to allocate memory. This is only
    possible with the small stack option enabled.

    \param data the data to hash
    \param len the length of data
    \param hash Byte array to hold hash value. Must be at least
    WC_SM3_DIGEST_SIZE (32) bytes.

    _Example_
    \code
    const byte* data;
    word32 data_len;
    byte hash[WC_SM3_DIGEST_SIZE];
    int ret = wc_Sm3Hash(data, data_len, hash);
    if (ret != 0) {
        // SM3 hash failure
    }
    \endcode

    \sa wc_InitSm3
    \sa wc_Sm3Update
    \sa wc_Sm3Final
*/
int wc_Sm3Hash(const byte* data, word32 len, byte* hash);


