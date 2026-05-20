/*!
    \file wolfssl/wolfcrypt/pkcs12.h
*/

/*!
    \ingroup PKCS12

    \brief Allocates and initializes a new, empty WC_PKCS12 structure
    using the default heap hint. The returned object must be released
    with wc_PKCS12_free() when the caller is finished with it. This is
    equivalent to calling wc_PKCS12_new_ex() with a NULL heap argument.

    \return A pointer to a newly allocated WC_PKCS12 structure on
    success.
    \return NULL if memory allocation fails.

    _Example_
    \code
    WC_PKCS12* p12 = wc_PKCS12_new();
    if (p12 == NULL) {
        // handle allocation failure
    }
    // ... use p12 ...
    wc_PKCS12_free(p12);
    \endcode

    \sa wc_PKCS12_new_ex
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_new(void);

/*!
    \ingroup PKCS12

    \brief Allocates and initializes a new, empty WC_PKCS12 structure
    using the supplied heap hint. The heap pointer is stored in the
    object and is used for all subsequent allocations performed on the
    structure. The returned object must be released with
    wc_PKCS12_free().

    \return A pointer to a newly allocated WC_PKCS12 structure on
    success.
    \return NULL if memory allocation fails.

    \param heap heap hint passed to the underlying allocator. May be
    NULL to use the default heap.

    _Example_
    \code
    void* heap = myHeapHint;
    WC_PKCS12* p12 = wc_PKCS12_new_ex(heap);
    if (p12 == NULL) {
        // handle allocation failure
    }
    wc_PKCS12_free(p12);
    \endcode

    \sa wc_PKCS12_new
    \sa wc_PKCS12_free
*/
WC_PKCS12* wc_PKCS12_new_ex(void* heap);

/*!
    \ingroup PKCS12

    \brief Releases all memory associated with a WC_PKCS12 structure
    previously created with wc_PKCS12_new(), wc_PKCS12_new_ex() or
    wc_PKCS12_create(). Passing a NULL pointer is a no-op.

    \return none No return value.

    \param pkcs12 pointer to the WC_PKCS12 structure to free. May be
    NULL.

    _Example_
    \code
    WC_PKCS12* p12 = wc_PKCS12_new();
    // ... use p12 ...
    wc_PKCS12_free(p12);
    \endcode

    \sa wc_PKCS12_new
    \sa wc_PKCS12_new_ex
*/
void wc_PKCS12_free(WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12

    \brief Parses a DER-encoded PKCS#12 buffer and populates the
    supplied WC_PKCS12 structure with the decoded ContentInfo entries.
    The caller is responsible for allocating the WC_PKCS12 structure
    (see wc_PKCS12_new()) before calling this function. The PKCS#12
    contents can then be decrypted and extracted with wc_PKCS12_parse().

    \return 0 on success.
    \return BAD_FUNC_ARG if any pointer argument is NULL.
    \return ASN_PARSE_E if the buffer is not valid PKCS#12 DER.
    \return ASN_VERSION_E if the version field is unsupported.
    \return MEMORY_E if memory allocation fails.

    \param der pointer to a buffer holding the DER-encoded PKCS#12
    contents.
    \param derSz size of the \c der buffer in bytes.
    \param pkcs12 pointer to a WC_PKCS12 structure to populate.

    _Example_
    \code
    WC_PKCS12* p12 = wc_PKCS12_new();
    if (wc_d2i_PKCS12(derBuf, derBufSz, p12) != 0) {
        // handle parse failure
    }
    wc_PKCS12_free(p12);
    \endcode

    \sa wc_PKCS12_new
    \sa wc_d2i_PKCS12_fp
    \sa wc_i2d_PKCS12
    \sa wc_PKCS12_parse
*/
int wc_d2i_PKCS12(const byte* der, word32 derSz, WC_PKCS12* pkcs12);

/*!
    \ingroup PKCS12

    \brief Reads a DER-encoded PKCS#12 file from disk and populates the
    referenced WC_PKCS12 pointer with the decoded contents. If
    \c *pkcs12 is NULL on entry, this function allocates a new
    WC_PKCS12 object and stores its pointer in \c *pkcs12. The caller
    must release the resulting object with wc_PKCS12_free(). This API
    is only available when wolfSSL is built with filesystem support
    (NO_FILESYSTEM not defined).

    \return 0 on success.
    \return BAD_FUNC_ARG if \c pkcs12 is NULL.
    \return MEMORY_E if memory allocation fails.
    \return <0 a negative error code returned by the file loader or by
    wc_d2i_PKCS12() when the file contents fail to parse.

    \param file path to a file containing DER-encoded PKCS#12 data.
    \param pkcs12 address of a WC_PKCS12 pointer to populate. If
    \c *pkcs12 is NULL, a new WC_PKCS12 will be allocated.

    _Example_
    \code
    WC_PKCS12* p12 = NULL;
    if (wc_d2i_PKCS12_fp("bundle.p12", &p12) != 0) {
        // handle parse / I/O failure
    }
    wc_PKCS12_free(p12);
    \endcode

    \sa wc_d2i_PKCS12
    \sa wc_PKCS12_free
*/
int wc_d2i_PKCS12_fp(const char* file, WC_PKCS12** pkcs12);

/*!
    \ingroup PKCS12

    \brief Serializes a populated WC_PKCS12 structure into DER form.
    The caller may either pass a pre-allocated output buffer in
    \c *der or pass \c *der as NULL to have a new buffer allocated by
    this function (which the caller must release with XFREE). When
    \c *der is NULL and \c derSz is non-NULL, the required buffer size
    is written to \c *derSz.

    \return >=0 the size of the DER encoding written, on success.
    \return BAD_FUNC_ARG if \c pkcs12 is NULL or no output destination
    is provided.
    \return MEMORY_E if memory allocation fails.
    \return LENGTH_ONLY_E when called with a NULL \c der buffer and a
    non-NULL \c derSz, after writing the required size into \c *derSz.

    \param pkcs12 pointer to a WC_PKCS12 structure to encode.
    \param der address of an output buffer pointer. May point to NULL,
    in which case a buffer is allocated and returned in \c *der.
    \param derSz address of an integer holding the buffer size on input
    and receiving the encoded size on output.

    _Example_
    \code
    byte* der = NULL;
    int   derSz = 0;
    int   ret;

    ret = wc_i2d_PKCS12(p12, &der, &derSz);
    if (ret < 0) {
        // handle encode failure
    }
    // ... use der / derSz ...
    XFREE(der, NULL, DYNAMIC_TYPE_PKCS);
    \endcode

    \sa wc_d2i_PKCS12
    \sa wc_PKCS12_create
*/
int wc_i2d_PKCS12(WC_PKCS12* pkcs12, byte** der, int* derSz);

/*!
    \ingroup PKCS12

    \brief Walks a WC_DerCertList linked list returned by
    wc_PKCS12_parse() and frees every node along with the certificate
    buffer it owns. The list is freed using the supplied heap hint,
    which must match the one used when the list was created. Passing a
    NULL list is a no-op.

    \return none No return value.

    \param list head of the WC_DerCertList chain to free. May be NULL.
    \param heap heap hint that was used to allocate the list entries.

    _Example_
    \code
    WC_DerCertList* ca = NULL;
    byte* key = NULL;  word32 keySz = 0;
    byte* cert = NULL; word32 certSz = 0;

    if (wc_PKCS12_parse(p12, "password", &key, &keySz,
                        &cert, &certSz, &ca) == 0) {
        // ... consume key, cert and ca ...
        wc_FreeCertList(ca, NULL);
        XFREE(key,  NULL, DYNAMIC_TYPE_PKCS);
        XFREE(cert, NULL, DYNAMIC_TYPE_PKCS);
    }
    \endcode

    \sa wc_PKCS12_parse
*/
void wc_FreeCertList(WC_DerCertList* list, void* heap);
