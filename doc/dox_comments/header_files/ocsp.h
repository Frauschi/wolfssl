/*!
    \ingroup OCSP

    \brief Allocates and initialises an OCSP context.

    This function allocates and initialises a WOLFSSL_OCSP structure for use
    with OCSP operations.

    \param cm   Pointer to the certificate manager.

    \return Pointer to allocated WOLFSSL_OCSP on success
    \return NULL on failure

    \sa wc_FreeOCSP
*/
WOLFSSL_OCSP* wc_NewOCSP(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup OCSP

    \brief Frees resources associated with an OCSP context.

    This function releases any resources associated with a WOLFSSL_OCSP structure.

    \param ocsp Pointer to the WOLFSSL_OCSP structure to free.

    \return void

    \sa wc_NewOCSP
*/
void wc_FreeOCSP(WOLFSSL_OCSP* ocsp);

/*!
    \ingroup OCSP

    \brief Checks the OCSP response for a given certificate.

    This function verifies an OCSP response for a specific certificate.

    \param ocsp       Pointer to the WOLFSSL_OCSP structure.
    \param cert       Pointer to the decoded certificate.
    \param response   Pointer to the OCSP response buffer.
    \param responseSz Size of the OCSP response buffer.
    \param heap       Optional heap pointer.

    \return 0 on success
    \return <0 on failure
*/
int wc_CheckCertOcspResponse(WOLFSSL_OCSP *ocsp, DecodedCert *cert, byte *response, int responseSz, void* heap);

/*!
    \ingroup OCSP

    \brief Allocates a new OcspRequest structure.

    This function allocates and zero-initializes an OcspRequest structure
    on the heap. The caller must free the returned object with
    wc_OcspRequest_free().

    \param heap  Pointer to a heap hint for dynamic memory allocation,
                 or NULL to use the default allocator.

    \return Pointer to a newly allocated OcspRequest on success.
    \return NULL on memory allocation failure.

    \sa wc_OcspRequest_free
    \sa wc_InitOcspRequest
*/
OcspRequest* wc_OcspRequest_new(void* heap);

/*!
    \ingroup OCSP

    \brief Frees an OcspRequest structure.

    This function releases all resources associated with an OcspRequest
    that was allocated with wc_OcspRequest_new(). It frees any internal
    allocations associated with the request before freeing the structure
    itself.

    \param request  Pointer to the OcspRequest to free. May be NULL,
                    in which case this function is a no-op.

    \return void

    \sa wc_OcspRequest_new
*/
void wc_OcspRequest_free(OcspRequest* request);

/*!
    \ingroup OCSP

    \brief Initializes an OcspRequest from a decoded certificate.

    This function populates an OcspRequest structure with the issuer hash,
    issuer key hash, and serial number extracted from the given decoded
    certificate. Optionally, a nonce can be included in the request.

    \param req       Pointer to the OcspRequest structure to initialize.
    \param cert      Pointer to the DecodedCert from which to extract
                     certificate information.
    \param useNonce  If non-zero, a nonce extension will be added to the
                     OCSP request.
    \param heap      Pointer to a heap hint for dynamic memory allocation,
                     or NULL.

    \return 0 on success.
    \return BAD_FUNC_ARG if req or cert is NULL.
    \return Other negative values on internal errors.

    \sa wc_EncodeOcspRequest
    \sa wc_OcspRequest_new
    \sa wc_OcspRequest_free
*/
int wc_InitOcspRequest(OcspRequest* req, DecodedCert* cert,
                                    byte useNonce, void* heap);

/*!
    \ingroup OCSP

    \brief Encodes an OCSP request into DER format.

    This function encodes a previously initialized OcspRequest into its
    DER wire format suitable for transmission to an OCSP responder.

    \param req     Pointer to the initialized OcspRequest to encode.
    \param output  Pointer to the output buffer that will receive the
                   DER-encoded OCSP request.
    \param size    Size of the output buffer in bytes.

    \return The size of the encoded request in bytes on success.
    \return Negative error code on failure.

    \sa wc_InitOcspRequest
    \sa wc_OcspRequest_new
*/
int wc_EncodeOcspRequest(OcspRequest* req, byte* output,
                                      word32 size);

/*!
    \ingroup OCSP

    \brief Allocates a new OcspResponse structure.

    This function allocates and zero-initializes an OcspResponse structure
    on the heap. The caller must free the returned object with
    wc_OcspResponse_free().

    \param heap  Pointer to a heap hint for dynamic memory allocation,
                 or NULL to use the default allocator.

    \return Pointer to a newly allocated OcspResponse on success.
    \return NULL on memory allocation failure.

    \sa wc_OcspResponse_free
*/
OcspResponse* wc_OcspResponse_new(void* heap);

/*!
    \ingroup OCSP

    \brief Frees an OcspResponse structure.

    This function releases all resources associated with an OcspResponse
    that was allocated with wc_OcspResponse_new(). It frees any internal
    allocations associated with the response before freeing the structure
    itself.

    \param response  Pointer to the OcspResponse to free. May be NULL,
                     in which case this function is a no-op.

    \return void

    \sa wc_OcspResponse_new
*/
void wc_OcspResponse_free(OcspResponse* response);

/*!
    \ingroup OCSP

    \brief Allocates and initializes a new OCSP Responder.

    This function creates an OcspResponder that can process OCSP requests
    and generate signed responses. The responder must have at least one
    signer added via wc_OcspResponder_AddSigner() before it can produce
    responses.

    Requires HAVE_OCSP_RESPONDER to be defined.

    \param heap       Pointer to a heap hint for dynamic memory allocation,
                      or NULL.
    \param sendCerts  If non-zero, the responder will include the signer
                      certificate in generated OCSP responses.

    \return Pointer to a newly allocated OcspResponder on success.
    \return NULL on failure (memory allocation or RNG initialization failure).

    \sa wc_OcspResponder_free
    \sa wc_OcspResponder_AddSigner
    \sa wc_OcspResponder_SetCertStatus
    \sa wc_OcspResponder_WriteResponse
*/
OcspResponder* wc_OcspResponder_new(void* heap, int sendCerts);

/*!
    \ingroup OCSP

    \brief Frees an OCSP Responder and all associated resources.

    This function releases all memory associated with an OcspResponder,
    including all CA entries, certificate statuses, private keys, and
    the internal RNG.

    Requires HAVE_OCSP_RESPONDER to be defined.

    \param responder  Pointer to the OcspResponder to free. May be NULL,
                      in which case this function is a no-op.

    \return void

    \sa wc_OcspResponder_new
*/
void wc_OcspResponder_free(OcspResponder* responder);

/*!
    \ingroup OCSP

    \brief Adds a signing certificate and key to the OCSP Responder.

    This function registers a signer with the OCSP responder. The signer
    certificate and its corresponding private key are used to sign OCSP
    responses. The signer can be either:
    - A CA certificate that directly issued the certificates being queried
      (issuerCertDer is NULL or zero-length).
    - An authorized OCSP responder delegated by the issuing CA
      (issuerCertDer points to the issuing CA certificate). In this case
      the signer certificate must have the OCSP Signing extended key usage.

    All certificate and key data must be in DER format.

    Requires HAVE_OCSP_RESPONDER to be defined.

    \param responder      Pointer to the OcspResponder.
    \param signerDer      Pointer to the DER-encoded signer certificate.
    \param signerDerSz    Size of the signer certificate in bytes.
    \param keyDer         Pointer to the DER-encoded private key.
    \param keyDerSz       Size of the private key in bytes.
    \param issuerCertDer  Pointer to the DER-encoded issuing CA certificate,
                          or NULL if the signer is itself the CA.
    \param issuerCertDerSz Size of the issuing CA certificate in bytes,
                           or 0 if the signer is itself the CA.

    \return 0 on success.
    \return BAD_FUNC_ARG if required parameters are NULL/zero, if the private
            key does not match the certificate, or if an authorized responder
            is missing the OCSP Signing extended key usage.
    \return MEMORY_E on memory allocation failure.
    \return DUPE_ENTRY_E if a signer with the same issuer hashes already exists.
    \return Other negative error codes on parsing or key loading failures.

    \sa wc_OcspResponder_new
    \sa wc_OcspResponder_SetCertStatus
    \sa wc_OcspResponder_WriteResponse
*/
int wc_OcspResponder_AddSigner(OcspResponder* responder,
    const byte* signerDer, word32 signerDerSz,
    const byte* keyDer, word32 keyDerSz,
    const byte* issuerCertDer, word32 issuerCertDerSz);

/*!
    \ingroup OCSP

    \brief Sets the revocation status of a certificate in the OCSP Responder.

    This function configures the status that the responder will report for
    a specific certificate identified by its serial number. The certificate
    must belong to a CA that has been previously added via
    wc_OcspResponder_AddSigner(). The CA is identified by its subject name.

    If a status entry already exists for the given serial number, it will
    be updated.

    Requires HAVE_OCSP_RESPONDER to be defined.

    \param responder        Pointer to the OcspResponder.
    \param caSubject        The issuing CA subject name in the one-line
                            distinguished name format used internally by
                            the library (e.g. "/C=US/O=Org/CN=CA"). To
                            avoid mismatches,
                            obtain this value from wc_GetDecodedCertSubject()
                            rather than constructing the string manually.
    \param caSubjectSz      Length of the caSubject string in bytes,
                            not including any NUL terminator.
    \param serial           Pointer to the certificate serial number bytes.
    \param serialSz         Size of the serial number in bytes.
    \param status           Certificate status: CERT_GOOD, CERT_REVOKED,
                            or CERT_UNKNOWN.
    \param revocationTime   The time of revocation (only used when status
                            is CERT_REVOKED, must be > 0 for revoked certs).
    \param revocationReason The CRL reason code for revocation (only used
                            when status is CERT_REVOKED). See enum
                            WC_CRL_Reason for valid values.
    \param validityPeriod   Validity period in seconds for CERT_GOOD
                            responses. Must be non-zero for CERT_GOOD
                            status and zero for other statuses.

    \return 0 on success.
    \return BAD_FUNC_ARG if required parameters are NULL/zero or if
            status/revocation parameters are inconsistent.
    \return ASN_NO_SIGNER_E if no CA with the given subject name is found.
    \return MEMORY_E on memory allocation failure.

    \sa wc_OcspResponder_AddSigner
    \sa wc_OcspResponder_WriteResponse
*/
int wc_OcspResponder_SetCertStatus(OcspResponder* responder,
    const char* caSubject, word32 caSubjectSz,
    const byte* serial, word32 serialSz, enum Ocsp_Cert_Status status,
    time_t revocationTime, enum WC_CRL_Reason revocationReason,
    word32 validityPeriod);

/*!
    \ingroup OCSP

    \brief Generates an OCSP response for a given OCSP request.

    This function processes a DER-encoded OCSP request, looks up the
    certificate status in the responder's database, and produces a signed
    OCSP response. The responder must have a signer and certificate status
    entries configured via wc_OcspResponder_AddSigner() and
    wc_OcspResponder_SetCertStatus() before calling this function.

    Requires HAVE_OCSP_RESPONDER to be defined.

    \param responder   Pointer to the OcspResponder.
    \param request     Pointer to the DER-encoded OCSP request.
    \param requestSz   Size of the OCSP request in bytes.
    \param response    Pointer to the output buffer for the DER-encoded
                       OCSP response.
    \param responseSz  Pointer to a word32 containing the size of the
                       response buffer on input, and receiving the actual
                       response size on output.

    \return 0 on success.
    \return BAD_FUNC_ARG if required parameters are NULL/zero.
    \return Negative error codes on decode, lookup, or encoding failures.

    \sa wc_OcspResponder_new
    \sa wc_OcspResponder_AddSigner
    \sa wc_OcspResponder_SetCertStatus
    \sa wc_OcspResponder_WriteErrorResponse
*/
int wc_OcspResponder_WriteResponse(OcspResponder* responder,
    const byte* request, word32 requestSz,
    byte* response, word32* responseSz);

/*!
    \ingroup OCSP

    \brief Generates an OCSP error response.

    This function encodes an OCSP response with an error status code and
    no response body. This is used when the responder cannot process a
    request (e.g., malformed request, internal error, unauthorized).

    Requires HAVE_OCSP_RESPONDER to be defined.

    \param status      The OCSP error status code. Must not be
                       OCSP_SUCCESSFUL. Valid values include
                       OCSP_MALFORMED_REQUEST, OCSP_INTERNAL_ERROR,
                       OCSP_TRY_LATER, OCSP_SIG_REQUIRED, and
                       OCSP_UNAUTHORIZED.
    \param response    Pointer to the output buffer for the DER-encoded
                       error response.
    \param responseSz  Pointer to a word32 containing the size of the
                       response buffer on input, and receiving the actual
                       response size on output.

    \return 0 on success.
    \return BAD_FUNC_ARG if responseSz is NULL or if status is
            OCSP_SUCCESSFUL.
    \return Negative error codes on encoding failure.

    \sa wc_OcspResponder_WriteResponse
*/
int wc_OcspResponder_WriteErrorResponse(
    enum Ocsp_Response_Status status,
    byte* response, word32* responseSz);

/*!
    \ingroup OCSP

    \brief Frees a WOLFSSL_OCSP_BASICRESP object.

    OpenSSL-compatibility wrapper that releases an OCSP basic response
    previously obtained from a function such as
    wolfSSL_OCSP_response_get1_basic(). Internally calls
    wolfSSL_OCSP_RESPONSE_free().

    \return void

    \param basicResponse  Pointer to the basic response to free. May be
                          NULL, in which case this is a no-op.

    _Example_
    \code
    WOLFSSL_OCSP_BASICRESP* bs = wolfSSL_OCSP_response_get1_basic(resp);
    // ... use bs ...
    wolfSSL_OCSP_BASICRESP_free(bs);
    \endcode

    \sa wolfSSL_OCSP_response_get1_basic
    \sa wolfSSL_OCSP_RESPONSE_free
*/
void wolfSSL_OCSP_BASICRESP_free(WOLFSSL_OCSP_BASICRESP* basicResponse);

/*!
    \ingroup OCSP

    \brief Frees a WOLFSSL_OCSP_CERTID object.

    OpenSSL-compatibility wrapper that frees an OCSP certificate ID
    previously allocated by a function such as wolfSSL_OCSP_cert_to_id()
    or wolfSSL_d2i_OCSP_CERTID().

    \return void

    \param certId  Pointer to the certificate ID to free.

    _Example_
    \code
    WOLFSSL_OCSP_CERTID* id = wolfSSL_OCSP_cert_to_id(NULL, subject, issuer);
    // ... use id ...
    wolfSSL_OCSP_CERTID_free(id);
    \endcode

    \sa wolfSSL_OCSP_cert_to_id
    \sa wolfSSL_d2i_OCSP_CERTID
*/
void wolfSSL_OCSP_CERTID_free(WOLFSSL_OCSP_CERTID* certId);

/*!
    \ingroup OCSP

    \brief Frees an OCSP request structure.

    OpenSSL-compatibility wrapper that releases an OcspRequest object
    previously allocated by wolfSSL_OCSP_REQUEST_new(), including any
    internal allocations.

    \return void

    \param request  Pointer to the OCSP request to free.

    _Example_
    \code
    OcspRequest* req = wolfSSL_OCSP_REQUEST_new();
    // ... use req ...
    wolfSSL_OCSP_REQUEST_free(req);
    \endcode

    \sa wolfSSL_OCSP_REQUEST_new
*/
void wolfSSL_OCSP_REQUEST_free(OcspRequest* request);

/*!
    \ingroup OCSP

    \brief Allocates a new OCSP request structure.

    OpenSSL-compatibility wrapper that allocates and zero-initializes
    an OcspRequest object. The caller must release the returned object
    with wolfSSL_OCSP_REQUEST_free().

    \return Pointer to a newly allocated OcspRequest on success.
    \return NULL on memory allocation failure.

    _Example_
    \code
    OcspRequest* req = wolfSSL_OCSP_REQUEST_new();
    if (req == NULL) {
        // allocation failure
    }
    \endcode

    \sa wolfSSL_OCSP_REQUEST_free
    \sa wolfSSL_OCSP_request_add0_id
*/
OcspRequest* wolfSSL_OCSP_REQUEST_new(void);

/*!
    \ingroup OCSP

    \brief Frees an OCSP request context.

    OpenSSL-compatibility wrapper that releases a WOLFSSL_OCSP_REQ_CTX
    previously allocated by wolfSSL_OCSP_REQ_CTX_new() or
    wolfSSL_OCSP_sendreq_new(), including its internal request/response
    BIO and buffer.

    \return void

    \param ctx  Pointer to the OCSP request context to free. May be NULL.

    _Example_
    \code
    WOLFSSL_OCSP_REQ_CTX* ctx = wolfSSL_OCSP_REQ_CTX_new(bio, 0);
    // ... use ctx ...
    wolfSSL_OCSP_REQ_CTX_free(ctx);
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_new
    \sa wolfSSL_OCSP_sendreq_new
*/
void wolfSSL_OCSP_REQ_CTX_free(WOLFSSL_OCSP_REQ_CTX *ctx);

/*!
    \ingroup OCSP

    \brief Drives the non-blocking I/O state machine of an OCSP request
    context.

    OpenSSL-compatibility wrapper that progresses the state machine of a
    WOLFSSL_OCSP_REQ_CTX. While in the write state, it sends the buffered
    HTTP request to the underlying BIO; while in the read state, it reads
    and parses the HTTP OCSP response. Should be called repeatedly while
    the operation has not yet completed.

    \return WOLFSSL_SUCCESS when the operation has completed.
    \return WOLFSSL_FATAL_ERROR if the BIO operation would block and the
            caller should retry.
    \return WOLFSSL_FAILURE on parameter or protocol errors.

    \param ctx  Pointer to a request context created by
                wolfSSL_OCSP_sendreq_new().

    _Example_
    \code
    WOLFSSL_OCSP_REQ_CTX* ctx = wolfSSL_OCSP_sendreq_new(bio, path, req, 0);
    int ret;
    while ((ret = wolfSSL_OCSP_REQ_CTX_nbio(ctx)) == WOLFSSL_FATAL_ERROR) {
        // wait for socket readiness, then retry
    }
    \endcode

    \sa wolfSSL_OCSP_REQ_CTX_new
    \sa wolfSSL_OCSP_sendreq_new
    \sa wolfSSL_OCSP_sendreq_nbio
*/
int wolfSSL_OCSP_REQ_CTX_nbio(WOLFSSL_OCSP_REQ_CTX *ctx);

/*!
    \ingroup OCSP

    \brief Frees an OCSP response structure.

    OpenSSL-compatibility wrapper that releases an OcspResponse object
    previously obtained from wolfSSL_d2i_OCSP_RESPONSE() or a similar
    decode routine, including any single-response entries and the
    encoded source buffer.

    \return void

    \param response  Pointer to the OCSP response to free. May be NULL.

    _Example_
    \code
    const unsigned char* p = der;
    OcspResponse* resp = wolfSSL_d2i_OCSP_RESPONSE(NULL, &p, derLen);
    // ... use resp ...
    wolfSSL_OCSP_RESPONSE_free(resp);
    \endcode

    \sa wolfSSL_d2i_OCSP_RESPONSE
    \sa wolfSSL_OCSP_BASICRESP_free
*/
void wolfSSL_OCSP_RESPONSE_free(OcspResponse* response);

/*!
    \ingroup OCSP

    \brief Returns a human-readable string for an OCSP certificate
    status value.

    OpenSSL-compatibility wrapper that maps an OCSP certificate status
    code (CERT_GOOD, CERT_REVOKED, CERT_UNKNOWN) to a short string
    suitable for logging or display.

    \return A pointer to a static string describing the status:
            "good", "revoked", "unknown", or "(UNKNOWN)" for unrecognized
            values. The returned pointer must not be freed.

    \param s  The OCSP certificate status value to translate.

    _Example_
    \code
    int status = wolfSSL_OCSP_single_get0_status(single, NULL, NULL,
                                                 NULL, NULL);
    printf("status: %s\n", wolfSSL_OCSP_cert_status_str(status));
    \endcode

    \sa wolfSSL_OCSP_single_get0_status
    \sa wolfSSL_OCSP_response_status_str
*/
const char *wolfSSL_OCSP_cert_status_str(long s);

/*!
    \ingroup OCSP

    \brief Returns a human-readable string for a CRL revocation reason
    code.

    OpenSSL-compatibility wrapper that maps a CRL reason code to its
    textual representation. In the current wolfSSL implementation this
    is a stub that always returns NULL.

    \return NULL in the current implementation.

    \param s  The CRL reason code to translate.

    _Example_
    \code
    const char* reasonStr = wolfSSL_OCSP_crl_reason_str(reason);
    \endcode

    \sa wolfSSL_OCSP_cert_status_str
    \sa wolfSSL_OCSP_single_get0_status
*/
const char* wolfSSL_OCSP_crl_reason_str(long s);

/*!
    \ingroup OCSP

    \brief Compares two OCSP certificate IDs for equality.

    OpenSSL-compatibility wrapper that compares two WOLFSSL_OCSP_CERTID
    objects by their hash algorithm OID, issuer name hash, issuer key
    hash, and (when present) serial number.

    \return 0 if the two IDs match.
    \return Non-zero if the IDs do not match.
    \return WOLFSSL_FATAL_ERROR if either argument is NULL.

    \param a  Pointer to the first OCSP certificate ID.
    \param b  Pointer to the second OCSP certificate ID.

    _Example_
    \code
    if (wolfSSL_OCSP_id_cmp(a, b) == 0) {
        // matching certificate IDs
    }
    \endcode

    \sa wolfSSL_OCSP_cert_to_id
    \sa wolfSSL_OCSP_CERTID_free
*/
int wolfSSL_OCSP_id_cmp(WOLFSSL_OCSP_CERTID *a, WOLFSSL_OCSP_CERTID *b);

/*!
    \ingroup OCSP

    \brief Returns the number of single responses in an OCSP basic
    response.

    OpenSSL-compatibility wrapper that counts the linked list of
    OcspEntry single responses contained in a WOLFSSL_OCSP_BASICRESP.

    \return The number of single responses on success.
    \return WOLFSSL_FAILURE if bs is NULL.

    \param bs  Pointer to the OCSP basic response.

    _Example_
    \code
    int n = wolfSSL_OCSP_resp_count(bs);
    for (int i = 0; i < n; ++i) {
        WOLFSSL_OCSP_SINGLERESP* s = wolfSSL_OCSP_resp_get0(bs, i);
        // process single response s
    }
    \endcode

    \sa wolfSSL_OCSP_resp_get0
    \sa wolfSSL_OCSP_response_get1_basic
*/
int wolfSSL_OCSP_resp_count(WOLFSSL_OCSP_BASICRESP *bs);

/*!
    \ingroup OCSP

    \brief Returns the OCSP response status code of a response.

    OpenSSL-compatibility wrapper that retrieves the top-level response
    status from a decoded OCSP response (e.g. OCSP_SUCCESSFUL,
    OCSP_MALFORMED_REQUEST, OCSP_INTERNAL_ERROR, OCSP_TRY_LATER,
    OCSP_SIG_REQUIRED, OCSP_UNAUTHORIZED).

    \return The OCSP response status value on success.
    \return -1 if response is NULL.

    \param response  Pointer to a decoded OCSP response.

    _Example_
    \code
    int status = wolfSSL_OCSP_response_status(resp);
    if (status != OCSP_SUCCESSFUL) {
        printf("OCSP failed: %s\n",
               wolfSSL_OCSP_response_status_str(status));
    }
    \endcode

    \sa wolfSSL_OCSP_response_status_str
    \sa wolfSSL_d2i_OCSP_RESPONSE
*/
int wolfSSL_OCSP_response_status(OcspResponse *response);

/*!
    \ingroup OCSP

    \brief Returns a human-readable string for an OCSP response status
    value.

    OpenSSL-compatibility wrapper that maps an OCSP response status code
    to its textual representation as defined by RFC 6960
    (e.g. "successful", "malformedrequest", "internalerror", "trylater",
    "sigrequired", "unauthorized").

    \return A pointer to a static string describing the status, or
            "(UNKNOWN)" for unrecognized values. The returned pointer
            must not be freed.

    \param s  The OCSP response status value to translate.

    _Example_
    \code
    int status = wolfSSL_OCSP_response_status(resp);
    printf("OCSP status: %s\n", wolfSSL_OCSP_response_status_str(status));
    \endcode

    \sa wolfSSL_OCSP_response_status
    \sa wolfSSL_OCSP_cert_status_str
*/
const char *wolfSSL_OCSP_response_status_str(long s);
