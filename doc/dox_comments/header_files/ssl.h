/*!
    \brief This function initializes the DTLS v1.2 client method.

    \return pointer This function returns a pointer to a new
    WOLFSSL_METHOD structure.

    \param heap pointer to a heap hint for memory allocation.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());
    …
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    \endcode

    \sa wolfSSL_Init
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_client_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function returns a WOLFSSL_METHOD similar to
    wolfSSLv23_client_method except that it is not determined
    which side yet (server/client).

    \return WOLFSSL_METHOD* On successful creations returns a WOLFSSL_METHOD
    pointer
    \return NULL Null if memory allocation error or failure to create method

    \param none No parameters.

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfSSLv23_method());
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfSSLv23_method(void);

/*!
    \ingroup Setup

    \brief The wolfSSLv3_server_method() function is used to indicate
    that the application is a server and will only support the SSL 3.0
    protocol.  This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the
    failure value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new

*/
WOLFSSL_METHOD *wolfSSLv3_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfSSLv3_client_method() function is used to indicate
    that the application is a client and will only support the SSL 3.0
    protocol.  This function allocates memory for and initializes a
    new wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the
    failure value of the underlying malloc() implementation will be
    returned (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_server_method() function is used to indicate that the
    application is a server and will only support the TLS 1.0 protocol. This
    function allocates memory for and initializes a new wolfSSL_METHOD
    structure to be used when creating the SSL/TLS context with
    wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_server_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_client_method() function is used to indicate
    that the application is a client and will only support the TLS 1.0
    protocol.  This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC,
    the failure value of the underlying malloc() implementation
    will be returned (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_client_method();
    if (method == NULL) {
	    unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_1_server_method() function is used to indicate
    that the application is a server and will only support the TLS 1.1
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_server_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_1_client_method() function is used to indicate
    that the application is a client and will only support the TLS 1.0
    protocol. This function allocates memory for and initializes a
    new wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the
    newly created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_1_client_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_2_server_method() function is used to indicate
    that the application is a server and will only support the TLS 1.2
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_server_method(void);

/*!
    \ingroup Setup

    \brief The wolfTLSv1_2_client_method() function is used to indicate
    that the application is a client and will only support the TLS 1.2
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_2_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfDTLSv1_client_method() function is used to indicate that
    the application is a client and will only support the DTLS 1.0 protocol.
    This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new(). This function is only available when wolfSSL has
    been compiled with DTLS support (--enable-dtls,
    or by defining wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_client_method(void);

/*!
    \ingroup Setup

    \brief The wolfDTLSv1_server_method() function is used to indicate
    that the application is a server and will only support the DTLS 1.0
    protocol.  This function allocates memory for and initializes a
    new wolfSSL_METHOD structure to be used when creating the SSL/TLS
    context with wolfSSL_CTX_new(). This function is only available
    when wolfSSL has been compiled with DTLS support (--enable-dtls,
    or by defining wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_server_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLSv1_3_server_method() function is used to indicate that
    the application is a server and will only support the DTLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context with
    wolfSSL_CTX_new(). This function is only available when wolfSSL has been
    compiled with DTLSv1.3 support (--enable-dtls13, or by defining
    wolfSSL_DTLS13).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_client_method
*/

WOLFSSL_METHOD *wolfDTLSv1_3_server_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLSv1_3_client_method() function is used to indicate that
    the application is a client and will only support the DTLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context with
    wolfSSL_CTX_new(). This function is only available when wolfSSL has been
    compiled with DTLSv1.3 support (--enable-dtls13, or by defining
    wolfSSL_DTLS13).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLSv1_3_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLSv1_3_server_method
*/
WOLFSSL_METHOD* wolfDTLSv1_3_client_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLS_server_method() function is used to indicate that the
    application is a server and will support the highest version of DTLS
    available and all the version up to the minimum version allowed.  The
    default minimum version allowed is based on the define
    WOLFSSL_MIN_DTLS_DOWNGRADE and can be changed at runtime using
    wolfSSL_SetMinVersion(). This function allocates memory for and initializes
    a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new(). This function is only available when wolfSSL has
    been compiled with DTLS support (--enable-dtls, or by defining
    wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_server_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLS_client_method
    \sa wolfSSL_SetMinVersion
*/
WOLFSSL_METHOD *wolfDTLS_server_method(void);
/*!
    \ingroup Setup

    \brief The wolfDTLS_client_method() function is used to indicate that the
    application is a client and will support the highest version of DTLS
    available and all the version up to the minimum version allowed.  The
    default minimum version allowed is based on the define
    WOLFSSL_MIN_DTLS_DOWNGRADE and can be changed at runtime using
    wolfSSL_SetMinVersion(). This function allocates memory for and initializes
    a new wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new(). This function is only available when wolfSSL has
    been compiled with DTLS support (--enable-dtls, or by defining
    wolfSSL_DTLS).

    \return * If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfDTLS_client_method();
    if (method == NULL) {
	    // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode


    \sa wolfDTLS_server_method
    \sa wolfSSL_SetMinVersion
*/
WOLFSSL_METHOD *wolfDTLS_client_method(void);
/*!
    \brief This function creates and initializes a WOLFSSL_METHOD for the
    server side.

    \return This function returns a WOLFSSL_METHOD pointer.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method());
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_server_method(void);

/*!
    \ingroup Setup

    \brief Since there is some differences between the first release and
    newer versions of chacha-poly AEAD construction we have added an option
    to communicate with servers/clients using the older version. By default
    wolfSSL uses the new version.

    \return 0 upon success

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param value whether or not to use the older version of setting up the
    information for poly1305. Passing a flag value of 1 indicates yes use the
    old poly AEAD, to switch back to using the new version pass a flag value
    of 0.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_use_old_poly(ssl, 1);
    if (ret != 0) {
        // failed to set poly1305 AEAD version
    }
    \endcode

    \sa none
*/
int wolfSSL_use_old_poly(WOLFSSL* ssl, int value);

/*!
    \brief The wolfSSL_dtls_import() function is used to parse in a serialized
    session state. This allows for picking up the connection after the
    handshake has been completed.

    \return Success If successful, the amount of the buffer read will be
    returned.
    \return Failure All unsuccessful return values will be less than 0.
    \return VERSION_ERROR If a version mismatch is found ie DTLS v1 and ctx
    was set up for DTLS v1.2 then VERSION_ERROR is returned.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf serialized session to import.
    \param sz size of serialized session buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    //get information sent from wc_dtls_export function and place it in buf
    fread(buf, 1, bufSz, input);
    ret = wolfSSL_dtls_import(ssl, buf, bufSz);
    if (ret < 0) {
    // handle error case
    }
    // no wolfSSL_accept needed since handshake was already done
    ...
    ret = wolfSSL_write(ssl) and wolfSSL_read(ssl);
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
int wolfSSL_dtls_import(WOLFSSL* ssl, const unsigned char* buf,
                                                               unsigned int sz);


/*!
    \brief Used to import a serialized TLS session. This function is for
    importing the state of the connection.
    WARNING: buf contains sensitive information about the state and is best to
    be encrypted before storing if stored.
    Additional debug info can be displayed with the macro
    WOLFSSL_SESSION_EXPORT_DEBUG defined.

    \return the number of bytes read from buffer 'buf'

    \param ssl WOLFSSL structure to import the session into
    \param buf serialized session
    \param sz  size of buffer 'buf'

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_export
 */
int wolfSSL_tls_import(WOLFSSL* ssl, const unsigned char* buf,
        unsigned int sz);

/*!
    \brief The wolfSSL_CTX_dtls_set_export() function is used to set
    the callback function for exporting a session. It is allowed to
    pass in NULL as the parameter func to clear the export function
    previously stored. Used on the server side and is called immediately
    after handshake is completed.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG If null or not expected arguments are passed in

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param func wc_dtls_export function to use when exporting a session.

    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passes
    // buf (serialized session) to destination
    WOLFSSL_CTX* ctx;
    int ret;
    ...
    ret = wolfSSL_CTX_dtls_set_export(ctx, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_dtls_set_export
    \sa Static buffer use
*/
int wolfSSL_CTX_dtls_set_export(WOLFSSL_CTX* ctx,
                                                           wc_dtls_export func);

/*!
    \brief The wolfSSL_dtls_set_export() function is used to set the callback
    function for exporting a session. It is allowed to pass in NULL as the
    parameter func to clear the export function previously stored. Used on
    the server side and is called immediately after handshake is completed.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG If null or not expected arguments are passed in

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param func wc_dtls_export function to use when exporting a session.

    _Example_
    \code
    int send_session(WOLFSSL* ssl, byte* buf, word32 sz, void* userCtx);
    // body of send session (wc_dtls_export) that passes
    // buf (serialized session) to destination
    WOLFSSL* ssl;
    int ret;
    ...
    ret = wolfSSL_dtls_set_export(ssl, send_session);
    if (ret != SSL_SUCCESS) {
        // handle error case
    }
    ...
    ret = wolfSSL_accept(ssl);
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
*/
int wolfSSL_dtls_set_export(WOLFSSL* ssl, wc_dtls_export func);

/*!
    \brief The wolfSSL_dtls_export() function is used to serialize a
    WOLFSSL session into the provided buffer. Allows for less memory
    overhead than using a function callback for sending a session and
    choice over when the session is serialized. If buffer is NULL when
    passed to function then sz will be set to the size of buffer needed
    for serializing the WOLFSSL session.

    \return Success If successful, the amount of the buffer used will
    be returned.
    \return Failure All unsuccessful return values will be less than 0.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf buffer to hold serialized session.
    \param sz size of buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    unsigned char buf[MAX];
    bufSz = MAX;
    ...
    ret = wolfSSL_dtls_export(ssl, buf, bufSz);
    if (ret < 0) {
        // handle error case
    }
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_dtls_set_export
    \sa wolfSSL_dtls_import
*/
int wolfSSL_dtls_export(WOLFSSL* ssl, unsigned char* buf,
                                                              unsigned int* sz);

/*!
    \brief Used to export a serialized TLS session. This function is for
    exporting a serialized state of the connection.
    In most cases wolfSSL_get1_session should be used instead of
    wolfSSL_tls_export.
    Additional debug info can be displayed with the macro
    WOLFSSL_SESSION_EXPORT_DEBUG defined.
    WARNING: buf contains sensitive information about the state and is best to
             be encrypted before storing if stored.

    \return the number of bytes written into buffer 'buf'

    \param ssl WOLFSSL structure to export the session from
    \param buf output of serialized session
    \param sz  size in bytes set in 'buf'

    \sa wolfSSL_dtls_import
    \sa wolfSSL_tls_import
 */
int wolfSSL_tls_export(WOLFSSL* ssl, unsigned char* buf,
        unsigned int* sz);

/*!
    \brief This function is used to set aside static memory for a CTX. Memory
    set aside is then used for the CTX’s lifetime and for any SSL objects
    created from the CTX. By passing in a NULL ctx pointer and a
    wolfSSL_method_func function the creation of the CTX itself will also
    use static memory. wolfSSL_method_func has the function signature of
    WOLFSSL_METHOD* (*wolfSSL_method_func)(void* heap);. Passing in 0 for max
    makes it behave as if not set and no max concurrent use restrictions is
    in place. The flag value passed in determines how the memory is used and
    behavior while operating. Available flags are the following: 0 - default
    general memory, WOLFMEM_IO_POOL - used for input/output buffer when
    sending receiving messages and overrides general memory, so all memory
    in buffer passed in is used for IO, WOLFMEM_IO_FIXED - same as
    WOLFMEM_IO_POOL but each SSL now keeps two buffers to themselves for
    their lifetime, WOLFMEM_TRACK_STATS - each SSL keeps track of memory
    stats while running.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE upon failure.

    \param ctx address of pointer to a WOLFSSL_CTX structure.
    \param method function to create protocol. (should be NULL if ctx is not
    also NULL)
    \param buf memory to use for all operations.
    \param sz size of memory buffer being passed in.
    \param flag type of memory.
    \param max max concurrent operations.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    int ret;
    unsigned char memory[MAX];
    int memorySz = MAX;
    unsigned char IO[MAX];
    int IOSz = MAX;
    int flag = WOLFMEM_IO_FIXED | WOLFMEM_TRACK_STATS;
    ...
    // create ctx also using static memory, start with general memory to use
    ctx = NULL:
    ret = wolfSSL_CTX_load_static_memory(&ctx, wolfSSLv23_server_method_ex,
    memory, memorySz, 0,    MAX_CONCURRENT_HANDSHAKES);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    // load in memory for use with IO
    ret = wolfSSL_CTX_load_static_memory(&ctx, NULL, IO, IOSz, flag,
    MAX_CONCURRENT_IO);
    if (ret != SSL_SUCCESS) {
    // handle error case
    }
    ...
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_is_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_load_static_memory(WOLFSSL_CTX** ctx,
                                            wolfSSL_method_func method,
                                            unsigned char* buf, unsigned int sz,
                                            int flag, int max);

/*!
    \brief This function does not change any of the connections behavior
    and is used only for gathering information about the static memory usage.

    \return 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param mem_stats structure to hold information about static memory usage.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int ret;
    WOLFSSL_MEM_STATS mem_stats;
    ...
    //get information about static memory with CTX
    ret = wolfSSL_CTX_is_static_memory(ctx, &mem_stats);
    if (ret == 1) {
        // handle case of is using static memory
        // print out or inspect elements of mem_stats
    }
    if (ret == 0) {
        //handle case of ctx not using static memory
    }
    …
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_load_static_memory
    \sa wolfSSL_is_static_memory
*/
int wolfSSL_CTX_is_static_memory(WOLFSSL_CTX* ctx,
                                                 WOLFSSL_MEM_STATS* mem_stats);

/*!
    \brief wolfSSL_is_static_memory is used to gather information about
    a SSL’s static memory usage. The return value indicates if static
    memory is being used and WOLFSSL_MEM_CONN_STATS will be filled out
    if and only if the flag WOLFMEM_TRACK_STATS was passed to the parent
    CTX when loading in static memory.

    \return 1 is returned if using static memory for the CTX is true.
    \return 0 is returned if not using static memory.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param mem_stats structure to contain static memory usage.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    WOLFSSL_MEM_CONN_STATS mem_stats;
    ...
    ret = wolfSSL_is_static_memory(ssl, mem_stats);
    if (ret == 1) {
        // handle case when is static memory
        // investigate elements in mem_stats if WOLFMEM_TRACK_STATS flag
    }
    ...
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_is_static_memory
*/
int wolfSSL_is_static_memory(WOLFSSL* ssl,
                                            WOLFSSL_MEM_CONN_STATS* mem_stats);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate file into the SSL context
    (WOLFSSL_CTX).  The file is provided by the file argument. The
    format argument specifies the format type of the file, either
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please see the examples
    for proper usage.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes might
    include the file is in the wrong format, or the wrong format has been
    given using the “format” argument, file doesn’t exist, can’t be read,
    or is corrupted, an out of memory condition occurs, Base16 decoding
    fails on the file.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the certificate
    to be loaded into the wolfSSL SSL context.
    \param format - format of the certificates pointed to by file. Possible
    options are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_file(ctx, “./client-cert.pem”,
                                     SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX* ctx, const char* file,
                                     int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a private key file into the SSL context
    (WOLFSSL_CTX). The file is provided by the file argument. The format
    argument specifies the format type of the file - SSL_FILETYPE_ASN1or
    SSL_FILETYPE_PEM.  Please see the examples for proper usage.

    If using an external key store and do not have the private key you can
    instead provide the public key and register the crypro callback to handle
    the signing. For this you can build with either build with crypto callbacks
    or PK callbacks. To enable crypto callbacks use --enable-cryptocb
    or WOLF_CRYPTO_CB and register a crypto callback using
    wc_CryptoCb_RegisterDevice and set the associated devId using
    wolfSSL_CTX_SetDevId.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE The file is in the wrong format, or the wrong format
    has been given using the “format” argument. The file doesn’t exist, can’t
    be read, or is corrupted. An out of memory condition occurs. Base16
    decoding fails on the file. The key file is encrypted but no password
    is provided.

    \param ctx pointer to a WOLFSSL_CTX structure.
    \param file path to the private key file.
    \param format format of the key file (SSL_FILETYPE_PEM or
    SSL_FILETYPE_ASN1).

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, “./server-key.pem”,
                                    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wc_CryptoCb_RegisterDevice
    \sa wolfSSL_CTX_SetDevId
*/
int wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX* ctx, const char* file, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads PEM-formatted CA certificate files into the SSL
    context (WOLFSSL_CTX).  These certificates will be treated as trusted root
    certificates and used to verify certs received from peers during the SSL
    handshake. The root certificate file, provided by the file argument, may
    be a single certificate or a file containing multiple certificates.
    If multiple CA certs are included in the same file, wolfSSL will load them
    in the same order they are presented in the file.  The path argument is
    a pointer to the name of a directory that contains certificates of
    trusted root CAs. If the value of file is not NULL, path may be specified
    as NULL if not needed.  If path is specified and NO_WOLFSSL_DIR was not
    defined when building the library, wolfSSL will load all CA certificates
    located in the given directory. This function will attempt to load all
    files in the directory. This function expects PEM formatted CERT_TYPE
    file with header “-----BEGIN CERTIFICATE-----”.

    \return SSL_SUCCESS up success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    path are NULL.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before the
    before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after the
    after date.
    \return BUFFER_E will be returned if a chain buffer is bigger than the
    receiving buffer.
    \return BAD_PATH_ERROR will be returned if opendir() fails when trying
    to open path.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing PEM-formatted CA
    certificates.
    \param path pointer to the name of a directory to load PEM-formatted
    certificates from.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations(ctx, “./ca-cert.pem”, NULL);
    if (ret != WOLFSSL_SUCCESS) {
    	// error loading CA certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations_ex
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX* ctx, const char* file,
                                                const char* path);

/*!
    \ingroup CertsKeys

    \brief This function loads PEM-formatted CA certificate files into the SSL
    context (WOLFSSL_CTX).  These certificates will be treated as trusted root
    certificates and used to verify certs received from peers during the SSL
    handshake. The root certificate file, provided by the file argument, may
    be a single certificate or a file containing multiple certificates.
    If multiple CA certs are included in the same file, wolfSSL will load them
    in the same order they are presented in the file.  The path argument is
    a pointer to the name of a directory that contains certificates of
    trusted root CAs. If the value of file is not NULL, path may be specified
    as NULL if not needed.  If path is specified and NO_WOLFSSL_DIR was not
    defined when building the library, wolfSSL will load all CA certificates
    located in the given directory. This function will attempt to load all
    files in the directory based on flags specified. This function expects PEM
    formatted CERT_TYPE files with header “-----BEGIN CERTIFICATE-----”.

    \return SSL_SUCCESS up success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    path are NULL. This will also be returned if at least one cert is loaded
    successfully but there is one or more that failed. Check error stack for reason.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than the
    receiving buffer.
    \return BAD_PATH_ERROR will be returned if opendir() fails when trying
    to open path.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing PEM-formatted CA
    certificates.
    \param path pointer to the name of a directory to load PEM-formatted
    certificates from.
    \param flags possible mask values are: WOLFSSL_LOAD_FLAG_IGNORE_ERR,
    WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY and WOLFSSL_LOAD_FLAG_PEM_CA_ONLY

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_verify_locations_ex(ctx, NULL, “./certs/external",
        WOLFSSL_LOAD_FLAG_PEM_CA_ONLY);
    if (ret != WOLFSSL_SUCCESS) {
        // error loading CA certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_load_verify_locations_ex(WOLFSSL_CTX* ctx, const char* file,
                                         const char* path, word32 flags);

/*!
    \ingroup CertsKeys

    \brief This function returns a pointer to an array of strings representing
    directories wolfSSL will search for system CA certs when
    wolfSSL_CTX_load_system_CA_certs is called. On systems that don't store
    certificates in an accessible system directory (such as Apple platforms),
    this function will always return NULL.

    \return Valid pointer on success.
    \return NULL pointer on failure.

    \param num pointer to a word32 that will be populated with the length of the
    array of strings.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    const char** dirs;
    word32 numDirs;

    dirs = wolfSSL_get_system_CA_dirs(&numDirs);
    for (int i = 0; i < numDirs; ++i) {
        printf("Potential system CA dir: %s\n", dirs[i]);
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_system_CA_certs
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_locations_ex
*/
const char** wolfSSL_get_system_CA_dirs(word32* num);

/*!
    \ingroup CertsKeys

    \brief On most platforms (including Linux and Windows), this function
    attempts to load CA certificates into a WOLFSSL_CTX from an OS-dependent
    CA certificate store. Loaded certificates will be trusted.

    On Apple platforms (excluding macOS), certificates can't be obtained from
    the system, and therefore cannot be loaded into the wolfSSL certificate
    manager. For these platforms, this function enables TLS connections bound to
    the WOLFSSL_CTX to use the native system trust APIs to verify authenticity
    of the peer certificate chain if the authenticity of the peer cannot first
    be authenticated against certificates loaded by the user.

    The platforms supported and tested are: Linux (Debian, Ubuntu,
    Gentoo, Fedora, RHEL), Windows 10/11, Android, macOS, and iOS.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_BAD_PATH if no system CA certs were loaded.
    \return WOLFSSL_FAILURE for other failure types (e.g. Windows cert store
    wasn't properly closed).

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_load_system_CA_certs(ctx,);
    if (ret != WOLFSSL_SUCCESS) {
        // error loading system CA certs
    }
    ...
    \endcode

    \sa wolfSSL_get_system_CA_dirs
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_locations_ex
*/
int wolfSSL_CTX_load_system_CA_certs(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function loads a certificate to use for verifying a peer
    when performing a TLS/SSL handshake. The peer certificate sent during the
    handshake is compared by using the SKID when available and the signature.
    If these two things do not match then any loaded CAs are used. Feature is
    enabled by defining the macro WOLFSSL_TRUST_PEER_CERT. Please see the
    examples for proper usage.

    \return SSL_SUCCES upon success.
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    type are invalid.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param file pointer to name of the file containing certificates
    \param type type of certificate being loaded ie SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    ...

    ret = wolfSSL_CTX_trust_peer_cert(ctx, “./peer-cert.pem”,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        // error loading trusted peer cert
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_trust_peer_cert(WOLFSSL_CTX* ctx, const char* file, int type);

/*!
    \ingroup CertsKeys

    \brief This function loads a chain of certificates into the SSL
    context (WOLFSSL_CTX).  The file containing the certificate chain
    is provided by the file argument, and must contain PEM-formatted
    certificates. This function will process up to MAX_CHAIN_DEPTH
    (default = 9, defined in internal.h) certificates, plus the subject cert.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might
    include the file is in the wrong format, or the wrong format has been
    given using the “format” argument, file doesn’t exist, can’t be read,
    or is corrupted, an out of memory condition occurs.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the chain of
    certificates to be loaded into the wolfSSL SSL context.  Certificates
    must be in PEM format.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
	    // error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *ctx,
                                                     const char *file);

/*!
    \ingroup openSSL

    \brief This function loads the private RSA key used in the SSL connection
    into the SSL context (WOLFSSL_CTX).  This function is only available when
    wolfSSL has been compiled with the OpenSSL compatibility layer enabled
    (--enable-opensslExtra, #define OPENSSL_EXTRA), and is identical to the
    more-typically used wolfSSL_CTX_use_PrivateKey_file() function. The file
    argument contains a pointer to the RSA private key file, in the format
    specified by format.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE  If the function call fails, possible causes might
    include: The input key file is in the wrong format, or the wrong format
    has been given using the “format” argument, file doesn’t exist, can’t
    be read, or is corrupted, an out of memory condition occurs.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the RSA private
    key to be loaded into the wolfSSL SSL context, with format as specified
    by format.
    \param format the encoding type of the RSA private key specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_use_RSAPrivateKey_file(ctx, “./server-key.pem”,
                                       SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_RSAPrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
int wolfSSL_CTX_use_RSAPrivateKey_file(WOLFSSL_CTX* ctx, const char* file, int format);

/*!
    \ingroup IO

    \brief This function returns the maximum chain depth allowed, which is 9 by
    default, for a valid session i.e. there is a non-null session object (ssl).

    \return MAX_CHAIN_DEPTH returned if the WOLFSSL structure is not
    NULL. By default the value is 9.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    long sslDep = wolfSSL_get_verify_depth(ssl);

    if(sslDep > EXPECTED){
    	// The verified depth is greater than what was expected
    } else {
    	// The verified depth is smaller or equal to the expected value
    }
    \endcode

    \sa wolfSSL_CTX_get_verify_depth
*/
long wolfSSL_get_verify_depth(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function gets the certificate chaining depth using the
    CTX structure.

    \return MAX_CHAIN_DEPTH returned if the CTX struct is not NULL. The
    constant representation of the max certificate chain peer depth.
    \return BAD_FUNC_ARG returned if the CTX structure is NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_METHOD method; // protocol method
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    long ret = wolfSSL_CTX_get_verify_depth(ctx);

    if(ret == EXPECTED){
    	//  You have the expected value
    } else {
    	//  Handle an unexpected depth
    }
    \endcode

    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_get_verify_depth
*/
long wolfSSL_CTX_get_verify_depth(WOLFSSL_CTX* ctx);

/*!
    \ingroup openSSL

    \brief This function loads a certificate file into the SSL session
    (WOLFSSL structure).  The certificate file is provided by the file
    argument.  The format argument specifies the format type of the file -
    either SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might
    include: The file is in the wrong format, or the wrong format has been
    given using the “format” argument, file doesn’t exist, can’t be read,
    or is corrupted, an out of memory condition occurs, Base16 decoding
    fails on the file

    \param ssl a pointer to a WOLFSSL structure, created with wolfSSL_new().
    \param file a pointer to the name of the file containing the certificate to
    be loaded into the wolfSSL SSL session, with format as specified by format.
    \param format the encoding type of the certificate specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_certificate_file(ssl, “./client-cert.pem”,
                                 SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_use_certificate_buffer
*/
int wolfSSL_use_certificate_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup openSSL

    \brief This function loads a private key file into the SSL session
    (WOLFSSL structure).  The key file is provided by the file argument.
    The format argument specifies the format type of the file -
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    If using an external key store and do not have the private key you can
    instead provide the public key and register the crypro callback to handle
    the signing. For this you can build with either build with crypto callbacks
    or PK callbacks. To enable crypto callbacks use --enable-cryptocb or
    WOLF_CRYPTO_CB and register a crypto callback using
    wc_CryptoCb_RegisterDevice and set the associated devId using
    wolfSSL_SetDevId.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes might
    include: The file is in the wrong format, or the wrong format has been
    given using the “format” argument, The file doesn’t exist, can’t be read,
    or is corrupted, An out of memory condition occurs, Base16 decoding
    fails on the file, The key file is encrypted but no password is provided

    \param ssl a pointer to a WOLFSSL structure, created with wolfSSL_new().
    \param file a pointer to the name of the file containing the key file to
    be loaded into the wolfSSL SSL session, with format as specified by format.
    \param format the encoding type of the key specified by file.  Possible
    values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_PrivateKey_file(ssl, “./server-key.pem”,
                                SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wc_CryptoCb_RegisterDevice
    \sa wolfSSL_SetDevId
*/
int wolfSSL_use_PrivateKey_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup openSSL

    \brief This function loads a chain of certificates into the SSL
    session (WOLFSSL structure).  The file containing the certificate
    chain is provided by the file argument, and must contain PEM-formatted
    certificates.  This function will process up to MAX_CHAIN_DEPTH
    (default = 9, defined in internal.h) certificates, plus the
    subject certificate.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE If the function call fails, possible causes
    might include: The file is in the wrong format, or the wrong format
    has been given using the “format” argument, file doesn’t exist,
    can’t be read, or is corrupted, an out of memory condition occurs

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new()
    \param file a pointer to the name of the file containing the chain
    of certificates to be loaded into the wolfSSL SSL session.
    Certificates must be in PEM format.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ctx;
    ...
    ret = wolfSSL_use_certificate_chain_file(ssl, “./cert-chain.pem”);
    if (ret != SSL_SUCCESS) {
    	// error loading cert file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_certificate_chain_file(WOLFSSL* ssl, const char *file);

/*!
    \ingroup openSSL

    \brief This function loads the private RSA key used in the SSL
    connection into the SSL session (WOLFSSL structure). This
    function is only available when wolfSSL has been compiled with
    the OpenSSL compatibility layer enabled (--enable-opensslExtra,
    #define OPENSSL_EXTRA), and is identical to the more-typically
    used wolfSSL_use_PrivateKey_file() function. The file argument
    contains a pointer to the RSA private key file, in the format
    specified by format.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE If the function call fails, possible causes might
    include: The input key file is in the wrong format, or the wrong format
    has been given using the “format” argument, file doesn’t exist, can’t
    be read, or is corrupted, an out of memory condition occurs

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new()
    \param file a pointer to the name of the file containing the RSA private
    key to be loaded into the wolfSSL SSL session, with format as specified
    by format.
    \param format the encoding type of the RSA private key specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_use_RSAPrivateKey_file(ssl, “./server-key.pem”,
                                   SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading private key file
    }
    ...
    \endcode

    \sa wolfSSL_CTX_use_RSAPrivateKey_file
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_PrivateKey_file
*/
int wolfSSL_use_RSAPrivateKey_file(WOLFSSL* ssl, const char* file, int format);

/*!
    \ingroup CertsKeys

    \brief This function is similar to wolfSSL_CTX_load_verify_locations,
    but allows the loading of DER-formatted CA files into the SSL context
    (WOLFSSL_CTX).  It may still be used to load PEM-formatted CA files as
    well. These certificates will be treated as trusted root certificates
    and used to verify certs received from peers during the SSL handshake.
    The root certificate file, provided by the file argument, may be a single
    certificate or a file containing multiple certificates.  If multiple CA
    certs are included in the same file, wolfSSL will load them in the same
    order they are presented in the file.  The format argument specifies the
    format which the certificates are in either, SSL_FILETYPE_PEM or
    SSL_FILETYPE_ASN1 (DER). Unlike wolfSSL_CTX_load_verify_locations,
    this function does not allow the loading of CA certificates from a given
    directory path. Note that this function is only available when the wolfSSL
    library was compiled with WOLFSSL_DER_LOAD defined.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE upon failure.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new()
    \param file a pointer to the name of the file containing the CA
    certificates to be loaded into the wolfSSL SSL context, with format
    as specified by format.
    \param format the encoding type of the certificates specified by file.
    Possible values include SSL_FILETYPE_PEM and SSL_FILETYPE_ASN1.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_der_load_verify_locations(ctx, “./ca-cert.der”,
                                          SSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
	    // error loading CA certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_load_verify_buffer
*/
int wolfSSL_CTX_der_load_verify_locations(WOLFSSL_CTX* ctx,
                                          const char* file, int format);

/*!
    \ingroup Setup

    \brief This function creates a new SSL context, taking a desired
    SSL/TLS protocol method for input.

    \return pointer If successful the call will return a pointer to the
    newly-created WOLFSSL_CTX.
    \return NULL upon failure.

    \param method pointer to the desired WOLFSSL_METHOD to use for the SSL
    context. This is created using one of the wolfSSLvXX_XXXX_method()
    functions to specify SSL/TLS/DTLS protocol level.
    This function frees the passed in WOLFSSL_METHOD struct on failure.

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    WOLFSSL_METHOD* method = 0;

    method = wolfSSLv3_client_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
    	// context creation failed
    }
    \endcode

    \sa wolfSSL_new
*/
WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD*);

/*!
    \ingroup Setup

    \brief This function creates a new SSL session, taking an already
    created SSL context as input.

    \return * If successful the call will return a pointer to the
    newly-created wolfSSL structure.
    \return NULL Upon failure.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL*     ssl = NULL;
    WOLFSSL_CTX* ctx = 0;

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
	    // context creation failed
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
	    // SSL object creation failed
    }
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL* wolfSSL_new(WOLFSSL_CTX*);

/*!
    \ingroup Setup

    \brief This function assigns a file descriptor (fd) as the
    input/output facility for the SSL connection. Typically this will be
    a socket file descriptor.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG upon failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param fd file descriptor to use with SSL/TLS connection.

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
    	// failed to set SSL file descriptor
    }
    \endcode

    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
*/
int  wolfSSL_set_fd(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief This function assigns a file descriptor (fd) as the
    input/output facility for the SSL connection. Typically this will be
    a socket file descriptor. This is a DTLS specific API because it marks that
    the socket is connected. recvfrom and sendto calls on this fd will have the
    addr and addr_len parameters set to NULL.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG upon failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param fd file descriptor to use with SSL/TLS connection.

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    if (connect(sockfd, peer_addr, peer_addr_len) != 0) {
        // handle connect error
    }
    ...
    ret = wolfSSL_set_dtls_fd_connected(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        // failed to set SSL file descriptor
    }
    \endcode

    \sa wolfSSL_CTX_SetIOSend
    \sa wolfSSL_CTX_SetIORecv
    \sa wolfSSL_SetIOReadCtx
    \sa wolfSSL_SetIOWriteCtx
    \sa wolfDTLS_SetChGoodCb
*/
int wolfSSL_set_dtls_fd_connected(WOLFSSL* ssl, int fd);

/*!
    \ingroup Setup

    \brief Allows setting a callback for a correctly processed and verified DTLS
           client hello. When using a cookie exchange mechanism (either the
           HelloVerifyRequest in DTLS 1.2 or the HelloRetryRequest with a cookie
           extension in DTLS 1.3) this callback is called after the cookie
           exchange has succeeded. This is useful to use one WOLFSSL object as
           the listener for new connections and being able to isolate the
           WOLFSSL object once the ClientHello is verified (either through a
           cookie exchange or just checking if the ClientHello had the correct
           format).
           DTLS 1.2:
           https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.1
           DTLS 1.3:
           https://www.rfc-editor.org/rfc/rfc8446#section-4.2.2

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG upon failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param cb ClientHelloGoodCb callback function pointer.
    \param user_ctx pointer to user context to be passed to callback.

    _Example_
    \code

    // Called when we have verified a connection
    static int chGoodCb(WOLFSSL* ssl, void* arg)
    {
        // setup peer and file descriptors

    }

    if (wolfDTLS_SetChGoodCb(ssl, chGoodCb, NULL) != WOLFSSL_SUCCESS) {
         // error setting callback
    }
    \endcode

    \sa wolfSSL_set_dtls_fd_connected
*/
int wolfDTLS_SetChGoodCb(WOLFSSL* ssl, ClientHelloGoodCb cb, void* user_ctx);

/*!
    \ingroup IO

    \brief Get the name of cipher at priority level passed in.

    \return string Success
    \return 0 Priority is either out of bounds or not valid.

    \param priority Integer representing the priority level of a cipher.

    _Example_
    \code
    printf("The cipher at 1 is %s", wolfSSL_get_cipher_list(1));
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
char* wolfSSL_get_cipher_list(int priority);

/*!
    \ingroup IO

    \brief This function gets the ciphers enabled in wolfSSL.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the buf parameter was NULL or if the
    len argument was less than or equal to zero.
    \return BUFFER_E returned if the buffer is not large enough and
    will overflow.

    \param buf a char pointer representing the buffer.
    \param len the length of the buffer.

    _Example_
    \code
    static void ShowCiphers(void){
	char* ciphers;
	int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

	if(ret == SSL_SUCCES){
	    	printf(“%s\n”, ciphers);
	    }
    }
    \endcode

    \sa GetCipherNames
    \sa wolfSSL_get_cipher_list
    \sa ShowCiphers
*/
int  wolfSSL_get_ciphers(char* buf, int len);

/*!
    \ingroup IO

    \brief This function gets the cipher name in the format DHE-RSA by
    passing through argument to wolfSSL_get_cipher_name_internal.

    \return string This function returns the string representation of the
    cipher suite that was matched.
    \return NULL error or cipher not found.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    char* cipherS = wolfSSL_get_cipher_name(ssl);

    if(cipher == NULL){
	    // There was not a cipher suite matched
    } else {
	    // There was a cipher suite matched
	    printf(“%s\n”, cipherS);
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
*/
const char* wolfSSL_get_cipher_name(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function returns the read file descriptor (fd) used as the
    input facility for the SSL connection.  Typically this
    will be a socket file descriptor.

    \return fd If successful the call will return the SSL session file
    descriptor.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_fd(ssl);
    ...
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_read_fd
    \sa wolfSSL_set_write_fd
*/
int  wolfSSL_get_fd(const WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function returns the write file descriptor (fd) used as the
    output facility for the SSL connection.  Typically this
    will be a socket file descriptor.

    \return fd If successful the call will return the SSL session file
    descriptor.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int sockfd;
    WOLFSSL* ssl = 0;
    ...
    sockfd = wolfSSL_get_wfd(ssl);
    ...
    \endcode

    \sa wolfSSL_set_fd
    \sa wolfSSL_set_read_fd
    \sa wolfSSL_set_write_fd
*/
int  wolfSSL_get_wfd(const WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function informs the WOLFSSL object that the underlying
     I/O is non-blocking. After an application creates a WOLFSSL object,
     if it will be used with a non-blocking socket, call
    wolfSSL_set_using_nonblock() on it. This lets the WOLFSSL object know
     that receiving EWOULDBLOCK means that the recvfrom call would
    block rather than that it timed out.

    \return none No return.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param nonblock value used to set non-blocking flag on WOLFSSL object.
    Use 1 to specify non-blocking, otherwise 0.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_using_nonblock(ssl, 1);
    \endcode

    \sa wolfSSL_get_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
void wolfSSL_set_using_nonblock(WOLFSSL* ssl, int nonblock);

/*!
    \ingroup IO

    \brief This function allows the application to determine if wolfSSL is
    using non-blocking I/O.  If wolfSSL is using non-blocking I/O, this
    function will return 1, otherwise 0. After an application creates a
    WOLFSSL object, if it will be used with a non-blocking socket, call
    wolfSSL_set_using_nonblock() on it. This lets the WOLFSSL object know
    that receiving EWOULDBLOCK means that the recvfrom call would block
    rather than that it timed out.

    \return 0 underlying I/O is blocking.
    \return 1 underlying I/O is non-blocking.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_get_using_nonblock(ssl);
    if (ret == 1) {
    	// underlying I/O is non-blocking
    }
    ...
    \endcode

    \sa wolfSSL_set_session
*/
int  wolfSSL_get_using_nonblock(WOLFSSL*);

/*!
    \ingroup IO

    \brief This function writes sz bytes from the buffer, data, to the SSL
    connection, ssl. If necessary, wolfSSL_write() will negotiate an SSL/TLS
    session if the handshake has not already been performed yet by
    wolfSSL_connect() or wolfSSL_accept(). When using (D)TLSv1.3 and early data
    feature is compiled in, this function progresses the handshake only up to
    the point when it is possible to send data. Next invocations of
    wolfSSL_Connect()/wolfSSL_Accept()/wolfSSL_read() will complete the
    handshake. wolfSSL_write() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_write() will return when
    the underlying I/O could not satisfy the needs of wolfSSL_write() to
    continue.  In this case, a call to wolfSSL_get_error() will yield either
    SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then
    repeat the call to wolfSSL_write() when the underlying I/O is ready. If the
    underlying I/O is blocking, wolfSSL_write() will only return once the buffer
    data of size sz has been completely written or an error occurred.

    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for
    the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_write() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data data buffer which will be sent to peer.
    \param sz size, in bytes, of data to send to the peer (data).

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags;
    int ret;
    ...

    ret = wolfSSL_write(ssl, msg, msgSz);
    if (ret <= 0) {
    	// wolfSSL_write() failed, call wolfSSL_get_error()
    }
    \endcode

    \sa wolfSSL_send
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_write(WOLFSSL* ssl, const void* data, int sz);

/*!
    \ingroup IO

    \brief This function reads sz bytes from the SSL session (ssl)
    internal read buffer into the buffer data. The bytes read are removed
    from the internal receive buffer. If necessary wolfSSL_read() will
    negotiate an SSL/TLS session if the handshake has not already been
    performed yet by wolfSSL_connect() or wolfSSL_accept(). The SSL/TLS
    protocol uses SSL records which have a maximum size of 16kB (the max
    record size can be controlled by the MAX_RECORD_SIZE define in
    <wolfssl_root>/wolfssl/internal.h).  As such, wolfSSL needs to read an
    entire SSL record internally before it is able to process and decrypt the
    record.  Because of this, a call to wolfSSL_read() will only be able to
    return the maximum buffer size which has been decrypted at the time of
    calling.  There may be additional not-yet-decrypted data waiting in the
    internal wolfSSL receive buffer which will be retrieved and decrypted with
    the next call to wolfSSL_read(). If sz is larger than the number of bytes
    in the internal read buffer, SSL_read() will return the bytes available in
    the internal read buffer.  If no bytes are buffered in the internal read
    buffer yet, a call to wolfSSL_read() will trigger processing of the next
    record.

    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure.  This may be caused by a either a
    clean (close notify alert) shutdown or just that the peer closed the
    connection.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_read() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_read() will place data read.
    \param sz number of bytes to read into data.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }

    See wolfSSL examples (client, server, echoclient, echoserver) for more
    complete examples of wolfSSL_read().
    \endcode

    \sa wolfSSL_recv
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
int  wolfSSL_read(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO

    \brief This function copies sz bytes from the SSL session (ssl) internal
    read buffer into the buffer data. This function is identical to
    wolfSSL_read() except that the data in the internal SSL session
    receive buffer is not removed or modified. If necessary, like
    wolfSSL_read(), wolfSSL_peek() will negotiate an SSL/TLS session if
    the handshake has not already been performed yet by wolfSSL_connect()
    or wolfSSL_accept(). The SSL/TLS protocol uses SSL records which have a
    maximum size of 16kB (the max record size can be controlled by the
    MAX_RECORD_SIZE define in <wolfssl_root>/wolfssl/internal.h).  As such,
    wolfSSL needs to read an entire SSL record internally before it is able
    to process and decrypt the record.  Because of this, a call to
    wolfSSL_peek() will only be able to return the maximum buffer size which
    has been decrypted at the time of calling.  There may be additional
    not-yet-decrypted data waiting in the internal wolfSSL receive buffer
    which will be retrieved and decrypted with the next call to
    wolfSSL_peek() / wolfSSL_read(). If sz is larger than the number of bytes
    in the internal read buffer, SSL_peek() will return the bytes available
    in the internal read buffer.  If no bytes are buffered in the internal
    read buffer yet, a call to wolfSSL_peek() will trigger processing of the
    next record.

    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure.  This may be caused by a either
    a clean (close notify alert) shutdown or just that the peer closed the
    connection.  Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an
    error occurred or, when using non-blocking sockets, the
    SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE error was received and and
    the application needs to call wolfSSL_peek() again. Use
    wolfSSL_get_error() to get a specific error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_peek() will place data read.
    \param sz number of bytes to read into data.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    ...

    input = wolfSSL_peek(ssl, reply, sizeof(reply));
    if (input > 0) {
	    // “input” number of bytes returned into buffer “reply”
    }
    \endcode

    \sa wolfSSL_read
*/
int  wolfSSL_peek(WOLFSSL* ssl, void* data, int sz);

/*!
    \ingroup IO

    \brief This function is called on the server side and waits for an SSL
    client to initiate the SSL/TLS handshake.  When this function is called,
    the underlying communication channel has already been set up.
    wolfSSL_accept() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_accept() will return
    when the underlying I/O could not satisfy the needs of wolfSSL_accept
    to continue the handshake.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
    The calling process must then repeat the call to wolfSSL_accept when
    data is available to read and wolfSSL will pick up where it left off.
    When using a non-blocking socket, nothing needs to be done, but select()
    can be used to check for the required condition. If the underlying I/O
    is blocking, wolfSSL_accept() will only return once the handshake has
    been finished or an error occurred.

    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
int  wolfSSL_accept(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function is called on the server side and statelessly listens
    for an SSL client to initiate the DTLS handshake.

    \return WOLFSSL_SUCCESS ClientHello containing a valid cookie was received.
    The connection can be continued with wolfSSL_accept().
    \return WOLFSSL_FAILURE The I/O layer returned WANT_READ. This is either
    because there is no data to read and we are using non-blocking sockets or
    we sent a cookie request and we are waiting for a reply. The user should
    call wolfDTLS_accept_stateless again after data becomes available in
    the I/O layer.
    \return WOLFSSL_FATAL_ERROR A fatal error occurred. The ssl object should be
    free'd and allocated again to continue.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    ...
    do {
        ret = wolfDTLS_accept_stateless(ssl);
        if (ret == WOLFSSL_FATAL_ERROR)
            // re-allocate the ssl object with wolfSSL_free() and wolfSSL_new()
    } while (ret != WOLFSSL_SUCCESS);
    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_accept
    \sa wolfSSL_get_error
    \sa wolfSSL_connect
*/
int  wolfDTLS_accept_stateless(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function frees an allocated WOLFSSL_CTX object.  This
    function decrements the CTX reference count and only frees the context
    when the reference count has reached 0.

    \return none No return.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_free(ctx);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
void wolfSSL_CTX_free(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function frees an allocated wolfSSL object.

    \return none No return.

    \param ssl pointer to the SSL object, created with wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL* ssl = 0;
    ...
    wolfSSL_free(ssl);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_CTX_free
*/
void wolfSSL_free(WOLFSSL* ssl);

/*!
    \ingroup TLS

    \brief This function shuts down an active SSL/TLS connection using
    the SSL session, ssl.  This function will try to send a “close notify”
    alert to the peer. The calling application can choose to wait for the
    peer to send its “close notify” alert in response or just go ahead
    and shut down the underlying connection after directly calling
    wolfSSL_shutdown (to save resources).  Either option is allowed by
    the TLS specification.  If the underlying connection will be used
    again in the future, the complete two-directional shutdown procedure
    must be performed to keep synchronization intact between the peers.
    wolfSSL_shutdown() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_shutdown() will
    return an error if the underlying I/O could not satisfy the needs of
    wolfSSL_shutdown() to continue. In this case, a call to
    wolfSSL_get_error() will yield either SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE.  The calling process must then repeat the call
    to wolfSSL_shutdown() when the underlying I/O is ready.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_SHUTDOWN_NOT_DONE will be returned when shutdown has not
    finished, and the function should be called again.
    \return SSL_FATAL_ERROR will be returned upon failure. Call
    wolfSSL_get_error() for a more specific error code.

    \param ssl pointer to the SSL session created with wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_shutdown(ssl);
    if (ret != 0) {
	    // failed to shut down SSL connection
    }
    \endcode

    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
int  wolfSSL_shutdown(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function writes sz bytes from the buffer, data, to the SSL
    connection, ssl, using the specified flags for the underlying write
    operation. If necessary wolfSSL_send() will negotiate an SSL/TLS session
    if the handshake has not already been performed yet by wolfSSL_connect()
    or wolfSSL_accept(). wolfSSL_send() works with both blocking and
    non-blocking I/O.  When the underlying I/O is non-blocking, wolfSSL_send()
    will return when the underlying I/O could not satisfy the needs of
    wolfSSL_send to continue.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
    The calling process must then repeat the call to wolfSSL_send() when
    the underlying I/O is ready. If the underlying I/O is blocking,
    wolfSSL_send() will only return once the buffer data of size sz has
    been completely written or an error occurred.

    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for
    the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_send() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data data buffer to send to peer.
    \param sz size, in bytes, of data to be sent to peer.
    \param flags the send flags to use for the underlying send operation.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char msg[64] = “hello wolfssl!”;
    int msgSz = (int)strlen(msg);
    int flags = ... ;
    ...

    input = wolfSSL_send(ssl, msg, msgSz, flags);
    if (input != msgSz) {
    	// wolfSSL_send() failed
    }
    \endcode

    \sa wolfSSL_write
    \sa wolfSSL_read
    \sa wolfSSL_recv
*/
int  wolfSSL_send(WOLFSSL* ssl, const void* data, int sz, int flags);

/*!
    \ingroup IO

    \brief This function reads sz bytes from the SSL session (ssl) internal
    read buffer into the buffer data using the specified flags for the
    underlying recv operation.  The bytes read are removed from the internal
    receive buffer.  This function is identical to wolfSSL_read() except
    that it allows the application to set the recv flags for the underlying
    read operation. If necessary wolfSSL_recv() will negotiate an SSL/TLS
    session if the handshake has not already been performed yet by
    wolfSSL_connect() or wolfSSL_accept(). The SSL/TLS protocol uses
    SSL records which have a maximum size of 16kB (the max record size
    can be controlled by the MAX_RECORD_SIZE define in
    <wolfssl_root>/wolfssl/internal.h). As such, wolfSSL needs to read an
    entire SSL record internally before it is able to process and decrypt
    the record. Because of this, a call to wolfSSL_recv() will only be
    able to return the maximum buffer size which has been decrypted at
    the time of calling.  There may be additional not-yet-decrypted data
    waiting in the internal wolfSSL receive buffer which will be
    retrieved and decrypted with the next call to wolfSSL_recv(). If sz
    is larger than the number of bytes in the internal read buffer,
    SSL_recv() will return the bytes available in the internal read buffer.
    If no bytes are buffered in the internal read buffer yet, a call to
    wolfSSL_recv() will trigger processing of the next record.

    \return >0 the number of bytes read upon success.
    \return 0 will be returned upon failure. This may be caused by a either
    a clean (close notify alert) shutdown or just that the peer closed the
    connection. Call wolfSSL_get_error() for the specific error code.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_recv() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param data buffer where wolfSSL_recv() will place data read.
    \param sz number of bytes to read into data.
    \param flags the recv flags to use for the underlying recv operation.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char reply[1024];
    int flags = ... ;
    ...

    input = wolfSSL_recv(ssl, reply, sizeof(reply), flags);
    if (input > 0) {
    	// “input” number of bytes returned into buffer “reply”
    }
    \endcode

    \sa wolfSSL_read
    \sa wolfSSL_write
    \sa wolfSSL_peek
    \sa wolfSSL_pending
*/
int  wolfSSL_recv(WOLFSSL* ssl, void* data, int sz, int flags);

/*!
    \ingroup Debug

    \brief This function returns a unique error code describing why the
    previous API function call (wolfSSL_connect, wolfSSL_accept, wolfSSL_read,
    wolfSSL_write, etc.) resulted in an error return code (SSL_FAILURE).
    The return value of the previous function is passed to wolfSSL_get_error
    through ret. After wolfSSL_get_error is called and returns the unique
    error code, wolfSSL_ERR_error_string() may be called to get a
    human-readable error string.  See wolfSSL_ERR_error_string() for more
    information.

    \return On successful completion, this function will return the
    unique error code describing why the previous API function failed.
    \return SSL_ERROR_NONE will be returned if ret > 0. For ret <= 0, there are
    some cases when this value can also be returned when a previous API appeared
    to return an error code but no error actually occurred. An example is
    calling wolfSSL_read() with a zero sz parameter. A 0 return from
    wolfSSL_read() usually indicates an error but in this case no error
    occurred. If wolfSSL_get_error() is called afterwards, SSL_ERROR_NONE will
    be returned.

    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param ret return value of the previous function that resulted in an error
    return code.

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode

    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
int  wolfSSL_get_error(WOLFSSL* ssl, int ret);

/*!
    \ingroup IO

    \brief This function gets the alert history.

    \return SSL_SUCCESS returned when the function completed successfully.
    Either there was alert history or there wasn’t, either way, the
    return value is SSL_SUCCESS.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param h a pointer to a WOLFSSL_ALERT_HISTORY structure that will hold the
    WOLFSSL struct’s alert_history member’s value.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_ALERT_HISTORY* h;
    ...
    wolfSSL_get_alert_history(ssl, h);
    // h now has a copy of the ssl->alert_history  contents
    \endcode

    \sa wolfSSL_get_error
*/
int  wolfSSL_get_alert_history(WOLFSSL* ssl, WOLFSSL_ALERT_HISTORY *h);

/*!
    \ingroup Setup

    \brief This function sets the session to be used when the SSL object,
    ssl, is used to establish a SSL/TLS connection. For session resumption,
    before calling wolfSSL_shutdown() with your session object, an application
    should save the session ID from the object with a call to
    wolfSSL_get1_session(), which returns a pointer to the session.
    Later, the application should create a new WOLFSSL object and assign
    the saved session with wolfSSL_set_session().  At this point, the
    application may call wolfSSL_connect() and wolfSSL will try to resume
    the session.  The wolfSSL server code allows session resumption by default.
    The object returned by wolfSSL_get1_session() needs to be freed after the
    application is done with it by calling wolfSSL_SESSION_free() on it.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return SSL_FAILURE will be returned on failure.  This could be caused
    by the session cache being disabled, or if the session has timed out.

    \return When OPENSSL_EXTRA and WOLFSSL_ERROR_CODE_OPENSSL are defined,
    SSL_SUCCESS will be returned even if the session has timed out.

    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param session pointer to the WOLFSSL_SESSION used to set the session
    for ssl.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get1_session(ssl);
    if (session == NULL) {
        // failed to get session object from ssl object
    }
    ...
    ret = wolfSSL_set_session(ssl, session);
    if (ret != SSL_SUCCESS) {
    	// failed to set the SSL session
    }
    wolfSSL_SESSION_free(session);
    ...
    \endcode

    \sa wolfSSL_get1_session
*/
int        wolfSSL_set_session(WOLFSSL* ssl, WOLFSSL_SESSION* session);

/*!
    \ingroup IO

    \brief When NO_SESSION_CACHE_REF is defined this function returns a pointer
    to the current session (WOLFSSL_SESSION) used in ssl. This function returns
    a non-persistent pointer to the WOLFSSL_SESSION object. The pointer returned
    will be freed when wolfSSL_free is called. This call should only be used to
    inspect or modify the current session. For session resumption it is
    recommended to use wolfSSL_get1_session(). For backwards compatibility when
    NO_SESSION_CACHE_REF is not defined this function returns a persistent
    session object pointer that is stored in the local cache. The cache size is
    finite and there is a risk that the session object will be overwritten by
    another ssl connection by the time the application calls
    wolfSSL_set_session() on it. It is recommended to define
    NO_SESSION_CACHE_REF in your application and to use wolfSSL_get1_session()
    for session resumption.

    \return pointer If successful the call will return a pointer to the the
    current SSL session object.
    \return NULL will be returned if ssl is NULL, the SSL session cache is
    disabled, wolfSSL doesn’t have the Session ID available, or mutex
    functions fail.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* session;
    ...
    session = wolfSSL_get_session(ssl);
    if (session == NULL) {
	    // failed to get session pointer
    }
    ...
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
WOLFSSL_SESSION* wolfSSL_get_session(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function flushes session from the session cache which
    have expired. The time, tm, is used for the time comparison. Note
    that wolfSSL currently uses a static table for sessions, so no flushing
    is needed. As such, this function is currently just a stub. This
    function provides OpenSSL compatibility (SSL_flush_sessions) when
    wolfSSL is compiled with the OpenSSL compatibility layer.

    \return none No returns.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param tm time used in session expiration comparison.

    _Example_
    \code
    WOLFSSL_CTX* ssl;
    ...
    wolfSSL_flush_sessions(ctx, time(0));
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
void       wolfSSL_flush_sessions(WOLFSSL_CTX* ctx, long tm);

/*!
    \ingroup TLS

    \brief This function associates the client session with the server id.
    If the newSession flag is on, an existing session won’t be reused.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct or id parameter
    is NULL or if len is not greater than zero.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param id a constant byte pointer that will be copied to the
    serverID member of the WOLFSSL_SESSION structure.
    \param len an int type representing the length of the session id parameter.
    \param newSession an int type representing the flag to denote whether
    to reuse a session or not.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    const byte id[MAX_SIZE];  // or dynamically create space
    int len = 0; // initialize length
    int newSession = 0; // flag to allow
    …
    int ret = wolfSSL_SetServerID(ssl, id, len, newSession);

    if (ret == WOLFSSL_SUCCESS) {
	    // The Id was successfully set
    }
    \endcode

    \sa wolfSSL_set_session
*/
int        wolfSSL_SetServerID(WOLFSSL* ssl, const unsigned char* id,
                                         int len, int newSession);

/*!
    \ingroup IO

    \brief This function gets the session index of the WOLFSSL structure.

    \return int The function returns an int type representing the
    sessionIndex within the WOLFSSL struct.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int sesIdx = wolfSSL_GetSessionIndex(ssl);

    if(sesIdx < 0 || sesIdx > sizeof(ssl->sessionIndex)/sizeof(int)){
    	// You have an out of bounds index number and something is not right.
    }
    \endcode

    \sa wolfSSL_GetSessionAtIndex
*/
int wolfSSL_GetSessionIndex(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function gets the session at specified index of the session
    cache and copies it into memory. The WOLFSSL_SESSION structure holds
    the session information.

    \return SSL_SUCCESS returned if the function executed successfully and
    no errors were thrown.
    \return BAD_MUTEX_E returned if there was an unlock or lock mutex error.
    \return SSL_FAILURE returned if the function did not execute successfully.

    \param index an int type representing the session index.
    \param session a pointer to the WOLFSSL_SESSION structure.

    _Example_
    \code
    int idx; // The index to locate the session.
    WOLFSSL_SESSION* session;  // Buffer to copy to.
    ...
    if(wolfSSL_GetSessionAtIndex(idx, session) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode

    \sa UnLockMutex
    \sa LockMutex
    \sa wolfSSL_GetSessionIndex
*/
int wolfSSL_GetSessionAtIndex(int index, WOLFSSL_SESSION* session);

/*!
    \ingroup IO

    \brief Returns the peer certificate chain from the WOLFSSL_SESSION struct.

    \return pointer A pointer to a WOLFSSL_X509_CHAIN structure that
    contains the peer certification chain.

    \param session a pointer to a WOLFSSL_SESSION structure.

    _Example_
    \code
    WOLFSSL_SESSION* session;
    WOLFSSL_X509_CHAIN* chain;
    ...
    chain = wolfSSL_SESSION_get_peer_chain(session);
    if(!chain){
    	// There was no chain. Failure case.
    }
    \endcode

    \sa wolfSSL_GetSessionAtIndex
    \sa wolfSSL_GetSessionIndex
    \sa AddSession
*/

    WOLFSSL_X509_CHAIN* wolfSSL_SESSION_get_peer_chain(WOLFSSL_SESSION* session);

/*!
    \ingroup Setup

    \brief This function sets the verification method for remote peers and
    also allows a verify callback to be registered with the SSL context.
    The verify callback will be called only when a verification failure has
    occurred.  If no verify callback is desired, the NULL pointer can be used
    for verify_callback. The verification mode of peer certificates is a
    logically OR’d list of flags.  The possible flag values include:
    SSL_VERIFY_NONE Client mode: the client will not verify the certificate
    received from the server and the handshake will continue as normal.
    Server mode: the server will not send a certificate request to the client.
    As such, client verification will not be enabled. SSL_VERIFY_PEER Client
    mode: the client will verify the certificate received from the server
    during the handshake.  This is turned on by default in wolfSSL, therefore,
    using this option has no effect. Server mode: the server will send a
    certificate request to the client and verify the client certificate
    received. SSL_VERIFY_FAIL_IF_NO_PEER_CERT Client mode: no effect when
    used on the client side. Server mode: the verification will fail on the
    server side if the client fails to send a certificate when requested to
    do so (when using SSL_VERIFY_PEER on the SSL server).
    SSL_VERIFY_FAIL_EXCEPT_PSK Client mode: no effect when used on the client
    side. Server mode: the verification is the same as
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT except in the case of a PSK connection.
    If a PSK connection is being made then the connection will go through
    without a peer cert.

    \return none No return.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode flags indicating verification mode for peer's cert.
    \param verify_callback callback to be called when verification fails.
    If no callback is desired, the NULL pointer can be used for
    verify_callback.

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    wolfSSL_CTX_set_verify(ctx, (WOLFSSL_VERIFY_PEER |
                           WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT), NULL);
    \endcode

    \sa wolfSSL_set_verify
*/
void wolfSSL_CTX_set_verify(WOLFSSL_CTX* ctx, int mode,
                                      VerifyCallback verify_callback);

/*!
    \ingroup Setup

    \brief This function sets the verification method for remote peers and
    also allows a verify callback to be registered with the SSL session.
    The verify callback will be called only when a verification failure has
    occurred. If no verify callback is desired, the NULL pointer can be used
    for verify_callback. The verification mode of peer certificates is a
    logically OR’d list of flags.  The possible flag values include:
    SSL_VERIFY_NONE Client mode: the client will not verify the certificate
    received from the server and the handshake will continue as normal. Server
    mode: the server will not send a certificate request to the client.
    As such, client verification will not be enabled. SSL_VERIFY_PEER Client
    mode: the client will verify the certificate received from the server
    during the handshake. This is turned on by default in wolfSSL, therefore,
    using this option has no effect. Server mode: the server will send a
    certificate request to the client and verify the client certificate
    received. SSL_VERIFY_FAIL_IF_NO_PEER_CERT Client mode: no effect when
    used on the client side. Server mode: the verification will fail on the
    server side if the client fails to send a certificate when requested to do
    so (when using SSL_VERIFY_PEER on the SSL server).
    SSL_VERIFY_FAIL_EXCEPT_PSK Client mode: no effect when used on the client
    side. Server mode: the verification is the same as
    SSL_VERIFY_FAIL_IF_NO_PEER_CERT except in the case of a PSK connection.
    If a PSK connection is being made then the connection will go through
    without a peer cert.

    \return none No return.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param mode flags indicating verification mode for peer's cert.
    \param verify_callback callback to be called when verification fails.
    If no callback is desired, the NULL pointer can
    be used for verify_callback.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    \endcode

    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_set_verify(WOLFSSL* ssl, int mode, VerifyCallback verify_callback);

/*!
    \ingroup CertsKeys

    \brief This function stores user CTX object information for verify callback.

    \return none No return.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx a void pointer that is set to WOLFSSL structure’s verifyCbCtx
    member’s value.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    (void*)ctx;
    ...
    if(ssl != NULL){
    wolfSSL_SetCertCbCtx(ssl, ctx);
    } else {
	    // Error case, the SSL is not initialized properly.
    }
    \endcode

    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_SetCertCbCtx(WOLFSSL* ssl, void* ctx);

/*!
    \ingroup CertsKeys

    \brief This function stores user CTX object information for verify callback.

    \return none No return.

    \param ctx a pointer to a WOLFSSL_CTX structure.
    \param userCtx a void pointer that is used to set WOLFSSL_CTX structure’s
    verifyCbCtx member’s value.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    void* userCtx = NULL; // Assign some user defined context
    ...
    if(ctx != NULL){
        wolfSSL_SetCertCbCtx(ctx, userCtx);
    } else {
        // Error case, the SSL is not initialized properly.
    }
    \endcode

    \sa wolfSSL_CTX_save_cert_cache
    \sa wolfSSL_CTX_restore_cert_cache
    \sa wolfSSL_CTX_set_verify
*/
void wolfSSL_CTX_SetCertCbCtx(WOLFSSL_CTX* ctx, void* userCtx);

/*!
    \ingroup IO

    \brief This function returns the number of bytes which are buffered and
    available in the SSL object to be read by wolfSSL_read().

    \return int This function returns the number of bytes pending.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int pending = 0;
    WOLFSSL* ssl = 0;
    ...

    pending = wolfSSL_pending(ssl);
    printf(“There are %d bytes buffered and available for reading”, pending);
    \endcode

    \sa wolfSSL_recv
    \sa wolfSSL_read
    \sa wolfSSL_peek
*/
int  wolfSSL_pending(WOLFSSL* ssl);

/*!
    \ingroup Debug

    \brief This function is for OpenSSL compatibility (SSL_load_error_string)
    only and takes no action.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_load_error_strings();
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
void wolfSSL_load_error_strings(void);

/*!
    \ingroup TLS

    \brief This function is called internally in wolfSSL_CTX_new(). This
    function is a wrapper around wolfSSL_Init() and exists for OpenSSL
    compatibility (SSL_library_init) when wolfSSL has been compiled with
    OpenSSL compatibility layer.  wolfSSL_Init() is the more typically-used
    wolfSSL initialization function.

    \return SSL_SUCCESS If successful the call will return.
    \return SSL_FATAL_ERROR is returned upon failure.

    \param none No parameters.

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_library_init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL
    }
    ...
    \endcode

    \sa wolfSSL_Init
    \sa wolfSSL_Cleanup
*/
int  wolfSSL_library_init(void);

/*!
    \brief This function sets the Device Id at the WOLFSSL session level.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    WOLFSSL* ssl;
    int DevId = -2;

    wolfSSL_SetDevId(ssl, devId);

    \endcode

    \sa wolfSSL_CTX_SetDevId
    \sa wolfSSL_CTX_GetDevId
*/
int wolfSSL_SetDevId(WOLFSSL* ssl, int devId);

/*!
    \brief This function sets the Device Id at the WOLFSSL_CTX context level.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param devId ID to use with crypto callbacks or async hardware. Set to INVALID_DEVID (-2) if not used

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int DevId = -2;

    wolfSSL_CTX_SetDevId(ctx, devId);

    \endcode

    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_GetDevId
*/
int wolfSSL_CTX_SetDevId(WOLFSSL_CTX* ctx, int devId);

/*!
    \brief This function retrieves the Device Id.

    \return devId upon success.
    \return INVALID_DEVID if both ssl and ctx are NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param ssl pointer to a SSL object, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx;

    wolfSSL_CTX_GetDevId(ctx, ssl);

    \endcode

    \sa wolfSSL_SetDevId
    \sa wolfSSL_CTX_SetDevId

*/
int wolfSSL_CTX_GetDevId(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function enables or disables SSL session caching.
    Behavior depends on the value used for mode. The following values
    for mode are available: SSL_SESS_CACHE_OFF- disable session caching.
    Session caching is turned on by default. SSL_SESS_CACHE_NO_AUTO_CLEAR -
    Disable auto-flushing of the session cache. Auto-flushing is turned on
    by default.

    \return SSL_SUCCESS will be returned upon success.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode modifier used to change behavior of the session cache.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (ret != SSL_SUCCESS) {
    	// failed to turn SSL session caching off
    }
    \endcode

    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_timeout
*/
long wolfSSL_CTX_set_session_cache_mode(WOLFSSL_CTX* ctx, long mode);

/*!
    \brief This function sets the session secret callback function. The
    SessionSecretCb type has the signature: int (*SessionSecretCb)(WOLFSSL* ssl,
    void* secret, int* secretSz, void* ctx). The sessionSecretCb member of
    the WOLFSSL struct is set to the parameter cb.

    \return SSL_SUCCESS returned if the execution of the function did not
    return an error.
    \return SSL_FATAL_ERROR returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a SessionSecretCb type that is a function pointer with the above
    signature.
    \param ctx a pointer to the user context to be stored

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    // Signature of SessionSecretCb
    int SessionSecretCB (WOLFSSL* ssl, void* secret, int* secretSz,
    void* ctx) = SessionSecretCb;
    …
    int wolfSSL_set_session_secret_cb(ssl, SessionSecretCB, (void*)ssl->ctx){
	    // Function body.
    }
    \endcode

    \sa SessionSecretCb
*/
int  wolfSSL_set_session_secret_cb(WOLFSSL* ssl, SessionSecretCb cb, void* ctx);

/*!
    \ingroup IO

    \brief This function persists the session cache to file. It doesn’t use
    memsave because of additional memory use.

    \return SSL_SUCCESS returned if the function executed without error.
    The session cache has been written to a file.
    \return SSL_BAD_FILE returned if fname cannot be opened or is otherwise
    corrupt.
    \return FWRITE_ERROR returned if XFWRITE failed to write to the file.
    \return BAD_MUTEX_E returned if there was a mutex lock failure.

    \param fname is a constant char pointer that points to a file for writing.

    _Example_
    \code
    const char* fname;
    ...
    if(wolfSSL_save_session_cache(fname) != SSL_SUCCESS){
    	// Fail to write to file.
    }
    \endcode

    \sa XFWRITE
    \sa wolfSSL_restore_session_cache
    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_save_session_cache(const char* fname);

/*!
    \ingroup IO

    \brief This function restores the persistent session cache from file. It
    does not use memstore because of additional memory use.

    \return SSL_SUCCESS returned if the function executed without error.
    \return SSL_BAD_FILE returned if the file passed into the function was
    corrupted and could not be opened by XFOPEN.
    \return FREAD_ERROR returned if the file had a read error from XFREAD.
    \return CACHE_MATCH_ERROR returned if the session cache header match
    failed.
    \return BAD_MUTEX_E returned if there was a mutex lock failure.

    \param fname a constant char pointer file input that will be read.

    _Example_
    \code
    const char *fname;
    ...
    if(wolfSSL_restore_session_cache(fname) != SSL_SUCCESS){
        // Failure case. The function did not return SSL_SUCCESS.
    }
    \endcode

    \sa XFREAD
    \sa XFOPEN
*/
int  wolfSSL_restore_session_cache(const char* fname);

/*!
    \ingroup IO

    \brief This function persists session cache to memory.

    \return SSL_SUCCESS returned if the function executed without error.
    The session cache has been successfully persisted to memory.
    \return BAD_MUTEX_E returned if there was a mutex lock error.
    \return BUFFER_E returned if the buffer size was too small.

    \param mem a void pointer representing the destination for the memory
    copy, XMEMCPY().
    \param sz an int type representing the size of mem.

    _Example_
    \code
    void* mem;
    int sz; // Max size of the memory buffer.
    …
    if(wolfSSL_memsave_session_cache(mem, sz) != SSL_SUCCESS){
    	// Failure case, you did not persist the session cache to memory
    }
    \endcode

    \sa XMEMCPY
    \sa wolfSSL_get_session_cache_memsize
*/
int  wolfSSL_memsave_session_cache(void* mem, int sz);

/*!
    \ingroup IO

    \brief This function restores the persistent session cache from memory.

    \return SSL_SUCCESS returned if the function executed without an error.
    \return BUFFER_E returned if the memory buffer is too small.
    \return BAD_MUTEX_E returned if the session cache mutex lock failed.
    \return CACHE_MATCH_ERROR returned if the session cache header match
    failed.

    \param mem a constant void pointer containing the source of the
    restoration.
    \param sz an integer representing the size of the memory buffer.

    _Example_
    \code
    const void* memoryFile;
    int szMf;
    ...
    if(wolfSSL_memrestore_session_cache(memoryFile, szMf) != SSL_SUCCESS){
    	// Failure case. SSL_SUCCESS was not returned.
    }
    \endcode

    \sa wolfSSL_save_session_cache
*/
int  wolfSSL_memrestore_session_cache(const void* mem, int sz);

/*!
    \ingroup IO

    \brief This function returns how large the session cache save buffer
    should be.

    \return int This function returns an integer that represents the size of
    the session cache save buffer.

    \param none No parameters.

    _Example_
    \code
    int sz = // Minimum size for error checking;
    ...
    if(sz < wolfSSL_get_session_cache_memsize()){
        // Memory buffer is too small
    }
    \endcode

    \sa wolfSSL_memrestore_session_cache
*/
int  wolfSSL_get_session_cache_memsize(void);

/*!
    \ingroup CertsKeys

    \brief This function writes the cert cache from memory to file.

    \return SSL_SUCCESS if CM_SaveCertCache exits normally.
    \return BAD_FUNC_ARG is returned if either of the arguments are NULL.
    \return SSL_BAD_FILE if the cert cache save file could not be opened.
    \return BAD_MUTEX_E if the lock mutex failed.
    \return MEMORY_E the allocation of memory failed.
    \return FWRITE_ERROR Certificate cache file write failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, holding the
    certificate information.
    \param fname  a constant char pointer that points to a file for writing.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    const char* fname;
    ...
    if(wolfSSL_CTX_save_cert_cache(ctx, fname)){
	    // file was written.
    }
    \endcode

    \sa CM_SaveCertCache
    \sa DoMemSaveCertCache
*/
int  wolfSSL_CTX_save_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys

    \brief This function persistes certificate cache from a file.

    \return SSL_SUCCESS returned if the function, CM_RestoreCertCache,
    executes normally.
    \return SSL_BAD_FILE returned if XFOPEN returns XBADFILE. The file is
    corrupted.
    \return MEMORY_E returned if the allocated memory for the temp buffer
    fails.
    \return BAD_FUNC_ARG returned if fname or ctx have a NULL value.

    \param ctx a pointer to a WOLFSSL_CTX structure, holding the certificate
    information.
    \param fname a constant char pointer that points to a file for reading.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* fname = "path to file";
    ...
    if(wolfSSL_CTX_restore_cert_cache(ctx, fname)){
    	// check to see if the execution was successful
    }
    \endcode

    \sa CM_RestoreCertCache
    \sa XFOPEN
*/
int  wolfSSL_CTX_restore_cert_cache(WOLFSSL_CTX* ctx, const char* fname);

/*!
    \ingroup CertsKeys

    \brief This function persists the certificate cache to memory.

    \return SSL_SUCCESS returned on successful execution of the function.
    No errors were thrown.
    \return BAD_MUTEX_E mutex error where the WOLFSSL_CERT_MANAGER member
    caLock was not 0 (zero).
    \return BAD_FUNC_ARG returned if ctx, mem, or used is NULL or if sz
    is less than or equal to 0 (zero).
    \return BUFFER_E output buffer mem was too small.

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    using wolfSSL_CTX_new().
    \param mem a void pointer to the destination (output buffer).
    \param sz the size of the output buffer.
    \param used a pointer to size of the cert cache header.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol );
    void* mem;
    int sz;
    int* used;
    ...
    if(wolfSSL_CTX_memsave_cert_cache(ctx, mem, sz, used) != SSL_SUCCESS){
	    // The function returned with an error
    }
    \endcode

    \sa DoMemSaveCertCache
    \sa GetCertCacheMemSize
    \sa CM_MemRestoreCertCache
    \sa CM_GetCertCacheMemSize
*/
int  wolfSSL_CTX_memsave_cert_cache(WOLFSSL_CTX* ctx, void* mem, int sz, int* used);

/*!
    \ingroup Setup

    \brief This function restores the certificate cache from memory.

    \return SSL_SUCCESS returned if the function and subroutines
    executed without an error.
    \return BAD_FUNC_ARG returned if the ctx or mem parameters are
    NULL or if the sz parameter is less than or equal to zero.
    \return BUFFER_E returned if the cert cache memory buffer is too small.
    \return CACHE_MATCH_ERROR returned if there was a cert cache
    header mismatch.
    \return BAD_MUTEX_E returned if the lock mutex on failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param mem a void pointer with a value that will be restored to
    the certificate cache.
    \param sz an int type that represents the size of the mem parameter.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    void* mem;
    int sz = (*int) sizeof(mem);
    …
    if(wolfSSL_CTX_memrestore_cert_cache(ssl->ctx, mem, sz)){
    	// The success case
    }
    \endcode

    \sa CM_MemRestoreCertCache
*/
int  wolfSSL_CTX_memrestore_cert_cache(WOLFSSL_CTX* ctx, const void* mem, int sz);

/*!
    \ingroup CertsKeys

    \brief Returns the size the certificate cache save buffer needs to be.

    \return int integer value returned representing the memory size
    upon success.
    \return BAD_FUNC_ARG is returned if the WOLFSSL_CTX struct is NULL.
    \return BAD_MUTEX_E - returned if there was a mutex lock error.

    \param ctx a pointer to a wolfSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol);
    ...
    int certCacheSize = wolfSSL_CTX_get_cert_cache_memsize(ctx);

    if(certCacheSize != BAD_FUNC_ARG || certCacheSize != BAD_MUTEX_E){
	// Successfully retrieved the memory size.
    }
    \endcode

    \sa CM_GetCertCacheMemSize
*/
int  wolfSSL_CTX_get_cert_cache_memsize(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function sets the cipher suite list for a given WOLFSSL_CTX.
    The list becomes the default cipher suite list for any new WOLFSSL
    sessions created from the context, and the order in the string is the
    local preference order from highest to lowest. Each call replaces the
    previous list. The list is a null-terminated, colon-delimited text
    string of suite names and/or OpenSSL-style group keywords, for example
    "TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA256".

    Each token in the colon-delimited list is one of the following:

    1. A specific cipher suite name. wolfSSL accepts both its own short name
       and the IANA name (when WOLFSSL_NO_ERROR_STRINGS is not defined). For
       example "ECDHE-RSA-AES128-GCM-SHA256" and
       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" are equivalent. The complete
       authoritative list of accepted names lives in the cipher_names[] array
       in src/internal.c; programs may also enumerate the suites compiled
       into the current build at runtime via wolfSSL_get_ciphers().

    2. An OpenSSL-compatible keyword that selects a family of suites or
       toggles a class on/off (see the keyword table below). Some keywords
       require OPENSSL_EXTRA or OPENSSL_ALL to be defined.

    3. A negated keyword "!keyword" to disallow a class (requires
       OPENSSL_EXTRA or OPENSSL_ALL). For example "HIGH:!aNULL".

    A "+" operator (e.g. "ECDHE+AESGCM") is recognized only to extract the
    leading public-key family token ("ECDHE", "RSA" or "DHE"); trailing parts
    after "+" are ignored by wolfSSL. To intersect with a specific cipher
    use the explicit suite name instead.

    OpenSSL-compatible group keywords:

    | Keyword           | Effect                                                       | Required build option |
    | ----------------- | ------------------------------------------------------------ | --------------------- |
    | DEFAULT / ALL     | Include all built suites; "ALL" also enables anonymous (aNULL) | OPENSSL_EXTRA / OPENSSL_ALL (also accepted as the entire string with no other tokens) |
    | HIGH              | All suites except static, anonymous, and NULL ciphers        | OPENSSL_EXTRA / OPENSSL_ALL (also accepted as the entire string with no other tokens) |
    | LOW / MEDIUM      | Accepted but do not restrict by bit size; behave as "RSA"    | OPENSSL_EXTRA / OPENSSL_ALL |
    | aNULL             | Anonymous (no authentication) suites                         | OPENSSL_EXTRA / OPENSSL_ALL; suites require HAVE_ANON |
    | eNULL / NULL      | Null encryption suites                                       | OPENSSL_EXTRA / OPENSSL_ALL; suites require HAVE_NULL_CIPHER |
    | kDH               | Static DH key exchange                                       | OPENSSL_EXTRA / OPENSSL_ALL |
    | DHE / EDH         | Ephemeral DH key exchange                                    | OPENSSL_EXTRA / OPENSSL_ALL; suites require !NO_DH |
    | ECDHE / EECDH     | Ephemeral ECDH key exchange                                  | OPENSSL_EXTRA / OPENSSL_ALL; suites require HAVE_ECC |
    | kRSA / RSA        | Static RSA key exchange                                      | OPENSSL_EXTRA / OPENSSL_ALL; suites require !NO_RSA |
    | PSK               | Pre-shared-key suites                                        | OPENSSL_EXTRA / OPENSSL_ALL; suites require !NO_PSK |
    | DSS               | Silently ignored — wolfSSL has no DSA ciphersuites           | OPENSSL_EXTRA / OPENSSL_ALL |
    | EXP / EXPORT      | Silently ignored — export-grade ciphers are not supported    | OPENSSL_EXTRA / OPENSSL_ALL |
    | AES128 / SHA1 / RC4 | When negated ("!AES128", etc.), disable that class         | WOLFSSL_SYS_CRYPTO_POLICY |
    | @SECLEVEL=n       | Set OpenSSL-compatible security level                        | WOLFSSL_SYS_CRYPTO_POLICY |

    Representative TLS 1.3 cipher suite names (each guarded by its own
    BUILD_* macro; most are enabled automatically by --enable-tls13):

    | Name (wolfSSL)               | IANA name                       | Required build option |
    | ---------------------------- | ------------------------------- | --------------------- |
    | TLS13-AES128-GCM-SHA256      | TLS_AES_128_GCM_SHA256          | BUILD_TLS_AES_128_GCM_SHA256 (default with TLS 1.3) |
    | TLS13-AES256-GCM-SHA384      | TLS_AES_256_GCM_SHA384          | BUILD_TLS_AES_256_GCM_SHA384 |
    | TLS13-CHACHA20-POLY1305-SHA256 | TLS_CHACHA20_POLY1305_SHA256  | BUILD_TLS_CHACHA20_POLY1305_SHA256 (HAVE_CHACHA + HAVE_POLY1305) |
    | TLS13-AES128-CCM-SHA256      | TLS_AES_128_CCM_SHA256          | BUILD_TLS_AES_128_CCM_SHA256 (HAVE_AESCCM) |
    | TLS13-AES128-CCM-8-SHA256    | TLS_AES_128_CCM_8_SHA256        | BUILD_TLS_AES_128_CCM_8_SHA256 (HAVE_AESCCM) |
    | TLS13-SM4-GCM-SM3            | TLS_SM4_GCM_SM3                 | BUILD_TLS_SM4_GCM_SM3 (WOLFSSL_SM4_GCM + WOLFSSL_SM3) |
    | TLS13-SM4-CCM-SM3            | TLS_SM4_CCM_SM3                 | BUILD_TLS_SM4_CCM_SM3 (WOLFSSL_SM4_CCM + WOLFSSL_SM3) |
    | TLS13-SHA256-SHA256          | TLS_SHA256_SHA256               | BUILD_TLS_SHA256_SHA256 (integrity-only) |
    | TLS13-SHA384-SHA384          | TLS_SHA384_SHA384               | BUILD_TLS_SHA384_SHA384 |

    Representative TLS 1.2 cipher suite name families (each individual suite
    is guarded by its own BUILD_* macro derived from the IANA name; the
    common build-option requirements are summarized below):

    | Name family / example                         | Typical requirements |
    | --------------------------------------------- | -------------------- |
    | ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-ECDSA-CHACHA20-POLY1305 | HAVE_ECC, HAVE_AESGCM (or HAVE_CHACHA + HAVE_POLY1305) |
    | ECDHE-RSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-CHACHA20-POLY1305 | HAVE_ECC, !NO_RSA, HAVE_AESGCM (or HAVE_CHACHA + HAVE_POLY1305) |
    | DHE-RSA-AES128-GCM-SHA256, DHE-RSA-AES256-GCM-SHA384, DHE-RSA-CHACHA20-POLY1305 | !NO_DH, !NO_RSA, HAVE_AESGCM (or HAVE_CHACHA + HAVE_POLY1305) |
    | AES128-SHA, AES256-SHA, AES128-SHA256, AES256-SHA256, AES128-GCM-SHA256, AES256-GCM-SHA384 (static-RSA) | !NO_RSA, !NO_AES_CBC and/or HAVE_AESGCM |
    | DES-CBC3-SHA, RC4-SHA, RC4-MD5                | Legacy: !NO_DES3 / !NO_RC4, !NO_OLD_TLS |
    | NULL-SHA, NULL-SHA256, NULL-MD5               | HAVE_NULL_CIPHER |
    | PSK-AES128-CBC-SHA256, PSK-AES256-GCM-SHA384, ECDHE-PSK-AES128-CBC-SHA256, DHE-PSK-AES256-GCM-SHA384 | !NO_PSK (HAVE_ECC for ECDHE-PSK, !NO_DH for DHE-PSK) |
    | ADH-AES128-SHA, ADH-AES256-SHA                | HAVE_ANON |
    | ECDHE-ECDSA-SM4-GCM-SM3, ECDHE-ECDSA-SM4-CCM-SM3 | WOLFSSL_SM2, WOLFSSL_SM3, WOLFSSL_SM4_GCM/WOLFSSL_SM4_CCM |

    Notes:
    - TLS 1.3 suite names and TLS 1.2 suite names may be mixed in the same
      list; wolfSSL groups them by version internally.
    - For DTLS, RC4-based stream ciphers in the list are silently dropped.
    - When set as the literal whole-string "DEFAULT", "ALL", "HIGH", or the
      empty string, wolfSSL installs its built-in default suite list and
      returns success without parsing further tokens.

    \return WOLFSSL_SUCCESS will be returned upon successful function completion.
    \return WOLFSSL_FAILURE will be returned on failure.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param list null-terminated text string and a colon-delimited list of
    cipher suites and/or keywords to use with the specified SSL context.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_cipher_list(ctx,
        "TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "DHE-RSA-AES256-SHA256");
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set cipher suite list
    }
    \endcode

    \sa wolfSSL_set_cipher_list
    \sa wolfSSL_get_ciphers
    \sa wolfSSL_get_cipher_list
    \sa wolfSSL_CTX_new
*/
int  wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);

/*!
    \ingroup Setup

    \brief This function sets the cipher suite list for a given WOLFSSL
    session. The list format and the set of recognized suite names and
    keywords are identical to those documented for wolfSSL_CTX_set_cipher_list();
    refer to that function for the full keyword/suite tables and required
    build options. Each call replaces the previous list on the session.

    \return WOLFSSL_SUCCESS will be returned upon successful function completion.
    \return WOLFSSL_FAILURE will be returned on failure.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param list null-terminated text string and a colon-delimited list of
    cipher suites and/or keywords to use with the specified SSL session.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_cipher_list(ssl,
        "TLS13-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "DHE-RSA-AES256-SHA256");
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set cipher suite list
    }
    \endcode

    \sa wolfSSL_CTX_set_cipher_list
    \sa wolfSSL_get_ciphers
    \sa wolfSSL_get_cipher_list
    \sa wolfSSL_new
*/
int  wolfSSL_set_cipher_list(WOLFSSL* ssl, const char* list);

/*!
    \brief This function informs the WOLFSSL DTLS object that the underlying
     UDP I/O is non-blocking. After an application creates a WOLFSSL object,
     if it will be used with a non-blocking UDP socket, call
    wolfSSL_dtls_set_using_nonblock() on it. This lets the WOLFSSL object know
     that receiving EWOULDBLOCK means that the recvfrom call would
    block rather than that it timed out.

    \return none No return.

    \param ssl pointer to the DTLS session, created with wolfSSL_new().
    \param nonblock value used to set non-blocking flag on WOLFSSL object.
    Use 1 to specify non-blocking, otherwise 0.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    wolfSSL_dtls_set_using_nonblock(ssl, 1);
    \endcode

    \sa wolfSSL_dtls_get_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
void wolfSSL_dtls_set_using_nonblock(WOLFSSL* ssl, int nonblock);
/*!
    \brief This function allows the application to determine if wolfSSL is
    using non-blocking I/O with UDP. If wolfSSL is using non-blocking I/O, this
    function will return 1, otherwise 0. After an application creates a
    WOLFSSL object, if it will be used with a non-blocking UDP socket, call
    wolfSSL_dtls_set_using_nonblock() on it. This lets the WOLFSSL object know
    that receiving EWOULDBLOCK means that the recvfrom call would block
    rather than that it timed out. This function is only meaningful to DTLS
    sessions.

    \return 0 underlying I/O is blocking.
    \return 1 underlying I/O is non-blocking.

    \param ssl pointer to the DTLS session, created with wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_dtls_get_using_nonblock(ssl);
    if (ret == 1) {
    	// underlying I/O is non-blocking
    }
    ...
    \endcode

    \sa wolfSSL_dtls_set_using_nonblock
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_using_nonblock
*/
int  wolfSSL_dtls_get_using_nonblock(WOLFSSL* ssl);
/*!
    \brief This function returns the current timeout value in seconds for
    the WOLFSSL object. When using non-blocking sockets, something in the user
    code needs to decide when to check for available recv data and how long
    it has been waiting. The value returned by this function indicates how
    long the application should wait.

    \return seconds The current DTLS timeout value in seconds
    \return NOT_COMPILED_IN if wolfSSL was not built with DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int timeout = 0;
    WOLFSSL* ssl;
    ...
    timeout = wolfSSL_get_dtls_current_timeout(ssl);
    printf(“DTLS timeout (sec) = %d\n”, timeout);
    \endcode

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls_get_current_timeout(WOLFSSL* ssl);
/*!
    \brief This function returns true if the application should setup a quicker
    timeout. When using non-blocking sockets, something in the user code needs
    to decide when to check for available data and how long it needs to wait. If
    this function returns true, it means that the library already detected some
    disruption in the communication, but it wants to wait for a little longer in
    case some messages from the other peers are still in flight. Is up to the
    application to fine tune the value of this timer, a good one may be
    dtls_get_current_timeout() / 4.

    \return true if the application code should setup a quicker timeout

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_set_send_more_acks
*/
int  wolfSSL_dtls13_use_quick_timeout(WOLFSSL *ssl);
/*!
  \ingroup Setup

    \brief This function sets whether the library should send ACKs to the other
    peer immediately when detecting disruption or not. Sending ACKs immediately
    assures minimum latency but it may consume more bandwidth than necessary. If
    the application manages the timer by itself and this option is set to 0 then
    application code can use wolfSSL_dtls13_use_quick_timeout() to determine if
    it should setup a quicker timeout to send those delayed ACKs.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param value 1 to set the option, 0 to disable the option

    \sa wolfSSL_dtls
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls13_use_quick_timeout
*/
void  wolfSSL_dtls13_set_send_more_acks(WOLFSSL *ssl, int value);

/*!
    \ingroup Setup

    \brief This function sets the dtls timeout.

    \return SSL_SUCCESS returned if the function executes without an error.
    The dtls_timeout_init and the dtls_timeout members of SSL have been set.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if
    the timeout is not greater than 0. It will also return if the timeout
    argument exceeds the maximum value allowed.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param timeout an int type that will be set to the dtls_timeout_init
    member of the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUT;
    ...
    if(wolfSSL_dtls_set_timeout_init(ssl, timeout)){
    	// the dtls timeout was set
    } else {
    	// Failed to set DTLS timeout.
    }
    \endcode

    \sa wolfSSL_dtls_set_timeout_max
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_init(WOLFSSL* ssl, int timeout);

/*!
    \brief This function sets the maximum dtls timeout.

    \return SSL_SUCCESS returned if the function executed without an error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if
    the timeout argument is not greater than zero or is less than the
    dtls_timeout_init member of the WOLFSSL structure.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param timeout an int type representing the dtls maximum timeout.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int timeout = TIMEOUTVAL;
    ...
    int ret = wolfSSL_dtls_set_timeout_max(ssl);
    if(!ret){
    	// Failed to set the max timeout
    }
    \endcode

    \sa wolfSSL_dtls_set_timeout_init
    \sa wolfSSL_dtls_got_timeout
*/
int  wolfSSL_dtls_set_timeout_max(WOLFSSL* ssl, int timeout);

/*!
    \brief When using non-blocking sockets with DTLS, this function should
    be called on the WOLFSSL object when the controlling code thinks the
    transmission has timed out. It performs the actions needed to retry
    the last transmit, including adjusting the timeout value. If it
    has been too long, this will return a failure.

    \return SSL_SUCCESS will be returned upon success
    \return SSL_FATAL_ERROR will be returned if there have been too many
    retransmissions/timeouts without getting a response from the peer.
    \return NOT_COMPILED_IN will be returned if wolfSSL was not compiled with
    DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    See the following files for usage examples:
    <wolfssl_root>/examples/client/client.c
    <wolfssl_root>/examples/server/server.c
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_got_timeout(WOLFSSL* ssl);

/*!
    \brief When using non-blocking sockets with DTLS, this function retransmits
    the last handshake flight ignoring the expected timeout value and
    retransmit count. It is useful for applications that are using DTLS and
    need to manage even the timeout and retry count.

    \return SSL_SUCCESS will be returned upon success
    \return SSL_FATAL_ERROR will be returned if there have been too many
    retransmissions/timeouts without getting a response from the peer.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls_retransmit(ssl);
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int wolfSSL_dtls_retransmit(WOLFSSL* ssl);

/*!
    \brief This function is used to determine if the SSL session has been
    configured to use DTLS.

    \return 1 If the SSL session (ssl) has been configured to use DTLS, this
    function will return 1.
    \return 0 otherwise.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_dtls(ssl);
    if (ret) {
    	// SSL session has been configured to use DTLS
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
*/
int  wolfSSL_dtls(WOLFSSL* ssl);

/*!
    \brief This function sets the DTLS peer, peer (sockaddr_in) with size of
    peerSz.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl    a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer   pointer to peer’s sockaddr_in structure. If NULL then the peer
                  information in ssl is cleared.
    \param peerSz size of the sockaddr_in structure pointed to by peer. If 0
                  then the peer information in ssl is cleared.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to set DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_set_pending_peer
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_set_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz);

/*!
    \brief This function sets the pending DTLS peer, peer (sockaddr_in) with
    size of peerSz. This sets the pending peer that will be upgraded to a
    regular peer when we successfully de-protect the next record. This is useful
    in scenarios where the peer's address can change to avoid off-path attackers
    from changing the peer address. This should be used with Connection ID's to
    allow seamless and safe transition to a new peer address.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl    a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer   pointer to peer’s sockaddr_in structure. If NULL then the peer
                  information in ssl is cleared.
    \param peerSz size of the sockaddr_in structure pointed to by peer. If 0
                  then the peer information in ssl is cleared.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_set_pending_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to set DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls_get_peer
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer,
                                   unsigned int peerSz);

/*!
    \brief This function gets the sockaddr_in (of size peerSz) of the current
    DTLS peer.  The function will compare peerSz to the actual DTLS peer size
    stored in the SSL session.  If the peer will fit into peer, the peer’s
    sockaddr_in will be copied into peer, with peerSz set to the size of peer.

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer pointer to memory location to store peer’s sockaddr_in
    structure.
    \param peerSz input/output size. As input, the size of the allocated memory
    pointed to by peer.  As output, the size of the actual sockaddr_in structure
    pointed to by peer.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in addr;
    ...
    ret = wolfSSL_dtls_get_peer(ssl, &addr, sizeof(addr));
    if (ret != SSL_SUCCESS) {
	    // failed to get DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_get_peer(WOLFSSL* ssl, void* peer, unsigned int* peerSz);

/*!
    \brief This function gets the sockaddr_in (of size peerSz) of the current
    DTLS peer.  This is a zero-copy alternative to wolfSSL_dtls_get_peer().

    \return SSL_SUCCESS will be returned upon success.
    \return SSL_FAILURE will be returned upon failure.
    \return SSL_NOT_IMPLEMENTED will be returned if wolfSSL was not compiled
    with DTLS support.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param peer pointer to return the internal buffer holding the peer address
    \param peerSz output the size of the actual sockaddr_in structure
    pointed to by peer.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    sockaddr_in* addr;
    unsigned int addrSz;
    ...
    ret = wolfSSL_dtls_get_peer(ssl, &addr, &addrSz);
    if (ret != SSL_SUCCESS) {
	    // failed to get DTLS peer
    }
    \endcode

    \sa wolfSSL_dtls_get_current_timeout
    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_set_peer
    \sa wolfSSL_dtls
*/
int  wolfSSL_dtls_get0_peer(WOLFSSL* ssl, const void** peer,
                            unsigned int* peerSz);

/*!
    \ingroup Debug

    \brief This function converts an error code returned by
    wolfSSL_get_error() into a more human-readable error string.
    errNumber is the error code returned by wolfSSL_get_error() and data
    is the storage buffer which the error string will be placed in.
    The maximum length of data is 80 characters by default, as defined by
    MAX_ERROR_SZ is wolfssl/wolfcrypt/error.h.

    \return success On successful completion, this function returns the same
    string as is returned in data.
    \return failure Upon failure, this function returns a string with the
    appropriate failure reason, msg.

    \param errNumber error code returned by wolfSSL_get_error().
    \param data output buffer containing human-readable error string matching
    errNumber.

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string(err, buffer);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
char* wolfSSL_ERR_error_string(unsigned long errNumber, char* data);

/*!
    \ingroup Debug

    \brief This function is a version of wolfSSL_ERR_error_string() where
    len specifies the maximum number of characters that may be written to buf.
    Like wolfSSL_ERR_error_string(), this function converts an error code
    returned from wolfSSL_get_error() into a more human-readable error string.
    The human-readable string is placed in buf.

    \return none No returns.

    \param e error code returned by wolfSSL_get_error().
    \param buff output buffer containing human-readable error string matching e.
    \param len maximum length in characters which may be written to buf.

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_error_string_n(err, buffer, 80);
    printf(“err = %d, %s\n”, err, buffer);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_error_string_n(unsigned long e, char* buf,
                                           unsigned long len);

/*!
    \ingroup TLS

    \brief This function checks the shutdown conditions in closeNotify or
    connReset or sentNotify members of the Options structure. The Options
    structure is within the WOLFSSL structure.

    \return 1 SSL_SENT_SHUTDOWN is returned.
    \return 2 SSL_RECEIVED_SHUTDOWN is returned.

    \param ssl a constant pointer to a WOLFSSL structure, created using
    wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    …
    int ret;
    ret = wolfSSL_get_shutdown(ssl);

    if(ret == 1){
	    SSL_SENT_SHUTDOWN
    } else if(ret == 2){
	    SSL_RECEIVED_SHUTDOWN
    } else {
	    Fatal error.
    }
    \endcode

    \sa wolfSSL_SESSION_free
*/
int  wolfSSL_get_shutdown(const WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function returns the resuming member of the options struct. The
    flag indicates whether or not to reuse a session. If not, a new session must
    be established.

    \return This function returns an int type held in the Options structure
    representing the flag for session reuse.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(!wolfSSL_session_reused(sslResume)){
	    // No session reuse allowed.
    }
    \endcode

    \sa wolfSSL_SESSION_free
    \sa wolfSSL_GetSessionIndex
    \sa wolfSSL_memsave_session_cache
*/
int  wolfSSL_session_reused(WOLFSSL* ssl);

/*!
    \ingroup TLS

    \brief This function checks to see if the connection is established.

    \return 0 returned if the connection is not established, i.e. the WOLFSSL
    struct is NULL or the handshake is not done.
    \return 1 returned if the connection is established i.e. the WOLFSSL
    handshake is done.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _EXAMPLE_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_is_init_finished(ssl)){
	    Handshake is done and connection is established
    }
    \endcode

    \sa wolfSSL_set_accept_state
    \sa wolfSSL_get_keys
    \sa wolfSSL_set_shutdown
*/
int  wolfSSL_is_init_finished(const WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief Returns the SSL version being used as a string.

    \return "SSLv3" Using SSLv3
    \return "TLSv1" Using TLSv1
    \return "TLSv1.1" Using TLSv1.1
    \return "TLSv1.2" Using TLSv1.2
    \return "TLSv1.3" Using TLSv1.3
    \return "DTLS": Using DTLS
    \return "DTLSv1.2" Using DTLSv1.2
    \return "unknown" There was a problem determining which version of TLS
    being used.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);
    printf(wolfSSL_get_version("Using version: %s", ssl));
    \endcode

    \sa wolfSSL_lib_version
*/
const char*  wolfSSL_get_version(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief Returns the current cipher suit an ssl session is using.

    \return ssl->options.cipherSuite An integer representing the current
    cipher suite.
    \return 0 The ssl session provided is null.

    \param ssl The SSL session to check.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_get_current_cipher_suite(ssl) == 0)
    {
        // Error getting cipher suite
    }
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_list
*/
int  wolfSSL_get_current_cipher_suite(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function returns a pointer to the current cipher in the
    ssl session.

    \return The function returns the address of the cipher member of the
    WOLFSSL struct. This is a pointer to the WOLFSSL_CIPHER structure.
    \return NULL returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    WOLFSSL_CIPHER* cipherCurr = wolfSSL_get_current_cipher;

    if(!cipherCurr){
    	// Failure case.
    } else {
    	// The cipher was returned to cipherCurr
    }
    \endcode

    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
WOLFSSL_CIPHER*  wolfSSL_get_current_cipher(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function matches the cipher suite in the SSL object with
    the available suites and returns the string representation.

    \return string This function returns the string representation of the
    matched cipher suite.
    \return none It will return “None” if there are no suites matched.

    \param cipher a constant pointer to a WOLFSSL_CIPHER structure.

    _Example_
    \code
    // gets cipher name in the format DHE_RSA ...
    const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl){
	WOLFSSL_CIPHER* cipher;
	const char* fullName;
    …
	cipher = wolfSSL_get_curent_cipher(ssl);
	fullName = wolfSSL_CIPHER_get_name(cipher);

	if(fullName){
		// sanity check on returned cipher
	}
    \endcode

    \sa wolfSSL_get_cipher
    \sa wolfSSL_get_current_cipher
    \sa wolfSSL_get_cipher_name_internal
    \sa wolfSSL_get_cipher_name
*/
const char*  wolfSSL_CIPHER_get_name(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup IO

    \brief This function matches the cipher suite in the SSL object with
    the available suites.

    \return This function returns the string value of the suite matched. It
    will return “None” if there are no suites matched.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    #ifdef WOLFSSL_DTLS
    …
    // make sure a valid suite is used
    if(wolfSSL_get_cipher(ssl) == NULL){
	    WOLFSSL_MSG(“Can not match cipher suite imported”);
	    return MATCH_SUITE_ERROR;
    }
    …
    #endif // WOLFSSL_DTLS
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_get_current_cipher
*/
const char*  wolfSSL_get_cipher(WOLFSSL*);

/*!
    \ingroup Setup

    \brief This function returns the WOLFSSL_SESSION from the WOLFSSL structure
    as a reference type. This requires calling wolfSSL_SESSION_free to release
    the session reference. The WOLFSSL_SESSION pointed to contains all the
    necessary information required to perform a session resumption and
    reestablish the connection without a new handshake. For
    session resumption, before calling wolfSSL_shutdown() with your session
    object, an application should save the session ID from the object with a
    call to wolfSSL_get1_session(), which returns a pointer to the session.
    Later, the application should create a new WOLFSSL object and assign the
    saved session with wolfSSL_set_session().  At this point, the application
    may call wolfSSL_connect() and wolfSSL will try to resume the session.
    The wolfSSL server code allows session resumption by default. The object
    returned by wolfSSL_get1_session() needs to be freed after the application
    is done with it by calling wolfSSL_SESSION_free() on it.

    \return WOLFSSL_SESSION On success return session pointer.
    \return NULL will be returned if ssl is NULL, the SSL session cache is
    disabled, wolfSSL doesn’t have the Session ID available, or mutex
    functions fail.

    \param ssl WOLFSSL structure to get session from.

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_SESSION* ses;
    // attempt/complete handshake
    wolfSSL_connect(ssl);
    ses  = wolfSSL_get1_session(ssl);
    // check ses information
    // disconnect / setup new SSL instance
    wolfSSL_set_session(ssl, ses);
    // attempt/resume handshake
    wolfSSL_SESSION_free(ses);
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_SESSION_free
*/
WOLFSSL_SESSION* wolfSSL_get1_session(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief The wolfSSLv23_client_method() function is used to indicate that
    the application is a client and will support the highest protocol
    version supported by the server between SSL 3.0 - TLS 1.3.  This function
    allocates memory for and initializes a new WOLFSSL_METHOD structure
    to be used when creating the SSL/TLS context with wolfSSL_CTX_new().
    Both wolfSSL clients and servers have robust version downgrade capability.
    If a specific protocol version method is used on either side, then only
    that version will be negotiated or an error will be returned.  For
    example, a client that uses TLSv1 and tries to connect to a SSLv3 only
    server will fail, likewise connecting to a TLSv1.1 will fail as well.
    To resolve this issue, a client that uses the wolfSSLv23_client_method()
    function will use the highest protocol version supported by the server and
    downgrade to SSLv3 if needed. In this case, the client will be able to
    connect to a server running SSLv3 - TLSv1.3.

    \return pointer upon success a pointer to a WOLFSSL_METHOD.
    \return Failure If memory allocation fails when calling XMALLOC,
    the failure value of the underlying malloc() implementation will be
    returned (typically NULL with errno will be set to ENOMEM).

    \param none No parameters

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;
    method = wolfSSLv23_client_method();
    if (method == NULL) {
	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD* wolfSSLv23_client_method(void);

/*!
    \ingroup IO

    \brief Allocates and initializes a new WOLFSSL_BIO using the supplied
    BIO method. The returned BIO has a reference count of one and is in an
    uninitialized state until first used or explicitly initialized. Mirrors
    OpenSSL's BIO_new().

    \return WOLFSSL_BIO* pointer to the newly created BIO on success.
    \return NULL on memory allocation failure or when method is NULL.

    \param method pointer to a WOLFSSL_BIO_METHOD describing the BIO type
    (for example wolfSSL_BIO_s_mem(), wolfSSL_BIO_f_base64()).

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        // handle error
    }
    \endcode

    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_new_mem_buf
*/
WOLFSSL_BIO* wolfSSL_BIO_new(WOLFSSL_BIO_METHOD* method);

/*!
    \ingroup IO

    \brief Frees a single WOLFSSL_BIO object. The BIO is detached from any
    chain it is part of (only this node is freed; see wolfSSL_BIO_free_all
    to free a full chain). If the BIO owns its underlying resource (file
    descriptor, FILE*, memory buffer) according to the close flag, that
    resource is released as well.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if bio is NULL or an error occurred.

    \param bio WOLFSSL_BIO to free.

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    // use bio
    wolfSSL_BIO_free(bio);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free_all
    \sa wolfSSL_BIO_vfree
*/
int  wolfSSL_BIO_free(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Frees a single WOLFSSL_BIO object without returning a status.
    Equivalent to wolfSSL_BIO_free() but with a void return, matching
    OpenSSL's BIO_vfree().

    \return none No return value.

    \param bio WOLFSSL_BIO to free.

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    wolfSSL_BIO_vfree(bio);
    \endcode

    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_free_all
*/
void wolfSSL_BIO_vfree(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Frees a chain of WOLFSSL_BIO objects. Walks the BIO chain
    starting at bio and frees each node in turn. Mirrors OpenSSL's
    BIO_free_all().

    \return none No return value.

    \param bio head of the BIO chain to free.

    _Example_
    \code
    WOLFSSL_BIO* b64 = wolfSSL_BIO_new(wolfSSL_BIO_f_base64());
    WOLFSSL_BIO* mem = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    b64 = wolfSSL_BIO_push(b64, mem);
    // ... use chain ...
    wolfSSL_BIO_free_all(b64);
    \endcode

    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_push
*/
void wolfSSL_BIO_free_all(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Reads a line (terminated by '\n' or the end of input) from a
    BIO into buf, NUL-terminating the result. At most sz-1 bytes are read.
    Behaviour depends on the BIO method; not all BIO types implement gets.

    \return >=0 number of bytes read into buf (excluding the terminating
    NUL).
    \return WOLFSSL_BIO_ERROR (-1) on error or when the method does not
    support gets.

    \param bio source WOLFSSL_BIO.
    \param buf destination buffer.
    \param sz size of buf in bytes.

    _Example_
    \code
    char line[128];
    int n = wolfSSL_BIO_gets(bio, line, sizeof(line));
    \endcode

    \sa wolfSSL_BIO_puts
    \sa wolfSSL_BIO_read
*/
int wolfSSL_BIO_gets(WOLFSSL_BIO* bio, char* buf, int sz);

/*!
    \ingroup IO

    \brief Writes a NUL-terminated string to a BIO. Equivalent to calling
    wolfSSL_BIO_write() with len set to strlen(buf).

    \return >=0 number of bytes written.
    \return WOLFSSL_BIO_ERROR (-1) on error.

    \param bio destination WOLFSSL_BIO.
    \param buf NUL-terminated string to write.

    _Example_
    \code
    wolfSSL_BIO_puts(bio, "hello\n");
    \endcode

    \sa wolfSSL_BIO_gets
    \sa wolfSSL_BIO_write
*/
int wolfSSL_BIO_puts(WOLFSSL_BIO* bio, const char* buf);

/*!
    \ingroup IO

    \brief Returns the next BIO in the chain after bio. BIO chains are
    typically built with wolfSSL_BIO_push().

    \return WOLFSSL_BIO* pointer to the next BIO in the chain.
    \return NULL if bio is NULL or if bio is the last in the chain.

    \param bio current WOLFSSL_BIO.

    _Example_
    \code
    WOLFSSL_BIO* nxt = wolfSSL_BIO_next(bio);
    \endcode

    \sa wolfSSL_BIO_push
    \sa wolfSSL_BIO_pop
*/
WOLFSSL_BIO* wolfSSL_BIO_next(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Walks the BIO chain starting at bio and returns the first BIO
    whose method type matches the supplied type. Mirrors OpenSSL's
    BIO_find_type().

    \return WOLFSSL_BIO* pointer to the matching BIO.
    \return NULL if no matching BIO is found.

    \param bio head of the BIO chain to search.
    \param type BIO type constant (for example WOLFSSL_BIO_SSL,
    WOLFSSL_BIO_MEMORY).

    _Example_
    \code
    WOLFSSL_BIO* ssl_bio = wolfSSL_BIO_find_type(chain, WOLFSSL_BIO_SSL);
    \endcode

    \sa wolfSSL_BIO_next
    \sa wolfSSL_BIO_method_type
*/
WOLFSSL_BIO* wolfSSL_BIO_find_type(WOLFSSL_BIO* bio, int type);

/*!
    \ingroup IO

    \brief Reads up to len bytes from a BIO into buf. The exact behaviour
    depends on the BIO method (memory, socket, file, filter chain, ...).
    Filter BIOs forward the call down the chain.

    \return >0 number of bytes read.
    \return 0 on EOF for some BIO types.
    \return WOLFSSL_BIO_ERROR (-1) on error; callers should check
    wolfSSL_BIO_should_retry() to determine whether the operation can be
    retried later.

    \param bio source WOLFSSL_BIO.
    \param buf destination buffer.
    \param len maximum number of bytes to read.

    _Example_
    \code
    char buf[256];
    int n = wolfSSL_BIO_read(bio, buf, sizeof(buf));
    \endcode

    \sa wolfSSL_BIO_write
    \sa wolfSSL_BIO_should_retry
*/
int  wolfSSL_BIO_read(WOLFSSL_BIO* bio, void* buf, int len);

/*!
    \ingroup IO

    \brief Writes up to len bytes from data to a BIO. The exact behaviour
    depends on the BIO method. Filter BIOs forward the call down the
    chain.

    \return >0 number of bytes written.
    \return 0 or WOLFSSL_BIO_ERROR (-1) on error; callers should check
    wolfSSL_BIO_should_retry() to determine whether the operation can be
    retried later.

    \param bio destination WOLFSSL_BIO.
    \param data buffer of bytes to write.
    \param len number of bytes to write.

    _Example_
    \code
    wolfSSL_BIO_write(bio, "hello", 5);
    \endcode

    \sa wolfSSL_BIO_read
    \sa wolfSSL_BIO_should_retry
*/
int  wolfSSL_BIO_write(WOLFSSL_BIO* bio, const void* data, int len);

/*!
    \ingroup IO

    \brief Pushes a BIO (or BIO chain) onto the end of another BIO. After
    the call, top becomes the head of the chain and append is reachable
    via wolfSSL_BIO_next(). Mirrors OpenSSL's BIO_push().

    \return WOLFSSL_BIO* pointer to top (the new head of the chain).

    \param top BIO that becomes the head of the new chain.
    \param append BIO (or chain) to append after top.

    _Example_
    \code
    WOLFSSL_BIO* b64 = wolfSSL_BIO_new(wolfSSL_BIO_f_base64());
    WOLFSSL_BIO* mem = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    b64 = wolfSSL_BIO_push(b64, mem);
    \endcode

    \sa wolfSSL_BIO_pop
    \sa wolfSSL_BIO_next
*/
WOLFSSL_BIO* wolfSSL_BIO_push(WOLFSSL_BIO* top, WOLFSSL_BIO* append);

/*!
    \ingroup IO

    \brief Removes bio from the chain it is part of and returns the BIO
    that was next in the chain (or NULL if there is none). The removed
    BIO is not freed.

    \return WOLFSSL_BIO* pointer to the next BIO that was linked after
    bio, or NULL if bio was the last (or only) element.

    \param bio BIO to remove from its chain.

    _Example_
    \code
    WOLFSSL_BIO* next = wolfSSL_BIO_pop(chain);
    \endcode

    \sa wolfSSL_BIO_push
    \sa wolfSSL_BIO_free
*/
WOLFSSL_BIO* wolfSSL_BIO_pop(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Flushes any buffered data on a BIO. For filter BIOs this may
    write out pending state (for example finalising a base64 stream).
    Mirrors OpenSSL's BIO_flush().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio WOLFSSL_BIO to flush.

    _Example_
    \code
    wolfSSL_BIO_flush(bio);
    \endcode

    \sa wolfSSL_BIO_write
*/
int  wolfSSL_BIO_flush(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Returns the number of bytes immediately available to read from
    a BIO without performing I/O on the underlying transport. For an SSL
    BIO this returns the number of bytes in the SSL read buffer.

    \return >=0 number of bytes pending on the BIO.
    \return 0 if nothing is pending or bio is NULL.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    int pending = wolfSSL_BIO_pending(bio);
    \endcode

    \sa wolfSSL_BIO_ctrl_pending
    \sa wolfSSL_BIO_wpending
*/
int  wolfSSL_BIO_pending(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Returns the BIO information callback previously installed with
    wolfSSL_BIO_set_callback(), or NULL if none has been set.

    \return wolf_bio_info_cb the currently installed callback, or NULL.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    wolf_bio_info_cb cb = wolfSSL_BIO_get_callback(bio);
    \endcode

    \sa wolfSSL_BIO_set_callback
    \sa wolfSSL_BIO_get_callback_arg
*/
wolf_bio_info_cb wolfSSL_BIO_get_callback(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Stores a caller-supplied pointer that will be passed to the
    BIO information callback installed with wolfSSL_BIO_set_callback().
    Mirrors OpenSSL's BIO_set_callback_arg().

    \return none No return value.

    \param bio WOLFSSL_BIO to update.
    \param arg opaque pointer made available to the callback through
    wolfSSL_BIO_get_callback_arg().

    _Example_
    \code
    wolfSSL_BIO_set_callback_arg(bio, (char*)my_ctx);
    \endcode

    \sa wolfSSL_BIO_set_callback
    \sa wolfSSL_BIO_get_callback_arg
*/
void  wolfSSL_BIO_set_callback_arg(WOLFSSL_BIO *bio, char *arg);

/*!
    \ingroup IO

    \brief Returns the callback argument pointer previously stored with
    wolfSSL_BIO_set_callback_arg().

    \return char* the stored callback argument, or NULL if none.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    char* arg = wolfSSL_BIO_get_callback_arg(bio);
    \endcode

    \sa wolfSSL_BIO_set_callback_arg
*/
char* wolfSSL_BIO_get_callback_arg(const WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the
    message-digest filter BIO. Data written to or read through this
    filter is fed into an EVP_MD context, allowing transparent hashing
    of streamed data.

    \return WOLFSSL_BIO_METHOD* pointer to the static message-digest BIO
    method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* md = wolfSSL_BIO_new(wolfSSL_BIO_f_md());
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_get_md_ctx
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_md(void);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the
    buffering filter BIO. A buffer BIO accumulates data so that small
    reads or writes on the downstream BIO are batched.

    \return WOLFSSL_BIO_METHOD* pointer to the static buffer BIO method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* buf = wolfSSL_BIO_new(wolfSSL_BIO_f_buffer());
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_set_write_buffer_size
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_buffer(void);

/*!
    \ingroup IO

    \brief Sets the size of the internal write buffer used by a buffer
    filter BIO created from wolfSSL_BIO_f_buffer().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if bio is NULL or allocation fails.

    \param bio buffer filter BIO to configure.
    \param size requested write buffer size in bytes.

    _Example_
    \code
    WOLFSSL_BIO* buf = wolfSSL_BIO_new(wolfSSL_BIO_f_buffer());
    wolfSSL_BIO_set_write_buffer_size(buf, 16384);
    \endcode

    \sa wolfSSL_BIO_f_buffer
*/
long wolfSSL_BIO_set_write_buffer_size(WOLFSSL_BIO* bio, long size);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the SSL
    filter BIO. An SSL BIO carries TLS-protected data: reads and writes
    are passed through a WOLFSSL session attached with
    wolfSSL_BIO_set_ssl().

    \return WOLFSSL_BIO_METHOD* pointer to the static SSL BIO method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* sb = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    wolfSSL_BIO_set_ssl(sb, ssl, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_set_ssl
    \sa wolfSSL_BIO_new_ssl
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_ssl(void);

/*!
    \ingroup IO

    \brief Allocates a datagram socket BIO wrapping the provided UDP file
    descriptor. The closeF flag controls whether the BIO closes the
    descriptor on free (BIO_CLOSE) or leaves it open (BIO_NOCLOSE).

    \return WOLFSSL_BIO* new datagram BIO on success.
    \return NULL on allocation failure.

    \param fd UDP socket file descriptor.
    \param closeF BIO_CLOSE or BIO_NOCLOSE.

    _Example_
    \code
    WOLFSSL_BIO* dgram = wolfSSL_BIO_new_dgram(sockfd, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_s_datagram
    \sa wolfSSL_BIO_new_socket
*/
WOLFSSL_BIO* wolfSSL_BIO_new_dgram(int fd, int closeF);

/*!
    \ingroup IO

    \brief Reports whether end-of-input has been reached on a BIO. For
    a memory BIO this returns non-zero once the read index has reached
    the end of the buffer; for file/socket BIOs it reflects the
    underlying transport.

    \return 1 if the BIO is at EOF.
    \return 0 if more data may be available.

    \param b WOLFSSL_BIO to query.

    _Example_
    \code
    if (wolfSSL_BIO_eof(bio)) {
        // no more data
    }
    \endcode

    \sa wolfSSL_BIO_read
    \sa wolfSSL_BIO_pending
*/
int         wolfSSL_BIO_eof(WOLFSSL_BIO* b);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD for an in-memory
    source/sink BIO. Writes append to an internal growing buffer and
    reads consume it.

    \return WOLFSSL_BIO_METHOD* pointer to the static memory BIO method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* mem = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_new_mem_buf
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_s_mem(void);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the
    base64 filter BIO. Data written through this filter is base64
    encoded; data read through it is base64 decoded.

    \return WOLFSSL_BIO_METHOD* pointer to the static base64 BIO method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* b64 = wolfSSL_BIO_new(wolfSSL_BIO_f_base64());
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_push
*/
WOLFSSL_BIO_METHOD* wolfSSL_BIO_f_base64(void);

/*!
    \ingroup IO

    \brief Sets one or more flags on a BIO using a bitwise OR of
    WOLFSSL_BIO_FLAG_* values. Existing flags are preserved.

    \return none No return value.

    \param bio WOLFSSL_BIO to modify.
    \param flags bitmask of WOLFSSL_BIO_FLAG_* values to set.

    _Example_
    \code
    wolfSSL_BIO_set_flags(bio, WOLFSSL_BIO_FLAG_READ);
    \endcode

    \sa wolfSSL_BIO_clear_flags
    \sa wolfSSL_BIO_should_retry
*/
void wolfSSL_BIO_set_flags(WOLFSSL_BIO* bio, int flags);

/*!
    \ingroup IO

    \brief Clears the supplied flag bits on a BIO. Flags not in the
    mask are left untouched.

    \return none No return value.

    \param bio WOLFSSL_BIO to modify.
    \param flags bitmask of WOLFSSL_BIO_FLAG_* values to clear.

    _Example_
    \code
    wolfSSL_BIO_clear_flags(bio, WOLFSSL_BIO_FLAG_RETRY);
    \endcode

    \sa wolfSSL_BIO_set_flags
    \sa wolfSSL_BIO_clear_retry_flags
*/
void wolfSSL_BIO_clear_flags(WOLFSSL_BIO *bio, int flags);

/*!
    \ingroup IO

    \brief Retrieves the file descriptor associated with a socket or
    file-descriptor BIO. If fd is non-NULL the descriptor is written
    there as well as returned.

    \return >=0 the file descriptor on success.
    \return WOLFSSL_FAILURE (-1) on error.

    \param bio WOLFSSL_BIO to query.
    \param fd optional output pointer that receives the descriptor.

    _Example_
    \code
    int sock;
    wolfSSL_BIO_get_fd(bio, &sock);
    \endcode

    \sa wolfSSL_BIO_set_fd
    \sa wolfSSL_BIO_new_socket
*/
int wolfSSL_BIO_get_fd(WOLFSSL_BIO *bio, int* fd);

/*!
    \ingroup IO

    \brief Stores a caller-supplied opaque pointer on a BIO at the
    given ex_data index. Indices are allocated with
    wolfSSL_BIO_get_ex_new_index().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio WOLFSSL_BIO to update.
    \param idx ex_data index.
    \param data opaque pointer to store.

    _Example_
    \code
    wolfSSL_BIO_set_ex_data(bio, idx, my_ptr);
    \endcode

    \sa wolfSSL_BIO_get_ex_data
*/
int wolfSSL_BIO_set_ex_data(WOLFSSL_BIO *bio, int idx, void *data);

/*!
    \ingroup IO

    \brief Retrieves the opaque pointer previously stored on a BIO at
    the given ex_data index.

    \return void* the stored pointer, or NULL if none.

    \param bio WOLFSSL_BIO to query.
    \param idx ex_data index.

    _Example_
    \code
    void* p = wolfSSL_BIO_get_ex_data(bio, idx);
    \endcode

    \sa wolfSSL_BIO_set_ex_data
*/
void *wolfSSL_BIO_get_ex_data(WOLFSSL_BIO *bio, int idx);

/*!
    \ingroup IO

    \brief Enables or disables non-blocking mode on a BIO. When set,
    socket BIOs report retryable conditions through
    wolfSSL_BIO_should_retry() instead of blocking.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio WOLFSSL_BIO to update.
    \param on non-zero to enable non-blocking mode, zero to disable.

    _Example_
    \code
    wolfSSL_BIO_set_nbio(bio, 1);
    \endcode

    \sa wolfSSL_BIO_should_retry
*/
long wolfSSL_BIO_set_nbio(WOLFSSL_BIO* bio, long on);

/*!
    \ingroup IO

    \brief Stores a custom data pointer on a BIO. Used by custom BIO
    methods (created via wolfSSL_BIO_meth_new()) to attach private
    state to each instance.

    \return none No return value.

    \param bio WOLFSSL_BIO to update.
    \param ptr opaque pointer to store.

    _Example_
    \code
    wolfSSL_BIO_set_data(bio, my_state);
    \endcode

    \sa wolfSSL_BIO_get_data
    \sa wolfSSL_BIO_meth_new
*/
void wolfSSL_BIO_set_data(WOLFSSL_BIO* bio, void* ptr);

/*!
    \ingroup IO

    \brief Retrieves the custom data pointer previously stored on a
    BIO with wolfSSL_BIO_set_data().

    \return void* the stored pointer, or NULL if none.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    void* state = wolfSSL_BIO_get_data(bio);
    \endcode

    \sa wolfSSL_BIO_set_data
*/
void* wolfSSL_BIO_get_data(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Sets the shutdown flag on a BIO. The flag governs whether
    the BIO will close the underlying resource (file descriptor, FILE*,
    etc.) when it is freed. Use BIO_CLOSE to close on free, BIO_NOCLOSE
    to leave the resource open.

    \return none No return value.

    \param bio WOLFSSL_BIO to update.
    \param shut new shutdown flag value (BIO_CLOSE or BIO_NOCLOSE).

    _Example_
    \code
    wolfSSL_BIO_set_shutdown(bio, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_get_shutdown
    \sa wolfSSL_BIO_set_close
*/
void wolfSSL_BIO_set_shutdown(WOLFSSL_BIO* bio, int shut);

/*!
    \ingroup IO

    \brief Returns the current shutdown flag for a BIO.

    \return BIO_CLOSE if the BIO will close its resource on free.
    \return BIO_NOCLOSE otherwise.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    int s = wolfSSL_BIO_get_shutdown(bio);
    \endcode

    \sa wolfSSL_BIO_set_shutdown
*/
int wolfSSL_BIO_get_shutdown(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Clears the WOLFSSL_BIO_FLAG_READ, WOLFSSL_BIO_FLAG_WRITE and
    WOLFSSL_BIO_FLAG_RETRY flags on a BIO. Mirrors OpenSSL's
    BIO_clear_retry_flags().

    \return none No return value.

    \param bio WOLFSSL_BIO to update.

    _Example_
    \code
    wolfSSL_BIO_clear_retry_flags(bio);
    \endcode

    \sa wolfSSL_BIO_should_retry
    \sa wolfSSL_BIO_set_flags
*/
void wolfSSL_BIO_clear_retry_flags(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Reports whether the last operation on a BIO failed in a way
    that can be retried (typically because a non-blocking socket would
    block).

    \return 1 if the operation should be retried.
    \return 0 otherwise.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    if (wolfSSL_BIO_read(bio, buf, len) <= 0) {
        if (wolfSSL_BIO_should_retry(bio)) {
            // try again later
        }
    }
    \endcode

    \sa wolfSSL_BIO_should_read
    \sa wolfSSL_BIO_should_write
*/
int wolfSSL_BIO_should_retry(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Reports whether the last retryable failure on a BIO was a
    read that should be retried.

    \return 1 if the BIO is waiting on a readable condition.
    \return 0 otherwise.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    if (wolfSSL_BIO_should_read(bio)) {
        // wait for readability and retry
    }
    \endcode

    \sa wolfSSL_BIO_should_retry
    \sa wolfSSL_BIO_should_write
*/
int wolfSSL_BIO_should_read(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Reports whether the last retryable failure on a BIO was a
    write that should be retried.

    \return 1 if the BIO is waiting on a writable condition.
    \return 0 otherwise.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    if (wolfSSL_BIO_should_write(bio)) {
        // wait for writability and retry
    }
    \endcode

    \sa wolfSSL_BIO_should_retry
    \sa wolfSSL_BIO_should_read
*/
int wolfSSL_BIO_should_write(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Allocates a new, empty WOLFSSL_BIO_METHOD for use as a custom
    BIO type. The caller fills it in with wolfSSL_BIO_meth_set_*() and
    eventually releases it with wolfSSL_BIO_meth_free().

    \return WOLFSSL_BIO_METHOD* pointer to the new method on success.
    \return NULL on memory allocation failure.

    \param type BIO type constant to assign (commonly an application
    chosen value).
    \param name human-readable name for diagnostics.

    _Example_
    \code
    WOLFSSL_BIO_METHOD* m = wolfSSL_BIO_meth_new(BIO_TYPE_SOURCE_SINK,
                                                 "my-bio");
    \endcode

    \sa wolfSSL_BIO_meth_free
    \sa wolfSSL_BIO_meth_set_read
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_meth_new(int type, const char* name);

/*!
    \ingroup IO

    \brief Frees a WOLFSSL_BIO_METHOD previously allocated with
    wolfSSL_BIO_meth_new(). Does not free BIOs that reference the
    method; the caller must ensure no live BIO still uses it.

    \return none No return value.

    \param biom WOLFSSL_BIO_METHOD to free.

    _Example_
    \code
    wolfSSL_BIO_meth_free(m);
    \endcode

    \sa wolfSSL_BIO_meth_new
*/
void wolfSSL_BIO_meth_free(WOLFSSL_BIO_METHOD* biom);

/*!
    \ingroup IO

    \brief Installs the write callback for a custom BIO method. The
    callback is invoked for wolfSSL_BIO_write() on BIOs created from
    this method.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if biom is NULL.

    \param biom custom BIO method to update.
    \param biom_write write callback to install.

    _Example_
    \code
    wolfSSL_BIO_meth_set_write(m, my_write_cb);
    \endcode

    \sa wolfSSL_BIO_meth_new
    \sa wolfSSL_BIO_meth_set_read
*/
int wolfSSL_BIO_meth_set_write(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_write_cb biom_write);

/*!
    \ingroup IO

    \brief Installs the read callback for a custom BIO method. The
    callback is invoked for wolfSSL_BIO_read() on BIOs created from
    this method.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if biom is NULL.

    \param biom custom BIO method to update.
    \param biom_read read callback to install.

    _Example_
    \code
    wolfSSL_BIO_meth_set_read(m, my_read_cb);
    \endcode

    \sa wolfSSL_BIO_meth_new
    \sa wolfSSL_BIO_meth_set_write
*/
int wolfSSL_BIO_meth_set_read(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_read_cb biom_read);

/*!
    \ingroup IO

    \brief Installs the puts callback for a custom BIO method. The
    callback is invoked for wolfSSL_BIO_puts() on BIOs created from
    this method.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if biom is NULL.

    \param biom custom BIO method to update.
    \param biom_puts puts callback to install.

    _Example_
    \code
    wolfSSL_BIO_meth_set_puts(m, my_puts_cb);
    \endcode

    \sa wolfSSL_BIO_meth_new
*/
int wolfSSL_BIO_meth_set_puts(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_puts_cb biom_puts);

/*!
    \ingroup IO

    \brief Installs the gets callback for a custom BIO method. The
    callback is invoked for wolfSSL_BIO_gets() on BIOs created from
    this method.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if biom is NULL.

    \param biom custom BIO method to update.
    \param biom_gets gets callback to install.

    _Example_
    \code
    wolfSSL_BIO_meth_set_gets(m, my_gets_cb);
    \endcode

    \sa wolfSSL_BIO_meth_new
*/
int wolfSSL_BIO_meth_set_gets(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_gets_cb biom_gets);

/*!
    \ingroup IO

    \brief Installs the ctrl callback for a custom BIO method. The
    callback handles BIO_ctrl() requests dispatched through
    wolfSSL_BIO_ctrl() and wolfSSL_BIO_int_ctrl().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if biom is NULL.

    \param biom custom BIO method to update.
    \param biom_ctrl ctrl callback to install.

    _Example_
    \code
    wolfSSL_BIO_meth_set_ctrl(m, my_ctrl_cb);
    \endcode

    \sa wolfSSL_BIO_meth_new
    \sa wolfSSL_BIO_ctrl
*/
int wolfSSL_BIO_meth_set_ctrl(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_ctrl_get_cb biom_ctrl);

/*!
    \ingroup IO

    \brief Installs the create callback for a custom BIO method. The
    callback is invoked when a BIO is allocated from this method, and
    can be used to set per-instance state.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if biom is NULL.

    \param biom custom BIO method to update.
    \param biom_create create callback to install.

    _Example_
    \code
    wolfSSL_BIO_meth_set_create(m, my_create_cb);
    \endcode

    \sa wolfSSL_BIO_meth_new
    \sa wolfSSL_BIO_meth_set_destroy
*/
int wolfSSL_BIO_meth_set_create(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_create_cb biom_create);

/*!
    \ingroup IO

    \brief Installs the destroy callback for a custom BIO method. The
    callback is invoked when a BIO using this method is freed, allowing
    per-instance state to be released.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if biom is NULL.

    \param biom custom BIO method to update.
    \param biom_destroy destroy callback to install.

    _Example_
    \code
    wolfSSL_BIO_meth_set_destroy(m, my_destroy_cb);
    \endcode

    \sa wolfSSL_BIO_meth_new
    \sa wolfSSL_BIO_meth_set_create
*/
int wolfSSL_BIO_meth_set_destroy(WOLFSSL_BIO_METHOD* biom, wolfSSL_BIO_meth_destroy_cb biom_destroy);

/*!
    \ingroup IO

    \brief Creates a memory BIO that reads from the supplied buffer.
    The BIO does not take ownership of buf; the buffer must remain
    valid for the lifetime of the BIO. If len is -1 the length is
    computed with strlen() on buf.

    \return WOLFSSL_BIO* new memory BIO on success.
    \return NULL on allocation failure or when buf is NULL.

    \param buf source buffer.
    \param len length of buf in bytes, or -1 to use strlen(buf).

    _Example_
    \code
    const char* pem = "-----BEGIN ...";
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_mem_buf(pem, -1);
    \endcode

    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO* wolfSSL_BIO_new_mem_buf(const void* buf, int len);

/*!
    \ingroup IO

    \brief Associates a WOLFSSL session with an SSL filter BIO. The flag
    parameter controls whether the BIO closes the WOLFSSL on free
    (BIO_CLOSE) or leaves the application to free it (BIO_NOCLOSE).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if b is not an SSL BIO.

    \param b SSL filter BIO (created from wolfSSL_BIO_f_ssl()).
    \param ssl WOLFSSL session to attach.
    \param flag BIO_CLOSE or BIO_NOCLOSE.

    _Example_
    \code
    WOLFSSL_BIO* sb = wolfSSL_BIO_new(wolfSSL_BIO_f_ssl());
    wolfSSL_BIO_set_ssl(sb, ssl, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_get_ssl
    \sa wolfSSL_BIO_new_ssl
*/
long wolfSSL_BIO_set_ssl(WOLFSSL_BIO* b, WOLFSSL* ssl, int flag);

/*!
    \ingroup IO

    \brief Retrieves the WOLFSSL session associated with an SSL filter
    BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if bio is not an SSL BIO or ssl is NULL.

    \param bio SSL filter BIO to query.
    \param ssl output pointer that receives the WOLFSSL session.

    _Example_
    \code
    WOLFSSL* ssl;
    wolfSSL_BIO_get_ssl(sb, &ssl);
    \endcode

    \sa wolfSSL_BIO_set_ssl
    \sa wolfSSL_BIO_new_ssl
*/
long wolfSSL_BIO_get_ssl(WOLFSSL_BIO* bio, WOLFSSL** ssl);

/*!
    \ingroup IO

    \brief Returns the BIO method type identifier (for example
    WOLFSSL_BIO_SSL, WOLFSSL_BIO_MEMORY) of a BIO.

    \return int BIO method type, or WOLFSSL_FAILURE if b is NULL.

    \param b WOLFSSL_BIO to query.

    _Example_
    \code
    int type = wolfSSL_BIO_method_type(bio);
    \endcode

    \sa wolfSSL_BIO_find_type
*/
int wolfSSL_BIO_method_type(const WOLFSSL_BIO *b);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the file
    source/sink BIO. Used to build BIOs that read from or write to a
    FILE*.

    \return WOLFSSL_BIO_METHOD* pointer to the static file BIO method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* fb = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_new_fp
    \sa wolfSSL_BIO_read_filename
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_file(void);

/*!
    \ingroup IO

    \brief Creates a file-descriptor BIO wrapping the supplied fd. The
    close_flag controls whether the BIO closes the descriptor when it
    is freed.

    \return WOLFSSL_BIO* new BIO on success.
    \return NULL on allocation failure.

    \param fd file descriptor.
    \param close_flag BIO_CLOSE or BIO_NOCLOSE.

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_fd(fd, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_set_fd
    \sa wolfSSL_BIO_get_fd
*/
WOLFSSL_BIO *wolfSSL_BIO_new_fd(int fd, int close_flag);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the
    paired memory BIO. A pair of such BIOs created with
    wolfSSL_BIO_new_bio_pair() act as two ends of an in-memory pipe.

    \return WOLFSSL_BIO_METHOD* pointer to the static BIO-pair method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* a = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    WOLFSSL_BIO* b = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    wolfSSL_BIO_make_bio_pair(a, b);
    \endcode

    \sa wolfSSL_BIO_make_bio_pair
    \sa wolfSSL_BIO_new_bio_pair
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_bio(void);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the
    datagram (UDP) source/sink BIO.

    \return WOLFSSL_BIO_METHOD* pointer to the static datagram BIO
    method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* d = wolfSSL_BIO_new(wolfSSL_BIO_s_datagram());
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_new_dgram
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_datagram(void);

/*!
    \ingroup IO

    \brief Returns the singleton WOLFSSL_BIO_METHOD describing the null
    sink BIO. Writes are discarded and reads return EOF; useful as a
    bit-bucket in BIO chains.

    \return WOLFSSL_BIO_METHOD* pointer to the static null BIO method.

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* n = wolfSSL_BIO_new(wolfSSL_BIO_s_null());
    \endcode

    \sa wolfSSL_BIO_new
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_null(void);

/*!
    \ingroup IO

    \brief Creates a connect BIO that, when activated with
    wolfSSL_BIO_do_connect(), opens a TCP connection. The string
    parameter contains either a hostname or a "host:port" combination.

    \return WOLFSSL_BIO* new connect BIO on success.
    \return NULL on allocation failure or when str is NULL.

    \param str hostname or "host:port" target.

    _Example_
    \code
    WOLFSSL_BIO* c = wolfSSL_BIO_new_connect("example.com:443");
    wolfSSL_BIO_do_connect(c);
    \endcode

    \sa wolfSSL_BIO_set_conn_hostname
    \sa wolfSSL_BIO_set_conn_port
    \sa wolfSSL_BIO_do_connect
*/
WOLFSSL_BIO *wolfSSL_BIO_new_connect(const char *str);

/*!
    \ingroup IO

    \brief Creates an accept BIO that, when activated with
    wolfSSL_BIO_do_accept(), listens for incoming TCP connections on
    the given port.

    \return WOLFSSL_BIO* new accept BIO on success.
    \return NULL on allocation failure.

    \param port port number or service name to listen on.

    _Example_
    \code
    WOLFSSL_BIO* a = wolfSSL_BIO_new_accept("4433");
    wolfSSL_BIO_do_accept(a);
    \endcode

    \sa wolfSSL_BIO_do_accept
*/
WOLFSSL_BIO *wolfSSL_BIO_new_accept(const char *port);

/*!
    \ingroup IO

    \brief Sets the hostname (and optionally port, when provided in
    "host:port" form) for a connect BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param b connect BIO to update.
    \param name hostname or "host:port" string.

    _Example_
    \code
    wolfSSL_BIO_set_conn_hostname(c, "example.com");
    \endcode

    \sa wolfSSL_BIO_new_connect
    \sa wolfSSL_BIO_set_conn_port
*/
long wolfSSL_BIO_set_conn_hostname(WOLFSSL_BIO* b, char* name);

/*!
    \ingroup IO

    \brief Sets the port (service name or numeric port) for a connect
    BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param b connect BIO to update.
    \param port port number or service name string.

    _Example_
    \code
    wolfSSL_BIO_set_conn_port(c, "443");
    \endcode

    \sa wolfSSL_BIO_set_conn_hostname
    \sa wolfSSL_BIO_new_connect
*/
long wolfSSL_BIO_set_conn_port(WOLFSSL_BIO *b, char* port);

/*!
    \ingroup IO

    \brief Initiates the outgoing TCP connection for a connect BIO
    (typically one created with wolfSSL_BIO_new_connect()).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param b connect BIO to activate.

    _Example_
    \code
    WOLFSSL_BIO* c = wolfSSL_BIO_new_connect("example.com:443");
    if (wolfSSL_BIO_do_connect(c) != WOLFSSL_SUCCESS) {
        // handle error
    }
    \endcode

    \sa wolfSSL_BIO_new_connect
    \sa wolfSSL_BIO_do_handshake
*/
long wolfSSL_BIO_do_connect(WOLFSSL_BIO *b);

/*!
    \ingroup IO

    \brief Activates an accept BIO. The first call binds and listens on
    the configured port; subsequent calls accept a new incoming
    connection and return a connected BIO chained to the accept BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param b accept BIO to activate.

    _Example_
    \code
    WOLFSSL_BIO* a = wolfSSL_BIO_new_accept("4433");
    wolfSSL_BIO_do_accept(a);  // bind and listen
    wolfSSL_BIO_do_accept(a);  // accept a connection
    \endcode

    \sa wolfSSL_BIO_new_accept
*/
int wolfSSL_BIO_do_accept(WOLFSSL_BIO *b);

/*!
    \ingroup IO

    \brief Allocates an SSL filter BIO and attaches a freshly created
    WOLFSSL session derived from ctx. If client is non-zero the session
    is initialised in client mode; otherwise server mode.

    \return WOLFSSL_BIO* new SSL BIO on success.
    \return NULL on allocation or session-creation failure.

    \param ctx WOLFSSL_CTX used to create the WOLFSSL session.
    \param client non-zero for client mode, zero for server mode.

    _Example_
    \code
    WOLFSSL_BIO* sb = wolfSSL_BIO_new_ssl(ctx, 1);
    \endcode

    \sa wolfSSL_BIO_new_ssl_connect
    \sa wolfSSL_BIO_get_ssl
*/
WOLFSSL_BIO* wolfSSL_BIO_new_ssl(WOLFSSL_CTX* ctx, int client);

/*!
    \ingroup IO

    \brief Builds a BIO chain consisting of an SSL filter BIO (client
    mode) on top of a connect BIO, ready for use with
    wolfSSL_BIO_set_conn_hostname() and wolfSSL_BIO_do_handshake().

    \return WOLFSSL_BIO* new SSL/connect BIO chain on success.
    \return NULL on allocation failure.

    \param ctx WOLFSSL_CTX used to create the WOLFSSL session.

    _Example_
    \code
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_ssl_connect(ctx);
    wolfSSL_BIO_set_conn_hostname(bio, "example.com:443");
    wolfSSL_BIO_do_handshake(bio);
    \endcode

    \sa wolfSSL_BIO_new_ssl
    \sa wolfSSL_BIO_do_handshake
*/
WOLFSSL_BIO* wolfSSL_BIO_new_ssl_connect(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief Drives the TLS handshake on an SSL filter BIO (or BIO chain
    rooted at one). Equivalent to calling wolfSSL_connect() or
    wolfSSL_accept() on the underlying WOLFSSL session.

    \return WOLFSSL_SUCCESS on a completed handshake.
    \return WOLFSSL_FAILURE on error; wolfSSL_BIO_should_retry() may
    indicate a retryable condition.

    \param b SSL BIO (or chain) to handshake on.

    _Example_
    \code
    wolfSSL_BIO_do_handshake(bio);
    \endcode

    \sa wolfSSL_BIO_new_ssl_connect
    \sa wolfSSL_BIO_should_retry
*/
long wolfSSL_BIO_do_handshake(WOLFSSL_BIO *b);

/*!
    \ingroup IO

    \brief Shuts down the TLS session attached to an SSL filter BIO,
    sending the close_notify alert.

    \return none No return value.

    \param b SSL filter BIO to shut down.

    _Example_
    \code
    wolfSSL_BIO_ssl_shutdown(sb);
    \endcode

    \sa wolfSSL_BIO_set_ssl
    \sa wolfSSL_shutdown
*/
void wolfSSL_BIO_ssl_shutdown(WOLFSSL_BIO* b);

/*!
    \ingroup IO

    \brief Dispatches a control operation to a BIO. The cmd argument
    selects the operation (one of the BIO_CTRL_* / BIO_C_* constants),
    larg and parg supply additional parameters. Mirrors OpenSSL's
    BIO_ctrl().

    \return long result of the operation; meaning depends on cmd.

    \param bp WOLFSSL_BIO target.
    \param cmd control operation identifier.
    \param larg long argument associated with cmd.
    \param parg pointer argument associated with cmd.

    _Example_
    \code
    wolfSSL_BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL);
    \endcode

    \sa wolfSSL_BIO_int_ctrl
    \sa wolfSSL_BIO_ctrl_pending
*/
long wolfSSL_BIO_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, void *parg);

/*!
    \ingroup IO

    \brief Dispatches a control operation to a BIO with two integer
    arguments. Mirrors OpenSSL's BIO_int_ctrl().

    \return long result of the operation; meaning depends on cmd.

    \param bp WOLFSSL_BIO target.
    \param cmd control operation identifier.
    \param larg long argument associated with cmd.
    \param iarg int argument associated with cmd.

    _Example_
    \code
    wolfSSL_BIO_int_ctrl(bio, BIO_C_SET_FD, BIO_NOCLOSE, fd);
    \endcode

    \sa wolfSSL_BIO_ctrl
*/
long wolfSSL_BIO_int_ctrl(WOLFSSL_BIO *bp, int cmd, long larg, int iarg);

/*!
    \ingroup IO

    \brief Increments the reference count of a BIO. The matching call
    to wolfSSL_BIO_free() must be made for each successful up_ref to
    actually release the BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if b is NULL.

    \param b WOLFSSL_BIO to share.

    _Example_
    \code
    wolfSSL_BIO_up_ref(bio);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_up_ref(WOLFSSL_BIO *b);

/*!
    \ingroup IO

    \brief Returns the cumulative number of bytes read from a BIO over
    its lifetime.

    \return word64 number of bytes read.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    word64 n = wolfSSL_BIO_number_read(bio);
    \endcode

    \sa wolfSSL_BIO_number_written
    \sa wolfSSL_BIO_read
*/
word64 wolfSSL_BIO_number_read(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Returns the cumulative number of bytes written to a BIO over
    its lifetime.

    \return word64 number of bytes written.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    word64 n = wolfSSL_BIO_number_written(bio);
    \endcode

    \sa wolfSSL_BIO_number_read
    \sa wolfSSL_BIO_write
*/
word64 wolfSSL_BIO_number_written(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Returns the current file offset (tell) of a file BIO.
    Mirrors OpenSSL's BIO_tell().

    \return >=0 current offset.
    \return WOLFSSL_FAILURE on error.

    \param bio file BIO to query.

    _Example_
    \code
    int pos = wolfSSL_BIO_tell(bio);
    \endcode

    \sa wolfSSL_BIO_seek
    \sa wolfSSL_BIO_s_file
*/
int  wolfSSL_BIO_tell(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Returns the total length in bytes of the data held in a
    memory BIO, or for a file BIO the length of the underlying file.

    \return >=0 length in bytes.
    \return WOLFSSL_FAILURE on error.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    int len = wolfSSL_BIO_get_len(bio);
    \endcode

    \sa wolfSSL_BIO_pending
*/
int wolfSSL_BIO_get_len(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Writes formatted output to a BIO. Behaves like fprintf() but
    targets a BIO instead of a FILE*.

    \return >=0 number of bytes written on success.
    \return WOLFSSL_FAILURE on error.

    \param bio destination WOLFSSL_BIO.
    \param format printf-style format string.

    _Example_
    \code
    wolfSSL_BIO_printf(bio, "value = %d\n", n);
    \endcode

    \sa wolfSSL_BIO_write
    \sa wolfSSL_BIO_dump
*/
int wolfSSL_BIO_printf(WOLFSSL_BIO* bio, const char* format, ...);

/*!
    \ingroup IO

    \brief Writes a hex/ASCII dump of length bytes from buf to a BIO,
    similar to OpenSSL's BIO_dump(). Each line shows offsets and both
    hex and printable forms.

    \return >=0 number of bytes written to the BIO.
    \return WOLFSSL_FAILURE on error.

    \param bio destination WOLFSSL_BIO.
    \param buf data to dump.
    \param length number of bytes from buf to dump.

    _Example_
    \code
    wolfSSL_BIO_dump(bio, data, len);
    \endcode

    \sa wolfSSL_BIO_printf
*/
int wolfSSL_BIO_dump(WOLFSSL_BIO *bio, const char* buf, int length);

/*!
    \ingroup IO

    \brief Returns the number of bytes currently buffered for writing
    on a BIO (for example pending bytes in a buffer filter BIO).

    \return >=0 number of bytes pending write.
    \return 0 if nothing is pending or bio is NULL.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    size_t w = wolfSSL_BIO_wpending(bio);
    \endcode

    \sa wolfSSL_BIO_pending
    \sa wolfSSL_BIO_ctrl_pending
*/
size_t wolfSSL_BIO_wpending(const WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Reports whether the BIO type supports the pending operation
    (wolfSSL_BIO_pending() / wolfSSL_BIO_ctrl_pending()). Mirrors
    OpenSSL's BIO_supports_pending().

    \return 1 if pending is supported by this BIO.
    \return 0 otherwise.

    \param bio WOLFSSL_BIO to query.

    _Example_
    \code
    if (wolfSSL_BIO_supports_pending(bio)) {
        int n = wolfSSL_BIO_pending(bio);
    }
    \endcode

    \sa wolfSSL_BIO_pending
*/
int wolfSSL_BIO_supports_pending(const WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief Opens the named file for reading and associates it with a
    file BIO. Equivalent to OpenSSL's BIO_read_filename().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error (file not found, allocation failure).

    \param b file BIO created from wolfSSL_BIO_s_file().
    \param name path of the file to open for reading.

    _Example_
    \code
    WOLFSSL_BIO* b = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    wolfSSL_BIO_read_filename(b, "cert.pem");
    \endcode

    \sa wolfSSL_BIO_s_file
    \sa wolfSSL_BIO_new_file
*/
int wolfSSL_BIO_read_filename(WOLFSSL_BIO *b, const char *name);

/*!
    \ingroup IO

    \brief Allocates a new file BIO wrapping an already-opened FILE*.
    The c flag (BIO_CLOSE or BIO_NOCLOSE) controls whether the BIO
    closes the FILE* when freed.

    \return WOLFSSL_BIO* new BIO on success.
    \return NULL on allocation failure.

    \param fp opened FILE*.
    \param c BIO_CLOSE or BIO_NOCLOSE.

    _Example_
    \code
    XFILE fp = XFOPEN("file.bin", "rb");
    WOLFSSL_BIO* bio = wolfSSL_BIO_new_fp(fp, BIO_CLOSE);
    \endcode

    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_new_file
*/
WOLFSSL_BIO* wolfSSL_BIO_new_fp(XFILE fp, int c);

/*!
    \ingroup IO

    \brief Allocates a new socket source/sink BIO wrapping the supplied
    file descriptor. The flag (BIO_CLOSE or BIO_NOCLOSE) controls
    whether the BIO closes the descriptor when freed.

    \return WOLFSSL_BIO* new socket BIO on success.
    \return NULL on allocation failure.

    \param sfd connected socket file descriptor.
    \param flag BIO_CLOSE or BIO_NOCLOSE.

    _Example_
    \code
    WOLFSSL_BIO* sb = wolfSSL_BIO_new_socket(sockfd, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_s_socket
    \sa wolfSSL_BIO_new_fd
*/
WOLFSSL_BIO*        wolfSSL_BIO_new_socket(int sfd, int flag);

/*!
    \ingroup IO

    \brief This is used to set a byte pointer to the start of the
    internal memory buffer.

    \return size On success the size of the buffer is returned
    \return SSL_FATAL_ERROR If an error case was encountered.

    \param bio WOLFSSL_BIO structure to get memory buffer of.
    \param p byte pointer to set to memory buffer.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    const byte* p;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_get_mem_data(bio, &p);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_get_mem_data(WOLFSSL_BIO* bio,void* p);

/*!
    \ingroup IO

    \brief This is used to set the init flag of a BIO, indicating whether
    the BIO has been initialised and is ready for use. Typically called
    from a custom BIO create callback.

    \param bio WOLFSSL_BIO structure to set the init flag on.
    \param init value to set (0 = not initialised, 1 = initialised).

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // inside a custom BIO create callback
    wolfSSL_BIO_set_init(bio, 1);
    \endcode

    \sa wolfSSL_BIO_get_init
    \sa wolfSSL_BIO_new
*/
void wolfSSL_BIO_set_init(WOLFSSL_BIO* bio, int init);

/*!
    \ingroup IO

    \brief This is used to retrieve the init flag of a BIO, indicating
    whether the BIO has been initialised and is ready for use.

    \return 1 if the BIO has been initialised.
    \return 0 if the BIO has not been initialised or bio is NULL.

    \param bio WOLFSSL_BIO structure to query.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // create bio with custom method
    if (wolfSSL_BIO_get_init(bio)) {
        // bio is ready
    }
    \endcode

    \sa wolfSSL_BIO_set_init
    \sa wolfSSL_BIO_new
*/
int wolfSSL_BIO_get_init(WOLFSSL_BIO* bio);

/*!
    \ingroup IO

    \brief Sets the file descriptor for bio to use.

    \return SSL_SUCCESS(1) upon success.

    \param b WOLFSSL_BIO structure to set fd.
    \param fd file descriptor to use.
    \param flag flag for behavior when closing fd.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int fd;
    // setup bio
    wolfSSL_BIO_set_fd(bio, fd, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fd(WOLFSSL_BIO* b, int fd, int flag);

/*!
    \ingroup IO

    \brief Sets the close flag, used to indicate that the i/o stream should be
     closed when the BIO is freed

    \return SSL_SUCCESS(1) upon success.

    \param b WOLFSSL_BIO structure.
    \param flag flag for behavior when closing i/o stream.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // setup bio
    wolfSSL_BIO_set_close(bio, BIO_NOCLOSE);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int wolfSSL_BIO_set_close(WOLFSSL_BIO *b, long flag);

/*!
    \ingroup IO

    \brief This is used to get a BIO_SOCKET type WOLFSSL_BIO_METHOD.

    \return WOLFSSL_BIO_METHOD pointer to a WOLFSSL_BIO_METHOD structure
    that is a socket type

    \param none No parameters.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_socket);
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
WOLFSSL_BIO_METHOD *wolfSSL_BIO_s_socket(void);

/*!
    \ingroup IO

    \brief This is used to set the size of write buffer for a
    WOLFSSL_BIO. If write buffer has been previously set this
    function will free it when resetting the size. It is similar to
    wolfSSL_BIO_reset in that it resets read and write indexes to 0.

    \return SSL_SUCCESS On successfully setting the write buffer.
    \return SSL_FAILURE If an error case was encountered.

    \param b WOLFSSL_BIO structure to set write buffer size.
    \param size size of buffer to allocate.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret = wolfSSL_BIO_set_write_buf_size(bio, 15000);
    // check return value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_set_write_buf_size(WOLFSSL_BIO *b, long size);

/*!
    \ingroup IO

    \brief This is used to pair two bios together. A pair of bios acts
    similar to a two way pipe writing to one can be read by the other
    and vice versa. It is expected that both bios be in the same thread,
    this function is not thread safe. Freeing one of the two bios removes
    both from being paired. If a write buffer size was not previously
    set for either of the bios it is set to a default size of 17000
    (WOLFSSL_BIO_SIZE) before being paired.

    \return SSL_SUCCESS On successfully pairing the two bios.
    \return SSL_FAILURE If an error case was encountered.

    \param b1 WOLFSSL_BIO structure to set pair.
    \param b2 second WOLFSSL_BIO structure to complete pair.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BIO* bio2;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    bio2 = wolfSSL_BIO_new(wolfSSL_BIO_s_bio());
    ret = wolfSSL_BIO_make_bio_pair(bio, bio2);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_make_bio_pair(WOLFSSL_BIO *b1, WOLFSSL_BIO *b2);

/*!
    \ingroup IO

    \brief This is used to set the read request flag back to 0.

    \return SSL_SUCCESS On successfully setting value.
    \return SSL_FAILURE If an error case was encountered.

    \param b WOLFSSL_BIO structure to set read request flag.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    ...
    ret = wolfSSL_BIO_ctrl_reset_read_request(bio);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new, wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_new, wolfSSL_BIO_free
*/
int  wolfSSL_BIO_ctrl_reset_read_request(WOLFSSL_BIO *b);

/*!
    \ingroup IO

    \brief This is used to get a buffer pointer for reading from. Unlike
    wolfSSL_BIO_nread the internal read index is not advanced by the number
    returned from the function call. Reading past the value returned can
    result in reading out of array bounds.

    \return >=0 on success return the number of bytes to read

    \param bio WOLFSSL_BIO structure to read from.
    \param buf pointer to set at beginning of read array.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nread0(bio, &bufPt); // read as many bytes as possible
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode

    \sa wolfSSL_BIO_new
*/
int  wolfSSL_BIO_nread0(WOLFSSL_BIO *bio, char **buf);

/*!
    \ingroup IO

    \brief This is used to get a buffer pointer for reading from. The internal
    read index is advanced by the number returned from the function call with
    buf being pointed to the beginning of the buffer to read from. In the
    case that less bytes are in the read buffer than the value requested with
    num the lesser value is returned. Reading past the value returned can
    result in reading out of array bounds.

    \return >=0 on success return the number of bytes to read
    \return WOLFSSL_BIO_ERROR(-1) on error case with nothing to read return -1

    \param bio WOLFSSL_BIO structure to read from.
    \param buf pointer to set at beginning of read array.
    \param num number of bytes to try and read.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;

    // set up bio
    ret = wolfSSL_BIO_nread(bio, &bufPt, 10); // try to read 10 bytes
    // handle negative ret check
    // read ret bytes from bufPt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_nwrite
*/
int  wolfSSL_BIO_nread(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO

    \brief Gets a pointer to the buffer for writing as many bytes as returned by
    the function. Writing more bytes to the pointer returned then the value
    returned can result in writing out of bounds.

    \return int Returns the number of bytes that can be written to the buffer
    pointer returned.
    \return WOLFSSL_BIO_UNSET(-2) in the case that is not part of a bio pair
    \return WOLFSSL_BIO_ERROR(-1) in the case that there is no more room to
    write to

    \param bio WOLFSSL_BIO structure to write to.
    \param buf pointer to buffer to write to.
    \param num number of bytes desired to be written.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    char* bufPt;
    int ret;
    // set up bio
    ret = wolfSSL_BIO_nwrite(bio, &bufPt, 10); // try to write 10 bytes
    // handle negative ret check
    // write ret bytes to bufPt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
    \sa wolfSSL_BIO_nread
*/
int  wolfSSL_BIO_nwrite(WOLFSSL_BIO *bio, char **buf, int num);

/*!
    \ingroup IO

    \brief Resets bio to an initial state. As an example for type BIO_BIO
    this resets the read and write index.

    \return 0 On successfully resetting the bio.
    \return WOLFSSL_BIO_ERROR(-1) Returned on bad input or unsuccessful reset.

    \param bio WOLFSSL_BIO structure to reset.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    // setup bio
    wolfSSL_BIO_reset(bio);
    //use pt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_reset(WOLFSSL_BIO *bio);

/*!
    \ingroup IO

    \brief This function adjusts the file pointer to the offset given. This
    is the offset from the head of the file.

    \return 0 On successfully seeking.
    \return -1 If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set.
    \param ofs offset into file.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, &fp);
    // check ret value
    ret  = wolfSSL_BIO_seek(bio, 3);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_seek(WOLFSSL_BIO *bio, int ofs);

/*!
    \ingroup IO

    \brief This is used to set and write to a file. WIll overwrite any data
    currently in the file and is set to close the file when the bio is freed.

    \return SSL_SUCCESS On successfully opening and setting file.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set file.
    \param name name of file to write to.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_write_filename(bio, “test.txt”);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_file
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
int  wolfSSL_BIO_write_filename(WOLFSSL_BIO *bio, char *name);

/*!
    \ingroup IO

    \brief This is used to set the end of file value. Common value is -1 so
    as not to get confused with expected positive values.

    \return 0 returned on completion

    \param bio WOLFSSL_BIO structure to set end of file value.
    \param v value to set in bio.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    ret  = wolfSSL_BIO_set_mem_eof_return(bio, -1);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_mem_eof_return(WOLFSSL_BIO *bio, int v);

/*!
    \ingroup IO

    \brief This is a getter function for WOLFSSL_BIO memory pointer.

    \return SSL_SUCCESS On successfully getting the pointer SSL_SUCCESS is
    returned (currently value of 1).
    \return SSL_FAILURE Returned if NULL arguments are passed in (currently
    value of 0).

    \param bio pointer to the WOLFSSL_BIO structure for getting memory pointer.
    \param m pointer to WOLFSSL_BUF_MEM structure. Is set to point to
    bio’s memory.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_BUF_MEM* pt;
    // setup bio
    wolfSSL_BIO_get_mem_ptr(bio, &pt);
    //use pt
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
*/
long wolfSSL_BIO_get_mem_ptr(WOLFSSL_BIO *bio, WOLFSSL_BUF_MEM **m);

/*!
    \ingroup CertsKeys

    \brief This function copies the name of the x509 into a buffer.

    \return A char pointer to the buffer with the WOLFSSL_X509_NAME structures
    name member’s data is returned if the function executed normally.

    \param name a pointer to a WOLFSSL_X509 structure.
    \param in a buffer to hold the name copied from the
    WOLFSSL_X509_NAME structure.
    \param sz the maximum size of the buffer.

    _Example_
    \code
    WOLFSSL_X509 x509;
    char* name;
    ...
    name = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(name <= 0){
    	// There’s nothing in the buffer.
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
char*       wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME* name, char* in, int sz);

/*!
    \ingroup CertsKeys

    \brief This function returns the name of the certificate issuer.

    \return point a pointer to the WOLFSSL_X509 struct’s issuer member is
    returned.
    \return NULL if the cert passed in is NULL.

    \param cert a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509;
    WOLFSSL_X509_NAME issuer;
    ...
    issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(x509), 0, 0);

    if(!issuer){
    	// NULL was returned
    } else {
    	// issuer hods the name of the certificate issuer.
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_NAME_oneline
*/
WOLFSSL_X509_NAME*  wolfSSL_X509_get_issuer_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief This function returns the subject member of the WOLFSSL_X509
    structure.

    \return pointer a pointer to the WOLFSSL_X509_NAME structure. The pointer
    may be NULL if the WOLFSSL_X509 struct is NULL or if the subject member of
    the structure is NULL.

    \param cert a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* cert;
    WOLFSSL_X509_NAME name;
    …
    name = wolfSSL_X509_get_subject_name(cert);
    if(name == NULL){
	    // Deal with the NULL cacse
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_X509_NAME*  wolfSSL_X509_get_subject_name(WOLFSSL_X509* cert);

/*!
    \ingroup CertsKeys

    \brief Checks the isCa member of the WOLFSSL_X509 structure and returns
    the value.

    \return isCA returns the value in the isCA member of the WOLFSSL_X509
    structure is returned.
    \return 0 returned if there is not a valid x509 structure passed in.

    \param x509 a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_X509_get_isCA(ssl)){
    	// This is the CA
    }else {
    	// Failure case
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
*/
int  wolfSSL_X509_get_isCA(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief This function gets the text related to the passed in NID value.

    \return int returns the size of the text buffer.

    \param name WOLFSSL_X509_NAME to search for text.
    \param nid NID to search for.
    \param buf buffer to hold text when found.
    \param len length of buffer.

    _Example_
    \code
    WOLFSSL_X509_NAME* name;
    char buffer[100];
    int bufferSz;
    int ret;
    // get WOLFSSL_X509_NAME
    ret = wolfSSL_X509_NAME_get_text_by_NID(name, NID_commonName,
    buffer, bufferSz);

    //check ret value
    \endcode

    \sa none
*/
int wolfSSL_X509_NAME_get_text_by_NID(WOLFSSL_X509_NAME* name, int nid,
                                      char* buf, int len);

/*!
    \ingroup CertsKeys

    \brief This function returns the value stored in the sigOID
    member of the WOLFSSL_X509 structure.

    \return 0 returned if the WOLFSSL_X509 structure is NULL.
    \return int an integer value is returned which was retrieved from
    the x509 object.

    \param x509 a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509SigType = wolfSSL_X509_get_signature_type(x509);

    if(x509SigType != EXPECTED){
	// Deal with an unexpected value
    }
    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_notAfter
    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_get_signature_type(WOLFSSL_X509* x509);

/*!
    \brief This function frees a WOLFSSL_X509 structure.


    \param x509 a pointer to the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;

    wolfSSL_X509_free(x509);

    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_notAfter

*/
void wolfSSL_X509_free(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief Gets the X509 signature and stores it in the buffer.

    \return SSL_SUCCESS returned if the function successfully executes.
    The signature is loaded into the buffer.
    \return SSL_FATAL_ERRROR returns if the x509 struct or the bufSz member
    is NULL. There is also a check for the length member of the sig structure
    (sig is a member of x509).

    \param x509 pointer to a WOLFSSL_X509 structure.
    \param buf a char pointer to the buffer.
    \param bufSz an integer pointer to the size of the buffer.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    unsigned char* buf; // Initialize
    int* bufSz = sizeof(buf)/sizeof(unsigned char);
    ...
    if(wolfSSL_X509_get_signature(x509, buf, bufSz) != SSL_SUCCESS){
	    // The function did not execute successfully.
    } else{
	    // The buffer was written to correctly.
    }
    \endcode

    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_get_signature_type
    \sa wolfSSL_X509_get_device_type
*/
int wolfSSL_X509_get_signature(WOLFSSL_X509* x509, unsigned char* buf, int* bufSz);

/*!
    \ingroup CertsKeys

    \brief This function adds a certificate to the WOLFSSL_X509_STRE structure.

    \return SSL_SUCCESS If certificate is added successfully.
    \return SSL_FATAL_ERROR: If certificate is not added successfully.

    \param store certificate store to add the certificate to.
    \param x509 certificate to add.

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    WOLFSSL_X509* x509;
    int ret;
    ret = wolfSSL_X509_STORE_add_cert(str, x509);
    //check ret value
    \endcode

    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_STORE_add_cert(WOLFSSL_X509_STORE* store, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief This function is a getter function for chain variable
    in WOLFSSL_X509_STORE_CTX structure. Currently chain is not populated.

    \return pointer if successful returns WOLFSSL_STACK
    (same as STACK_OF(WOLFSSL_X509)) pointer
    \return Null upon failure

    \param ctx certificate store ctx to get parse chain from.

    _Example_
    \code
    WOLFSSL_STACK* sk;
    WOLFSSL_X509_STORE_CTX* ctx;
    sk = wolfSSL_X509_STORE_CTX_get_chain(ctx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode

    \sa wolfSSL_sk_X509_free
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_CTX_get_chain(
                                                   WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief This function takes in a flag to change the behavior of the
    WOLFSSL_X509_STORE structure passed in. An example of a flag used
    is WOLFSSL_CRL_CHECK.

    \return SSL_SUCCESS If no errors were encountered when setting the flag.
    \return <0 a negative value will be returned upon failure.

    \param str certificate store to set flag in.
    \param flag flag for behavior.

    _Example_
    \code
    WOLFSSL_X509_STORE* str;
    int ret;
    // create and set up str
    ret = wolfSSL_X509_STORE_set_flags(str, WOLFSSL_CRL_CHECKALL);
    If (ret != SSL_SUCCESS) {
    	//check ret value and handle error case
    }
    \endcode

    \sa wolfSSL_X509_STORE_new
    \sa wolfSSL_X509_STORE_free
*/
int wolfSSL_X509_STORE_set_flags(WOLFSSL_X509_STORE* store,
                                                            unsigned long flag);

/*!
    \ingroup CertsKeys

    \brief This function the certificate "not before" validity encoded as
    a byte array.


    \return NULL returned if the WOLFSSL_X509 structure is NULL.
    \return byte is returned that contains the notBeforeData.

    \param x509 pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    byte* notBeforeData = wolfSSL_X509_notBefore(x509);


    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notAfter
    \sa wolfSSL_X509_free
*/
const byte* wolfSSL_X509_notBefore(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief This function the certificate "not after" validity encoded as
    a byte array.

    \return NULL returned if the WOLFSSL_X509 structure is NULL.
    \return byte is returned that contains the notAfterData.

    \param x509 pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    byte* notAfterData = wolfSSL_X509_notAfter(x509);


    \endcode

    \sa wolfSSL_X509_get_signature
    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_get_der
    \sa wolfSSL_X509_get_serial_number
    \sa wolfSSL_X509_notBefore
    \sa wolfSSL_X509_free
*/
const byte* wolfSSL_X509_notAfter(WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief This function is used to copy a WOLFSSL_ASN1_INTEGER
    value to a WOLFSSL_BIGNUM structure.

    \return pointer On successfully copying the WOLFSSL_ASN1_INTEGER
    value a WOLFSSL_BIGNUM pointer is returned.
    \return Null upon failure.

    \param ai WOLFSSL_ASN1_INTEGER structure to copy from.
    \param bn if wanting to copy into an already existing
    WOLFSSL_BIGNUM struct then pass in a pointer to it.
    Optionally this can be NULL and a new WOLFSSL_BIGNUM
    structure will be created.

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* ai;
    WOLFSSL_BIGNUM* bn;
    // create ai
    bn = wolfSSL_ASN1_INTEGER_to_BN(ai, NULL);

    // or if having already created bn and wanting to reuse structure
    // wolfSSL_ASN1_INTEGER_to_BN(ai, bn);
    // check bn is or return value is not NULL
    \endcode

    \sa none
*/
WOLFSSL_BIGNUM *wolfSSL_ASN1_INTEGER_to_BN(const WOLFSSL_ASN1_INTEGER *ai,
                                       WOLFSSL_BIGNUM *bn);

/*!
    \ingroup Setup

    \brief This function adds the certificate to the internal chain
    being built in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS after successfully adding the certificate.
    \return SSL_FAILURE if failing to add the certificate to the chain.

    \param ctx WOLFSSL_CTX structure to add certificate to.
    \param x509 certificate to add to the chain.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL_X509* x509;
    int ret;
    // create ctx
    ret = wolfSSL_CTX_add_extra_chain_cert(ctx, x509);
    // check ret value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_add_extra_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief This function returns the get read ahead flag from a
    WOLFSSL_CTX structure.

    \return flag On success returns the read ahead flag.
    \return SSL_FAILURE If ctx is NULL then SSL_FAILURE is returned.

    \param ctx WOLFSSL_CTX structure to get read ahead flag from.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    // setup ctx
    flag = wolfSSL_CTX_get_read_ahead(ctx);
    //check flag
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_read_ahead
*/
int  wolfSSL_CTX_get_read_ahead(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function sets the read ahead flag in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS If ctx read ahead flag set.
    \return SSL_FAILURE If ctx is NULL then SSL_FAILURE is returned.

    \param ctx WOLFSSL_CTX structure to set read ahead flag.
    \param v read ahead flag

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    int flag;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_read_ahead(ctx, flag);
    // check return value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_get_read_ahead
*/
int  wolfSSL_CTX_set_read_ahead(WOLFSSL_CTX* ctx, int v);

/*!
    \ingroup Setup

    \brief This function sets the options argument to use with OCSP.

    \return SSL_FAILURE If ctx or it’s cert manager is NULL.
    \return SSL_SUCCESS If successfully set.

    \param ctx WOLFSSL_CTX structure to set user argument.
    \param arg user argument.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_status_arg(ctx, data);

    //check ret value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup CertsKeys

    \brief Sets a callback to select the client certificate and private key.

    This function allows the application to register a callback that will be invoked
    when a client certificate is requested during the handshake. The callback can
    select and provide the certificate and key to use.

    \param ctx The WOLFSSL_CTX object.
    \param cb  The callback function to select the client certificate and key.

    \return void

    _Example_
    \code
    int my_client_cert_cb(WOLFSSL *ssl, WOLFSSL_X509 **x509, WOLFSSL_EVP_PKEY **pkey) { ... }
    wolfSSL_CTX_set_client_cert_cb(ctx, my_client_cert_cb);
    \endcode

    \sa wolfSSL_CTX_set_cert_cb
*/
void wolfSSL_CTX_set_client_cert_cb(WOLFSSL_CTX *ctx, client_cert_cb cb);

/*!
    \ingroup CertsKeys

    \brief Sets a generic certificate setup callback.

    This function allows the application to register a callback that will be invoked
    during certificate setup. The callback can perform custom certificate selection
    or loading logic.

    \param ctx The WOLFSSL_CTX object.
    \param cb  The callback function for certificate setup.
    \param arg User argument to pass to the callback.

    \return void

    _Example_
    \code
    int my_cert_setup_cb(WOLFSSL* ssl, void* arg) { ... }
    wolfSSL_CTX_set_cert_cb(ctx, my_cert_setup_cb, NULL);
    \endcode

    \sa wolfSSL_CTX_set_client_cert_cb
*/
void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx, CertSetupCallback cb, void *arg);

/*!
    \ingroup OCSP

    \brief Sets the callback to be used for handling OCSP status requests (OCSP stapling).

    This function allows the application to register a callback that will be invoked
    when an OCSP status request is received during the TLS handshake. The callback
    can provide an OCSP response to be stapled to the handshake. This API is only
    useful on the server side.

    \param ctx The WOLFSSL_CTX object.
    \param cb  The callback function to handle OCSP status requests.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    _Example_
    \code
    int my_ocsp_status_cb(WOLFSSL* ssl, void* arg) { ... }
    wolfSSL_CTX_set_tlsext_status_cb(ctx, my_ocsp_status_cb);
    \endcode

    \sa wolfSSL_CTX_get_tlsext_status_cb
    \sa wolfSSL_CTX_set_tlsext_status_arg
*/
int wolfSSL_CTX_set_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb cb);

/*!
    \ingroup OCSP

    \brief Gets the currently set OCSP status callback for the context.

    \param ctx The WOLFSSL_CTX object.
    \param cb  Pointer to receive the callback function.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    \sa wolfSSL_CTX_set_tlsext_status_cb
*/
int wolfSSL_CTX_get_tlsext_status_cb(WOLFSSL_CTX* ctx, tlsextStatusCb* cb);

/*!
    \ingroup OCSP

    \brief Sets the argument to be passed to the OCSP status callback.

    \param ctx The WOLFSSL_CTX object.
    \param arg The user argument to pass to the callback.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    \sa wolfSSL_CTX_set_tlsext_status_cb
*/
long wolfSSL_CTX_set_tlsext_status_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup OCSP

    \brief Gets the OCSP response that will be sent (stapled) to the peer.

    \param ssl The WOLFSSL session.
    \param resp Pointer to receive the response buffer.

    \return Length of the response, or negative value on error.

    \sa wolfSSL_set_tlsext_status_ocsp_resp
*/
long wolfSSL_get_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char **resp);

/*!
    \ingroup OCSP

    \brief Sets the OCSP response to be sent (stapled) to the peer.

    The buffer in resp becomes owned by wolfSSL and will be freed by
    wolfSSL. The application must not free the buffer after calling this
    function.

    \param ssl The WOLFSSL session.
    \param resp Pointer to the response buffer.
    \param len  Length of the response buffer.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.

    \sa wolfSSL_get_tlsext_status_ocsp_resp
*/
long wolfSSL_set_tlsext_status_ocsp_resp(WOLFSSL *ssl, unsigned char *resp, int len);

/*!
    \ingroup OCSP

    \brief Sets multiple OCSP responses for TLS multi-certificate chains.

    The buffer in resp becomes owned by wolfSSL and will be freed by
    wolfSSL. The application must not free the buffer after calling this
    function.

    \param ssl The WOLFSSL session.
    \param resp Pointer to the response buffer.
    \param len  Length of the response buffer.
    \param idx  Index of the certificate chain.

    \return SSL_SUCCESS on success, SSL_FAILURE otherwise.
*/
int wolfSSL_set_tlsext_status_ocsp_resp_multi(WOLFSSL* ssl, unsigned char *resp, int len, word32 idx);

/*!
    \ingroup OCSP

    \brief Sets a callback to verify the OCSP status response.

    It is recommended to enable SESSION_CERTS in order to have access to the
    peer's certificate chain during OCSP verification.

    \param ctx   The WOLFSSL_CTX object.
    \param cb    The callback function.
    \param cbArg User argument to pass to the callback.

    \return void

    _Example_
    \code
    void my_ocsp_verify_cb(WOLFSSL* ssl, int err, byte* resp, word32 respSz, word32 idx, void* arg)
    {
        (void)arg;
        if (err == 0 && staple && stapleSz > 0) {
            printf("Client: OCSP staple received, size=%u\n", stapleSz);
            return 0;
        }
        // Manual OCSP staple verification if err != 0
        if (err != 0 && staple && stapleSz > 0) {
            WOLFSSL_CERT_MANAGER* cm = NULL;
            DecodedCert cert;
            byte certInit = 0;
            WOLFSSL_OCSP* ocsp = NULL;
            WOLFSSL_X509_CHAIN* peerCerts;
            int i;

            cm = wolfSSL_CertManagerNew();
            if (cm == NULL)
                goto cleanup;
            if (wolfSSL_CertManagerLoadCA(cm, CA_CERT, NULL) != WOLFSSL_SUCCESS)
                goto cleanup;

            peerCerts = wolfSSL_get_peer_chain(ssl);
            if (peerCerts == NULL || wolfSSL_get_chain_count(peerCerts) <= (int)idx)
                goto cleanup;

            for (i = idx + 1; i < wolfSSL_get_chain_count(peerCerts); i++) {
                if (wolfSSL_CertManagerLoadCABuffer(cm, wolfSSL_get_chain_cert(peerCerts, i),
                        wolfSSL_get_chain_length(peerCerts, i), WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
                    goto cleanup;
            }

            wc_InitDecodedCert(&cert, wolfSSL_get_chain_cert(peerCerts, idx), wolfSSL_get_chain_length(peerCerts, idx), NULL);
            certInit = 1;
            if (wc_ParseCert(&cert, CERT_TYPE, VERIFY, cm) != 0)
                goto cleanup;
            if ((ocsp = wc_NewOCSP(cm)) == NULL)
                goto cleanup;
            if (wc_CheckCertOcspResponse(ocsp, &cert, staple, stapleSz, NULL) != 0)
                goto cleanup;

            printf("Client: Manual OCSP staple verification succeeded for idx=%u\n", idx);
            err = 0;
    cleanup:
            wc_FreeOCSP(ocsp);
            if (certInit)
                wc_FreeDecodedCert(&cert);
            wolfSSL_CertManagerFree(cm);
            if (err == 0)
                return 0;
            printf("Client: Manual OCSP staple verification failed for idx=%u\n", idx);
        }
        printf("Client: OCSP staple verify error=%d\n", err);
        return err;
    }
    wolfSSL_CTX_set_ocsp_status_verify_cb(ctx, my_ocsp_verify_cb, NULL);
    \endcode
*/
void wolfSSL_CTX_set_ocsp_status_verify_cb(WOLFSSL_CTX* ctx, ocspVerifyStatusCb cb, void* cbArg);

/*!
    \ingroup Setup

    \brief This function sets the optional argument to be passed to
    the PRF callback.

    \return SSL_FAILURE If ctx is NULL.
    \return SSL_SUCCESS If successfully set.

    \param ctx WOLFSSL_CTX structure to set user argument.
    \param arg user argument.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    int ret;
    // setup ctx
    ret = wolfSSL_CTX_set_tlsext_opaques_prf_input_callback_arg(ctx, data);
    //check ret value
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
long wolfSSL_CTX_set_tlsext_opaque_prf_input_callback_arg(
        WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup Setup

    \brief This function ORs the bits in \p opt into the options mask of the
    given WOLFSSL_CTX. The options mask is inherited by every WOLFSSL session
    later created from this context. Bits are accumulated — to remove an
    option, use wolfSSL_CTX_clear_options(). The OpenSSL-style "SSL_OP_*"
    macros are aliases for the corresponding "WOLFSSL_OP_*" values; either
    spelling may be used.

    Effective options:

    | Macro                                | Effect |
    | ------------------------------------ | ------ |
    | SSL_OP_NO_SSLv2                      | Disable SSLv2 (wolfSSL never supports SSLv2; flag is accepted for OpenSSL compatibility) |
    | SSL_OP_NO_SSLv3                      | Disable SSLv3 |
    | SSL_OP_NO_TLSv1                      | Disable TLS 1.0 |
    | SSL_OP_NO_TLSv1_1                    | Disable TLS 1.1 |
    | SSL_OP_NO_TLSv1_2                    | Disable TLS 1.2 |
    | SSL_OP_NO_TLSv1_3                    | Disable TLS 1.3 (requires WOLFSSL_TLS13) |
    | SSL_OP_NO_COMPRESSION                | Disable record-layer compression (no-op unless HAVE_LIBZ) |
    | SSL_OP_NO_TICKET                     | Disable RFC 5077 session tickets (TLS 1.2 only; TLS 1.3 ignores this flag); requires HAVE_SESSION_TICKET and (OPENSSL_EXTRA or HAVE_WEBSERVER or WOLFSSL_WPAS_SMALL) |
    | SSL_OP_NO_RENEGOTIATION              | Reject peer-initiated renegotiation |
    | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION | Disable session resumption on renegotiation |
    | SSL_OP_COOKIE_EXCHANGE               | Enable HelloVerifyRequest cookie exchange (default-on for DTLS) |
    | SSL_OP_NO_QUERY_MTU                  | DTLS: do not query the path MTU |
    | SSL_OP_CIPHER_SERVER_PREFERENCE      | Server uses its own cipher preference order rather than the client's |
    | SSL_OP_SINGLE_DH_USE                 | Generate a fresh DH key for every handshake |
    | SSL_OP_SINGLE_ECDH_USE               | Generate a fresh ECDH key for every handshake |
    | SSL_OP_EPHEMERAL_RSA                 | Use ephemeral RSA (legacy, accepted for OpenSSL compatibility) |
    | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS   | Do not insert empty fragments before a record (CBC BEAST workaround) |
    | SSL_OP_PKCS1_CHECK_1 / _2            | Accepted for OpenSSL compatibility |
    | SSL_OP_LEGACY_SERVER_CONNECT         | Always allow legacy (unsafe) initial connect; defined as 0 — no effect (requires the openssl/ssl.h compatibility header) |

    Convenience macros and bug-workaround flags (all members of SSL_OP_ALL,
    accepted for OpenSSL compatibility but otherwise no-ops in wolfSSL):

    - SSL_OP_ALL (bitwise OR of all bug-workaround flags below)
    - SSL_OP_MICROSOFT_SESS_ID_BUG
    - SSL_OP_NETSCAPE_CHALLENGE_BUG
    - SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
    - SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
    - SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
    - SSL_OP_MSIE_SSLV2_RSA_PADDING
    - SSL_OP_SSLEAY_080_CLIENT_DH_BUG
    - SSL_OP_TLS_D5_BUG
    - SSL_OP_TLS_BLOCK_PADDING_BUG
    - SSL_OP_TLS_ROLLBACK_BUG
    - SSL_OP_NETSCAPE_CA_DN_BUG
    - SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG

    Convenience composite:

    - SSL_OP_NO_SSL_MASK = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3

    \param ctx WOLFSSL_CTX structure on which to set the options mask.
    \param opt the bitmask of SSL_OP_* / WOLFSSL_OP_* flags to OR into the
    current mask.

    \return BAD_FUNC_ARG if \p ctx is NULL.
    \return The updated options mask value stored in \p ctx on success.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    long mask;
    mask = wolfSSL_CTX_set_options(ctx,
        SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    // 'mask' now reflects the accumulated options stored in ctx
    \endcode

    \sa wolfSSL_CTX_clear_options
    \sa wolfSSL_CTX_get_options
    \sa wolfSSL_set_options
    \sa wolfSSL_get_options
*/
long wolfSSL_CTX_set_options(WOLFSSL_CTX* ctx, long opt);

/*!
    \ingroup Setup

    \brief This function ORs the bits in \p op into the options mask of the
    given WOLFSSL session. The set of recognized "SSL_OP_*" / "WOLFSSL_OP_*"
    flags is identical to that documented for wolfSSL_CTX_set_options();
    refer to that function for the full options table and the build-option
    requirements of individual flags. Flags inherited from the parent
    WOLFSSL_CTX remain set; setting SSL_OP_NO_TLSv1_3 here lowers the
    session's negotiated minor version to TLS 1.2.

    \param s WOLFSSL session on which to set the options mask.
    \param op the bitmask of SSL_OP_* / WOLFSSL_OP_* flags to OR into the
    current mask.

    \return The updated options mask value stored in \p s on success, or 0 if
    \p s is NULL.

    _Example_
    \code
    WOLFSSL* ssl;
    long mask;
    mask = wolfSSL_set_options(ssl, SSL_OP_NO_TLSv1_3);
    // 'mask' now reflects the accumulated options stored in ssl
    \endcode

    \sa wolfSSL_CTX_set_options
    \sa wolfSSL_clear_options
    \sa wolfSSL_get_options
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_set_options(WOLFSSL *s, long op);

/*!
    \ingroup Setup

    \brief This function returns the current options mask.

    \return val Returns the mask value stored in ssl.

    \param s WOLFSSL structure to get options mask from.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned long mask;
    mask  = wolfSSL_get_options(ssl);
    // check mask
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_set_options
*/
long wolfSSL_get_options(const WOLFSSL *s);

/*!
    \ingroup Setup

    \brief This is used to set the debug argument passed around.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If an NULL ssl passed in.

    \param s WOLFSSL structure to set argument in.
    \param arg argument to use.

    _Example_
    \code
    WOLFSSL* ssl;
    void* args;
    int ret;
    // create ssl object
    ret  = wolfSSL_set_tlsext_debug_arg(ssl, args);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_set_tlsext_debug_arg(WOLFSSL *s, void *arg);

/*!
    \ingroup openSSL

    \brief This function is called when the client application request
    that a server send back an OCSP status response (also known as
    OCSP stapling).Currently, the only supported type is
    TLSEXT_STATUSTYPE_ocsp.

    \return 1 upon success.
    \return 0 upon error.

    \param s pointer to WOLFSSL struct which is created by SSL_new() function
    \param type ssl extension type which TLSEXT_STATUSTYPE_ocsp is
    only supported.

    _Example_
    \code
    WOLFSSL *ssl;
    WOLFSSL_CTX *ctx;
    int ret;
    ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    ssl = wolfSSL_new(ctx);
    ret = WolfSSL_set_tlsext_status_type(ssl,TLSEXT_STATUSTYPE_ocsp);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_new
    \sa wolfSSL_free
    \sa wolfSSL_CTX_free
*/
long wolfSSL_set_tlsext_status_type(WOLFSSL *s, int type);

/*!
    \ingroup Setup

    \brief This is used to get the results after trying to verify the peer's
    certificate.

    \return X509_V_OK On successful verification.
    \return SSL_FAILURE If an NULL ssl passed in.

    \param ssl WOLFSSL structure to get verification results from.

    _Example_
    \code
    WOLFSSL* ssl;
    long ret;
    // attempt/complete handshake
    ret  = wolfSSL_get_verify_result(ssl);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_get_verify_result(const WOLFSSL *ssl);

/*!
    \ingroup Debug

    \brief This function converts an error code returned by
    wolfSSL_get_error() into a more human-readable error string
    and prints that string to the output file - fp.  err is the
    error code returned by wolfSSL_get_error() and fp is the
    file which the error string will be placed in.

    \return none No returns.

    \param fp output file for human-readable error string to be written to.
    \param err error code returned by wolfSSL_get_error().

    _Example_
    \code
    int err = 0;
    WOLFSSL* ssl;
    FILE* fp = ...
    ...
    err = wolfSSL_get_error(ssl, 0);
    wolfSSL_ERR_print_errors_fp(fp, err);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_print_errors_fp(XFILE fp, int err);

/*!
    \ingroup Debug

    \brief This function uses the provided callback to handle error reporting.
    The callback function is executed for each error line. The string, length,
    and userdata are passed into the callback parameters.

    \return none No returns.

    \param cb the callback function.
    \param u userdata to pass into the callback function.

    _Example_
    \code
    int error_cb(const char *str, size_t len, void *u)
    { fprintf((FILE*)u, "%-*.*s\n", (int)len, (int)len, str); return 0; }
    ...
    FILE* fp = ...
    wolfSSL_ERR_print_errors_cb(error_cb, fp);
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_error_string_n
    \sa wolfSSL_load_error_strings
*/
void  wolfSSL_ERR_print_errors_cb (
        int (*cb)(const char *str, size_t len, void *u), void *u);

/*!
    \brief The function sets the client_psk_cb member of the
    WOLFSSL_CTX structure.

    \return none No returns.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param cb wc_psk_client_callback is a function pointer that will be
    stored in the WOLFSSL_CTX structure. Return value is the key length on
    success or zero on error.
    unsigned int (*wc_psk_client_callback)
    PSK client callback parameters:
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    const char* hint - A stored string that could be displayed to provide a
                        hint to the user.
    char* identity - The ID will be stored here.
    unsigned int id_max_len - Size of the ID buffer.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol def );
    …
    static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    Unsigned int key_max_len){
    …
    wolfSSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);
    \endcode

    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
void wolfSSL_CTX_set_psk_client_callback(WOLFSSL_CTX* ctx,
                                                    wc_psk_client_callback cb);

/*!
    \brief Sets the PSK client side callback.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to type wc_psk_client_callback. Return value
    is the key length on success or zero on error.
    unsigned int (*wc_psk_client_callback)
    PSK client callback parameters:
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    const char* hint - A stored string that could be displayed to provide a
                        hint to the user.
    char* identity - The ID will be stored here.
    unsigned int id_max_len - Size of the ID buffer.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.

    _Example_
    \code
    WOLFSSL* ssl;
    static WC_INLINE unsigned int my_psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max_len, unsigned char* key,
    Unsigned int key_max_len){
    …
    if(ssl){
    wolfSSL_set_psk_client_callback(ssl, my_psk_client_cb);
    } else {
    	// could not set callback
    }
    \endcode

    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_set_psk_server_callback
*/
void wolfSSL_set_psk_client_callback(WOLFSSL* ssl,
                                                    wc_psk_client_callback cb);

/*!
    \ingroup CertsKeys

    \brief This function returns the psk identity hint.

    \return pointer a const char pointer to the value that was stored in
    the arrays member of the WOLFSSL structure is returned.
    \return NULL returned if the WOLFSSL or Arrays structures are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char* idHint;
    ...
    idHint = wolfSSL_get_psk_identity_hint(ssl);
    if(idHint){
    	// The hint was retrieved
    	return idHint;
    } else {
    	// Hint wasn’t successfully retrieved
    }
    \endcode

    \sa wolfSSL_get_psk_identity
*/
const char* wolfSSL_get_psk_identity_hint(const WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief The function returns a constant pointer to the client_identity
    member of the Arrays structure.

    \return string the string value of the client_identity member of the
    Arrays structure.
    \return NULL if the WOLFSSL structure is NULL or if the Arrays member of
    the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* pskID;
    ...
    pskID = wolfSSL_get_psk_identity(ssl);

    if(pskID == NULL){
	    // There is not a value in pskID
    }
    \endcode

    \sa wolfSSL_get_psk_identity_hint
    \sa wolfSSL_use_psk_identity_hint
*/
const char* wolfSSL_get_psk_identity(const WOLFSSL*);

/*!
    \ingroup CertsKeys

    \brief This function stores the hint argument in the server_hint
    member of the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned for successful execution of the function.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param hint a constant char pointer that will be copied to the
    WOLFSSL_CTX structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    const char* hint;
    int ret;
    …
    ret = wolfSSL_CTX_use_psk_identity_hint(ctx, hint);
    if(ret == SSL_SUCCESS){
    	// Function was successful.
	return ret;
    } else {
    	// Failure case.
    }
    \endcode

    \sa wolfSSL_use_psk_identity_hint
*/
int wolfSSL_CTX_use_psk_identity_hint(WOLFSSL_CTX* ctx, const char* hint);

/*!
    \ingroup CertsKeys

    \brief This function stores the hint argument in the server_hint member
    of the Arrays structure within the WOLFSSL structure.

    \return SSL_SUCCESS returned if the hint was successfully stored in the
    WOLFSSL structure.
    \return SSL_FAILURE returned if the WOLFSSL or Arrays structures are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param hint a constant character pointer that holds the hint to be saved
    in memory.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* hint;
    ...
    if(wolfSSL_use_psk_identity_hint(ssl, hint) != SSL_SUCCESS){
    	// Handle failure case.
    }
    \endcode

    \sa wolfSSL_CTX_use_psk_identity_hint
*/
int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint);

/*!
    \brief This function sets the psk callback for the server side in
    the WOLFSSL_CTX structure.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer for the callback and will be stored in
    the WOLFSSL_CTX structure. Return value is the key length on success or
    zero on error.
    unsigned int (*wc_psk_server_callback)
    PSK server callback parameters
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    char* identity - The ID will be stored here.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // Function body.
    }
    …
    if(ctx != NULL){
        wolfSSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);
    } else {
    	// The CTX object was not properly initialized.
    }
    \endcode

    \sa wc_psk_server_callback
    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
*/
void wolfSSL_CTX_set_psk_server_callback(WOLFSSL_CTX* ctx,
                                                    wc_psk_server_callback cb);

/*!
    \brief Sets the psk callback for the server side by setting the
    WOLFSSL structure options members.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer for the callback and will be stored in
    the WOLFSSL structure. Return value is the key length on success or  zero
    on error.
    unsigned int (*wc_psk_server_callback)
    PSK server callback parameters
    WOLFSSL* ssl - Pointer to the wolfSSL structure
    char* identity - The ID will be stored here.
    unsigned char* key - The key will be stored here.
    unsigned int key_max_len - The max size of the key.


    _Example_
    \code
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    …
    static unsigned int my_psk_server_cb(WOLFSSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
    {
        // Function body.
    }
    …
    if(ssl != NULL && cb != NULL){
        wolfSSL_set_psk_server_callback(ssl, my_psk_server_cb);
    }
    \endcode

    \sa wolfSSL_set_psk_client_callback
    \sa wolfSSL_CTX_set_psk_server_callback
    \sa wolfSSL_CTX_set_psk_client_callback
    \sa wolfSSL_get_psk_identity_hint
    \sa wc_psk_server_callback
    \sa InitSuites
*/
void wolfSSL_set_psk_server_callback(WOLFSSL* ssl,
                                                    wc_psk_server_callback cb);


/*!
    \brief Sets a PSK user context in the WOLFSSL structure options member.

    \return WOLFSSL_SUCCESS or WOLFSSL_FAILURE

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param psk_ctx void pointer to user PSK context

    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_set_psk_callback_ctx(WOLFSSL* ssl, void* psk_ctx);

/*!
    \brief Sets a PSK user context in the WOLFSSL_CTX structure.

    \return WOLFSSL_SUCCESS or WOLFSSL_FAILURE

    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().
    \param psk_ctx void pointer to user PSK context

    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
int wolfSSL_CTX_set_psk_callback_ctx(WOLFSSL_CTX* ctx, void* psk_ctx);

/*!
    \brief Get a PSK user context in the WOLFSSL structure options member.

    \return void pointer to user PSK context

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_CTX_get_psk_callback_ctx
*/
void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl);

/*!
    \brief Get a PSK user context in the WOLFSSL_CTX structure.

    \return void pointer to user PSK context

    \param ctx a pointer to a WOLFSSL_CTX structure, created using wolfSSL_CTX_new().

    \sa wolfSSL_CTX_set_psk_callback_ctx
    \sa wolfSSL_set_psk_callback_ctx
    \sa wolfSSL_get_psk_callback_ctx
*/
void* wolfSSL_CTX_get_psk_callback_ctx(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function enables the havAnon member of the CTX structure if
    HAVE_ANON is defined during compilation.

    \return SSL_SUCCESS returned if the function executed successfully and the
    haveAnnon member of the CTX is set to 1.
    \return SSL_FAILURE returned if the CTX structure was NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    #ifdef HAVE_ANON
	if(cipherList == NULL){
	    wolfSSL_CTX_allow_anon_cipher(ctx);
	    if(wolfSSL_CTX_set_cipher_list(ctx, “ADH_AES128_SHA”) != SSL_SUCCESS){
		    // failure case
	    }
    }
    #endif
    \endcode

    \sa none
*/
int wolfSSL_CTX_allow_anon_cipher(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief The wolfSSLv23_server_method() function is used to indicate
    that the application is a server and will support clients connecting
    with protocol version from SSL 3.0 - TLS 1.3.  This function allocates
    memory for and initializes a new WOLFSSL_METHOD structure to be used when
    creating the SSL/TLS context with wolfSSL_CTX_new().

    \return pointer If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return Failure If memory allocation fails when calling XMALLOC, the
    failure value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    \param none No parameters

    _Example_
    \code
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfSSLv23_server_method();
    if (method == NULL) {
    	// unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv23_server_method(void);

/*!
    \ingroup Setup

    \brief This is used to get the internal error state of the WOLFSSL structure.

    \return wolfssl_error returns ssl error state, usually a negative
    \return BAD_FUNC_ARG if ssl is NULL.

    \return ssl WOLFSSL structure to get state from.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create ssl object
    ret  = wolfSSL_state(ssl);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int  wolfSSL_state(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief This function gets the peer’s certificate.

    \return pointer a pointer to the peerCert member of the WOLFSSL_X509
    structure if it exists.
    \return 0 returned if the peer certificate issuer size is not defined.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    WOLFSSL_X509* peerCert = wolfSSL_get_peer_certificate(ssl);

    if(peerCert){
    	// You have a pointer peerCert to the peer certification
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLFSSL_X509* wolfSSL_get_peer_certificate(WOLFSSL* ssl);

/*!
    \ingroup Debug

    \brief This function is similar to calling wolfSSL_get_error() and
    getting SSL_ERROR_WANT_READ in return.  If the underlying error state
    is SSL_ERROR_WANT_READ, this function will return 1, otherwise, 0.

    \return 1 wolfSSL_get_error() would return SSL_ERROR_WANT_READ, the
    underlying I/O has data available for reading.
    \return 0 There is no SSL_ERROR_WANT_READ error state.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_want_read(ssl);
    if (ret == 1) {
    	// underlying I/O has data available for reading (SSL_ERROR_WANT_READ)
    }
    \endcode

    \sa wolfSSL_want_write
    \sa wolfSSL_get_error
*/
int wolfSSL_want_read(WOLFSSL* ssl);

/*!
    \ingroup Debug

    \brief This function is similar to calling wolfSSL_get_error() and getting
    SSL_ERROR_WANT_WRITE in return. If the underlying error state is
    SSL_ERROR_WANT_WRITE, this function will return 1, otherwise, 0.

    \return 1 wolfSSL_get_error() would return SSL_ERROR_WANT_WRITE, the
    underlying I/O needs data to be written in order for progress to be
    made in the underlying SSL connection.
    \return 0 There is no SSL_ERROR_WANT_WRITE error state.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_want_write(ssl);
    if (ret == 1) {
    	// underlying I/O needs data to be written (SSL_ERROR_WANT_WRITE)
    }
    \endcode

    \sa wolfSSL_want_read
    \sa wolfSSL_get_error
*/
int wolfSSL_want_write(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief wolfSSL by default checks the peer certificate for a valid date
    range and a verified signature.  Calling this function before
    wolfSSL_connect() or wolfSSL_accept() will add a domain name check to
    the list of checks to perform.  dn holds the domain name to check
    against the peer certificate when it’s received.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE will be returned if a memory error was encountered.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param dn domain name to check against the peer certificate when received.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    char* domain = (char*) “www.yassl.com”;
    ...

    ret = wolfSSL_check_domain_name(ssl, domain);
    if (ret != SSL_SUCCESS) {
       // failed to enable domain name check
    }
    \endcode

    \sa none
*/
int wolfSSL_check_domain_name(WOLFSSL* ssl, const char* dn);

/*!
    \ingroup Setup

    \brief Calling this function before wolfSSL_connect() or wolfSSL_accept()
    adds an IP-address identity check against the peer certificate SAN
    iPAddress entries.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE if parameters are invalid or memory allocation fails.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ipaddr NULL-terminated ASCII IP address string to verify against the
    peer certificate.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    const char* ip = "127.0.0.1";
    ...

    ret = wolfSSL_check_ip_address(ssl, ip);
    if (ret != SSL_SUCCESS) {
       // failed to enable IP check
    }
    \endcode

    \sa wolfSSL_check_domain_name
*/
int wolfSSL_check_ip_address(WOLFSSL* ssl, const char* ipaddr);

/*!
    \ingroup TLS

    \brief Initializes the wolfSSL library for use.  Must be called once per
    application and before any other call to the library.

    \return SSL_SUCCESS If successful the call will return.
    \return BAD_MUTEX_E is an error that may be returned.
    \return WC_INIT_E wolfCrypt initialization error returned.

    _Example_
    \code
    int ret = 0;
    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
	    failed to initialize wolfSSL library
    }

    \endcode

    \sa wolfSSL_Cleanup
*/
int wolfSSL_Init(void);

/*!
    \ingroup TLS

    \brief Un-initializes the wolfSSL library from further use. Doesn’t have
    to be called, though it will free any resources used by the library.

    \return SSL_SUCCESS return no errors.
    \return BAD_MUTEX_E a mutex error return.]

    _Example_
    \code
    wolfSSL_Cleanup();
    \endcode

    \sa wolfSSL_Init
*/
int wolfSSL_Cleanup(void);

/*!
    \ingroup IO

    \brief This function returns the current library version.

    \return LIBWOLFSSL_VERSION_STRING a const char pointer defining the
    version.

    \param none No parameters.

    _Example_
    \code
    char version[MAXSIZE];
    version = wolfSSL_KeepArrays();
    …
    if(version != ExpectedVersion){
	    // Handle the mismatch case
    }
    \endcode

    \sa word32_wolfSSL_lib_version_hex
*/
const char* wolfSSL_lib_version(void);

/*!
    \ingroup IO

    \brief This function returns the current library version in hexadecimal
    notation.

    \return LILBWOLFSSL_VERSION_HEX returns the hexadecimal version defined in
     wolfssl/version.h.

    \param none No parameters.

    _Example_
    \code
    word32 libV;
    libV = wolfSSL_lib_version_hex();

    if(libV != EXPECTED_HEX){
	    // How to handle an unexpected value
    } else {
	    // The expected result for libV
    }
    \endcode

    \sa wolfSSL_lib_version
*/
word32 wolfSSL_lib_version_hex(void);

/*!
    \ingroup IO

    \brief Performs the actual connect or accept based on the side of the SSL
    method.  If called from the client side then an wolfSSL_connect() is done
    while a wolfSSL_accept() is performed if called from the server side.

    \return SSL_SUCCESS will be returned if successful. (Note, older versions
    will return 0.)
    \return SSL_FATAL_ERROR will be returned if the underlying call resulted
    in an error. Use wolfSSL_get_error() to get a specific error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret = SSL_FATAL_ERROR;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_negotiate(ssl);
    if (ret == SSL_FATAL_ERROR) {
    	// SSL establishment failed
	int error_code = wolfSSL_get_error(ssl);
	...
    }
    ...
    \endcode

    \sa SSL_connect
    \sa SSL_accept
*/
int wolfSSL_negotiate(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Turns on the ability to use compression for the SSL connection.
    Both sides must have compression turned on otherwise compression will not be
    used. The zlib library performs the actual data compression. To compile
    into the library use --with-libz for the configure system and define
    HAVE_LIBZ otherwise. Keep in mind that while compressing data before
    sending decreases the actual size of the messages being sent and received,
    the amount of data saved by compression usually takes longer in time to
    analyze than it does to send it raw on all but the slowest of networks.

    \return SSL_SUCCESS upon success.
    \return NOT_COMPILED_IN will be returned if compression support wasn’t
    built into the library.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_compression(ssl);
    if (ret == SSL_SUCCESS) {
    	// successfully enabled compression for SSL session
    }
    \endcode

    \sa none
*/
int wolfSSL_set_compression(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the SSL session timeout value in seconds.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned if ssl is NULL.

    \param ssl pointer to the SSL object, created with wolfSSL_new().
    \param to value, in seconds, used to set the SSL session timeout.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl = 0;
    ...

    ret = wolfSSL_set_timeout(ssl, 500);
    if (ret != SSL_SUCCESS) {
    	// failed to set session timeout value
    }
    ...
    \endcode

    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
*/
int wolfSSL_set_timeout(WOLFSSL* ssl, unsigned int to);

/*!
    \ingroup Setup

    \brief This function sets the timeout value for SSL sessions, in seconds,
    for the specified SSL context.

    \return the previous timeout value, if WOLFSSL_ERROR_CODE_OPENSSL is
    \return defined on success. If not defined, SSL_SUCCESS will be returned.
    \return BAD_FUNC_ARG will be returned when the input context (ctx) is null.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param to session timeout value in seconds.

    _Example_
    \code
    WOLFSSL_CTX*    ctx    = 0;
    ...
    ret = wolfSSL_CTX_set_timeout(ctx, 500);
    if (ret != SSL_SUCCESS) {
	    // failed to set session timeout value
    }
    \endcode

    \sa wolfSSL_flush_sessions
    \sa wolfSSL_get1_session
    \sa wolfSSL_set_session
    \sa wolfSSL_get_sessionID
    \sa wolfSSL_CTX_set_session_cache_mode
*/
int wolfSSL_CTX_set_timeout(WOLFSSL_CTX* ctx, unsigned int to);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s certificate chain.

    \return chain If successful the call will return the peer’s
    certificate chain.
    \return 0 will be returned if an invalid WOLFSSL pointer is passed to the
    function.

    \param ssl pointer to a valid WOLFSSL structure.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_chain(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief Retrieve's the peers certificate chain count.

    \return Success If successful the call will return the peer’s certificate
    chain count.
    \return 0 will be returned if an invalid chain pointer is passed to
    the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
int  wolfSSL_get_chain_count(WOLFSSL_X509_CHAIN* chain);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s ASN1.DER certificate length in bytes
    at index (idx).

    \return Success If successful the call will return the peer’s
    certificate length in bytes by index.
    \return 0 will be returned if an invalid chain pointer is passed
    to the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx index to start of chain.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_cert
    \sa wolfSSL_get_chain_cert_pem
*/
int  wolfSSL_get_chain_length(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s ASN1.DER certificate at index (idx).

    \return Success If successful the call will return the peer’s
    certificate by index.
    \return 0 will be returned if an invalid chain pointer is passed
    to the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx index to start of chain.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert_pem
*/
unsigned char* wolfSSL_get_chain_cert(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup CertsKeys

    \brief This function gets the peer’s wolfSSL_X509_certificate at
    index (idx) from the chain of certificates.

    \return pointer returns a pointer to a WOLFSSL_X509 structure.

    \param chain a pointer to the WOLFSSL_X509_CHAIN used for no dynamic
    memory SESSION_CACHE.
    \param idx the index of the WOLFSSL_X509 certificate.

    Note that it is the user's responsibility to free the returned memory
    by calling wolfSSL_FreeX509().

    _Example_
    \code
    WOLFSSL_X509_CHAIN* chain = &session->chain;
    int idx = 999; // set idx
    ...
    WOLFSSL_X509_CHAIN ptr;
    prt = wolfSSL_get_chain_X509(chain, idx);

    if(ptr != NULL){
        // ptr contains the cert at the index specified
        wolfSSL_FreeX509(ptr);
    } else {
        // ptr is NULL
    }
    \endcode

    \sa InitDecodedCert
    \sa ParseCertRelative
    \sa CopyDecodedToX509
*/
WOLFSSL_X509* wolfSSL_get_chain_X509(WOLFSSL_X509_CHAIN* chain, int idx);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s PEM certificate at index (idx).

    \return Success If successful the call will return the peer’s
    certificate by index.
    \return 0 will be returned if an invalid chain pointer is passed to
    the function.

    \param chain pointer to a valid WOLFSSL_X509_CHAIN structure.
    \param idx indexto start of chain.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_get_peer_chain
    \sa wolfSSL_get_chain_count
    \sa wolfSSL_get_chain_length
    \sa wolfSSL_get_chain_cert
*/
int  wolfSSL_get_chain_cert_pem(WOLFSSL_X509_CHAIN* chain, int idx,
                                unsigned char* buf, int inLen, int* outLen);

/*!
    \ingroup openSSL

    \brief Retrieves the session’s ID.  The session ID is always 32 bytes long.

    \return id The session ID.

    \param session pointer to a valid wolfssl session.

    _Example_
    \code
    none
    \endcode

    \sa SSL_get_session
*/
const unsigned char* wolfSSL_get_sessionID(const WOLFSSL_SESSION* s);

/*!
    \ingroup openSSL

    \brief Retrieves the peer’s certificate serial number. The serial
    number buffer (in) should be at least 32 bytes long and be provided
    as the *inOutSz argument as input. After calling the function *inOutSz
    will hold the actual length in bytes written to the in buffer.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if a bad function argument
    was encountered.

    \param in The serial number buffer and should be at least 32 bytes long
    \param inOutSz will hold the actual length in bytes written to the
    in buffer.

    _Example_
    \code
    none
    \endcode

    \sa SSL_get_peer_certificate
*/
int  wolfSSL_X509_get_serial_number(WOLFSSL_X509* x509, unsigned char* in,
                                    int* inOutSz);

/*!
    \ingroup CertsKeys

    \brief Returns the common name of the subject from the certificate.

    \return NULL returned if the x509 structure is null
    \return string a string representation of the subject's common
    name is returned upon success

    \param x509 a pointer to a WOLFSSL_X509 structure containing
    certificate information.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    ...
    int x509Cn = wolfSSL_X509_get_subjectCN(x509);
    if(x509Cn == NULL){
	    // Deal with NULL case
    } else {
	    // x509Cn contains the common name
    }
    \endcode

    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name

*/
char*  wolfSSL_X509_get_subjectCN(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief This function gets the DER encoded certificate in the
    WOLFSSL_X509 struct.

    \return buffer This function returns the DerBuffer structure’s
    buffer member, which is of type byte.
    \return NULL returned if the x509 or outSz parameter is NULL.

    \param x509 a pointer to a WOLFSSL_X509 structure containing
    certificate information.
    \param outSz length of the derBuffer member of the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
							DYNAMIC_TYPE_X509);
    int* outSz; // initialize
    ...
    byte* x509Der = wolfSSL_X509_get_der(x509, outSz);
    if(x509Der == NULL){
	    // Failure case one of the parameters was NULL
    }
    \endcode

    \sa wolfSSL_X509_version
    \sa wolfSSL_X509_Name_get_entry
    \sa wolfSSL_X509_get_next_altname
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
const unsigned char* wolfSSL_X509_get_der(WOLFSSL_X509* x509, int* outSz);

/*!
    \ingroup CertsKeys

    \brief This function checks to see if x509 is NULL and if it’s not,
    it returns the notAfter member of the x509 struct.

    \return pointer to struct with ASN1_TIME to the notAfter
    member of the x509 struct.
    \return NULL returned if the x509 object is NULL.

    \param x509 a pointer to the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    ...
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notAfter(x509);
    if(notAfter == NULL){
        // Failure case, the x509 object is null.
    }
    \endcode

    \sa wolfSSL_X509_get_notBefore
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notAfter(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief This function retrieves the version of the X509 certificate.

    \return 0 returned if the x509 structure is NULL.
    \return version the version stored in the x509 structure will be returned.

    \param x509 a pointer to a WOLFSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509;
    int version;
    ...
    version = wolfSSL_X509_version(x509);
    if(!version){
	    // The function returned 0, failure case.
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
*/
int wolfSSL_X509_version(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys

    \brief If NO_STDIO_FILESYSTEM is defined this function will allocate
    heap memory, initialize a WOLFSSL_X509 structure and return a pointer to it.

    \return *WOLFSSL_X509 WOLFSSL_X509 structure pointer is returned if
    the function executes successfully.
    \return NULL if the call to XFTELL macro returns a negative value.

    \param x509 a pointer to a WOLFSSL_X509 pointer.
    \param file a defined type that is a pointer to a FILE.

    _Example_
    \code
    WOLFSSL_X509* x509a = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    WOLFSSL_X509** x509 = x509a;
    XFILE file;  (mapped to struct fs_file*)
    ...
    WOLFSSL_X509* newX509 = wolfSSL_X509_d2i_fp(x509, file);
    if(newX509 == NULL){
	    // The function returned NULL
    }
    \endcode

    \sa wolfSSL_X509_d2i
    \sa XFTELL
    \sa XREWIND
    \sa XFSEEK
*/
WOLFSSL_X509*
        wolfSSL_X509_d2i_fp(WOLFSSL_X509** x509, FILE* file);

/*!
    \ingroup CertsKeys

    \brief The function loads the x509 certificate into memory.

    \return pointer a successful execution returns pointer to a
    WOLFSSL_X509 structure.
    \return NULL returned if the certificate was not able to be written.

    \param fname the certificate file to be loaded.
    \param format the format of the certificate.

    _Example_
    \code
    #define cliCert    “certs/client-cert.pem”
    …
    X509* x509;
    …
    x509 = wolfSSL_X509_load_certificate_file(cliCert, SSL_FILETYPE_PEM);
    AssertNotNull(x509);
    \endcode

    \sa InitDecodedCert
    \sa PemToDer
    \sa wolfSSL_get_certificate
    \sa AssertNotNull
*/
WOLFSSL_X509*
    wolfSSL_X509_load_certificate_file(const char* fname, int format);

/*!
    \ingroup CertsKeys

    \brief This function copies the device type from the x509 structure
    to the buffer.

    \return pointer returns a byte pointer holding the device type from
    the x509 structure.
    \return NULL returned if the buffer size is NULL.

    \param x509 pointer to a WOLFSSL_X509 structure, created with
    WOLFSSL_X509_new().
    \param in a pointer to a byte type that will hold the device type
    (the buffer).
    \param inOutSz the minimum of either the parameter inOutSz or the
    deviceTypeSz member of the x509 structure.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509);
    byte* in;
    int* inOutSz;
    ...
    byte* deviceType = wolfSSL_X509_get_device_type(x509, in, inOutSz);

    if(!deviceType){
	    // Failure case, NULL was returned.
    }
    \endcode

    \sa wolfSSL_X509_get_hw_type
    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_d2i
*/
unsigned char*
           wolfSSL_X509_get_device_type(WOLFSSL_X509* x509, unsigned char* in,
                                        int* inOutSz);

/*!
    \ingroup CertsKeys

    \brief The function copies the hwType member of the WOLFSSL_X509
    structure to the buffer.

    \return byte The function returns a byte type of the data previously held
    in the hwType member of the WOLFSSL_X509 structure.
    \return NULL returned if  inOutSz is NULL.

    \param x509 a pointer to a WOLFSSL_X509 structure containing certificate
    information.
    \param in pointer to type byte that represents the buffer.
    \param inOutSz pointer to type int that represents the size of the buffer.

    _Example_
    \code
    WOLFSSL_X509* x509;  // X509 certificate
    byte* in;  // initialize the buffer
    int* inOutSz;  // holds the size of the buffer
    ...
    byte* hwType = wolfSSL_X509_get_hw_type(x509, in, inOutSz);

    if(hwType == NULL){
	    // Failure case function returned NULL.
    }
    \endcode

    \sa wolfSSL_X509_get_hw_serial_number
    \sa wolfSSL_X509_get_device_type
*/
unsigned char*
           wolfSSL_X509_get_hw_type(WOLFSSL_X509* x509, unsigned char* in,
                                    int* inOutSz);

/*!
    \ingroup CertsKeys

    \brief This function returns the hwSerialNum member of the x509 object.

    \return pointer the function returns a byte pointer to the in buffer that
    will contain the serial number loaded from the x509 object.

    \param x509 pointer to a WOLFSSL_X509 structure containing certificate
    information.
    \param in a pointer to the buffer that will be copied to.
    \param inOutSz a pointer to the size of the buffer.

    _Example_
    \code
    char* serial;
    byte* in;
    int* inOutSz;
    WOLFSSL_X509 x509;
    ...
    serial = wolfSSL_X509_get_hw_serial_number(x509, in, inOutSz);

    if(serial == NULL || serial <= 0){
    	// Failure case
    }
    \endcode

    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_isCA
    \sa wolfSSL_get_peer_certificate
    \sa wolfSSL_X509_version
*/
unsigned char*
           wolfSSL_X509_get_hw_serial_number(WOLFSSL_X509* x509,
                                             unsigned char* in, int* inOutSz);

/*!
    \ingroup IO

    \brief This function is called on the client side and initiates an
    SSL/TLS handshake with a server only long enough to get the peer’s
    certificate chain.  When this function is called, the underlying
    communication channel has already been set up. wolfSSL_connect_cert()
    works with both blocking and non-blocking I/O.  When the underlying I/O
    is non-blocking, wolfSSL_connect_cert() will return when the underlying
    I/O could not satisfy the needs of wolfSSL_connect_cert() to continue the
    handshake.  In this case, a call to wolfSSL_get_error() will yield either
    SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process must then
    repeat the call to wolfSSL_connect_cert() when the underlying I/O is ready
    and wolfSSL will pick up where it left off. When using a non-blocking
    socket, nothing needs to be done, but select() can be used to check for
    the required condition. If the underlying I/O is blocking,
    wolfSSL_connect_cert() will only return once the peer’s certificate chain
    has been received.

    \return SSL_SUCCESS upon success.
    \return SSL_FAILURE will be returned if the SSL session parameter is NULL.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a more
    detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    ret = wolfSSL_connect_cert(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept
*/
int  wolfSSL_connect_cert(WOLFSSL* ssl);

/*!
    \ingroup openSSL

    \brief wolfSSL_d2i_PKCS12_bio (d2i_PKCS12_bio) copies in the PKCS12
    information from WOLFSSL_BIO to the structure WC_PKCS12. The information
    is divided up in the structure as a list of Content Infos along with a
    structure to hold optional MAC information. After the information has been
    divided into chunks (but not decrypted) in the structure WC_PKCS12, it can
    then be parsed and decrypted by calling.

    \return WC_PKCS12 pointer to a WC_PKCS12 structure.
    \return Failure If function failed it will return NULL.

    \param bio WOLFSSL_BIO structure to read PKCS12 buffer from.
    \param pkcs12 WC_PKCS12 structure pointer for new PKCS12 structure created.
    Can be NULL

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode

    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_d2i_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12** pkcs12);

/*!
    \ingroup openSSL

    \brief wolfSSL_i2d_PKCS12_bio (i2d_PKCS12_bio) copies in the cert
    information from the structure WC_PKCS12 to WOLFSSL_BIO.

    \return 1 for success.
    \return Failure 0.

    \param bio WOLFSSL_BIO structure to write PKCS12 buffer to.
    \param pkcs12 WC_PKCS12 structure for PKCS12 structure as input.

    _Example_
    \code
    WC_PKCS12 pkcs12;
    FILE *f;
    byte buffer[5300];
    char file[] = "./test.p12";
    int bytes;
    WOLFSSL_BIO* bio;
    pkcs12 = wc_PKCS12_new();
    f = fopen(file, "rb");
    bytes = (int)fread(buffer, 1, sizeof(buffer), f);
    fclose(f);
    //convert the DER file into an internal structure
    wc_d2i_PKCS12(buffer, bytes, pkcs12);
    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    //convert PKCS12 structure into bio
    wolfSSL_i2d_PKCS12_bio(bio, pkcs12);
    wc_PKCS12_free(pkcs)
    //use bio
    \endcode

    \sa wolfSSL_PKCS12_parse
    \sa wc_PKCS12_free
*/
WC_PKCS12* wolfSSL_i2d_PKCS12_bio(WOLFSSL_BIO* bio,
                                       WC_PKCS12* pkcs12);

/*!
    \ingroup openSSL

    \brief PKCS12 can be enabled with adding –enable-opensslextra to the
    configure command. It can use triple DES and RC4 for decryption so would
    recommend also enabling these features when enabling opensslextra
    (--enable-des3 –enable-arc4). wolfSSL does not currently support RC2 so
    decryption with RC2 is currently not available. This may be noticeable
    with default encryption schemes used by OpenSSL command line to create
    .p12 files. wolfSSL_PKCS12_parse (PKCS12_parse). The first thing this
    function does is check the MAC is correct if present. If the MAC fails
    then the function returns and does not try to decrypt any of the stored
    Content Infos. This function then parses through each Content Info
    looking for a bag type, if the bag type is known it is decrypted as
    needed and either stored in the list of certificates being built or as
    a key found. After parsing through all bags the key found is then
    compared with the certificate list until a matching pair is found.
    This matching pair is then returned as the key and certificate,
    optionally the certificate list found is returned as a STACK_OF
    certificates. At the moment a CRL, Secret or SafeContents bag will be
    skipped over and not parsed. It can be seen if these or other “Unknown”
    bags are skipped over by viewing the debug print out. Additional attributes
    such as friendly name are skipped over when parsing a PKCS12 file.

    \return SSL_SUCCESS On successfully parsing PKCS12.
    \return SSL_FAILURE If an error case was encountered.

    \param pkcs12 WC_PKCS12 structure to parse.
    \param paswd password for decrypting PKCS12.
    \param pkey structure to hold private key decoded from PKCS12.
    \param cert structure to hold certificate decoded from PKCS12.
    \param stack optional stack of extra certificates.

    _Example_
    \code
    WC_PKCS12* pkcs;
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* cert;
    WOLFSSL_EVP_PKEY* pkey;
    STACK_OF(X509) certs;
    //bio loads in PKCS12 file
    wolfSSL_d2i_PKCS12_bio(bio, &pkcs);
    wolfSSL_PKCS12_parse(pkcs, “a password”, &pkey, &cert, &certs)
    wc_PKCS12_free(pkcs)
    //use cert, pkey, and optionally certs stack
    \endcode

    \sa wolfSSL_d2i_PKCS12_bio
    \sa wc_PKCS12_free
*/
int wolfSSL_PKCS12_parse(WC_PKCS12* pkcs12, const char* psw,
     WOLFSSL_EVP_PKEY** pkey, WOLFSSL_X509** cert, WOLF_STACK_OF(WOLFSSL_X509)** ca);

/*!
    \ingroup CertsKeys

    \brief Server Diffie-Hellman Ephemeral parameters setting. This function
    sets up the group parameters to be used if the server negotiates a cipher
    suite that uses DHE.

    \return SSL_SUCCESS upon success.
    \return MEMORY_ERROR will be returned if a memory error was encountered.
    \return SIDE_ERROR will be returned if this function is called on an SSL
    client instead of an SSL server.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param p Diffie-Hellman prime number parameter.
    \param pSz size of p.
    \param g Diffie-Hellman “generator” parameter.
    \param gSz size of g.

    _Example_
    \code
    WOLFSSL* ssl;
    static unsigned char p[] = {...};
    static unsigned char g[] = {...};
    ...
    wolfSSL_SetTmpDH(ssl, p, sizeof(p), g, sizeof(g));
    \endcode

    \sa SSL_accept
*/
int  wolfSSL_SetTmpDH(WOLFSSL* ssl, const unsigned char* p, int pSz,
                                const unsigned char* g, int gSz);

/*!
    \ingroup CertsKeys

    \brief The function calls the wolfSSL_SetTMpDH_buffer_wrapper,
    which is a wrapper for Diffie-Hellman parameters.

    \return SSL_SUCCESS on successful execution.
    \return SSL_BAD_FILETYPE if the file type is not PEM and is not
    ASN.1. It will also be returned if the wc_DhParamsLoad does not
    return normally.
    \return SSL_NO_PEM_HEADER returns from PemToDer if there is not
    a PEM header.
    \return SSL_BAD_FILE returned if there is a file error in PemToDer.
    \return SSL_FATAL_ERROR returned from PemToDer if there was a copy error.
    \return MEMORY_E - if there was a memory allocation error.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if
    there was otherwise a NULL argument passed to a subroutine.
    \return DH_KEY_SIZE_E is returned if their is a key size error in
    wolfSSL_SetTmpDH() or in wolfSSL_CTX_SetTmpDH().
    \return SIDE_ERROR returned if it is not the server side
    in wolfSSL_SetTmpDH.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf allocated buffer passed in from wolfSSL_SetTMpDH_file_wrapper.
    \param sz a long int that holds the size of the file
    (fname within wolfSSL_SetTmpDH_file_wrapper).
    \param format an integer type passed through from
    wolfSSL_SetTmpDH_file_wrapper() that is a representation of the certificate
    format.

    _Example_
    \code
    Static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    long sz = 0;
    byte* myBuffer = staticBuffer[FILE_BUFFER_SIZE];
    …
    if(ssl)
    ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    \endcode

    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wc_DhParamsLoad
    \sa wolfSSL_SetTmpDH
    \sa PemToDer
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int  wolfSSL_SetTmpDH_buffer(WOLFSSL* ssl, const unsigned char* b, long sz,
                                       int format);

/*!
    \ingroup CertsKeys

    \brief This function calls wolfSSL_SetTmpDH_file_wrapper to set server
    Diffie-Hellman parameters.

    \return SSL_SUCCESS returned on successful completion of this function
    and its subroutines.
    \return MEMORY_E returned if a memory allocation failed in this function
    or a subroutine.
    \return SIDE_ERROR if the side member of the Options structure found
    in the WOLFSSL struct is not the server side.
    \return SSL_BAD_FILETYPE returns if the certificate fails a set of checks.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is less than
    the value of the minDhKeySz member in the WOLFSSL struct.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is greater
    than the value of the maxDhKeySz member in the WOLFSSL struct.
    \return BAD_FUNC_ARG returns if an argument value is NULL that is not
    permitted such as, the WOLFSSL structure.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param fname a constant char pointer holding the certificate.
    \param format an integer type that holds the format of the certification.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* dhParam;
    …
    AssertIntNE(SSL_SUCCESS,
    wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM));
    \endcode

    \sa wolfSSL_CTX_SetTmpDH_file
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
*/
int  wolfSSL_SetTmpDH_file(WOLFSSL* ssl, const char* f, int format);

/*!
    \ingroup CertsKeys

    \brief Sets the parameters for the server CTX Diffie-Hellman.

    \return SSL_SUCCESS returned if the function and all subroutines
    return without error.
    \return BAD_FUNC_ARG returned if the CTX, p or g parameters are NULL.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is less than
    the value of the minDhKeySz member of the WOLFSSL_CTX struct.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is greater
    than the value of the maxDhKeySz member of the WOLFSSL_CTX struct.
    \return MEMORY_E returned if the allocation of memory failed in this
    function or a subroutine.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param p a constant unsigned char pointer loaded into the buffer
    member of the serverDH_P struct.
    \param pSz an int type representing the size of p, initialized
    to MAX_DH_SIZE.
    \param g a constant unsigned char pointer loaded into the buffer
    member of the serverDH_G struct.
    \param gSz an int type representing the size of g, initialized to
    MAX_DH_SIZE.

    _Exmaple_
    \code
    WOLFSSL_CTX* ctx =  WOLFSSL_CTX_new( protocol );
    byte* p;
    byte* g;
    word32 pSz = (word32)sizeof(p)/sizeof(byte);
    word32 gSz = (word32)sizeof(g)/sizeof(byte);
    …
    int ret =  wolfSSL_CTX_SetTmpDH(ctx, p, pSz, g, gSz);

    if(ret != SSL_SUCCESS){
    	// Failure case
    }
    \endcode

    \sa wolfSSL_SetTmpDH
    \sa wc_DhParamsLoad
*/
int  wolfSSL_CTX_SetTmpDH(WOLFSSL_CTX* ctx, const unsigned char* p,
                                    int pSz, const unsigned char* g, int gSz);

/*!
    \ingroup CertsKeys

    \brief A wrapper function that calls wolfSSL_SetTmpDH_buffer_wrapper

    \return 0 returned for a successful execution.
    \return BAD_FUNC_ARG returned if the ctx or buf parameters are NULL.
    \return MEMORY_E if there is a memory allocation error.
    \return SSL_BAD_FILETYPE returned if format is not correct.

    \param ctx a pointer to a WOLFSSL structure, created using
    wolfSSL_CTX_new().
    \param buf a pointer to a constant unsigned char type that is
    allocated as the buffer and passed through to
    wolfSSL_SetTmpDH_buffer_wrapper.
    \param sz a long integer type that is derived from the fname parameter
    in wolfSSL_SetTmpDH_file_wrapper().
    \param format an integer type passed through from
    wolfSSL_SetTmpDH_file_wrapper().

    _Example_
    \code
    static int wolfSSL_SetTmpDH_file_wrapper(WOLFSSL_CTX* ctx, WOLFSSL* ssl,
    Const char* fname, int format);
    #ifdef WOLFSSL_SMALL_STACK
    byte staticBuffer[1]; // force heap usage
    #else
    byte* staticBuffer;
    long sz = 0;
    …
    if(ssl){
    	ret = wolfSSL_SetTmpDH_buffer(ssl, myBuffer, sz, format);
    } else {
    ret = wolfSSL_CTX_SetTmpDH_buffer(ctx, myBuffer, sz, format);
    }
    \endcode

    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTMpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int  wolfSSL_CTX_SetTmpDH_buffer(WOLFSSL_CTX* ctx, const unsigned char* b,
                                           long sz, int format);

/*!
    \ingroup CertsKeys

    \brief The function calls wolfSSL_SetTmpDH_file_wrapper to set the server
    Diffie-Hellman parameters.

    \return SSL_SUCCESS returned if the wolfSSL_SetTmpDH_file_wrapper or any
    of its subroutines return successfully.
    \return MEMORY_E returned if an allocation of dynamic memory fails in a
    subroutine.
    \return BAD_FUNC_ARG returned if the ctx or fname parameters are NULL or
    if
    a subroutine is passed a NULL argument.
    \return SSL_BAD_FILE returned if the certificate file is unable to open or
    if the a set of checks on the file fail from wolfSSL_SetTmpDH_file_wrapper.
    \return SSL_BAD_FILETYPE returned if the format is not PEM or ASN.1 from
    wolfSSL_SetTmpDH_buffer_wrapper().
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is less than
    the value of the minDhKeySz member of the WOLFSSL_CTX struct.
    \return DH_KEY_SIZE_E returned if the DH parameter's key size is greater
    than the value of the maxDhKeySz member of the WOLFSSL_CTX struct.
    \return SIDE_ERROR returned in wolfSSL_SetTmpDH() if the side is not the
    server end.
    \return SSL_NO_PEM_HEADER returned from PemToDer if there is no PEM header.
    \return SSL_FATAL_ERROR returned from PemToDer if there is a memory copy
    failure.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param fname a constant character pointer to a certificate file.
    \param format an integer type passed through from
    wolfSSL_SetTmpDH_file_wrapper() that is a representation of
    the certificate format.

    _Example_
    \code
    #define dhParam     “certs/dh2048.pem”
    #DEFINE aSSERTiNTne(x, y)     AssertInt(x, y, !=, ==)
    WOLFSSL_CTX* ctx;
    …
    AssertNotNull(ctx = wolfSSL_CTX_new(wolfSSLv23_client_method()))
    …
    AssertIntNE(SSL_SUCCESS, wolfSSL_CTX_SetTmpDH_file(NULL, dhParam,
    SSL_FILETYPE_PEM));
    \endcode

    \sa wolfSSL_SetTmpDH_buffer_wrapper
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH_buffer
    \sa wolfSSL_CTX_SetTmpDH_buffer
    \sa wolfSSL_SetTmpDH_file_wrapper
    \sa AllocDer
    \sa PemToDer
*/
int  wolfSSL_CTX_SetTmpDH_file(WOLFSSL_CTX* ctx, const char* f,
                                             int format);

/*!
    \ingroup CertsKeys

    \brief This function sets the minimum size (in bits) of the Diffie Hellman
    key size by accessing the minDhKeySz member in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned if the function completes successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if
    the keySz_bits is greater than 16,000 or not divisible by 8.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param keySz_bits a word16 type used to set the minimum DH key size in bits.
    The WOLFSSL_CTX struct holds this information in the minDhKeySz member.

    _Example_
    \code
    public static int CTX_SetMinDhKey_Sz(IntPtr ctx, short minDhKey){
    …
    return wolfSSL_CTX_SetMinDhKey_Sz(local_ctx, minDhKeyBits);
    \endcode

    \sa wolfSSL_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetMaxDhKey_Sz
    \sa wolfSSL_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
    \sa wolfSSL_CTX_SetTMpDH_file
*/
int wolfSSL_CTX_SetMinDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum size (in bits) for a Diffie-Hellman key in the
    WOLFSSL structure.

    \return SSL_SUCCESS the minimum size was successfully set.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL or if the keySz_bits is
    greater than 16,000 or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz_bits a word16 type used to set the minimum DH key size in bits.
    The WOLFSSL_CTX struct holds this information in the minDhKeySz member.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz_bits;
    ...
    if(wolfSSL_SetMinDhKey_Sz(ssl, keySz_bits) != SSL_SUCCESS){
	    // Failed to set.
    }
    \endcode

    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMinDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief This function sets the maximum size (in bits) of the Diffie Hellman
    key size by accessing the maxDhKeySz member in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned if the function completes successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if
    the keySz_bits is greater than 16,000 or not divisible by 8.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param keySz_bits a word16 type used to set the maximum DH key size in bits.
    The WOLFSSL_CTX struct holds this information in the maxDhKeySz member.

    _Example_
    \code
    public static int CTX_SetMaxDhKey_Sz(IntPtr ctx, short maxDhKey){
    …
    return wolfSSL_CTX_SetMaxDhKey_Sz(local_ctx, keySz_bits);
    \endcode

    \sa wolfSSL_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
    \sa wolfSSL_CTX_SetTMpDH_file
*/
int wolfSSL_CTX_SetMaxDhKey_Sz(WOLFSSL_CTX* ctx, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief Sets the maximum size (in bits) for a Diffie-Hellman key in the
    WOLFSSL structure.

    \return SSL_SUCCESS the maximum size was successfully set.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL or the keySz parameter
    was greater than the allowable size or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz a word16 type representing the bit size of the maximum DH key.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    word16 keySz;
    ...
    if(wolfSSL_SetMaxDhKey(ssl, keySz) != SSL_SUCCESS){
	    // Failed to set.
    }
    \endcode

    \sa wolfSSL_CTX_SetMaxDhKey_Sz
    \sa wolfSSL_GetDhKey_Sz
*/
int wolfSSL_SetMaxDhKey_Sz(WOLFSSL* ssl, word16 keySz_bits);

/*!
    \ingroup CertsKeys

    \brief Returns the value of dhKeySz (in bits) that is a member of the
    options structure. This value represents the Diffie-Hellman key size in
    bytes.

    \return dhKeySz returns the value held in ssl->options.dhKeySz which is an
    integer value representing a size in bits.
    \return BAD_FUNC_ARG returns if the WOLFSSL struct is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int dhKeySz;
    ...
    dhKeySz = wolfSSL_GetDhKey_Sz(ssl);

    if(dhKeySz == BAD_FUNC_ARG || dhKeySz <= 0){
    	// Failure case
    } else {
    	// dhKeySz holds the size of the key.
    }
    \endcode

    \sa wolfSSL_SetMinDhKey_sz
    \sa wolfSSL_CTX_SetMinDhKey_Sz
    \sa wolfSSL_CTX_SetTmpDH
    \sa wolfSSL_SetTmpDH
    \sa wolfSSL_CTX_SetTmpDH_file
*/
int wolfSSL_GetDhKey_Sz(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum RSA key size in both the WOLFSSL_CTX structure
    and the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the ctx structure is NULL or the keySz
    is less than zero or not divisible by 8.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param keySz a short integer type stored in minRsaKeySz in the ctx
    structure and the cm structure converted to bytes.

    _Example_
    \code
    WOLFSSL_CTX* ctx = SSL_CTX_new(method);
    (void)minDhKeyBits;
    ourCert = myoptarg;
    …
    minDhKeyBits = atoi(myoptarg);
    …
    if(wolfSSL_CTX_SetMinRsaKey_Sz(ctx, minRsaKeyBits) != SSL_SUCCESS){
    …
    \endcode

    \sa wolfSSL_SetMinRsaKey_Sz
*/
int wolfSSL_CTX_SetMinRsaKey_Sz(WOLFSSL_CTX* ctx, short keySz);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum allowable key size in bits for RSA located in the
    WOLFSSL structure.

    \return SSL_SUCCESS the minimum was set successfully.
    \return BAD_FUNC_ARG returned if the ssl structure is NULL or if the ksySz
    is less than zero or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz a short integer value representing the the minimum key in bits.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    short keySz;
    …

    int isSet =  wolfSSL_SetMinRsaKey_Sz(ssl, keySz);
    if(isSet != SSL_SUCCESS){
	    Failed to set.
    }
    \endcode

    \sa wolfSSL_CTX_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinRsaKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief Sets the minimum size in bits for the ECC key in the WOLF_CTX
    structure and the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned for a successful execution and the minEccKeySz
    member is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or if
    the keySz is negative or not divisible by 8.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param keySz a short integer type that represents the minimum ECC key
    size in bits.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    short keySz; // minimum key size
    …
    if(wolfSSL_CTX_SetMinEccKey(ctx, keySz) != SSL_SUCCESS){
	    // Failed to set min key size
    }
    \endcode

    \sa wolfSSL_SetMinEccKey_Sz
*/
int wolfSSL_CTX_SetMinEccKey_Sz(WOLFSSL_CTX* ctx, short keySz);

/*!
    \ingroup CertsKeys

    \brief Sets the value of the minEccKeySz member of the options structure.
    The options struct is a member of the WOLFSSL structure and is
    accessed through the ssl parameter.

    \return SSL_SUCCESS if the function successfully set the minEccKeySz
    member of the options structure.
    \return BAD_FUNC_ARG if the WOLFSSL_CTX structure is NULL or if the
    key size (keySz) is less than 0 (zero) or not divisible by 8.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param keySz value used to set the minimum ECC key size. Sets
    value in the options structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx); // New session
    short keySz = 999; // should be set to min key size allowable
    ...
    if(wolfSSL_SetMinEccKey_Sz(ssl, keySz) != SSL_SUCCESS){
	    // Failure case.
    }
    \endcode

    \sa wolfSSL_CTX_SetMinEccKey_Sz
    \sa wolfSSL_CTX_SetMinRsaKey_Sz
    \sa wolfSSL_SetMinRsaKey_Sz
*/
int wolfSSL_SetMinEccKey_Sz(WOLFSSL* ssl, short keySz);

/*!
    \ingroup CertsKeys

    \brief This function is used by EAP_TLS and EAP-TTLS to derive
    keying material from the master secret.

    \return BUFFER_E returned if the actual size of the buffer exceeds
    the maximum size allowable.
    \return MEMORY_E returned if there is an error with memory allocation.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param key a void pointer variable that will hold the result
    of the p_hash function.
    \param len an unsigned integer that represents the length of
    the key variable.
    \param label a constant char pointer that is copied from in wc_PRF().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);;
    void* key;
    unsigned int len;
    const char* label;
    …
    return wolfSSL_make_eap_keys(ssl, key, len, label);
    \endcode

    \sa wc_PRF
    \sa wc_HmacFinal
    \sa wc_HmacUpdate
*/
int wolfSSL_make_eap_keys(WOLFSSL* ssl, void* key, unsigned int len,
                                                             const char* label);

/*!
    \ingroup IO

    \brief Simulates writev semantics but doesn’t actually do block at a time
    because of SSL_write() behavior and because front adds may be small.
    Makes porting into software that uses writev easier.

    \return >0 the number of bytes written upon success.
    \return 0 will be returned upon failure.  Call wolfSSL_get_error() for
    the specific error code.
    \return MEMORY_ERROR will be returned if a memory error was encountered.
    \return SSL_FATAL_ERROR will be returned upon failure when either an error
    occurred or, when using non-blocking sockets, the SSL_ERROR_WANT_READ or
    SSL_ERROR_WANT_WRITE error was received and and the application needs to
    call wolfSSL_write() again.  Use wolfSSL_get_error() to get a specific
    error code.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param iov array of I/O vectors to write
    \param iovcnt number of vectors in iov array.

    _Example_
    \code
    WOLFSSL* ssl = 0;
    char *bufA = “hello\n”;
    char *bufB = “hello world\n”;
    int iovcnt;
    struct iovec iov[2];

    iov[0].iov_base = buffA;
    iov[0].iov_len = strlen(buffA);
    iov[1].iov_base = buffB;
    iov[1].iov_len = strlen(buffB);
    iovcnt = 2;
    ...
    ret = wolfSSL_writev(ssl, iov, iovcnt);
    // wrote “ret” bytes, or error if <= 0.
    \endcode

    \sa wolfSSL_write
*/
int wolfSSL_writev(WOLFSSL* ssl, const struct iovec* iov,
                                     int iovcnt);

/*!
    \ingroup Setup

    \brief This function unloads the CA signer list and frees
    the whole signer table.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or there
    are otherwise unpermitted argument values passed in a subroutine.
    \return BAD_MUTEX_E returned if there was a mutex error. The LockMutex()
    did not return 0.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    if(wolfSSL_CTX_UnloadCAs(ctx) != SSL_SUCCESS){
    	// The function did not unload CAs
    }
    \endcode

    \sa wolfSSL_CertManagerUnloadCAs
    \sa LockMutex
    \sa UnlockMutex
*/
int wolfSSL_CTX_UnloadCAs(WOLFSSL_CTX* ctx);


/*!
    \ingroup Setup

    \brief This function unloads intermediate certificates added to the CA
    signer list and frees them.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX struct is NULL or there
    are otherwise unpermitted argument values passed in a subroutine.
    \return BAD_STATE_E returned if the WOLFSSL_CTX has a reference count > 1.
    \return BAD_MUTEX_E returned if there was a mutex error. The LockMutex()
    did not return 0.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_METHOD method = wolfTLSv1_2_client_method();
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(method);
    …
    if(wolfSSL_CTX_UnloadIntermediateCerts(ctx) != NULL){
        // The function did not unload CAs
    }
    \endcode

    \sa wolfSSL_CTX_UnloadCAs
    \sa wolfSSL_CertManagerUnloadIntermediateCerts
*/
int wolfSSL_CTX_UnloadIntermediateCerts(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is used to unload all previously loaded trusted peer
    certificates. Feature is enabled by defining the macro
    WOLFSSL_TRUST_PEER_CERT.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if ctx is NULL.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_Unload_trust_peers(ctx);
    if (ret != SSL_SUCCESS) {
        // error unloading trusted peer certs
    }
    ...
    \endcode

    \sa wolfSSL_CTX_trust_peer_buffer
    \sa wolfSSL_CTX_trust_peer_cert
*/
int wolfSSL_CTX_Unload_trust_peers(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function loads a certificate to use for verifying a peer
    when performing a TLS/SSL handshake. The peer certificate sent during
    the handshake is compared by using the SKID when available and the
    signature. If these two things do not match then any loaded CAs are used.
    Is the same functionality as wolfSSL_CTX_trust_peer_cert except is from
    a buffer instead of a file. Feature is enabled by defining the macro
    WOLFSSL_TRUST_PEER_CERT Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_FAILURE will be returned if ctx is NULL, or if both file and
    type are invalid.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param buffer pointer to the buffer containing certificates.
    \param sz length of the buffer input.
    \param type type of certificate being loaded i.e. SSL_FILETYPE_ASN1 or
    SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    ...

    ret = wolfSSL_CTX_trust_peer_buffer(ctx, bufferPtr, bufferSz,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    // error loading trusted peer cert
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_PrivateKey_file
    \sa wolfSSL_CTX_use_certificate_chain_file
    \sa wolfSSL_CTX_trust_peer_cert
    \sa wolfSSL_CTX_Unload_trust_peers
    \sa wolfSSL_use_certificate_file
    \sa wolfSSL_use_PrivateKey_file
    \sa wolfSSL_use_certificate_chain_file
*/
int wolfSSL_CTX_trust_peer_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                  long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a CA certificate buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz. format specifies
    the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    More than one CA certificate may be loaded per buffer as long as the
    format is in PEM.  Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in pointer to the CA certificate buffer.
    \param sz size of the input CA certificate buffer, in.
    \param format format of the buffer certificate, either SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    ret = wolfSSL_CTX_load_verify_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* in,
                                   long sz, int format);


/*!
    \ingroup CertsKeys

    \brief This function loads a CA certificate buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz. format specifies
    the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    More than one CA certificate may be loaded per buffer as long as the
    format is in PEM.  The _ex version was added in PR 2413 and supports
    additional arguments for userChain and flags.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in pointer to the CA certificate buffer.
    \param sz size of the input CA certificate buffer, in.
    \param format format of the buffer certificate, either SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.
    \param userChain If using format WOLFSSL_FILETYPE_ASN1 this set to non-zero
    indicates a chain of DER's is being presented.
    \param flags: See ssl.h around WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    // Example for force loading an expired certificate
    ret = wolfSSL_CTX_load_verify_buffer_ex(ctx, certBuff, sz, SSL_FILETYPE_PEM,
        0, (WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY));
    if (ret != SSL_SUCCESS) {
    	// error loading CA certs from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX* ctx,
                                      const unsigned char* in, long sz,
                                      int format, int userChain, word32 flags);

/*!
    \ingroup CertsKeys

    \brief This function loads a CA certificate chain buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz. format specifies
    the format type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    More than one CA certificate may be loaded per buffer as long as the
    format is in PEM.  Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in pointer to the CA certificate buffer.
    \param sz size of the input CA certificate buffer, in.
    \param format format of the buffer certificate, either SSL_FILETYPE_ASN1
    or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...

    ret = wolfSSL_CTX_load_verify_chain_buffer_format(ctx,
                         certBuff, sz, WOLFSSL_FILETYPE_ASN1);
    if (ret != SSL_SUCCESS) {
        // error loading CA certs from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_load_verify_chain_buffer_format(WOLFSSL_CTX* ctx,
                                               const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate buffer into the WOLFSSL Context.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file.  The buffer is
    provided by the in argument of size sz.  format specifies the format
    type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please
    see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the certificate to be loaded.
    \param sz the size of the input buffer.
    \param format the format of the certificate located in the input
    buffer (in).  Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    // error loading certificate from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx,
                                       const unsigned char* in, long sz,
                                       int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a private key buffer into the SSL Context.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file.  The buffer is
    provided by the in argument of size sz.  format specifies the format type
    of the buffer; SSL_FILETYPE_ASN1or SSL_FILETYPE_PEM.  Please see the
    examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return NO_PASSWORD will be returned if the key file is encrypted but no
    password is provided.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the private key to be loaded.
    \param sz the size of the input buffer.
    \param format the format of the private key located in the input
    buffer (in).  Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte keyBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, keyBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// error loading private key from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx,
                                      const unsigned char* in, long sz,
                                      int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate chain buffer into the WOLFSSL
    Context. It behaves like the non-buffered version, only differing in
    its ability to be called with a buffer as input instead of a file.
    The buffer is provided by the in argument of size sz.  The buffer must
    be in PEM format and start with the subject’s certificate, ending with
    the root certificate. Please see the examples for proper usage.

    \return SSL_SUCCESS upon success
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param in the input buffer containing the PEM-formatted certificate
    chain to be loaded.
    \param sz the size of the input buffer.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx;
    byte certChainBuff[...];
    long sz = sizeof(certBuff);
    ...
    ret = wolfSSL_CTX_use_certificate_chain_buffer(ctx, certChainBuff, sz);
    if (ret != SSL_SUCCESS) {
    	// error loading certificate chain from buffer
    }
    ...
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_CTX_use_certificate_chain_buffer(WOLFSSL_CTX* ctx,
                                             const unsigned char* in, long sz);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate buffer into the WOLFSSL object.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file. The buffer
    is provided by the in argument of size sz.  format specifies the format
    type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.
    Please see the examples for proper usage.

    \return SSL_SUCCESS upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t
    be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing certificate to load.
    \param sz size of the certificate located in buffer.
    \param format format of the certificate to be loaded.
    Possible values are SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret;
    byte certBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...

    ret = wolfSSL_use_certificate_buffer(ssl, certBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate from buffer
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_PrivateKey_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_certificate_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a private key buffer into the WOLFSSL object.
    It behaves like the non-buffered version, only differing in its ability
    to be called with a buffer as input instead of a file.  The buffer is
    provided by the in argument of size sz. format specifies the format
    type of the buffer; SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.  Please
    see the examples for proper usage.

    \return SSL_SUCCESS upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return NO_PASSWORD will be returned if the key file is encrypted but no
    password is provided.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing private key to load.
    \param sz size of the private key located in buffer.
    \param format format of the private key to be loaded.  Possible values are
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret;
    byte keyBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...
    ret = wolfSSL_use_PrivateKey_buffer(ssl, keyBuff, buffSz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	// failed to load private key from buffer
    }
    \endcode

    \sa wolfSSL_use_PrivateKey
    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_certificate_chain_buffer
*/
int wolfSSL_use_PrivateKey_buffer(WOLFSSL* ssl, const unsigned char* in,
                                               long sz, int format);

/*!
    \ingroup CertsKeys

    \brief This function loads a certificate chain buffer into the WOLFSSL
    object.  It behaves like the non-buffered version, only differing in its
    ability to be called with a buffer as input instead of a file. The buffer
    is provided by the in argument of size sz.  The buffer must be in PEM format
    and start with the subject’s certificate, ending with the root certificate.
    Please see the examples for proper usage.

    \return SSL_SUCCES upon success.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BUFFER_E will be returned if a chain buffer is bigger than
    the receiving buffer.

    \param ssl pointer to the SSL session, created with wolfSSL_new().
    \param in buffer containing certificate to load.
    \param sz size of the certificate located in buffer.

    _Example_
    \code
    int ret;
    byte certChainBuff[...];
    WOLFSSL* ssl = 0;
    long buffSz = sizeof(certBuff);
    ...
    ret = wolfSSL_use_certificate_chain_buffer(ssl, certChainBuff, buffSz);
    if (ret != SSL_SUCCESS) {
    	// failed to load certificate chain from buffer
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa wolfSSL_CTX_use_certificate_buffer
    \sa wolfSSL_CTX_use_PrivateKey_buffer
    \sa wolfSSL_CTX_use_certificate_chain_buffer
    \sa wolfSSL_use_certificate_buffer
    \sa wolfSSL_use_PrivateKey_buffer
*/
int wolfSSL_use_certificate_chain_buffer(WOLFSSL* ssl,
                                         const unsigned char* in, long sz);

/*!
    \ingroup CertsKeys

    \brief This function unloads any certificates or keys that SSL owns.

    \return SSL_SUCCESS - returned if the function executed successfully.
    \return BAD_FUNC_ARG - returned if the WOLFSSL object is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    int unloadKeys = wolfSSL_UnloadCertsKeys(ssl);
    if(unloadKeys != SSL_SUCCESS){
	    // Failure case.
    }
    \endcode

    \sa wolfSSL_CTX_UnloadCAs
*/
int wolfSSL_UnloadCertsKeys(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function turns on grouping of handshake messages where possible.

    \return SSL_SUCCESS will be returned upon success.
    \return BAD_FUNC_ARG will be returned if the input context is null.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    ret = wolfSSL_CTX_set_group_messages(ctx);
    if (ret != SSL_SUCCESS) {
	    // failed to set handshake message grouping
    }
    \endcode

    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_new
*/
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function turns on grouping of handshake messages where possible.

    \return SSL_SUCCESS will be returned upon success.
    \return BAD_FUNC_ARG will be returned if the input context is null.

    \param ssl pointer to the SSL session, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = 0;
    ...
    ret = wolfSSL_set_group_messages(ssl);
    if (ret != SSL_SUCCESS) {
	// failed to set handshake message grouping
    }
    \endcode

    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_new
*/
int wolfSSL_set_group_messages(WOLFSSL* ssl);

/*!
    \brief This function sets the fuzzer callback.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cbf a CallbackFuzzer type that is a function pointer of the form:
    int (*CallbackFuzzer)(WOLFSSL* ssl, const unsigned char* buf, int sz, int
    type, void* fuzzCtx);
    \param fCtx a void pointer type that will be set to the fuzzerCtx member of
    the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    void* fCtx;

    int callbackFuzzerCB(WOLFSSL* ssl, const unsigned char* buf, int sz,
				int type, void* fuzzCtx){
    // function definition
    }
    …
    wolfSSL_SetFuzzerCb(ssl, callbackFuzzerCB, fCtx);
    \endcode

    \sa CallbackFuzzer
*/
void wolfSSL_SetFuzzerCb(WOLFSSL* ssl, CallbackFuzzer cbf, void* fCtx);

/*!
    \brief This function sets a new dtls cookie secret.

    \return 0 returned if the function executed without an error.
    \return BAD_FUNC_ARG returned if there was an argument passed
    to the function with an unacceptable value.
    \return COOKIE_SECRET_SZ returned if the secret size is 0.
    \return MEMORY_ERROR returned if there was a problem allocating
    memory for a new cookie secret.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param secret a constant byte pointer representing the secret buffer.
    \param secretSz the size of the buffer.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const* byte secret;
    word32 secretSz; // size of secret
    …
    if(!wolfSSL_DTLS_SetCookieSecret(ssl, secret, secretSz)){
    	// Code block for failure to set DTLS cookie secret
    } else {
    	// Success! Cookie secret is set.
    }
    \endcode

    \sa ForceZero
    \sa wc_RNG_GenerateBlock
*/
int   wolfSSL_DTLS_SetCookieSecret(WOLFSSL* ssl,
                                               const byte* secret,
                                               word32 secretSz);

/*!
    \brief This function retrieves the random number.

    \return rng upon success.
    \return NULL if ssl is NULL.

    \param ssl pointer to a SSL object, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;

    wolfSSL_GetRNG(ssl);

    \endcode

    \sa  wolfSSL_CTX_new_rng

*/
WC_RNG* wolfSSL_GetRNG(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the minimum downgrade version allowed.
    Applicable only when the connection allows downgrade using
    (wolfSSLv23_client_method or wolfSSLv23_server_method).

    \return SSL_SUCCESS returned if the function returned without
    error and the minimum version is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure was
    NULL or if the minimum version is not supported.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param version an integer representation of the version to be set as the
    minimum: WOLFSSL_SSLV3 = 0, WOLFSSL_TLSV1 = 1, WOLFSSL_TLSV1_1 = 2 or
    WOLFSSL_TLSV1_2 = 3.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version; // macrop representation
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
    	// Failed to set min version
    }
    \endcode

    \sa SetMinVersionHelper
*/
int wolfSSL_CTX_SetMinVersion(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup TLS

    \brief This function sets the minimum downgrade version allowed.
    Applicable only when the connection allows downgrade using
    (wolfSSLv23_client_method or wolfSSLv23_server_method).

    \return SSL_SUCCESS returned if this function and its subroutine executes
    without error.
    \return BAD_FUNC_ARG returned if the SSL object is NULL.  In
    the subroutine this error is thrown if there is not a good version match.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param version an integer representation of the version to be set as the
    minimum: WOLFSSL_SSLV3 = 0, WOLFSSL_TLSV1 = 1, WOLFSSL_TLSV1_1 = 2 or
    WOLFSSL_TLSV1_2 = 3.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(protocol method);
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    int version;  macro representation
    …
    if(wolfSSL_CTX_SetMinVersion(ssl->ctx, version) != SSL_SUCCESS){
	    Failed to set min version
    }
    \endcode

    \sa SetMinVersionHelper
*/
int wolfSSL_SetMinVersion(WOLFSSL* ssl, int version);

/*!
    \brief This function returns the size of the WOLFSSL object and will be
    dependent on build options and settings.  If SHOW_SIZES has been defined
    when building wolfSSL, this function will also print the sizes of individual
    objects within the WOLFSSL object (Suites, Ciphers, etc.) to stdout.

    \return size This function returns the size of the WOLFSSL object.

    \param none No parameters.

    _Example_
    \code
    int size = 0;
    size = wolfSSL_GetObjectSize();
    printf(“sizeof(WOLFSSL) = %d\n”, size);
    \endcode

    \sa wolfSSL_new
*/
int wolfSSL_GetObjectSize(void);  /* object size based on build */
/*!
    \brief Returns the record layer size of the plaintext input. This is helpful
    when an application wants to know how many bytes will be sent across the
    Transport layer, given a specified plaintext input size. This function
    must be called after the SSL/TLS handshake has been completed.

    \return size Upon success, the requested size will be returned
    \return INPUT_SIZE_E will be returned if the input size is greater than the
    maximum TLS fragment size (see wolfSSL_GetMaxOutputSize())
    \return BAD_FUNC_ARG will be returned upon invalid function argument, or if
    the SSL/TLS handshake has not been completed yet

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param inSz size of plaintext data.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetMaxOutputSize
*/
int wolfSSL_GetOutputSize(WOLFSSL* ssl, int inSz);

/*!
    \brief Returns the maximum record layer size for plaintext data.  This
    will correspond to either the maximum SSL/TLS record size as specified
    by the protocol standard, the maximum TLS fragment size as set by the
    TLS Max Fragment Length extension. This function is helpful when the
    application has called wolfSSL_GetOutputSize() and received a INPUT_SIZE_E
    error. This function must be called after the SSL/TLS handshake has been
    completed.

    \return size Upon success, the maximum output size will be returned
    \return BAD_FUNC_ARG will be returned upon invalid function argument,
    or if the SSL/TLS handshake has not been completed yet.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetOutputSize
*/
int wolfSSL_GetMaxOutputSize(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the SSL/TLS protocol version for the specified
    SSL session (WOLFSSL object) using the version as specified by version.
    This will override the protocol setting for the SSL session (ssl) -
    originally defined and set by the SSL context (wolfSSL_CTX_new())
    method type.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG will be returned if the input SSL object is
    NULL or an incorrect protocol version is given for version.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param version SSL/TLS protocol version.  Possible values include
    WOLFSSL_SSLV3, WOLFSSL_TLSV1, WOLFSSL_TLSV1_1, WOLFSSL_TLSV1_2.

    _Example_
    \code
    int ret = 0;
    WOLFSSL* ssl;
    ...

    ret = wolfSSL_SetVersion(ssl, WOLFSSL_TLSV1);
    if (ret != SSL_SUCCESS) {
        // failed to set SSL session protocol version
    }
    \endcode

    \sa wolfSSL_CTX_new
*/
int wolfSSL_SetVersion(WOLFSSL* ssl, int version);

/*!
    \brief Allows caller to set the Atomic User Record Processing
    Mac/Encrypt Callback.  The callback should return 0 for success
    or < 0 for an error.  The ssl and ctx pointers are available
    for the user’s convenience.  macOut is the output buffer where
    the result of the mac should be stored.  macIn is the mac input
    buffer and macInSz notes the size of the buffer.  macContent
    and macVerify are needed for wolfSSL_SetTlsHmacInner() and be
    passed along as is.  encOut is the output buffer where the result
    on the encryption should be stored.  encIn is the input buffer to
    encrypt while encSz is the size of the input.  An example callback
    can be found wolfssl/test.h myMacEncryptCb().

    \return none No return.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for Mac/Encrypt.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_CTX_SetMacEncryptCb(WOLFSSL_CTX* ctx, CallbackMacEncrypt cb);

/*!
    \brief Allows caller to set the Atomic User Record Processing Mac/Encrypt
    Callback Context to ctx.

    \return none No return.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx pointer to the user context to be stored.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_SetMacEncryptCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Atomic User Record Processing
    Mac/Encrypt Callback Context previously stored with
    wolfSSL_SetMacEncryptCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_SetMacEncryptCtx
*/
void* wolfSSL_GetMacEncryptCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Atomic User Record Processing
    Decrypt/Verify Callback.  The callback should return 0 for success
    or < 0 for an error.  The ssl and ctx pointers are available for
    the user’s convenience.  decOut is the output buffer where the result
    of the decryption should be stored.  decIn is the encrypted input
    buffer and decInSz notes the size of the buffer.  content and verify
    are needed for wolfSSL_SetTlsHmacInner() and be passed along as is.
    padSz is an output variable that should be set with the total value
    of the padding.  That is, the mac size plus any padding and pad bytes.
    An example callback can be found wolfssl/test.h myDecryptVerifyCb().

    \return none No returns.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for Decrypt/Verify.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetMacEncryptCtx
    \sa wolfSSL_GetMacEncryptCtx
*/
void  wolfSSL_CTX_SetDecryptVerifyCb(WOLFSSL_CTX* ctx,
                                               CallbackDecryptVerify cb);

/*!
    \brief Allows caller to set the Atomic User Record Processing
    Decrypt/Verify Callback Context to ctx.

    \return none No returns.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx pointer to the user context to be stored.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_GetDecryptVerifyCtx
*/
void  wolfSSL_SetDecryptVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Atomic User Record Processing
    Decrypt/Verify Callback Context previously stored with
    wolfSSL_SetDecryptVerifyCtx().

    \return pointer If successful the call will return a valid pointer to the
    context.
    \return NULL will be returned for a blank context.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetDecryptVerifyCb
    \sa wolfSSL_SetDecryptVerifyCtx
*/
void* wolfSSL_GetDecryptVerifyCtx(WOLFSSL* ssl);

/*!
    \brief Allows retrieval of the Hmac/Mac secret from the handshake process.
    The verify parameter specifies whether this is for verification of a
    peer message.

    \return pointer If successful the call will return a valid pointer to the
    secret.  The size of the secret can be obtained from wolfSSL_GetHmacSize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param verify specifies whether this is for verification of a peer message.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetHmacSize
*/
const unsigned char* wolfSSL_GetMacSecret(WOLFSSL* ssl, int verify);

/*!
    \brief Allows retrieval of the client write key from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    key. The size of the key can be obtained from wolfSSL_GetKeySize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
*/
const unsigned char* wolfSSL_GetClientWriteKey(WOLFSSL*);

/*!
    \brief Allows retrieval of the client write IV (initialization vector)
    from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    IV.  The size of the IV can be obtained from wolfSSL_GetCipherBlockSize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetCipherBlockSize()
    \sa wolfSSL_GetClientWriteKey()
*/
const unsigned char* wolfSSL_GetClientWriteIV(WOLFSSL*);

/*!
    \brief Allows retrieval of the server write key from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    key.  The size of the key can be obtained from wolfSSL_GetKeySize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetServerWriteIV
*/
const unsigned char* wolfSSL_GetServerWriteKey(WOLFSSL*);

/*!
    \brief Allows retrieval of the server write IV (initialization vector)
    from the handshake process.

    \return pointer If successful the call will return a valid pointer to the
    IV.  The size of the IV can be obtained from wolfSSL_GetCipherBlockSize().
    \return NULL will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetClientWriteKey
*/
const unsigned char* wolfSSL_GetServerWriteIV(WOLFSSL*);

/*!
    \brief Allows retrieval of the key size from the handshake process.

    \return size If successful the call will return the key size in bytes.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
int                  wolfSSL_GetKeySize(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Returns the iv_size member of the specs structure
    held in the WOLFSSL struct.

    \return iv_size returns the value held in ssl->specs.iv_size.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int ivSize;
    ...
    ivSize = wolfSSL_GetIVSize(ssl);

    if(ivSize > 0){
    	// ivSize holds the specs.iv_size value.
    }
    \endcode

    \sa wolfSSL_GetKeySize
    \sa wolfSSL_GetClientWriteIV
    \sa wolfSSL_GetServerWriteIV
*/
int                  wolfSSL_GetIVSize(WOLFSSL* ssl);

/*!
    \brief Allows retrieval of the side of this WOLFSSL connection.

    \return success If successful the call will return either
    WOLFSSL_SERVER_END or WOLFSSL_CLIENT_END depending on the
    side of WOLFSSL object.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetClientWriteKey
    \sa wolfSSL_GetServerWriteKey
*/
int                  wolfSSL_GetSide(WOLFSSL* ssl);

/*!
    \brief Allows caller to determine if the negotiated protocol version
    is at least TLS version 1.1 or greater.

    \return true/false If successful the call will return 1 for true or
    0 for false.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetSide
*/
int                  wolfSSL_IsTLSv1_1(WOLFSSL* ssl);

/*!
    \brief Allows caller to determine the negotiated bulk cipher algorithm
    from the handshake.

    \return If successful the call will return one of the following:
    wolfssl_cipher_null, wolfssl_des, wolfssl_triple_des, wolfssl_aes,
    wolfssl_aes_gcm, wolfssl_aes_ccm, wolfssl_camellia.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetCipherBlockSize
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetBulkCipher(WOLFSSL* ssl);

/*!
    \brief Allows caller to determine the negotiated cipher block size from
    the handshake.

    \return size If successful the call will return the size in bytes of the
    cipher block size.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetCipherBlockSize(WOLFSSL* ssl);

/*!
    \brief Allows caller to determine the negotiated aead mac size from the
    handshake.  For cipher type WOLFSSL_AEAD_TYPE.

    \return size If successful the call will return the size in bytes of the
    aead mac size.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetKeySize
*/
int                  wolfSSL_GetAeadMacSize(WOLFSSL* ssl);

/*!
    \brief Allows caller to determine the negotiated (h)mac size from the
    handshake. For cipher types except WOLFSSL_AEAD_TYPE.

    \return size If successful the call will return the size in bytes of
    the (h)mac size.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetHmacSize(WOLFSSL* ssl);

/*!
    \brief Allows caller to determine the negotiated (h)mac type from the
    handshake.  For cipher types except WOLFSSL_AEAD_TYPE.

    \return If successful the call will return one of the following:
    MD5, SHA, SHA256, SHA384.
    \return BAD_FUNC_ARG may be returned for an error state.
    \return SSL_FATAL_ERROR may also be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacSize
*/
int                  wolfSSL_GetHmacType(WOLFSSL* ssl);

/*!
    \brief Allows caller to determine the negotiated cipher type
    from the handshake.

    \return If successful the call will return one of the following:
    WOLFSSL_BLOCK_TYPE, WOLFSSL_STREAM_TYPE, WOLFSSL_AEAD_TYPE.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int                  wolfSSL_GetCipherType(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Hmac Inner vector for message
    sending/receiving.  The result is written to inner which should
    be at least wolfSSL_GetHmacSize() bytes.  The size of the message
    is specified by sz, content is the type of message, and verify
    specifies whether this is a verification of a peer message. Valid
    for cipher types excluding WOLFSSL_AEAD_TYPE.

    \return 1 upon success.
    \return BAD_FUNC_ARG will be returned for an error state.

    \param none No parameters.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_GetBulkCipher
    \sa wolfSSL_GetHmacType
*/
int wolfSSL_SetTlsHmacInner(WOLFSSL* ssl, byte* inner,
                            word32 sz, int content, int verify);

/*!
    \brief Allows caller to set the Public Key Callback for ECC Signing.
    The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    in is the input buffer to sign while inSz denotes the length of the input.
    out is the output buffer where the result of the signature should be stored.
    outSz is an input/output variable that specifies the size of the output
    buffer upon invocation and the actual size of the signature should be stored
    there before returning.  keyDer is the ECC Private key in ASN1 format and
    keySz is the length of the key in bytes.  An example callback can be found
    wolfssl/test.h myEccSign().

    \return none No returns.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for ECC signing.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetEccSignCtx
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCb(WOLFSSL_CTX* ctx, CallbackEccSign cb);

/*!
    \brief Allows caller to set the Public Key Ecc Signing Callback
    Context to ctx.

    \return none No returns.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().
    \param ctx a pointer to the user context to be stored

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_GetEccSignCtx
*/
void  wolfSSL_SetEccSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key Ecc Signing Callback
    Context previously stored with wolfSSL_SetEccSignCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param ssl a pointer to a WOLFSSL object, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_SetEccSignCtx
*/
void* wolfSSL_GetEccSignCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Ecc Signing Callback
    Context to ctx.

    \return none No returns.

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param ctx a pointer to the user context to be stored

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_GetEccSignCtx
*/
void  wolfSSL_CTX_SetEccSignCtx(WOLFSSL_CTX* ctx, void *userCtx);

/*!
    \brief Allows caller to retrieve the Public Key Ecc Signing Callback
    Context previously stored with wolfSSL_SetEccSignCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_SetEccSignCtx
*/
void* wolfSSL_CTX_GetEccSignCtx(WOLFSSL_CTX* ctx);

/*!
    \brief Allows caller to set the Public Key Callback for ECC Verification.
    The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    sig is the signature to verify and sigSz denotes the length of the
    signature. hash is an input buffer containing the digest of the message
    and hashSz denotes the length in bytes of the hash.  result is an output
    variable where the result of the verification should be stored, 1 for
    success and 0 for failure.  keyDer is the ECC Private key in ASN1
    format and keySz is the length of the key in bytes.  An example
    callback can be found wolfssl/test.h myEccVerify().

    \return none No returns.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for ECC verification.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetEccVerifyCtx
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_CTX_SetEccVerifyCb(WOLFSSL_CTX* ctx, CallbackEccVerify cb);

/*!
    \brief Allows caller to set the Public Key Ecc Verification Callback
    Context to ctx.

    \return none No returns.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx pointer to the user context to be stored.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_GetEccVerifyCtx
*/
void  wolfSSL_SetEccVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key Ecc Verification Callback
    Context previously stored with wolfSSL_SetEccVerifyCtx().

    \return pointer If successful the call will return a valid pointer to the
    context.
    \return NULL will be returned for a blank context.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetEccVerifyCb
    \sa wolfSSL_SetEccVerifyCtx
*/
void* wolfSSL_GetEccVerifyCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Signing.
    The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    in is the input buffer to sign while inSz denotes the length of the input.
    out is the output buffer where the result of the signature should be stored.
    outSz is an input/output variable that specifies the size of the output
    buffer upon invocation and the actual size of the signature should be
    stored there before returning.  keyDer is the RSA Private key in ASN1 format
    and keySz is the length of the key in bytes.  An example callback can be
    found wolfssl/test.h myRsaSign().

    \return none No returns.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for RSA signing.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaSignCtx
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_CTX_SetRsaSignCb(WOLFSSL_CTX* ctx, CallbackRsaSign cb);

/*!
    \brief Allows caller to set the Public Key RSA Signing Callback Context
    to ctx.

    \return none No Returns.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx pointer to the user context to be stored.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_GetRsaSignCtx
*/
void  wolfSSL_SetRsaSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Signing Callback
    Context previously stored with wolfSSL_SetRsaSignCtx().

    \return pointer If successful the call will return a valid pointer to the
    context.
    \return NULL will be returned for a blank context.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_SetRsaSignCtx
*/
void* wolfSSL_GetRsaSignCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Verification.
    The callback should return the number of plaintext bytes for success or
    < 0 for an error.  The ssl and ctx pointers are available for the user’s
    convenience.  sig is the signature to verify and sigSz denotes the length
    of the signature.  out should be set to the beginning of the verification
    buffer after the decryption process and any padding.  keyDer is the RSA
    Public key in ASN1 format and keySz is the length of the key in bytes.
    An example callback can be found wolfssl/test.h myRsaVerify().

    \return none No returns.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for RSA verification.

    \sa wolfSSL_SetRsaVerifyCtx
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_CTX_SetRsaVerifyCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);

/*!
    \brief Allows caller to set the Public Key RSA Verification Callback
    Context to ctx.

    \return none No returns.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx pointer to the user context to be stored.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_GetRsaVerifyCtx
*/
void  wolfSSL_SetRsaVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Verification Callback
    Context previously stored with wolfSSL_SetRsaVerifyCtx().

    \return pointer If successful the call will return a valid pointer to
    the context.
    \return NULL will be returned for a blank context.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaVerifyCb
    \sa wolfSSL_SetRsaVerifyCtx
*/
void* wolfSSL_GetRsaVerifyCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Public
    Encrypt.  The callback should return 0 for success or < 0 for an error.
    The ssl and ctx pointers are available for the user’s convenience.
    in is the input buffer to encrypt while inSz denotes the length of
    the input.  out is the output buffer where the result of the encryption
    should be stored.  outSz is an input/output variable that specifies
    the size of the output buffer upon invocation and the actual size of
    the encryption should be stored there before returning.  keyDer is the
    RSA Public key in ASN1 format and keySz is the length of the key in
    bytes. An example callback can be found wolfssl/test.h myRsaEnc().

    \return none No returns.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for RSA public encrypt.

    _Examples_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaEncCtx
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_CTX_SetRsaEncCb(WOLFSSL_CTX* ctx, CallbackRsaEnc cb);

/*!
    \brief Allows caller to set the Public Key RSA Public Encrypt
    Callback Context to ctx.

    \return none No returns.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx pointer to the user context to be stored.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_GetRsaEncCtx
*/
void  wolfSSL_SetRsaEncCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Public Encrypt
    Callback Context previously stored with wolfSSL_SetRsaEncCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaEncCb
    \sa wolfSSL_SetRsaEncCtx
*/
void* wolfSSL_GetRsaEncCtx(WOLFSSL* ssl);

/*!
    \brief Allows caller to set the Public Key Callback for RSA Private
    Decrypt.  The callback should return the number of plaintext bytes
    for success or < 0 for an error.  The ssl and ctx pointers are available
    for the user’s convenience.  in is the input buffer to decrypt and inSz
    denotes the length of the input.  out should be set to the beginning
    of the decryption buffer after the decryption process and any padding.
    keyDer is the RSA Private key in ASN1 format and keySz is the length
    of the key in bytes.  An example callback can be found
    wolfssl/test.h myRsaDec().

    \return none No returns.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb callback function to register for RSA private decrypt.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_SetRsaDecCtx
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_CTX_SetRsaDecCb(WOLFSSL_CTX* ctx, CallbackRsaDec cb);

/*!
    \brief Allows caller to set the Public Key RSA Private Decrypt
    Callback Context to ctx.

    \return none No returns.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ctx pointer to the user context to be stored.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_GetRsaDecCtx
*/
void  wolfSSL_SetRsaDecCtx(WOLFSSL* ssl, void *ctx);

/*!
    \brief Allows caller to retrieve the Public Key RSA Private Decrypt
    Callback Context previously stored with wolfSSL_SetRsaDecCtx().

    \return pointer If successful the call will return a valid pointer
    to the context.
    \return NULL will be returned for a blank context.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_SetRsaDecCb
    \sa wolfSSL_SetRsaDecCtx
*/
void* wolfSSL_GetRsaDecCtx(WOLFSSL* ssl);

/*!
    \brief This function registers a callback with the SSL context
    (WOLFSSL_CTX) to be called when a new CA certificate is loaded
    into wolfSSL.  The callback is given a buffer with the DER-encoded
    certificate.

    \return none No return.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb function to be registered as the CA callback for the
    wolfSSL context, ctx. The signature of this function must follow that
    as shown above in the Synopsis section.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;

    // CA callback prototype
    int MyCACallback(unsigned char *der, int sz, int type);

    // Register the custom CA callback with the SSL context
    wolfSSL_CTX_SetCACb(ctx, MyCACallback);

    int MyCACallback(unsigned char* der, int sz, int type)
    {
    	// custom CA callback function, DER-encoded cert
        // located in “der” of size “sz” with type “type”
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
*/
void wolfSSL_CTX_SetCACb(WOLFSSL_CTX* ctx, CallbackCACache cb);

/*!
    \ingroup CertManager
    \brief Allocates and initializes a new Certificate Manager context.
    This context may be used independent of SSL needs.  It may be used to
    load certificates, verify certificates, and check the revocation status.

    \return WOLFSSL_CERT_MANAGER If successful the call will return a valid
    WOLFSSL_CERT_MANAGER pointer.
    \return NULL will be returned for an error state.

    \param heap pointer to a heap hint for memory allocation.

    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew_ex(void* heap);

/*!
    \ingroup CertManager
    \brief Allocates and initializes a new Certificate Manager context.
    This context may be used independent of SSL needs.  It may be used to
    load certificates, verify certificates, and check the revocation status.

    \return WOLFSSL_CERT_MANAGER If successful the call will return a
    valid WOLFSSL_CERT_MANAGER pointer.
    \return NULL will be returned for an error state.

    \param none No parameters.

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    cm = wolfSSL_CertManagerNew();
    if (cm == NULL) {
	// error creating new cert manager
    }
    \endcode

    \sa wolfSSL_CertManagerFree
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CertManagerNew(void);

/*!
    \ingroup CertManager
    \brief Frees all resources associated with the Certificate Manager
    context.  Call this when you no longer need to use the Certificate Manager.

    \return none

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    ...
    wolfSSL_CertManagerFree(cm);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
void wolfSSL_CertManagerFree(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief Specifies the locations for CA certificate loading into the
    manager context.  The PEM certificate CAfile may contain several
    trusted CA certificates.  If CApath is not NULL it specifies a
    directory containing CA certificates in PEM format.

    \return SSL_SUCCESS If successful the call will return.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist,
    can’t be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a
    pointer is not provided.
    \return SSL_FATAL_ERROR - will be returned upon failure.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created
    using wolfSSL_CertManagerNew().
    \param file pointer to the name of the file containing CA
    certificates to load.
    \param path pointer to the name of a directory path containing CA c
    ertificates to load.  The NULL pointer may be used if no
    certificate directory is desired.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerLoadCA(cm, “path/to/cert-file.pem”, 0);
    if (ret != SSL_SUCCESS) {
	// error loading CA certs into cert manager
    }
    \endcode

    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerLoadCA(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                 const char* d);

/*!
    \ingroup CertManager
    \brief Loads the CA Buffer by calling wolfSSL_CTX_load_verify_buffer and
    returning that result using a temporary cm so as not to lose the information
    in the cm passed into the function.

    \return SSL_FATAL_ERROR is returned if the WOLFSSL_CERT_MANAGER struct is
    NULL or if wolfSSL_CTX_new() returns NULL.
    \return SSL_SUCCESS is returned for a successful execution.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param in buffer for cert information.
    \param sz length of the buffer.
    \param format certificate format, either PEM or DER.

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = (WOLFSSL_CERT_MANAGER*)vp;
    …
    const unsigned char* in;
    long sz;
    int format;
    …
    if(wolfSSL_CertManagerLoadCABuffer(vp, sz, format) != SSL_SUCCESS){
	    Error returned. Failure case code block.
    }
    \endcode

    \sa wolfSSL_CTX_load_verify_buffer
    \sa ProcessChainBuffer
    \sa ProcessBuffer
    \sa cm_pick_method
*/
int wolfSSL_CertManagerLoadCABuffer(WOLFSSL_CERT_MANAGER* cm,
                                  const unsigned char* buff, long sz,
                                  int format);

/*!
    \ingroup CertManager
    \brief This function unloads the CA signer list.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E returned if there was a mutex error.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure,
    created using wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    ...
    if(wolfSSL_CertManagerUnloadCAs(cm) != SSL_SUCCESS){
        Failure case.
    }
    \endcode

    \sa UnlockMutex
*/
int wolfSSL_CertManagerUnloadCAs(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief This function unloads intermediate certificates add to the CA
    signer list.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E returned if there was a mutex error.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure,
    created using wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    ...
    if(wolfSSL_CertManagerUnloadIntermediateCerts(cm) != SSL_SUCCESS){
    	Failure case.
    }
    \endcode

    \sa UnlockMutex
*/
int wolfSSL_CertManagerUnloadIntermediateCerts(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief The function will free the Trusted Peer linked list and unlocks
    the trusted peer list.

    \return SSL_SUCCESS if the function completed normally.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER is NULL.
    \return BAD_MUTEX_E mutex  error if tpLock, a member of the
    WOLFSSL_CERT_MANAGER struct, is 0 (nill).

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    if(wolfSSL_CertManagerUnload_trust_peers(cm) != SSL_SUCCESS){
	    The function did not execute successfully.
    }
    \endcode

    \sa UnLockMutex
*/
int wolfSSL_CertManagerUnload_trust_peers(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief Specifies the certificate to verify with the Certificate Manager
    context.  The format can be SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.

    \return SSL_SUCCESS If successful.
    \return ASN_SIG_CONFIRM_E will be returned if the signature could not be
    verified.
    \return ASN_SIG_OID_E will be returned if the signature type is not
    supported.
    \return CRL_CERT_REVOKED is an error that is returned if this certificate
    has been revoked.
    \return CRL_MISSING is an error that is returned if a current issuer CRL is
    not available.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before the
    before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after the
    after date.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t be
    read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer is
    not provided.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param fname pointer to the name of the file containing the certificates
    to verify.
    \param format format of the certificate to verify - either
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerVerify(cm, “path/to/cert-file.pem”,
    SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
	    error verifying certificate
    }
    \endcode

    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerifyBuffer
*/
int wolfSSL_CertManagerVerify(WOLFSSL_CERT_MANAGER* cm, const char* f,
                                                                    int format);

/*!
    \ingroup CertManager
    \brief Specifies the certificate buffer to verify with the Certificate
    Manager context.  The format can be SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.

    \return SSL_SUCCESS If successful.
    \return ASN_SIG_CONFIRM_E will be returned if the signature could not
    be verified.
    \return ASN_SIG_OID_E will be returned if the signature type is not
    supported.
    \return CRL_CERT_REVOKED is an error that is returned if this certificate
    has been revoked.
    \return CRL_MISSING is an error that is returned if a current issuer CRL
    is not available.
    \return ASN_BEFORE_DATE_E will be returned if the current date is before
    the before date.
    \return ASN_AFTER_DATE_E will be returned if the current date is after
    the after date.
    \return SSL_BAD_FILETYPE will be returned if the file is the wrong format.
    \return SSL_BAD_FILE will be returned if the file doesn’t exist, can’t
    be read, or is corrupted.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return ASN_INPUT_E will be returned if Base16 decoding fails on the file.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer
    is not provided.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param buff buffer containing the certificates to verify.
    \param sz size of the buffer, buf.
    \param format format of the certificate to verify, located in buf - either
    SSL_FILETYPE_ASN1 or SSL_FILETYPE_PEM.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    int sz = 0;
    WOLFSSL_CERT_MANAGER* cm;
    byte certBuff[...];
    ...

    ret = wolfSSL_CertManagerVerifyBuffer(cm, certBuff, sz, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
    	error verifying certificate
    }

    \endcode

    \sa wolfSSL_CertManagerLoadCA
    \sa wolfSSL_CertManagerVerify
*/
int wolfSSL_CertManagerVerifyBuffer(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* buff, long sz, int format);

/*!
    \ingroup CertManager
    \brief The function sets the verifyCallback function in the Certificate
    Manager. If present, it will be called for each cert loaded. If there is
    a verification error, the verify callback can be used to over-ride the
    error.

    \return none No return.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param verify_callback a VerifyCallback function pointer to the callback
    routine

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int myVerify(int preverify, WOLFSSL_X509_STORE_CTX* store)
    { // do custom verification of certificate }

    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new(Protocol define);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    ...
    wolfSSL_CertManagerSetVerify(cm, myVerify);

    \endcode

    \sa wolfSSL_CertManagerVerify
*/
void wolfSSL_CertManagerSetVerify(WOLFSSL_CERT_MANAGER* cm,
        VerifyCallback verify_callback);

/*!
    \brief Check CRL if the option is enabled and compares the cert to the
    CRL list.

    \return SSL_SUCCESS returns if the function returned as expected. If
    the crlEnabled member of the WOLFSSL_CERT_MANAGER struct is turned on.
    \return MEMORY_E returns if the allocated memory failed.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER is NULL.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER struct.
    \param der pointer to a DER formatted certificate.
    \param sz size of the certificate.

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm;
    byte* der;
    int sz; // size of der
    ...
    if(wolfSSL_CertManagerCheckCRL(cm, der, sz) != SSL_SUCCESS){
    	// Error returned. Deal with failure case.
    }
    \endcode

    \sa CheckCertCRL
    \sa ParseCertRelative
    \sa wolfSSL_CertManagerSetCRL_CB
    \sa InitDecodedCert
*/
int wolfSSL_CertManagerCheckCRL(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* der, int sz);

/*!
    \ingroup CertManager
    \brief Turns on Certificate Revocation List checking when verifying
    certificates with the Certificate Manager.  By default, CRL checking
    is off.  options include WOLFSSL_CRL_CHECKALL which performs CRL
    checking on each certificate in the chain versus the Leaf certificate
    only which is the default.

    \return SSL_SUCCESS If successful the call will return.
    \return NOT_COMPILED_IN will be returned if wolfSSL was not built with
    CRL enabled.
    \return MEMORY_E will be returned if an out of memory condition occurs.
    \return BAD_FUNC_ARG is the error that will be returned if a pointer
    is not provided.
    \return SSL_FAILURE will be returned if the CRL context cannot be
    initialized properly.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param options options to use when enabling the Certification Manager, cm.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...

    ret = wolfSSL_CertManagerEnableCRL(cm, 0);
    if (ret != SSL_SUCCESS) {
    	error enabling cert manager
    }

    ...
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CertManagerEnableCRL(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief Turns off Certificate Revocation List checking when verifying
    certificates with the Certificate Manager.  By default, CRL checking is
    off.  You can use this function to temporarily or permanently disable CRL
    checking with this Certificate Manager context that previously had CRL
    checking enabled.

    \return SSL_SUCCESS If successful the call will return.
    \return BAD_FUNC_ARG is the error that will be returned if a function
    pointer is not provided.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int ret = 0;
    WOLFSSL_CERT_MANAGER* cm;
    ...
    ret = wolfSSL_CertManagerDisableCRL(cm);
    if (ret != SSL_SUCCESS) {
    	error disabling cert manager
    }
    ...
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
*/
int wolfSSL_CertManagerDisableCRL(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief Error checks and passes through to LoadCRL() in order to load the
    cert into the CRL for revocation checking. An updated CRL can be loaded by
    first calling wolfSSL_CertManagerFreeCRL, then loading the new CRL.

    \return SSL_SUCCESS if there is no error in wolfSSL_CertManagerLoadCRL and
    if LoadCRL returns successfully.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER struct is NULL.
    \return SSL_FATAL_ERROR if wolfSSL_CertManagerEnableCRL returns anything
    other than SSL_SUCCESS.
    \return BAD_PATH_ERROR if the path is NULL.
    \return MEMORY_E if LoadCRL fails to allocate heap memory.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param path a constant char pointer holding the CRL path.
    \param type type of certificate to be loaded.
    \param monitor requests monitoring in LoadCRL().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type,
    int monitor);
    …
    wolfSSL_CertManagerLoadCRL(SSL_CM(ssl), path, type, monitor);
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa wolfSSL_LoadCRL
    \sa wolfSSL_CertManagerFreeCRL
*/
int wolfSSL_CertManagerLoadCRL(WOLFSSL_CERT_MANAGER* cm,
                               const char* path, int type, int monitor);

/*!
    \ingroup CertManager
    \brief The function loads the CRL file by calling BufferLoadCRL.

    \return SSL_SUCCESS returned if the function completed without errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.
    \return SSL_FATAL_ERROR returned if there is an error associated
    with the WOLFSSL_CERT_MANAGER.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure.
    \param buff a constant byte type and is the buffer.
    \param sz a long int representing the size of the buffer.
    \param type a long integer that holds the certificate type.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CERT_MANAGER* cm;
    const unsigned char* buff;
    long sz; size of buffer
    int type;  cert type
    ...
    int ret = wolfSSL_CertManagerLoadCRLBuffer(cm, buff, sz, type);
    if(ret == SSL_SUCCESS){
	return ret;
    } else {
    	Failure case.
    }
    \endcode

    \sa BufferLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
*/
int wolfSSL_CertManagerLoadCRLBuffer(WOLFSSL_CERT_MANAGER* cm,
                                     const unsigned char* buff, long sz,
                                     int type);

/*!
    \ingroup CertManager
    \brief This function sets the CRL Certificate Manager callback. If
    HAVE_CRL is defined and a matching CRL record is not found then the
    cbMissingCRL is called (set via wolfSSL_CertManagerSetCRL_Cb). This
    allows you to externally retrieve the CRL and load it.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm the WOLFSSL_CERT_MANAGER structure holding the information for
    the certificate.
    \param cb a function pointer to (*CbMissingCRL) that is set to the
    cbMissingCRL member of the WOLFSSL_CERT_MANAGER.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url){
	    Function body.
    }
    …
    CbMissingCRL cb = CbMissingCRL;
    …
    if(ctx){
        return wolfSSL_CertManagerSetCRL_Cb(SSL_CM(ssl), cb);
    }
    \endcode

    \sa CbMissingCRL
    \sa wolfSSL_SetCRL_Cb
*/
int wolfSSL_CertManagerSetCRL_Cb(WOLFSSL_CERT_MANAGER* cm,
                                 CbMissingCRL cb);

/*!
    \ingroup CertManager
    \brief This function sets the CRL Update callback. If
    HAVE_CRL and HAVE_CRL_UPDATE_CB is defined , and an entry with the same
    issuer and a lower CRL number exists when a CRL is added, then the
    CbUpdateCRL is called with the details of the existing entry and the
    new one replacing it.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm the WOLFSSL_CERT_MANAGER structure holding the information for
    the certificate.
    \param cb a function pointer to (*CbUpdateCRL) that is set to the
    cbUpdateCRL member of the WOLFSSL_CERT_MANAGER.
    Signature requirement:
	void (*CbUpdateCRL)(CrlInfo *old, CrlInfo *new);

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(CrlInfo *old, CrlInfo *new){
	    Function body.
    }
    …
    CbUpdateCRL cb = CbUpdateCRL;
    …
    if(ctx){
        return wolfSSL_CertManagerSetCRLUpdate_Cb(SSL_CM(ssl), cb);
    }
    \endcode

    \sa CbUpdateCRL
*/
int wolfSSL_CertManagerSetCRLUpdate_Cb(WOLFSSL_CERT_MANAGER* cm,
                                       CbUpdateCRL cb);

/*!
    \ingroup CertManager
    \brief This function yields a structure with parsed CRL information from
    an encoded CRL buffer.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm   the WOLFSSL_CERT_MANAGER structure..
    \param info pointer to caller managed CrlInfo structure that will receive
                the CRL information.
    \param buff input buffer containing encoded CRL.
    \param sz   the length in bytes of the input CRL data in buff.
    \param type WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_DER

    _Example_
    \code
    #include <wolfssl/ssl.h>

    CrlInfo info;
    WOLFSSL_CERT_MANAGER* cm = NULL;

    cm = wolfSSL_CertManagerNew();

    // Read crl data from file into buffer

    wolfSSL_CertManagerGetCRLInfo(cm, &info, crlData, crlDataLen,
                                  WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa CbUpdateCRL
    \sa wolfSSL_SetCRL_Cb
*/
int wolfSSL_CertManagerGetCRLInfo(WOLFSSL_CERT_MANAGER* cm, CrlInfo* info,
    const byte* buff, long sz, int type)

/*!
    \ingroup CertManager
    \brief This function frees the CRL stored in the Cert Manager. An
    application can update the CRL by calling wolfSSL_CertManagerFreeCRL
    and then loading the new CRL.

    \return SSL_SUCCESS returned upon successful execution of the function and
    subroutines.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is NULL.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().

    _Example_
    \code
    #include <wolfssl/ssl.h>

    const char* crl1     = "./certs/crl/crl.pem";
    WOLFSSL_CERT_MANAGER* cm = NULL;

    cm = wolfSSL_CertManagerNew();
    wolfSSL_CertManagerLoadCRL(cm, crl1, WOLFSSL_FILETYPE_PEM, 0);
    …
    wolfSSL_CertManagerFreeCRL(cm);
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
*/
int wolfSSL_CertManagerFreeCRL(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief The function enables the WOLFSSL_CERT_MANAGER’s member, ocspEnabled
    to signify that the OCSP check option is enabled.

    \return SSL_SUCCESS returned on successful execution of the function. The
    ocspEnabled member of the WOLFSSL_CERT_MANAGER is enabled.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is
    NULL or if an argument value that is not allowed is passed to a subroutine.
    \return MEMORY_E returned if there is an error allocating memory within
    this function or a subroutine.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param der a byte pointer to the certificate.
    \param sz an int type representing the size of the DER cert.

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* der;
    int sz; size of der
    ...
    if(wolfSSL_CertManagerCheckOCSP(cm, der, sz) != SSL_SUCCESS){
	 Failure case.
    }
    \endcode

    \sa ParseCertRelative
    \sa CheckCertOCSP
*/
int wolfSSL_CertManagerCheckOCSP(WOLFSSL_CERT_MANAGER* cm,
                                const unsigned char* der, int sz);

/*!
    \ingroup CertManager
    \brief Turns on OCSP if it’s turned off and if compiled with the
    set option available.

    \return SSL_SUCCESS returned if the function call is successful.
    \return BAD_FUNC_ARG if cm struct is NULL.
    \return MEMORY_E if WOLFSSL_OCSP struct value is NULL.
    \return SSL_FAILURE initialization of WOLFSSL_OCSP struct fails
    to initialize.
    \return NOT_COMPILED_IN build not compiled with correct feature enabled.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, created using
    wolfSSL_CertManagerNew().
    \param options used to set values in WOLFSSL_CERT_MANAGER struct.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    int options;
    …
    if(wolfSSL_CertManagerEnableOCSP(SSL_CM(ssl), options) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode

    \sa wolfSSL_CertManagerNew
*/
int wolfSSL_CertManagerEnableOCSP(WOLFSSL_CERT_MANAGER* cm,
                                                                   int options);

/*!
    \ingroup CertManager
    \brief Disables OCSP certificate revocation.

    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRL successfully disabled the
    crlEnabled member of the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CertManagerDisableOCSP(ssl) != SSL_SUCCESS){
	    Fail case.
    }
    \endcode

    \sa wolfSSL_DisableCRL
*/
int wolfSSL_CertManagerDisableOCSP(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup CertManager
    \brief The function copies the url to the ocspOverrideURL member of the
    WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS the function was able to execute as expected.
    \return BAD_FUNC_ARG the WOLFSSL_CERT_MANAGER struct is NULL.
    \return MEMEORY_E Memory was not able to be allocated for the
    ocspOverrideURL member of the certificate manager.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    #include <wolfssl/ssl.h>
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CertManagerNew();
    const char* url;
    …
    int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url)
    …
    if(wolfSSL_CertManagerSetOCSPOverrideURL(SSL_CM(ssl), url) != SSL_SUCCESS){
	    Failure case.
    }
    \endcode

    \sa ocspOverrideURL
    \sa wolfSSL_SetOCSP_OverrideURL
*/
int wolfSSL_CertManagerSetOCSPOverrideURL(WOLFSSL_CERT_MANAGER* cm,
                                          const char* url);

/*!
    \ingroup CertManager
    \brief The function sets the OCSP callback in the WOLFSSL_CERT_MANAGER.

    \return SSL_SUCCESS returned on successful execution. The arguments are
    saved in the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER is NULL.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure.
    \param ioCb a function pointer of type CbOCSPIO.
    \param respFreeCb - a function pointer of type CbOCSPRespFree.
    \param ioCbCtx - a void pointer variable to the I/O callback user
    registered context.

    _Example_
    \code
    #include <wolfssl/ssl.h>

    wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb,
    CbOCSPRespFree respFreeCb, void* ioCbCtx){
    …
    return wolfSSL_CertManagerSetOCSP_Cb(SSL_CM(ssl), ioCb, respFreeCb, ioCbCtx);
    \endcode

    \sa wolfSSL_CertManagerSetOCSPOverrideURL
    \sa wolfSSL_CertManagerCheckOCSP
    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa wolfSSL_EnableOCSP
    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_SetOCSP_Cb
*/
int wolfSSL_CertManagerSetOCSP_Cb(WOLFSSL_CERT_MANAGER* cm,
                                  CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                                  void* ioCbCtx);

/*!
    \ingroup CertManager
    \brief This function turns on OCSP stapling if it is not turned on as well
    as set the options.

    \return SSL_SUCCESS returned if there were no errors and the function
    executed successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CERT_MANAGER structure is
    NULL or otherwise if there was a unpermitted argument value passed to
    a subroutine.
    \return MEMORY_E returned if there was an issue allocating memory.
    \return SSL_FAILURE returned if the initialization of the OCSP
    structure failed.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with
    HAVE_CERTIFICATE_STATUS_REQUEST option.

    \param cm a pointer to a WOLFSSL_CERT_MANAGER structure, a member of the
    WOLFSSL_CTX structure.

    _Example_
    \code
    int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx){
    …
    return wolfSSL_CertManagerEnableOCSPStapling(ctx->cm);
    \endcode

    \sa wolfSSL_CTX_EnableOCSPStapling
*/
int wolfSSL_CertManagerEnableOCSPStapling(
                                                      WOLFSSL_CERT_MANAGER* cm);

/*!
    \brief Enables CRL certificate revocation.

    \return SSL_SUCCESS the function and subroutines returned with no errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.
    \return MEMORY_E returned if the allocation of memory failed.
    \return SSL_FAILURE returned if the InitCRL function does not return
    successfully.
    \return NOT_COMPILED_IN HAVE_CRL was not enabled during the compiling.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param options an integer that is used to determine the setting of
    crlCheckAll member of the WOLFSSL_CERT_MANAGER structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_EnableCRL(ssl, WOLFSSL_CRL_CHECKALL) != SSL_SUCCESS){
	    // Failure case. SSL_SUCCESS was not returned by this function or
    a subroutine
    }
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
*/
int wolfSSL_EnableCRL(WOLFSSL* ssl, int options);

/*!
    \brief Disables CRL certificate revocation.

    \return SSL_SUCCESS wolfSSL_CertMangerDisableCRL successfully disabled
    the crlEnabled member of the WOLFSSL_CERT_MANAGER structure.
    \return BAD_FUNC_ARG the WOLFSSL structure was NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_DisableCRL(ssl) != SSL_SUCCESS){
    	// Failure case
    }
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableCRL(WOLFSSL* ssl);

/*!
    \brief A wrapper function that ends up calling LoadCRL to load the
    certificate for revocation checking.

    \return WOLFSSL_SUCCESS returned if the function and all of the
    subroutines executed without error.
    \return SSL_FATAL_ERROR returned if one of the subroutines does not
    return successfully.
    \return BAD_FUNC_ARG if the WOLFSSL_CERT_MANAGER or the WOLFSSL
    structure are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param path a constant character pointer that holds the path to the
    crl file.
    \param type an integer representing the type of certificate.
    \param monitor an integer variable used to verify the monitor path if
    requested.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    const char* crlPemDir;
    …
    if(wolfSSL_LoadCRL(ssl, crlPemDir, SSL_FILETYPE_PEM, 0) != SSL_SUCCESS){
    	// Failure case. Did not return SSL_SUCCESS.
    }
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
    \sa wolfSSL_CertManagerEnableCRL
    \sa LoadCRL
*/
int wolfSSL_LoadCRL(WOLFSSL* ssl, const char* path, int type, int monitor);

/*!
    \brief Sets the CRL callback in the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned if the function or subroutine executes
    without error. The cbMissingCRL member of the WOLFSSL_CERT_MANAGER is set.
    \return BAD_FUNC_ARG returned if the WOLFSSL or WOLFSSL_CERT_MANAGER
    structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to CbMissingCRL.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    void cb(const char* url) // required signature
    {
    	// Function body
    }
    …
    int crlCb = wolfSSL_SetCRL_Cb(ssl, cb);
    if(crlCb != SSL_SUCCESS){
    	// The callback was not set properly
    }
    \endcode

    \sa CbMissingCRL
    \sa wolfSSL_CertManagerSetCRL_Cb
*/
int wolfSSL_SetCRL_Cb(WOLFSSL* ssl, CbMissingCRL cb);

/*!
    \brief This function enables OCSP certificate verification. The value of
    options if formed by or’ing one or more of the following options:
    WOLFSSL_OCSP_URL_OVERRIDE - use the override URL instead of the URL in
     certificates. The override URL is specified using the
     wolfSSL_CTX_SetOCSP_OverrideURL() function.
    WOLFSSL_OCSP_CHECKALL - Set all OCSP checks on
    WOLFSSL_OCSP_NO_NONCE - Set nonce option for creating OCSP requests

    \return SSL_SUCCESS returned if the function and subroutines executes
    without errors.
    \return BAD_FUNC_ARG returned if an argument in this function or any
    subroutine receives an invalid argument value.
    \return MEMORY_E returned if there was an error allocating memory for
    a structure or other variable.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with the
    HAVE_OCSP option.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param options an integer type passed to wolfSSL_CertMangerENableOCSP()
    used for settings check.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    int options; // initialize to option constant
    …
    int ret = wolfSSL_EnableOCSP(ssl, options);
    if(ret != SSL_SUCCESS){
    	// OCSP is not enabled
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSP
*/
int wolfSSL_EnableOCSP(WOLFSSL* ssl, int options);

/*!
    \brief Disables the OCSP certificate revocation option.

    \return SSL_SUCCESS returned if the function and its subroutine return with
    no errors. The ocspEnabled member of the WOLFSSL_CERT_MANAGER structure was
    successfully set.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if(wolfSSL_DisableOCSP(ssl) != SSL_SUCCESS){
	    // Returned with an error. Failure case in this block.
    }
    \endcode

    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_DisableOCSP(WOLFSSL* ssl);

/*!
    \brief This function sets the ocspOverrideURL member in the
    WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned on successful execution of the function.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL or if a
    unpermitted argument was passed to a subroutine.
    \return MEMORY_E returned if there was an error allocating memory in the
    subroutine.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param url a constant char pointer to the url that will be stored in the
    ocspOverrideURL member of the WOLFSSL_CERT_MANAGER structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    char url[URLSZ];
    ...
    if(wolfSSL_SetOCSP_OverrideURL(ssl, url)){
    	// The override url is set to the new value
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSPOverrideURL
*/
int wolfSSL_SetOCSP_OverrideURL(WOLFSSL* ssl, const char* url);

/*!
    \brief This function sets the OCSP callback in the
    WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned if the function executes without error.
    The ocspIOCb, ocspRespFreeCb, and ocspIOCtx members of the CM are set.
    \return BAD_FUNC_ARG returned if the WOLFSSL or WOLFSSL_CERT_MANAGER
    structures are NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ioCb a function pointer to type CbOCSPIO.
    \param respFreeCb a function pointer to type CbOCSPRespFree which is the
    call to free the response memory.
    \param ioCbCtx a void pointer that will be held in the ocspIOCtx member
    of the CM.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int OCSPIO_CB(void* , const char*, int , unsigned char* , int,
    unsigned char**){  // must have this signature
    // Function Body
    }
    …
    void OCSPRespFree_CB(void* , unsigned char* ){ // must have this signature
    	// function body
    }
    …
    void* ioCbCtx;
    CbOCSPRespFree CB_OCSPRespFree;

    if(wolfSSL_SetOCSP_Cb(ssl, OCSPIO_CB( pass args ), CB_OCSPRespFree,
				ioCbCtx) != SSL_SUCCESS){
	    // Callback not set
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
int wolfSSL_SetOCSP_Cb(WOLFSSL* ssl, CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                       void* ioCbCtx);

/*!
    \brief Enables CRL certificate verification through the CTX.

    \return SSL_SUCCESS returned if this function and it’s subroutines
    execute without errors.
    \return BAD_FUNC_ARG returned if the CTX struct is NULL or there
    was otherwise an invalid argument passed in a subroutine.
    \return MEMORY_E returned if there was an error allocating
    memory during execution of the function.
    \return SSL_FAILURE returned if the crl member of the
    WOLFSSL_CERT_MANAGER fails to initialize correctly.
    \return NOT_COMPILED_IN wolfSSL was not compiled with the HAVE_CRL option.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param options option flags for enabling CRL.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_EnableCRL(ssl->ctx, options) != SSL_SUCCESS){
    	// The function failed
    }
    \endcode

    \sa wolfSSL_CertManagerEnableCRL
    \sa InitCRL
    \sa wolfSSL_CTX_DisableCRL
*/
int wolfSSL_CTX_EnableCRL(WOLFSSL_CTX* ctx, int options);

/*!
    \brief This function disables CRL verification in the CTX structure.

    \return SSL_SUCCESS returned if the function executes without error.
    The crlEnabled member of the WOLFSSL_CERT_MANAGER struct is set to 0.
    \return BAD_FUNC_ARG returned if either the CTX struct or the CM
    struct has a NULL value.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_CTX_DisableCRL(ssl->ctx) != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode

    \sa wolfSSL_CertManagerDisableCRL
*/
int wolfSSL_CTX_DisableCRL(WOLFSSL_CTX* ctx);

/*!
    \brief This function loads CRL into the WOLFSSL_CTX structure through
    wolfSSL_CertManagerLoadCRL().

    \return SSL_SUCCESS - returned if the function and its subroutines
    execute without error.
    \return BAD_FUNC_ARG - returned if this function or any subroutines
    are passed NULL structures.
    \return BAD_PATH_ERROR - returned if the path variable opens as NULL.
    \return MEMORY_E - returned if an allocation of memory failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param path the path to the certificate.
    \param type an integer variable holding the type of certificate.
    \param monitor an integer variable used to determine if the monitor
    path is requested.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    const char* path;
    …
    return wolfSSL_CTX_LoadCRL(ctx, path, SSL_FILETYPE_PEM, 0);
    \endcode

    \sa wolfSSL_CertManagerLoadCRL
    \sa LoadCRL
*/
int wolfSSL_CTX_LoadCRL(WOLFSSL_CTX* ctx, const char* path, int type, int monitor);

/*!
    \brief This function will set the callback argument to the cbMissingCRL
    member of the WOLFSSL_CERT_MANAGER structure by calling
    wolfSSL_CertManagerSetCRL_Cb.

    \return SSL_SUCCESS returned for a successful execution. The
    WOLFSSL_CERT_MANAGER structure’s member cbMssingCRL was successfully
    set to cb.
    \return BAD_FUNC_ARG returned if WOLFSSL_CTX or WOLFSSL_CERT_MANAGER
    are NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created with
    wolfSSL_CTX_new().
    \param cb a pointer to a callback function of type CbMissingCRL.
    Signature requirement:
	void (*CbMissingCRL)(const char* url);

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    void cb(const char* url) // Required signature
    {
    	// Function body
    }
    …
    if (wolfSSL_CTX_SetCRL_Cb(ctx, cb) != SSL_SUCCESS){
    	// Failure case, cb was not set correctly.
    }
    \endcode

    \sa wolfSSL_CertManagerSetCRL_Cb
    \sa CbMissingCRL
*/
int wolfSSL_CTX_SetCRL_Cb(WOLFSSL_CTX* ctx, CbMissingCRL cb);

/*!
    \brief This function sets options to configure behavior of OCSP
    functionality in wolfSSL.  The value of options if formed by or’ing
    one or more of the following options:
    WOLFSSL_OCSP_URL_OVERRIDE - use the override URL instead of the URL in
     certificates. The override URL is specified using the
     wolfSSL_CTX_SetOCSP_OverrideURL() function.
    WOLFSSL_OCSP_CHECKALL - Set all OCSP checks on
    WOLFSSL_OCSP_NO_NONCE - Set nonce option for creating OCSP requests

    This function only sets the OCSP options when wolfSSL has been compiled with
    OCSP support (--enable-ocsp, #define HAVE_OCSP).

    \return SSL_SUCCESS is returned upon success.
    \return SSL_FAILURE is returned upon failure.
    \return NOT_COMPILED_IN is returned when this function has been called,
    but OCSP support was not enabled when wolfSSL was compiled.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param options value used to set the OCSP options.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    int options; // initialize to option constant
    …
    int ret = wolfSSL_CTX_EnableOCSP(ctx, options);
    if(ret != SSL_SUCCESS){
        // OCSP is not enabled
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSP
    \sa wolfSSL_EnableOCSP
*/
int wolfSSL_CTX_EnableOCSP(WOLFSSL_CTX* ctx, int options);

/*!
    \brief This function disables OCSP certificate revocation checking by
    affecting the ocspEnabled member of the WOLFSSL_CERT_MANAGER structure.

    \return SSL_SUCCESS returned if the function executes without error.
    The ocspEnabled member of the CM has been disabled.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(!wolfSSL_CTX_DisableOCSP(ssl->ctx)){
    	// OCSP is not disabled
    }
    \endcode

    \sa wolfSSL_DisableOCSP
    \sa wolfSSL_CertManagerDisableOCSP
*/
int wolfSSL_CTX_DisableOCSP(WOLFSSL_CTX* ctx);

/*!
    \brief This function manually sets the URL for OCSP to use. By default,
    OCSP will use the URL found in the individual certificate unless the
    WOLFSSL_OCSP_URL_OVERRIDE option is set using the wolfSSL_CTX_EnableOCSP.

    \return SSL_SUCCESS is returned upon success.
    \return SSL_FAILURE is returned upon failure.
    \return NOT_COMPILED_IN is returned when this function has been called,
    but OCSP support was not enabled when wolfSSL was compiled.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param url pointer to the OCSP URL for wolfSSL to use.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_OCSP_set_override_url(ctx, “custom-url-here”);
    \endcode

    \sa wolfSSL_CTX_OCSP_set_options
*/
int wolfSSL_CTX_SetOCSP_OverrideURL(WOLFSSL_CTX* ctx, const char* url);

/*!
    \brief Sets the callback for the OCSP in the WOLFSSL_CTX structure.

    \return SSL_SUCCESS returned if the function executed successfully. The
    ocspIOCb, ocspRespFreeCb, and ocspIOCtx members in the CM were
    successfully set.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX or
    WOLFSSL_CERT_MANAGER structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param ioCb a CbOCSPIO type that is a function pointer.
    \param respFreeCb a CbOCSPRespFree type that is a function pointer.
    \param ioCbCtx a void pointer that will be held in the WOLFSSL_CERT_MANAGER.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    …
    CbOCSPIO ocspIOCb;
    CbOCSPRespFree ocspRespFreeCb;
    …
    void* ioCbCtx;

    int isSetOCSP = wolfSSL_CTX_SetOCSP_Cb(ctx, ocspIOCb,
    ocspRespFreeCb, ioCbCtx);

    if(isSetOCSP != SSL_SUCCESS){
    	// The function did not return successfully.
    }
    \endcode

    \sa wolfSSL_CertManagerSetOCSP_Cb
    \sa CbOCSPIO
    \sa CbOCSPRespFree
*/
int wolfSSL_CTX_SetOCSP_Cb(WOLFSSL_CTX* ctx,
                           CbOCSPIO ioCb, CbOCSPRespFree respFreeCb,
                           void* ioCbCtx);

/*!
    \brief This function enables OCSP stapling by calling
    wolfSSL_CertManagerEnableOCSPStapling().

    \return SSL_SUCCESS returned if there were no errors and the function
    executed successfully.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or
    otherwise if there was a unpermitted argument value passed to a subroutine.
    \return MEMORY_E returned if there was an issue allocating memory.
    \return SSL_FAILURE returned if the initialization of the OCSP
    structure failed.
    \return NOT_COMPILED_IN returned if wolfSSL was not compiled with
    HAVE_CERTIFICATE_STATUS_REQUEST option.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL* ssl = WOLFSSL_new();
    ssl->method.version; // set to desired protocol
    ...
    if(!wolfSSL_CTX_EnableOCSPStapling(ssl->ctx)){
    	// OCSP stapling is not enabled
    }
    \endcode

    \sa wolfSSL_CertManagerEnableOCSPStapling
    \sa InitOCSP
*/
int wolfSSL_CTX_EnableOCSPStapling(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys

    \brief Normally, at the end of the SSL handshake, wolfSSL frees
    temporary arrays.  Calling this function before the handshake begins
    will prevent wolfSSL from freeing temporary arrays.  Temporary arrays
    may be needed for things such as wolfSSL_get_keys() or PSK hints.
    When the user is done with temporary arrays, either wolfSSL_FreeArrays()
    may be called to free the resources immediately, or alternatively the
    resources will be freed when the associated SSL object is freed.

    \return none No return.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_KeepArrays(ssl);
    \endcode

    \sa wolfSSL_FreeArrays
*/
void wolfSSL_KeepArrays(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief Normally, at the end of the SSL handshake, wolfSSL frees temporary
    arrays.  If wolfSSL_KeepArrays() has been called before the handshake,
    wolfSSL will not free temporary arrays.  This function explicitly frees
    temporary arrays and should be called when the user is done with temporary
    arrays and does not want to wait for the SSL object to be freed to free
    these resources.

    \return none No return.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_FreeArrays(ssl);
    \endcode

    \sa wolfSSL_KeepArrays
*/
void wolfSSL_FreeArrays(WOLFSSL* ssl);

/*!
    \brief This function enables the use of Server Name Indication in the SSL
    object passed in the 'ssl' parameter. It means that the SNI extension will
    be sent on ClientHello by wolfSSL client and wolfSSL server will respond
    ClientHello + SNI with either ServerHello + blank SNI or alert fatal in
    case of SNI mismatch.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ssl is NULL, data is NULL, type is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the server name data.
    \param size size of the server name data.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseSNI
*/
int wolfSSL_UseSNI(WOLFSSL* ssl, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief This function enables the use of Server Name Indication for SSL
    objects created from the SSL context passed in the 'ctx' parameter. It
    means that the SNI extension will be sent on ClientHello by wolfSSL
    clients and wolfSSL servers will respond ClientHello + SNI with either
    ServerHello + blank SNI or alert fatal in case of SNI mismatch.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ctx is NULL, data is NULL, type is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the server name data.
    \param size size of the server name data.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, WOLFSSL_SNI_HOST_NAME, "www.yassl.com",
        strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSNI
*/
int wolfSSL_CTX_UseSNI(WOLFSSL_CTX* ctx, unsigned char type,
                                         const void* data, unsigned short size);

/*!
    \brief This function is called on the server side to configure the
    behavior of the SSL session using Server Name Indication in the SSL
    object passed in the 'ssl' parameter. The options are explained below.

    \return none No returns.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param options a bitwise semaphore with the chosen options. The available
    options are: enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01,
    WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }; Normally the server will abort the
    handshake by sending a fatal-level unrecognized_name(112) alert if the
    hostname provided by the client mismatch with the servers.
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH With this option set, the server
    will not send a SNI response instead of aborting the session.
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH - With this option set, the server
    will send a SNI response as if the host names match instead of aborting
    the session.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    wolfSSL_SNI_SetOptions(ssl, WOLFSSL_SNI_HOST_NAME,
        WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_SNI_SetOptions
*/
void wolfSSL_SNI_SetOptions(WOLFSSL* ssl, unsigned char type,
                                                         unsigned char options);

/*!
    \brief This function is called on the server side to configure the behavior
    of the SSL sessions using Server Name Indication for SSL objects created
    from the SSL context passed in the 'ctx' parameter. The options are
    explained below.

    \return none No returns.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param type indicates which type of server name is been passed in data.
    The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param options a bitwise semaphore with the chosen options. The available
    options are: enum { WOLFSSL_SNI_CONTINUE_ON_MISMATCH = 0x01,
    WOLFSSL_SNI_ANSWER_ON_MISMATCH = 0x02 }; Normally the server will abort
    the handshake by sending a fatal-level unrecognized_name(112) alert if the
    hostname provided by the client mismatch with the servers.
    \param WOLFSSL_SNI_CONTINUE_ON_MISMATCH With this option set, the
    server will not send a SNI response instead of aborting the session.
    \param WOLFSSL_SNI_ANSWER_ON_MISMATCH With this option set, the server
    will send a SNI response as if the host names match instead of aborting
    the session.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
       // context creation failed
    }
    ret = wolfSSL_CTX_UseSNI(ctx, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    wolfSSL_CTX_SNI_SetOptions(ctx, WOLFSSL_SNI_HOST_NAME,
    WOLFSSL_SNI_CONTINUE_ON_MISMATCH);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_SetOptions
*/
void wolfSSL_CTX_SNI_SetOptions(WOLFSSL_CTX* ctx,
                                     unsigned char type, unsigned char options);

/*!
    \brief This function is called on the server side to retrieve the Server
    Name Indication provided by the client from the Client Hello message sent
    by the client to start a session. It does not requires context or session
    setup to retrieve the SNI.

    \return WOLFSSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of this
    cases: buffer is NULL, bufferSz <= 0, sni is NULL, inOutSz is NULL or <= 0
    \return BUFFER_ERROR is the error returned when there is a malformed
    Client Hello message.
    \return INCOMPLETE_DATA is the error returned when there is not enough
    data to complete the extraction.

    \param buffer pointer to the data provided by the client (Client Hello).
    \param bufferSz size of the Client Hello message.
    \param type indicates which type of server name is been retrieved
    from the buffer. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param sni pointer to where the output is going to be stored.
    \param inOutSz pointer to the output size, this value will be updated
    to MIN("SNI's length", inOutSz).

    _Example_
    \code
    unsigned char buffer[1024] = {0};
    unsigned char result[32]   = {0};
    int           length       = 32;
    // read Client Hello to buffer...
    ret = wolfSSL_SNI_GetFromBuffer(buffer, sizeof(buffer), 0, result, &length));
    if (ret != WOLFSSL_SUCCESS) {
        // sni retrieve failed
    }
    \endcode

    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
    \sa wolfSSL_SNI_GetRequest
*/
int wolfSSL_SNI_GetFromBuffer(
                 const unsigned char* clientHello, unsigned int helloSz,
                 unsigned char type, unsigned char* sni, unsigned int* inOutSz);

/*!
    \ingroup IO

    \brief This function gets the status of an SNI object.

    \return value This function returns the byte value of the SNI struct’s
    status member if the SNI is not NULL.
    \return 0 if the SNI object is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param type the SNI type.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
    …
    Byte type = WOLFSSL_SNI_HOST_NAME;
    char* request = (char*)&type;
    AssertIntEQ(WOLFSSL_SNI_NO_MATCH, wolfSSL_SNI_Status(ssl, type));
    …
    \endcode

    \sa TLSX_SNI_Status
    \sa TLSX_SNI_find
    \sa TLSX_Find
*/
unsigned char wolfSSL_SNI_Status(WOLFSSL* ssl, unsigned char type);

/*!
    \brief This function is called on the server side to retrieve the
    Server Name Indication provided by the client in a SSL session.

    \return size the size of the provided SNI data.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param type indicates which type of server name is been retrieved in
    data. The known types are: enum { WOLFSSL_SNI_HOST_NAME = 0 };
    \param data pointer to the data provided by the client.

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSNI(ssl, 0, "www.yassl.com", strlen("www.yassl.com"));
    if (ret != WOLFSSL_SUCCESS) {
        // sni usage failed
    }
    if (wolfSSL_accept(ssl) == SSL_SUCCESS) {
        void *data = NULL;
        unsigned short size = wolfSSL_SNI_GetRequest(ssl, 0, &data);
    }
    \endcode

    \sa wolfSSL_UseSNI
    \sa wolfSSL_CTX_UseSNI
*/
unsigned short wolfSSL_SNI_GetRequest(WOLFSSL *ssl,
                                               unsigned char type, void** data);

/*!
    \ingroup Setup

    \brief Setup ALPN use for a wolfSSL session.

    \return WOLFSSL_SUCCESS: upon success.
    \return BAD_FUNC_ARG Returned if ssl or protocol_name_list
    is null or protocol_name_listSz is too large or options
    contain something not supported.
    \return MEMORY_ERROR Error allocating memory for protocol list.
    \return SSL_FAILURE upon failure.

    \param ssl The wolfSSL session to use.
    \param protocol_name_list List of protocol names to use.
    Comma delimited string is required.
    \param protocol_name_listSz Size of the list of protocol names.
    \param options WOLFSSL_ALPN_CONTINUE_ON_MISMATCH or
    WOLFSSL_ALPN_FAILED_ON_MISMATCH.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    char alpn_list[] = {};

    if (wolfSSL_UseALPN(ssl, alpn_list, sizeof(alpn_list),
        WOLFSSL_APN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
    {
       // Error setting session ticket
    }
    \endcode

    \sa TLSX_UseALPN
*/
int wolfSSL_UseALPN(WOLFSSL* ssl, char *protocol_name_list,
                                unsigned int protocol_name_listSz,
                                unsigned char options);

/*!
    \ingroup TLS

    \brief This function gets the protocol name set by the server.

    \return SSL_SUCCESS returned on successful execution where no
    errors were thrown.
    \return SSL_FATAL_ERROR returned if the extension was not found or
    if there was no protocol match with peer. There will also be an
    error thrown if there is more than one protocol name accepted.
    \return SSL_ALPN_NOT_FOUND returned signifying that no protocol
    match with peer was found.
    \return BAD_FUNC_ARG returned if there was a NULL argument passed
    into the function.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param protocol_name a pointer to a char that represents the protocol
    name and will be held in the ALPN structure.
    \param size a word16 type that represents the size of the protocol_name.

    _Example_
    \code
    WOLFSSL_CTX* ctx = WOLFSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new(ctx);
    ...
    int err;
    char* protocol_name = NULL;
    Word16 protocol_nameSz = 0;
    err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);

    if(err == SSL_SUCCESS){
	    // Sent ALPN protocol
    }
    \endcode

    \sa TLSX_ALPN_GetRequest
    \sa TLSX_Find
*/
int wolfSSL_ALPN_GetProtocol(WOLFSSL* ssl, char **protocol_name,
                                         unsigned short *size);

/*!
    \ingroup TLS

    \brief This function copies the alpn_client_list data from the SSL
    object to the buffer.

    \return SSL_SUCCESS returned if the function executed without error. The
    alpn_client_list member of the SSL object has been copied to the
    list parameter.
    \return BAD_FUNC_ARG returned if the list or listSz parameter is NULL.
    \return BUFFER_ERROR returned if there will be a problem with the
    list buffer (either it’s NULL or the size is 0).
    \return MEMORY_ERROR returned if there was a problem dynamically
    allocating memory.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param list a pointer to the buffer. The data from the SSL object will
    be copied into it.
    \param listSz the buffer size.

    _Example_
    \code
    #import <wolfssl/ssl.h>

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method);
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    #ifdef HAVE_ALPN
    char* list = NULL;
    word16 listSz = 0;
    …
    err = wolfSSL_ALPN_GetPeerProtocol(ssl, &list, &listSz);

    if(err == SSL_SUCCESS){
	    List of protocols names sent by client
    }
    \endcode

    \sa wolfSSL_UseALPN
*/
int wolfSSL_ALPN_GetPeerProtocol(WOLFSSL* ssl, char **list,
                                             unsigned short *listSz);

/*!
    \brief This function is called on the client side to enable the use of
    Maximum Fragment Length in the SSL object passed in the 'ssl' parameter.
    It means that the Maximum Fragment Length extension will be sent on
    ClientHello by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ssl is NULL, mfl is out of range.
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param mfl indicates which is the Maximum Fragment Length requested for the
    session. The available options are: enum { WOLFSSL_MFL_2_9  = 1, 512 bytes
    WOLFSSL_MFL_2_10 = 2, 1024 bytes WOLFSSL_MFL_2_11 = 3, 2048 bytes
    WOLFSSL_MFL_2_12 = 4, 4096 bytes WOLFSSL_MFL_2_13 = 5, 8192
    bytes wolfSSL ONLY!!! };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseMaxFragment(ssl, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseMaxFragment(WOLFSSL* ssl, unsigned char mfl);

/*!
    \brief This function is called on the client side to enable the use
    of Maximum Fragment Length for SSL objects created from the SSL context
    passed in the 'ctx' parameter. It means that the Maximum Fragment Length
    extension will be sent on ClientHello by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ctx is NULL, mfl is out of range.
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param mfl indicates which is the Maximum Fragment Length requested
    for the session. The available options are:
    enum { WOLFSSL_MFL_2_9  = 1 512 bytes, WOLFSSL_MFL_2_10 = 2 1024 bytes,
           WOLFSSL_MFL_2_11 = 3 2048 bytes WOLFSSL_MFL_2_12 = 4 4096 bytes,
           WOLFSSL_MFL_2_13 = 5 8192 bytes wolfSSL ONLY!!!,
           WOLFSSL_MFL_2_13 = 6  256 bytes wolfSSL ONLY!!!
    };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseMaxFragment(ctx, WOLFSSL_MFL_2_11);
    if (ret != 0) {
        // max fragment usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseMaxFragment(WOLFSSL_CTX* ctx, unsigned char mfl);

/*!
    \brief This function is called on the client side to enable the use of
    Truncated HMAC in the SSL object passed in the 'ssl' parameter. It
    means that the Truncated HMAC extension will be sent on ClientHello
    by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ssl is NULL
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new()

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseTruncatedHMAC(ssl);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_CTX_UseMaxFragment
*/
int wolfSSL_UseTruncatedHMAC(WOLFSSL* ssl);

/*!
    \brief This function is called on the client side to enable the use of
    Truncated HMAC for SSL objects created from the SSL context passed in
    the 'ctx' parameter. It means that the Truncated HMAC extension will
    be sent on ClientHello by wolfSSL clients.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of
    these cases: ctx is NULL
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseTruncatedHMAC(ctx);
    if (ret != 0) {
        // truncated HMAC usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseMaxFragment
*/
int wolfSSL_CTX_UseTruncatedHMAC(WOLFSSL_CTX* ctx);

/*!
    \brief Stapling eliminates the need to contact the CA. Stapling
    lowers the cost of certificate revocation check presented in OCSP.

    \return SSL_SUCCESS returned if TLSX_UseCertificateStatusRequest
    executes without error.
    \return MEMORY_E returned if there is an error with the allocation
    of memory.
    \return BAD_FUNC_ARG returned if there is an argument that has a
    NULL or otherwise unacceptable value passed into the function.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param status_type a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.
    \param options a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    if (wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR2_OCSP,
    WOLFSSL_CSR2_OCSP_USE_NONCE) != SSL_SUCCESS){
	    // Failed case.
    }
    \endcode

    \sa TLSX_UseCertificateStatusRequest
    \sa wolfSSL_CTX_UseOCSPStapling
*/
int wolfSSL_UseOCSPStapling(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief This function requests the certificate status during the handshake.

    \return SSL_SUCCESS returned if the function and subroutines execute
    without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or
    otherwise if a unpermitted value is passed to a subroutine.
    \return MEMORY_E returned if the function or subroutine failed to properly
    allocate memory.

    \param ctx a pointer to a WOLFSSL_CTX structure,
    created using wolfSSL_CTX_new().
    \param status_type a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.
    \param options a byte type that is passed through to
    TLSX_UseCertificateStatusRequest() and stored in the
    CertificateStatusRequest structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte statusRequest = 0; // Initialize status request
    …
    switch(statusRequest){
    	case WOLFSSL_CSR_OCSP:
    		if(wolfSSL_CTX_UseOCSPStapling(ssl->ctx, WOLFSSL_CSR_OCSP,
    WOLF_CSR_OCSP_USE_NONCE) != SSL_SUCCESS){
    // UseCertificateStatusRequest failed
    }
    // Continue switch cases
    \endcode

    \sa wolfSSL_UseOCSPStaplingV2
    \sa wolfSSL_UseOCSPStapling
    \sa TLSX_UseCertificateStatusRequest
*/
int wolfSSL_CTX_UseOCSPStapling(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief The function sets the status type and options for OCSP.

    \return SSL_SUCCESS - returned if the function and subroutines
    executed without error.
    \return MEMORY_E - returned if there was an allocation of memory error.
    \return BAD_FUNC_ARG - returned if a NULL or otherwise unaccepted
    argument was passed to the function or a subroutine.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param status_type a byte type that loads the OCSP status type.
    \param options a byte type that holds the OCSP options, set in
    wolfSSL_SNI_SetOptions() and wolfSSL_CTX_SNI_SetOptions().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if (wolfSSL_UseOCSPStaplingV2(ssl, WOLFSSL_CSR2_OCSP_MULTI, 0) != SSL_SUCCESS){
    	// Did not execute properly. Failure case code block.
    }
    \endcode

    \sa TLSX_UseCertificatStatusRequestV2
    \sa wolfSSL_SNI_SetOptions
    \sa wolfSSL_CTX_SNI_SetOptions
*/
int wolfSSL_UseOCSPStaplingV2(WOLFSSL* ssl,
                              unsigned char status_type, unsigned char options);

/*!
    \brief Creates and initializes the certificate status request
    for OCSP Stapling.

    \return SSL_SUCCESS if the function and subroutines executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL_CTX structure is NULL or if
    the side variable is not client side.
    \return MEMORY_E returned if the allocation of memory failed.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param status_type a byte type that is located in the
    CertificatStatusRequest structure and must be either WOLFSSL_CSR2_OCSP
    or WOLFSSL_CSR2_OCSP_MULTI.
    \param options a byte type that will be held in
    CertificateStatusRequestItemV2 struct.

    _Example_
    \code
    WOLFSSL_CTX* ctx  = wolfSSL_CTX_new( protocol method );
    byte status_type;
    byte options;
    ...
    if(wolfSSL_CTX_UseOCSPStaplingV2(ctx, status_type, options); != SSL_SUCCESS){
    	// Failure case.
    }
    \endcode

    \sa TLSX_UseCertificateStatusRequestV2
    \sa wc_RNG_GenerateBlock
    \sa TLSX_Push
*/
int wolfSSL_CTX_UseOCSPStaplingV2(WOLFSSL_CTX* ctx,
                              unsigned char status_type, unsigned char options);

/*!
    \brief This function is called on the client side to enable the use of
    Supported Elliptic Curves Extension in the SSL object passed in the 'ssl'
    parameter. It means that the supported curves enabled will be sent on
    ClientHello by wolfSSL clients. This function can be called more than
    one time to enable multiple curves.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ssl is NULL, name is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ssl pointer to a SSL object, created with wolfSSL_new().
    \param name indicates which curve will be supported for the session. The
    available options are: enum { WOLFSSL_ECC_SECP160R1 = 0x10,
    WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15,
    WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18,
    WOLFSSL_ECC_SECP521R1 = 0x19 };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    WOLFSSL* ssl = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        // ssl creation failed
    }
    ret = wolfSSL_UseSupportedCurve(ssl, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_UseSupportedCurve
*/
int wolfSSL_UseSupportedCurve(WOLFSSL* ssl, word16 name);

/*!
    \brief This function is called on the client side to enable the use of
    Supported Elliptic Curves Extension for SSL objects created from the SSL
    context passed in the 'ctx' parameter. It means that the supported curves
    enabled will be sent on ClientHello by wolfSSL clients. This function can
    be called more than one time to enable multiple curves.

    \return SSL_SUCCESS upon success.
    \return BAD_FUNC_ARG is the error that will be returned in one of these
    cases: ctx is NULL, name is a unknown value. (see below)
    \return MEMORY_E is the error returned when there is not enough memory.

    \param ctx pointer to a SSL context, created with wolfSSL_CTX_new().
    \param name indicates which curve will be supported for the session.
    The available options are: enum { WOLFSSL_ECC_SECP160R1 = 0x10,
    WOLFSSL_ECC_SECP192R1 = 0x13, WOLFSSL_ECC_SECP224R1 = 0x15,
    WOLFSSL_ECC_SECP256R1 = 0x17, WOLFSSL_ECC_SECP384R1 = 0x18,
    WOLFSSL_ECC_SECP521R1 = 0x19 };

    _Example_
    \code
    int ret = 0;
    WOLFSSL_CTX* ctx = 0;
    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        // context creation failed
    }
    ret = wolfSSL_CTX_UseSupportedCurve(ctx, WOLFSSL_ECC_SECP256R1);
    if (ret != 0) {
        // Elliptic Curve Extension usage failed
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_UseSupportedCurve
*/
int wolfSSL_CTX_UseSupportedCurve(WOLFSSL_CTX* ctx,
                                                           word16 name);

/*!
    \ingroup IO

    \brief This function forces secure renegotiation for the supplied
    WOLFSSL structure.  This is not recommended.

    \return SSL_SUCCESS Successfully set secure renegotiation.
    \return BAD_FUNC_ARG Returns error if ssl is null.
    \return MEMORY_E Returns error if unable to allocate memory for secure
    renegotiation.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSecureRenegotiation(ssl) != SSL_SUCCESS)
    {
        // Error setting secure renegotiation
    }
    \endcode

    \sa TLSX_Find
    \sa TLSX_UseSecureRenegotiation
*/
int wolfSSL_UseSecureRenegotiation(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function executes a secure renegotiation handshake; this is user
    forced as wolfSSL discourages this functionality.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure was NULL or otherwise
    if an unacceptable argument was passed in a subroutine.
    \return SECURE_RENEGOTIATION_E returned if there was an error with
    renegotiating the handshake.
    \return SSL_FATAL_ERROR returned if there was an error with the
    server or client configuration and the renegotiation could
    not be completed. See wolfSSL_negotiate().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    if(wolfSSL_Rehandshake(ssl) != SSL_SUCCESS){
	    // There was an error and the rehandshake is not successful.
    }
    \endcode

    \sa wolfSSL_negotiate
    \sa wc_InitSha512
    \sa wc_InitSha384
    \sa wc_InitSha256
    \sa wc_InitSha
    \sa wc_InitMd5
*/
int wolfSSL_Rehandshake(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief Force provided WOLFSSL structure to use session ticket. The
    constant HAVE_SESSION_TICKET should be defined and the constant
    NO_WOLFSSL_CLIENT should not be defined to use this function.

    \return SSL_SUCCESS Successfully set use session ticket.
    \return BAD_FUNC_ARG Returned if ssl is null.
    \return MEMORY_E Error allocating memory for setting session ticket.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    WOLFSSL_METHOD method = // Some wolfSSL method
    ctx = wolfSSL_CTX_new(method);
    ssl = wolfSSL_new(ctx);

    if(wolfSSL_UseSessionTicket(ssl) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode

    \sa TLSX_UseSessionTicket
*/
int wolfSSL_UseSessionTicket(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets wolfSSL context to use a session ticket.

    \return SSL_SUCCESS Function executed successfully.
    \return BAD_FUNC_ARG Returned if ctx is null.
    \return MEMORY_E Error allocating memory in internal function.

    \param ctx The WOLFSSL_CTX structure to use.

    _Example_
    \code
    wolfSSL_Init();
    WOLFSSL_CTX* ctx;
    WOLFSSL_METHOD method = // Some wolfSSL method ;
    ctx = wolfSSL_CTX_new(method);

    if(wolfSSL_CTX_UseSessionTicket(ctx) != SSL_SUCCESS)
    {
        // Error setting session ticket
    }
    \endcode

    \sa TLSX_UseSessionTicket
*/
int wolfSSL_CTX_UseSessionTicket(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief This function copies the ticket member of the Session structure to
    the buffer. If buf is NULL and bufSz is non-NULL, bufSz will be set to the
    ticket length.

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if ssl or bufSz is NULL, or if bufSz
    is non-NULL and buf is NULL


    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a byte pointer representing the memory buffer.
    \param bufSz a word32 pointer representing the buffer size.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buf;
    word32 bufSz;  // Initialize with buf size
    …
    if(wolfSSL_get_SessionTicket(ssl, buf, bufSz) <= 0){
	    // Nothing was written to the buffer
    } else {
	    // the buffer holds the content from ssl->session->ticket
    }
    \endcode

    \sa wolfSSL_UseSessionTicket
    \sa wolfSSL_set_SessionTicket
*/
int wolfSSL_get_SessionTicket(WOLFSSL* ssl, unsigned char* buf, word32* bufSz);

/*!
    \ingroup IO

    \brief This function sets the ticket member of the WOLFSSL_SESSION
    structure within the WOLFSSL struct. The buffer passed into the function
    is copied to memory.

    \return SSL_SUCCESS returned on successful execution of the function.
    The function returned without errors.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL. This will
    also be thrown if the buf argument is NULL but the bufSz argument
    is not zero.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param buf a byte pointer that gets loaded into the ticket member
    of the session structure.
    \param bufSz a word32 type that represents the size of the buffer.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    byte* buffer; // File to load
    word32 bufSz;
    ...
    if(wolfSSL_KeepArrays(ssl, buffer, bufSz) != SSL_SUCCESS){
    	// There was an error loading the buffer to memory.
    }
    \endcode

    \sa wolfSSL_set_SessionTicket_cb
*/
int wolfSSL_set_SessionTicket(WOLFSSL* ssl, const unsigned char* buf,
                              word32 bufSz);

/*!
    \brief This function sets the session ticket callback. The type
    CallbackSessionTicket is a function pointer with the signature of:
    int (*CallbackSessionTicket)(WOLFSSL*, const unsigned char*, int, void*)

    \return SSL_SUCCESS returned if the function executed without error.
    \return BAD_FUNC_ARG returned if the WOLFSSL structure is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer to the type CallbackSessionTicket.
    \param ctx a void pointer to the session_ticket_ctx member of the
    WOLFSSL structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int sessionTicketCB(WOLFSSL* ssl, const unsigned char* ticket, int ticketSz,
				void* ctx){ … }
    wolfSSL_set_SessionTicket_cb(ssl, sessionTicketCB, (void*)”initial session”);
    \endcode

    \sa wolfSSL_get_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
*/
int wolfSSL_set_SessionTicket_cb(WOLFSSL* ssl,
                                 CallbackSessionTicket cb, void* ctx);

/*!
    \brief This function sends a session ticket to the client after a TLS v1.3
    handhsake has been established.

    \return WOLFSSL_SUCCESS returned if a new session ticket was sent.
    \return BAD_FUNC_ARG returned if WOLFSSL structure is NULL, or not using
    TLS v1.3.
    \return SIDE_ERROR returned if not a server.
    \return NOT_READY_ERROR returned if the handshake has not completed.
    \return WOLFSSL_FATAL_ERROR returned if creating or sending message fails.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    ret = wolfSSL_send_SessionTicket(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // New session ticket not sent.
    }
    \endcode

    \sa wolfSSL_get_SessionTicket
    \sa CallbackSessionTicket
    \sa sessionTicketCB
 */
int wolfSSL_send_SessionTicket(WOLFSSL* ssl);

/*!
    \brief This function sets the session ticket key encrypt callback function
    for a server to support session tickets as specified in RFC 5077.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure. This is caused by passing
    invalid arguments to the function.

    \param ctx pointer to the WOLFSSL_CTX object, created with wolfSSL_CTX_new().
    \param cb user callback function to encrypt/decrypt session tickets
    \param ssl(Callback) pointer to the WOLFSSL object, created with
    wolfSSL_new()
    \param key_name(Callback) unique key name for this ticket context, should
    be randomly generated
    \param iv(Callback) unique IV for this ticket, up to 128 bits, should
    be randomly generated
    \param mac(Callback) up to 256 bit mac for this ticket
    \param enc(Callback) if this encrypt parameter is true the user should fill
    in key_name, iv, mac, and encrypt the ticket in-place of length inLen and
    set the resulting output length in *outLen.  Returning WOLFSSL_TICKET_RET_OK
    tells wolfSSL that the encryption was successful. If this encrypt parameter
    is false, the user should perform a decrypt of the ticket in-place of length
    inLen using key_name, iv, and mac. The resulting decrypt length should be
    set in *outLen. Returning WOLFSSL_TICKET_RET_OK tells wolfSSL to proceed
    using the decrypted ticket. Returning WOLFSSL_TICKET_RET_CREATE tells
    wolfSSL to use the decrypted ticket but also to generate a new one to
    send to the client, helpful if recently rolled keys and don’t want to
    force a full handshake.  Returning WOLFSSL_TICKET_RET_REJECT tells
    wolfSSL to reject this ticket, perform a full handshake, and create
    a new standard session ID for normal session resumption. Returning
    WOLFSSL_TICKET_RET_FATAL tells wolfSSL to end the connection
    attempt with a fatal error.
    \param ticket(Callback) the input/output buffer for the encrypted ticket.
    See the enc parameter
    \param inLen(Callback) the input length of the ticket parameter
    \param outLen(Callback) the resulting output length of the ticket parameter.
    When entering the callback outLen will indicate the maximum size available
    in the ticket buffer.
    \param userCtx(Callback) the user context set with
    wolfSSL_CTX_set_TicketEncCtx()

    _Example_
    \code
    See wolfssl/test.h myTicketEncCb() used by the example
    server and example echoserver.
    \endcode

    \sa wolfSSL_CTX_set_TicketHint
    \sa wolfSSL_CTX_set_TicketEncCtx
*/
int wolfSSL_CTX_set_TicketEncCb(WOLFSSL_CTX* ctx,
                                            SessionTicketEncCb cb);

/*!
    \brief This function sets the session ticket hint relayed to the client.
    For server side use.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure.  This is caused by passing
    invalid arguments to the function.

    \param ctx pointer to the WOLFSSL_CTX object, created with wolfSSL_CTX_new().
    \param hint number of seconds the ticket might be valid for.  Hint to client.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCb
*/
int wolfSSL_CTX_set_TicketHint(WOLFSSL_CTX* ctx, int hint);

/*!
    \brief This function sets the session ticket encrypt user context for the
    callback.  For server side use.

    \return SSL_SUCCESS will be returned upon successfully setting the session.
    \return BAD_FUNC_ARG will be returned on failure.  This is caused by
    passing invalid arguments to the function.

    \param ctx pointer to the WOLFSSL_CTX object, created
    with wolfSSL_CTX_new().
    \param userCtx the user context for the callback

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCb
*/
int wolfSSL_CTX_set_TicketEncCtx(WOLFSSL_CTX* ctx, void* userCtx);

/*!
    \brief This function gets the session ticket encrypt user context for the
    callback.  For server side use.

    \return userCtx will be returned upon successfully getting the session.
    \return NULL will be returned on failure.  This is caused by
    passing invalid arguments to the function, or when the user context has
    not been set.

    \param ctx pointer to the WOLFSSL_CTX object, created
    with wolfSSL_CTX_new().

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_CTX_set_TicketEncCtx
*/
void* wolfSSL_CTX_get_TicketEncCtx(WOLFSSL_CTX* ctx);

/*!
    \brief This function sets the handshake done callback. The hsDoneCb and
    hsDoneCtx members of the WOLFSSL structure are set in this function.

    \return SSL_SUCCESS returned if the function executed without an error.
    The hsDoneCb and hsDoneCtx members of the WOLFSSL struct are set.
    \return BAD_FUNC_ARG returned if the WOLFSSL struct is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param cb a function pointer of type HandShakeDoneCb with the signature of
    the form: int (*HandShakeDoneCb)(WOLFSSL*, void*);
    \param user_ctx a void pointer to the user registered context.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    …
    int myHsDoneCb(WOLFSSL* ssl, void* user_ctx){
        // callback function
    }
    …
    wolfSSL_SetHsDoneCb(ssl, myHsDoneCb, NULL);
    \endcode

    \sa HandShakeDoneCb
*/
int wolfSSL_SetHsDoneCb(WOLFSSL* ssl, HandShakeDoneCb cb, void* user_ctx);

/*!
    \ingroup IO

    \brief This function prints the statistics from the session.

    \return SSL_SUCCESS returned if the function and subroutines return without
    error. The session stats have been successfully retrieved and printed.
    \return BAD_FUNC_ARG returned if the subroutine wolfSSL_get_session_stats()
    was passed an unacceptable argument.
    \return BAD_MUTEX_E returned if there was a mutex error in the subroutine.

    \param none No parameters.

    _Example_
    \code
    // You will need to have a session object to retrieve stats from.
    if(wolfSSL_PrintSessionStats(void) != SSL_SUCCESS	){
        // Did not print session stats
    }

    \endcode

    \sa wolfSSL_get_session_stats
*/
int wolfSSL_PrintSessionStats(void);

/*!
    \ingroup IO

    \brief This function gets the statistics for the session.

    \return SSL_SUCCESS returned if the function and subroutines return without
    error. The session stats have been successfully retrieved and printed.
    \return BAD_FUNC_ARG returned if the subroutine wolfSSL_get_session_stats()
    was passed an unacceptable argument.
    \return BAD_MUTEX_E returned if there was a mutex error in the subroutine.

    \param active a word32 pointer representing the total current sessions.
    \param total a word32 pointer representing the total sessions.
    \param peak a word32 pointer representing the peak sessions.
    \param maxSessions a word32 pointer representing the maximum sessions.

    _Example_
    \code
    int wolfSSL_PrintSessionStats(void){
    …
    ret = wolfSSL_get_session_stats(&totalSessionsNow,
    &totalSessionsSeen, &peak, &maxSessions);
    …
    return ret;
    \endcode

    \sa wolfSSL_PrintSessionStats
*/
int wolfSSL_get_session_stats(unsigned int* active,
                                          unsigned int* total,
                                          unsigned int* peak,
                                          unsigned int* maxSessions);

/*!
    \ingroup TLS

    \brief This function copies the values of cr and sr then passes through to
    wc_PRF (pseudo random function) and returns that value.

    \return 0 on success
    \return BUFFER_E returned if there will be an error
    with the size of the buffer.
    \return MEMORY_E returned if a subroutine failed
    to allocate dynamic memory.

    \param ms the master secret held in the Arrays structure.
    \param msLen the length of the master secret.
    \param pms the pre-master secret held in the Arrays structure.
    \param pmsLen the length of the pre-master secret.
    \param cr the client random.
    \param sr the server random.
    \param tls1_2 signifies that the version is at least tls version 1.2.
    \param hash_type signifies the hash type.

    _Example_
    \code
    WOLFSSL* ssl;

    called in MakeTlsMasterSecret and retrieves the necessary
    information as follows:

    int MakeTlsMasterSecret(WOLFSSL* ssl){
	int ret;
	ret = wolfSSL_makeTlsMasterSecret(ssl->arrays->masterSecret, SECRET_LEN,
    ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
    ssl->arrays->clientRandom, ssl->arrays->serverRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    return ret;

    }
    \endcode

    \sa wc_PRF
    \sa MakeTlsMasterSecret
*/

int wolfSSL_MakeTlsMasterSecret(unsigned char* ms, word32 msLen,
                               const unsigned char* pms, word32 pmsLen,
                               const unsigned char* cr, const unsigned char* sr,
                               int tls1_2, int hash_type);

/*!
    \ingroup CertsKeys

    \brief An external facing wrapper to derive TLS Keys.

    \return 0 returned on success.
    \return BUFFER_E returned if the sum of labLen and
    seedLen (computes total size) exceeds the maximum size.
    \return MEMORY_E returned if the allocation of memory failed.

    \param key_data a byte pointer that is allocateded in DeriveTlsKeys
    and passed through to wc_PRF to hold the final hash.
    \param keyLen a word32 type that is derived in DeriveTlsKeys
    from the WOLFSSL structure’s specs member.
    \param ms a constant pointer type holding the master secret
    held in the arrays structure within the WOLFSSL structure.
    \param msLen a word32 type that holds the length of the
    master secret in an enumerated define, SECRET_LEN.
    \param sr a constant byte pointer to the serverRandom
    member of the arrays structure within the WOLFSSL structure.
    \param cr a constant byte pointer to the clientRandom
    member of the arrays structure within the WOLFSSL structure.
    \param tls1_2 an integer type returned from IsAtLeastTLSv1_2().
    \param hash_type an integer type held in the WOLFSSL structure.

    _Example_
    \code
    int DeriveTlsKeys(WOLFSSL* ssl){
    int ret;
    …
    ret = wolfSSL_DeriveTlsKeys(key_data, length, ssl->arrays->masterSecret,
    SECRET_LEN, ssl->arrays->clientRandom,
    IsAtLeastTLSv1_2(ssl), ssl->specs.mac_algorithm);
    …
    }
    \endcode

    \sa wc_PRF
    \sa DeriveTlsKeys
    \sa IsAtLeastTLSv1_2
*/

int wolfSSL_DeriveTlsKeys(unsigned char* key_data, word32 keyLen,
                               const unsigned char* ms, word32 msLen,
                               const unsigned char* sr, const unsigned char* cr,
                               int tls1_2, int hash_type);

/*!
    \brief wolfSSL_connect_ex() is an extension that allows
    a HandShake Callback to be set. This can be useful in
    embedded systems for debugging support when a debugger isn’t
    available and sniffing is impractical. The HandShake Callback
    will be called whether or not a handshake error occurred.
    No dynamic memory is used since the maximum number of SSL
    packets is known.  Packet names can be accessed through packetNames[].
    The connect extension also allows a Timeout Callback to be set along
    with a timeout value.  This is useful if the user doesn’t want
    to wait for the TCP stack to timeout. This extension can be called
    with either, both, or neither callbacks.

    \return SSL_SUCCESS upon success.
    \return GETTIME_ERROR will be returned if gettimeofday()
    encountered an error.
    \return SETITIMER_ERROR will be returned if setitimer()
    encountered an error.
    \return SIGACT_ERROR will be returned if sigaction() encountered an error.
    \return SSL_FATAL_ERROR will be returned if the underlying SSL_connect()
    call encountered an error.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param hsCb HandShake Callback function pointer.
    \param toCb Timeout Callback function pointer.
    \param timeout timeout value to use with the Timeout Callback.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_accept_ex
*/
int wolfSSL_connect_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                       TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

/*!
    \brief wolfSSL_accept_ex() is an extension that allows a HandShake Callback
    to be set. This can be useful in embedded systems for debugging support
    when a debugger isn’t available and sniffing is impractical. The HandShake
    Callback will be called whether or not a handshake error occurred.
    No dynamic memory is used since the maximum number of SSL packets is known.
    Packet names can be accessed through packetNames[]. The connect extension
    also allows a Timeout Callback to be set along with a timeout value.
    This is useful if the user doesn’t want to wait for the TCP stack to timeout.
    This extension can be called with either, both, or neither callbacks.

    \return SSL_SUCCESS upon success.
    \return GETTIME_ERROR will be returned if gettimeofday()
    encountered an error.
    \return SETITIMER_ERROR will be returned if setitimer()
    encountered an error.
    \return SIGACT_ERROR will be returned if sigaction() encountered an error.
    \return SSL_FATAL_ERROR will be returned if the underlying
    SSL_accept() call encountered an error.

    \param ssl pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param hsCb HandShake Callback function pointer.
    \param toCb Timeout Callback function pointer.
    \param timeout timeout value to use with the Timeout Callback.

    _Example_
    \code
    none
    \endcode

    \sa wolfSSL_connect_ex
*/
int wolfSSL_accept_ex(WOLFSSL* ssl, HandShakeCallBack hsCb,
                      TimeoutCallBack toCb, WOLFSSL_TIMEVAL timeout);

/*!
    \ingroup IO

    \brief This is used to set the internal file pointer for a BIO.

    \return SSL_SUCCESS On successfully setting file pointer.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set pair.
    \param fp file pointer to set in bio.
    \param c close file behavior flag.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_set_fp(bio, fp, BIO_CLOSE);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_get_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_set_fp(WOLFSSL_BIO *bio, XFILE fp, int c);

/*!
    \ingroup IO

    \brief This is used to get the internal file pointer for a BIO.

    \return SSL_SUCCESS On successfully getting file pointer.
    \return SSL_FAILURE If an error case was encountered.

    \param bio WOLFSSL_BIO structure to set pair.
    \param fp file pointer to set in bio.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    XFILE fp;
    int ret;
    bio  = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
    ret  = wolfSSL_BIO_get_fp(bio, &fp);
    // check ret value
    \endcode

    \sa wolfSSL_BIO_new
    \sa wolfSSL_BIO_s_mem
    \sa wolfSSL_BIO_set_fp
    \sa wolfSSL_BIO_free
*/
long wolfSSL_BIO_get_fp(WOLFSSL_BIO *bio, XFILE* fp);

/*!
    \ingroup Setup

    \brief This function checks that the private key is a match
    with the certificate being used.

    \return SSL_SUCCESS On successfully match.
    \return SSL_FAILURE If an error case was encountered.
    \return <0 All error cases other than SSL_FAILURE are negative values.

    \param ssl WOLFSSL structure to check.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;
    // create and set up ssl
    ret  = wolfSSL_check_private_key(ssl);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_check_private_key(const WOLFSSL* ssl);

/*!
    \ingroup CertsKeys

    \brief This function looks for and returns the extension index
    matching the passed in NID value.

    \return >= 0 If successful the extension index is returned.
    \return -1 If extension is not found or error is encountered.

    \param x certificate to get parse through for extension.
    \param nid extension OID to be found.
    \param lastpos start search from extension after lastpos.
                   Set to -1 initially.

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int lastPos = -1;
    int idx;

    idx = wolfSSL_X509_get_ext_by_NID(x509, NID_basic_constraints, lastPos);
    \endcode

*/
int wolfSSL_X509_get_ext_by_NID(const WOLFSSL_X509 *x, int nid, int lastpos);

/*!
    \ingroup CertsKeys

    \brief This function looks for and returns the extension
    matching the passed in NID value.

    \return pointer If successful a STACK_OF(WOLFSSL_ASN1_OBJECT)
    pointer is returned.
    \return NULL If extension is not found or error is encountered.

    \param x509 certificate to get parse through for extension.
    \param nid extension OID to be found.
    \param c if not NULL is set to -2 for multiple extensions found -1
    if not found, 0 if found and not critical and 1 if found and critical.
    \param idx if NULL return first extension matched otherwise if not
    stored in x509 start at idx.

    _Example_
    \code
    const WOLFSSL_X509* x509;
    int c;
    int idx = 0;
    STACK_OF(WOLFSSL_ASN1_OBJECT)* sk;

    sk = wolfSSL_X509_get_ext_d2i(x509, NID_basic_constraints, &c, &idx);
    //check sk for NULL and then use it. sk needs freed after done.
    \endcode

    \sa wolfSSL_sk_ASN1_OBJECT_free
*/
void* wolfSSL_X509_get_ext_d2i(const WOLFSSL_X509* x509,
                                                     int nid, int* c, int* idx);

/*!
    \ingroup CertsKeys

    \brief This function returns the hash of the DER certificate.

    \return SSL_SUCCESS On successfully creating a hash.
    \return SSL_FAILURE Returned on bad input or unsuccessful hash.

    \param x509 certificate to get the hash of.
    \param digest the hash algorithm to use.
    \param buf buffer to hold hash.
    \param len length of buffer.

    _Example_
    \code
    WOLFSSL_X509* x509;
    unsigned char buffer[64];
    unsigned int bufferSz;
    int ret;

    ret = wolfSSL_X509_digest(x509, wolfSSL_EVP_sha256(), buffer, &bufferSz);
    //check ret value
    \endcode

    \sa none
*/
int wolfSSL_X509_digest(const WOLFSSL_X509* x509,
        const WOLFSSL_EVP_MD* digest, unsigned char* buf, unsigned int* len);

/*!
    \ingroup Setup

    \brief his is used to set the certificate for WOLFSSL structure to use
    during a handshake.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL argument passed in.

    \param ssl WOLFSSL structure to set certificate in.
    \param x509 certificate to use.

    _Example_
    \code WOLFSSL* ssl;
    WOLFSSL_X509* x509
    int ret;
    // create ssl object and x509
    ret  = wolfSSL_use_certificate(ssl, x509);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup Setup

    \brief This is used to set the certificate for WOLFSSL structure
    to use during a handshake. A DER formatted buffer is expected.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL argument passed in.

    \param ssl WOLFSSL structure to set certificate in.
    \param der DER certificate to use.
    \param derSz size of the DER buffer passed in.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* der;
    int derSz;
    int ret;
    // create ssl object and set DER variables
    ret  = wolfSSL_use_certificate_ASN1(ssl, der, derSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_certificate_ASN1(WOLFSSL* ssl, const unsigned char* der,
                                 int derSz);

/*!
    \ingroup CertsKeys

    \brief This is used to set the private key for the WOLFSSL structure.

    \return SSL_SUCCESS On successful setting argument.
    \return SSL_FAILURE If a NULL ssl passed in. All error
    cases will be negative values.

    \param ssl WOLFSSL structure to set argument in.
    \param pkey private key to use.

    _Example_
    \code
    WOLFSSL* ssl;
    WOLFSSL_EVP_PKEY* pkey;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey(ssl, pkey);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_use_PrivateKey(WOLFSSL* ssl, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys

    \brief This is used to set the private key for the WOLFSSL
    structure. A DER formatted key buffer is expected.

    \return SSL_SUCCESS On successful setting parsing and
    setting the private key.
    \return SSL_FAILURE If an NULL ssl passed in. All error cases
    will be negative values.

    \param pri type of private key.
    \param ssl WOLFSSL structure to set argument in.
    \param der buffer holding DER key.
    \param derSz size of der buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up private key
    ret  = wolfSSL_use_PrivateKey_ASN1(1, ssl, pkey, pkeySz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_PrivateKey_ASN1(int pri, WOLFSSL* ssl,
                        const unsigned char* der, long derSz);

/*!
    \ingroup CertsKeys

    \brief This is used to set the private key for the WOLFSSL
    structure. A DER formatted RSA key buffer is expected.

    \return SSL_SUCCESS On successful setting parsing and setting
    the private key.
    \return SSL_FAILURE If an NULL ssl passed in. All error cases
    will be negative values.

    \param ssl WOLFSSL structure to set argument in.
    \param der buffer holding DER key.
    \param derSz size of der buffer.

    _Example_
    \code
    WOLFSSL* ssl;
    unsigned char* pkey;
    long pkeySz;
    int ret;
    // create ssl object and set up RSA private key
    ret  = wolfSSL_use_RSAPrivateKey_ASN1(ssl, pkey, pkeySz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
    \sa wolfSSL_use_PrivateKey
*/
int wolfSSL_use_RSAPrivateKey_ASN1(WOLFSSL* ssl, unsigned char* der,
                                                                long derSz);

/*!
    \ingroup CertsKeys

    \brief This function duplicates the parameters in dsa to a
    newly created WOLFSSL_DH structure.

    \return WOLFSSL_DH If duplicated returns WOLFSSL_DH structure
    \return NULL upon failure

    \param dsa WOLFSSL_DSA structure to duplicate.

    _Example_
    \code
    WOLFSSL_DH* dh;
    WOLFSSL_DSA* dsa;
    // set up dsa
    dh = wolfSSL_DSA_dup_DH(dsa);

    // check dh is not null
    \endcode

    \sa none
*/
WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *r);

/*!
    \ingroup Setup

    \brief This is used to get the master key after completing a handshake.

    \return >0 On successfully getting data returns a value greater than 0
    \return 0  If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer
    size needed is returned

    \param ses WOLFSSL_SESSION structure to get master secret buffer from.
    \param out buffer to hold data.
    \param outSz size of out buffer passed in. (if 0 function will
    return max buffer size needed)

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret(ses, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_SESSION_get_master_secret(ses, buffer, bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key(const WOLFSSL_SESSION* ses,
        unsigned char* out, int outSz);

/*!
    \ingroup Setup

    \brief This is used to get the master secret key length.

    \return size Returns master secret key size.

    \param ses WOLFSSL_SESSION structure to get master secret buffer from.

    _Example_
    \code
    WOLFSSL_SESSION ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    // complete handshake and get session structure
    bufferSz  = wolfSSL_SESSION_get_master_secret_length(ses);
    buffer = malloc(bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int wolfSSL_SESSION_get_master_key_length(const WOLFSSL_SESSION* ses);

/*!
    \ingroup Setup

    \brief This is a setter function for the WOLFSSL_X509_STORE
    structure in ctx.

    \return none No return.

    \param ctx pointer to the WOLFSSL_CTX structure for setting
    cert store pointer.
    \param str pointer to the WOLFSSL_X509_STORE to set in ctx.

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx and st
    st = wolfSSL_CTX_set_cert_store(ctx, st);
    //use st
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void wolfSSL_CTX_set_cert_store(WOLFSSL_CTX* ctx,
                                                       WOLFSSL_X509_STORE* str);

/*!
    \ingroup CertsKeys

    \brief This function get the DER buffer from bio and converts it
    to a WOLFSSL_X509 structure.

    \return pointer returns a WOLFSSL_X509 structure pointer on success.
    \return Null returns NULL on failure

    \param bio pointer to the WOLFSSL_BIO structure that has the DER
    certificate buffer.
    \param x509 pointer that get set to new WOLFSSL_X509 structure created.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // load DER into bio
    x509 = wolfSSL_d2i_X509_bio(bio, NULL);
    Or
    wolfSSL_d2i_X509_bio(bio, &x509);
    // use x509 returned (check for NULL)
    \endcode

    \sa none
*/
WOLFSSL_X509* wolfSSL_d2i_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509** x509);

/*!
    \ingroup Setup

    \brief This is a getter function for the WOLFSSL_X509_STORE
    structure in ctx.

    \return WOLFSSL_X509_STORE* On successfully getting the pointer.
    \return NULL Returned if NULL arguments are passed in.

    \param ctx pointer to the WOLFSSL_CTX structure for getting cert
    store pointer.

    _Example_
    \code
    WOLFSSL_CTX ctx;
    WOLFSSL_X509_STORE* st;
    // setup ctx
    st = wolfSSL_CTX_get_cert_store(ctx);
    //use st
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
    \sa wolfSSL_CTX_set_cert_store
*/
WOLFSSL_X509_STORE* wolfSSL_CTX_get_cert_store(WOLFSSL_CTX* ctx);

/*!
    \ingroup IO

    \brief Gets the number of pending bytes to read. If BIO type is BIO_BIO
    then is the number to read from pair. If BIO contains an SSL object then
    is pending data from SSL object (wolfSSL_pending(ssl)). If is BIO_MEMORY
    type then returns the size of memory buffer.

    \return >=0 number of pending bytes.

    \param bio pointer to the WOLFSSL_BIO structure that has already
    been created.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    int pending;
    bio = wolfSSL_BIO_new();
    …
    pending = wolfSSL_BIO_ctrl_pending(bio);
    \endcode

    \sa wolfSSL_BIO_make_bio_pair
    \sa wolfSSL_BIO_new
*/
size_t wolfSSL_BIO_ctrl_pending(WOLFSSL_BIO *b);

/*!
    \ingroup Setup

    \brief This is used to get the random data sent by the server
    during the handshake.

    \return >0 On successfully getting data returns a value greater than 0
    \return 0  If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer size
    needed is returned

    \param ssl WOLFSSL structure to get clients random data buffer from.
    \param out buffer to hold random data.
    \param outSz size of out buffer passed in. (if 0 function will return max
    buffer size needed)

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_server_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_server_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_server_random(const WOLFSSL *ssl,
                                             unsigned char *out, size_t outlen);

/*!
    \ingroup Setup

    \brief This is used to get the random data sent by the client during
    the handshake.

    \return >0 On successfully getting data returns a value greater than 0
    \return 0 If no random data buffer or an error state returns 0
    \return max If outSz passed in is 0 then the maximum buffer size needed
    is returned

    \param ssl WOLFSSL structure to get clients random data buffer from.
    \param out buffer to hold random data.
    \param outSz size of out buffer passed in. (if 0 function will return max
    buffer size needed)

    _Example_
    \code
    WOLFSSL ssl;
    unsigned char* buffer;
    size_t bufferSz;
    size_t ret;
    bufferSz  = wolfSSL_get_client_random(ssl, NULL, 0);
    buffer = malloc(bufferSz);
    ret  = wolfSSL_get_client_random(ssl, buffer, bufferSz);
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
size_t wolfSSL_get_client_random(const WOLFSSL* ssl,
                                              unsigned char* out, size_t outSz);

/*!
    \ingroup Setup

    \brief This is a getter function for the password callback set in ctx.

    \return func On success returns the callback function.
    \return NULL If ctx is NULL then NULL is returned.

    \param ctx WOLFSSL_CTX structure to get call back from.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    wc_pem_password_cb cb;
    // setup ctx
    cb = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use cb
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
wc_pem_password_cb* wolfSSL_CTX_get_default_passwd_cb(WOLFSSL_CTX*
                                                                  ctx);

/*!
    \ingroup Setup

    \brief This is a getter function for the password callback user
    data set in ctx.

    \return pointer On success returns the user data pointer.
    \return NULL If ctx is NULL then NULL is returned.

    \param ctx WOLFSSL_CTX structure to get user data from.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    void* data;
    // setup ctx
    data = wolfSSL_CTX_get_default_passwd_cb(ctx);
    //use data
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
void *wolfSSL_CTX_get_default_passwd_cb_userdata(WOLFSSL_CTX *ctx);

/*!
    \ingroup CertsKeys

    \brief This function behaves the same as wolfSSL_PEM_read_bio_X509.
    AUX signifies containing extra information such as trusted/rejected use
    cases and friendly name for human readability.

    \return WOLFSSL_X509 on successfully parsing the PEM buffer a WOLFSSL_X509
    structure is returned.
    \return Null if failed to parse PEM buffer.

    \param bp WOLFSSL_BIO structure to get PEM buffer from.
    \param x if setting WOLFSSL_X509 by function side effect.
    \param cb password callback.
    \param u NULL terminated user password.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_X509* x509;
    // setup bio
    X509 = wolfSSL_PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    //check x509 is not null and then use it
    \endcode

    \sa wolfSSL_PEM_read_bio_X509
*/
WOLFSSL_X509 *wolfSSL_PEM_read_bio_X509_AUX
        (WOLFSSL_BIO *bp, WOLFSSL_X509 **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup CertsKeys

    \brief Initializes the WOLFSSL_CTX structure’s dh member with the
    Diffie-Hellman parameters.

    \return SSL_SUCCESS returned if the function executed successfully.
    \return BAD_FUNC_ARG returned if the ctx or dh structures are NULL.
    \return SSL_FATAL_ERROR returned if there was an error setting a
    structure value.
    \return MEMORY_E returned if their was a failure to allocate memory.

    \param ctx a pointer to a WOLFSSL_CTX structure, created using
    wolfSSL_CTX_new().
    \param dh a pointer to a WOLFSSL_DH structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL_DH* dh;
    …
    return wolfSSL_CTX_set_tmp_dh(ctx, dh);
    \endcode

    \sa wolfSSL_BN_bn2bin
*/
long wolfSSL_CTX_set_tmp_dh(WOLFSSL_CTX* ctx, WOLFSSL_DH* dh);

/*!
    \ingroup CertsKeys

    \brief This function get the DSA parameters from a PEM buffer in bio.

    \return WOLFSSL_DSA on successfully parsing the PEM buffer a WOLFSSL_DSA
    structure is created and returned.
    \return Null if failed to parse PEM buffer.

    \param bio pointer to the WOLFSSL_BIO structure for getting PEM
    memory pointer.
    \param x pointer to be set to new WOLFSSL_DSA structure.
    \param cb password callback function.
    \param u null terminated password string.

    _Example_
    \code
    WOLFSSL_BIO* bio;
    WOLFSSL_DSA* dsa;
    // setup bio
    dsa = wolfSSL_PEM_read_bio_DSAparams(bio, NULL, NULL, NULL);

    // check dsa is not NULL and then use dsa
    \endcode

    \sa none
*/
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp,
    WOLFSSL_DSA **x, wc_pem_password_cb *cb, void *u);

/*!
    \ingroup Debug

    \brief This function returns the absolute value of the last error from
    WOLFSSL_ERROR encountered.

    \return error Returns absolute value of last error.

    \param none No parameters.

    _Example_
    \code
    unsigned long err;
    ...
    err = wolfSSL_ERR_peek_last_error();
    // inspect err value
    \endcode

    \sa wolfSSL_ERR_print_errors_fp
*/
unsigned long wolfSSL_ERR_peek_last_error(void);

/*!
    \ingroup CertsKeys

    \brief This function gets the peer’s certificate chain.

    \return pointer returns a pointer to the peer’s Certificate stack.
    \return NULL returned if no peer certificate.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( method );
    WOLFSSL* ssl = wolfSSL_new(ctx);
    ...
    wolfSSL_connect(ssl);
    STACK_OF(WOLFSSL_X509)* chain = wolfSSL_get_peer_cert_chain(ssl);
    ifchain){
	    // You have a pointer to the peer certificate chain
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
    \sa wolfSSL_X509_get_isCA
*/
WOLF_STACK_OF(WOLFSSL_X509)* wolfSSL_get_peer_cert_chain(const WOLFSSL*);

/*!
    \ingroup Setup

    \brief This function resets option bits of WOLFSSL_CTX object.

    \return option new option bits

    \param ctx pointer to the SSL context.

    _Example_
    \code
    WOLFSSL_CTX* ctx = 0;
    ...
    wolfSSL_CTX_clear_options(ctx, SSL_OP_NO_TLSv1);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_new
    \sa wolfSSL_free
*/
long wolfSSL_CTX_clear_options(WOLFSSL_CTX* ctx, long opt);

/*!
    \ingroup IO

    \brief This function sets the jObjectRef member of the WOLFSSL structure.

    \return SSL_SUCCESS returned if jObjectRef is properly set to objPtr.
    \return SSL_FAILURE returned if the function did not properly execute and
    jObjectRef is not set.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param objPtr a void pointer that will be set to jObjectRef.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = WOLFSSL_new();
    void* objPtr = &obj;
    ...
    if(wolfSSL_set_jobject(ssl, objPtr)){
    	// The success case
    }
    \endcode

    \sa wolfSSL_get_jobject
*/
int wolfSSL_set_jobject(WOLFSSL* ssl, void* objPtr);

/*!
    \ingroup IO

    \brief This function returns the jObjectRef member of the WOLFSSL structure.

    \return value If the WOLFSSL struct is not NULL, the function returns the
    jObjectRef value.
    \return NULL returned if the WOLFSSL struct is NULL.

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    WOLFSSL* ssl = wolfSSL(ctx);
    ...
    void* jobject = wolfSSL_get_jobject(ssl);

    if(jobject != NULL){
    	// Success case
    }
    \endcode

    \sa wolfSSL_set_jobject
*/
void* wolfSSL_get_jobject(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets a callback in the ssl. The callback is to
    observe handshake messages. NULL value of cb resets the callback.

    \return SSL_SUCCESS On success.
    \return SSL_FAILURE If an NULL ssl passed in.

    \param ssl WOLFSSL structure to set callback argument.

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    \endcode

    \sa wolfSSL_set_msg_callback_arg
*/
int wolfSSL_set_msg_callback(WOLFSSL *ssl, SSL_Msg_Cb cb);

/*!
    \ingroup Setup

    \brief This function sets associated callback context value in the ssl.
    The value is handed over to the callback argument.

    \return none No return.

    \param ssl WOLFSSL structure to set callback argument.

    _Example_
    \code
    static cb(int write_p, int version, int content_type,
    const void *buf, size_t len, WOLFSSL *ssl, void *arg)
    …
    WOLFSSL* ssl;
    ret  = wolfSSL_set_msg_callback(ssl, cb);
    // check ret
    wolfSSL_set_msg_callback(ssl, arg);
    \endcode

    \sa wolfSSL_set_msg_callback
*/
int wolfSSL_set_msg_callback_arg(WOLFSSL *ssl, void* arg);

/*!
    \ingroup CertsKeys

    \brief This function returns the next, if any, altname from the peer certificate.

    \return NULL if there is not a next altname.
    \return cert->altNamesNext->name from the WOLFSSL_X509 structure that is a
    string value from the altName list is returned if it exists.

    \param cert a pointer to the wolfSSL_X509 structure.

    _Example_
    \code
    WOLFSSL_X509 x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), NULL,
                                                        DYNAMIC_TYPE_X509);
    …
    int x509NextAltName = wolfSSL_X509_get_next_altname(x509);
    if(x509NextAltName == NULL){
            //There isn’t another alt name
    }
    \endcode

    \sa wolfSSL_X509_get_issuer_name
    \sa wolfSSL_X509_get_subject_name
*/
char* wolfSSL_X509_get_next_altname(WOLFSSL_X509*);

/*!
    \ingroup CertsKeys

    \brief The function checks to see if x509 is NULL and if it’s not, it
    returns the notBefore member of the x509 struct.

    \return pointer to struct with ASN1_TIME to the notBefore
        member of the x509 struct.
    \return NULL the function returns NULL if the x509 structure is NULL.

    \param x509 a pointer to the WOLFSSL_X509 struct.

    _Example_
    \code
    WOLFSSL_X509* x509 = (WOLFSSL_X509)XMALLOC(sizeof(WOLFSSL_X509), NULL,
    DYNAMIC_TYPE_X509) ;
    …
    const WOLFSSL_ASN1_TIME* notAfter = wolfSSL_X509_get_notBefore(x509);
    if(notAfter == NULL){
            //The x509 object was NULL
    }
    \endcode

    \sa wolfSSL_X509_get_notAfter
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_get_notBefore(WOLFSSL_X509*);

/*!
    \ingroup IO

    \brief This function is called on the client side and initiates an SSL/TLS
    handshake with a server.  When this function is called, the underlying
    communication channel has already been set up.
    wolfSSL_connect() works with both blocking and non-blocking I/O.  When the
    underlying I/O is non-blocking, wolfSSL_connect() will return when the
    underlying I/O could not satisfy the needs of wolfSSL_connect to continue
    the handshake.  In this case, a call to wolfSSL_get_error() will yield
    either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.  The calling process
    must then repeat the call to wolfSSL_connect() when the underlying I/O is
    ready and wolfSSL will pick up where it left off. When using a non-blocking
    socket, nothing needs to be done, but select() can be used to check for the
    required condition.
    If the underlying I/O is blocking, wolfSSL_connect() will only return once
    the handshake has been finished or an error occurred.
    wolfSSL takes a different approach to certificate verification than OpenSSL
    does.  The default policy for the client is to verify the server, this
    means that if you don't load CAs to verify the server you'll get a connect
    error, unable to verify (-155).  It you want to mimic OpenSSL behavior of
    having SSL_connect succeed even if verifying the server fails and reducing
    security you can do this by calling:
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); before calling SSL_new();
    Though it's not recommended.

    \return SSL_SUCCESS If successful.
    \return SSL_FATAL_ERROR will be returned if an error occurred.  To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...
    ret = wolfSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
    err = wolfSSL_get_error(ssl, ret);
    printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_accept
*/
int  wolfSSL_connect(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is called on the server side to indicate that a
    HelloRetryRequest message must contain a Cookie and, in case of using
    protocol DTLS v1.3, that the handshake will always include a cookie
    exchange. Please note that when using protocol DTLS v1.3, the cookie
    exchange is enabled by default. The Cookie holds a hash of the current
    transcript so that another server process can handle the ClientHello in
    reply.  The secret is used when generating the integrity check on the Cookie
    data.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] secret a pointer to a buffer holding the secret.
    Passing NULL indicates to generate a new random secret.
    \param [in] secretSz Size of the secret in bytes.
    Passing 0 indicates to use the default size: WC_SHA256_DIGEST_SIZE (or WC_SHA_DIGEST_SIZE when SHA-256 not available).

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a client.
    \return WOLFSSL_SUCCESS if successful.
    \return MEMORY_ERROR if allocating dynamic memory for storing secret failed.
    \return Another -ve value on internal error.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    char secret[32];
    ...
    ret = wolfSSL__send_hrr_cookie(ssl, secret, sizeof(secret));
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set use of Cookie and secret
    }
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_disable_hrr_cookie
*/
int  wolfSSL_send_hrr_cookie(WOLFSSL* ssl,
    const unsigned char* secret, unsigned int secretSz);

/*!

    \ingroup Setup

    \brief This function is called on the server side to indicate that a
    HelloRetryRequest message must NOT contain a Cookie and that, if using
    protocol DTLS v1.3, a cookie exchange will not be included in the
    handshake. Please note that not doing a cookie exchange when using protocol
    DTLS v1.3 can make the server susceptible to DoS/Amplification attacks.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return WOLFSSL_SUCCESS if successful
    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3
    \return SIDE_ERROR if invoked on client

    \sa wolfSSL_send_hrr_cookie
*/
int wolfSSL_disable_hrr_cookie(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is called on the server to stop it from sending
    a resumption session ticket once the handshake is complete.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a client.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_ticket_TLSv13(ctx);
    if (ret != 0) {
        // failed to set no ticket
    }
    \endcode

    \sa wolfSSL_no_ticket_TLSv13
*/
int  wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is called on the server to stop it from sending
    a resumption session ticket once the handshake is complete.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a client.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_ticket_TLSv13(ssl);
    if (ret != 0) {
        // failed to set no ticket
    }
    \endcode

    \sa wolfSSL_CTX_no_ticket_TLSv13
*/
int  wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 wolfSSL context to disallow
    Diffie-Hellman (DH) style key exchanges when handshakes are using
    pre-shared keys for authentication.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_no_dhe_psk(ctx);
    if (ret != 0) {
        // failed to set no DHE for PSK handshakes
    }
    \endcode

    \sa wolfSSL_no_dhe_psk
*/
int  wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 client or server wolfSSL to
    disallow Diffie-Hellman (DH) style key exchanges when handshakes are using
    pre-shared keys for authentication.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_no_dhe_psk(ssl);
    if (ret != 0) {
        // failed to set no DHE for PSK handshakes
    }
    \endcode

    \sa wolfSSL_CTX_no_dhe_psk
*/
int  wolfSSL_no_dhe_psk(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function is called on a TLS v1.3 client or server wolfSSL to
    force the rollover of keys. A KeyUpdate message is sent to the peer and
    new keys are calculated for encryption. The peer will send back a KeyUpdate
    message and the new decryption keys will then be calculated.
    This function can only be called after a handshake has been completed.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return WANT_WRITE if the writing is not ready.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_update_keys(ssl);
    if (ret == WANT_WRITE) {
        // need to call again when I/O ready
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // failed to send key update
    }
    \endcode

    \sa wolfSSL_write
*/
int  wolfSSL_update_keys(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function is called on a TLS v1.3 client or server wolfSSL to
    determine whether a rollover of keys is in progress. When
    wolfSSL_update_keys() is called, a KeyUpdate message is sent and the
    encryption key is updated. The decryption key is updated when the response
    is received.

    \param [in] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [out] required   0 when no key update response required. 1 when no key update response required.

    \return 0 on successful.
    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int required;
    ...
    ret = wolfSSL_key_update_response(ssl, &required);
    if (ret != 0) {
        // bad parameters
    }
    if (required) {
        // encrypt Key updated, awaiting response to change decrypt key
    }
    \endcode

    \sa wolfSSL_update_keys
*/
int  wolfSSL_key_update_response(WOLFSSL* ssl, int* required);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 client wolfSSL context to allow
    a client certificate to be sent post handshake upon request from server.
    This is useful when connecting to a web server that has some pages that
    require client authentication and others that don't.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a server.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ctx);
    if (ret != 0) {
        // failed to allow post handshake authentication
    }
    \endcode

    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_CTX_allow_post_handshake_auth(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief This function is called on a TLS v1.3 client wolfSSL to allow
    a client certificate to be sent post handshake upon request from server.
    A Post-Handshake Client Authentication extension is sent in the ClientHello.
    This is useful when connecting to a web server that has some pages that
    require client authentication and others that don't.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a server.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_allow_post_handshake_auth(ssl);
    if (ret != 0) {
        // failed to allow post handshake authentication
    }
    \endcode

    \sa wolfSSL_CTX_allow_post_handshake_auth
    \sa wolfSSL_request_certificate
*/
int  wolfSSL_allow_post_handshake_auth(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function requests a client certificate from the TLS v1.3 client.
    This is useful when a web server is serving some pages that require client
    authentication and others that don't.
    A maximum of 256 requests can be sent on a connection.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return WANT_WRITE if the writing is not ready.
    \return SIDE_ERROR if called with a client.
    \return NOT_READY_ERROR if called when the handshake is not finished.
    \return POST_HAND_AUTH_ERROR if posthandshake authentication is disallowed.
    \return MEMORY_E if dynamic memory allocation fails.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_request_certificate(ssl);
    if (ret == WANT_WRITE) {
        // need to call again when I/O ready
    }
    else if (ret != WOLFSSL_SUCCESS) {
        // failed to request a client certificate
    }
    \endcode

    \sa wolfSSL_allow_post_handshake_auth
    \sa wolfSSL_write
*/
int  wolfSSL_request_certificate(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the list of signature algorithms to allow on a
    wolfSSL context in order of preference. The list is a null-terminated text
    string and a colon-delimited list, where each element is of the form
    "<public-key>+<digest>" (for example "RSA-PSS+SHA256:ECDSA+SHA384"). The
    Edwards-curve algorithms "ED25519" and "ED448" are written without a digest
    suffix, since the hash is implied by the algorithm. The previous list
    stored in the context is replaced.

    Recognized public-key tokens and digest tokens, together with the build
    options that must be enabled for each token to be accepted, are listed in
    the tables below.

    Public-key tokens:

    | Token             | Required build option                              |
    | ----------------- | -------------------------------------------------- |
    | RSA               | !NO_RSA                                            |
    | RSA-PSS  /  PSS   | !NO_RSA and WC_RSA_PSS                             |
    | ECDSA             | HAVE_ECC                                           |
    | ED25519           | HAVE_ED25519 (no digest suffix)                    |
    | ED448             | HAVE_ED448   (no digest suffix)                    |
    | DSA               | !NO_DSA                                            |
    | SM2               | WOLFSSL_SM2 and WOLFSSL_SM3 (digest is SM3)        |

    Digest tokens:

    | Token   | Required build option                                        |
    | ------- | ------------------------------------------------------------ |
    | SHA256  | !NO_SHA256                                                   |
    | SHA384  | WOLFSSL_SHA384                                               |
    | SHA512  | WOLFSSL_SHA512                                               |
    | SHA224  | WOLFSSL_SHA224                                               |
    | SM3     | WOLFSSL_SM3                                                  |
    | SHA1    | !NO_SHA, plus !NO_OLD_TLS or WOLFSSL_ALLOW_TLS_SHA1          |

    Notes for TLS 1.3: per RFC 8446, RSA PKCS#1 v1.5, DSA, SHA-1, and SHA-224
    cannot be used as handshake signatures and will be filtered out at
    negotiation time even if listed. Specifying "RSA-PSS+SHAxxx" causes both
    the rsa_pss_rsae_shaxxx and rsa_pss_pss_shaxxx schemes to be added.
    Brainpool ECDSA signature schemes (RFC 8734) cannot be selected through
    this string interface; they are negotiated automatically when
    HAVE_ECC_BRAINPOOL is enabled.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created with
    wolfSSL_CTX_new().
    \param [in] list a colon-delimited list of "<public-key>+<digest>"
    elements (or "ED25519" / "ED448" without a digest).

    \return WOLFSSL_SUCCESS if successful.
    \return WOLFSSL_FAILURE if a pointer parameter is NULL, allocation of the
    suites structure fails, or any token in the list is not recognized or not
    supported by the current build.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    const char* list = "RSA-PSS+SHA256:ECDSA+SHA384:ED25519";
    ...
    ret = wolfSSL_CTX_set1_sigalgs_list(ctx, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set signature algorithm list
    }
    \endcode

    \sa wolfSSL_set1_sigalgs_list
    \sa wolfSSL_CTX_set1_groups_list
*/
int  wolfSSL_CTX_set1_sigalgs_list(WOLFSSL_CTX* ctx, const char* list);

/*!
    \ingroup Setup

    \brief This function sets the list of signature algorithms to allow on a
    wolfSSL session in order of preference. The list format and the set of
    recognized public-key and digest tokens are identical to those documented
    for wolfSSL_CTX_set1_sigalgs_list(); refer to that function for the full
    token tables and TLS 1.3 caveats. The previous list stored in the session
    is replaced.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using
    wolfSSL_new().
    \param [in] list a colon-delimited list of "<public-key>+<digest>"
    elements (or "ED25519" / "ED448" without a digest).

    \return WOLFSSL_SUCCESS if successful.
    \return WOLFSSL_FAILURE if a pointer parameter is NULL, allocation of the
    suites structure fails, or any token in the list is not recognized or not
    supported by the current build.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    const char* list = "RSA-PSS+SHA256:ECDSA+SHA384:ED25519";
    ...
    ret = wolfSSL_set1_sigalgs_list(ssl, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set signature algorithm list
    }
    \endcode

    \sa wolfSSL_CTX_set1_sigalgs_list
    \sa wolfSSL_set1_groups_list
*/
int  wolfSSL_set1_sigalgs_list(WOLFSSL* ssl, const char* list);

/*!
    \ingroup Setup

    \brief This function sets the list of key-exchange groups (named elliptic
    curves and KEMs) to allow on a wolfSSL context in order of preference. The
    list is a null-terminated, colon-delimited text string of group names, for
    example "P-384:P-256:X25519". Call this function to set the key-exchange
    parameters used with TLS v1.3 connections (the function is compiled in
    only when HAVE_ECC, WOLFSSL_TLS13, and HAVE_SUPPORTED_CURVES are defined).

    Recognized group names and the build options each one requires are listed
    below. Names are matched case-sensitively against the table.

    NIST / SEC curves (require HAVE_ECC):

    | Name      | Curve / Group                                                |
    | --------- | ------------------------------------------------------------ |
    | P-160     | secp160r1                                                    |
    | P-160-2   | secp160r2                                                    |
    | P-192     | secp192r1 (prime192v1)                                       |
    | P-224     | secp224r1                                                    |
    | P-256     | secp256r1 (prime256v1) — also accepted as "prime256v1" / "secp256r1" |
    | P-384     | secp384r1 — also accepted as "secp384r1"                     |
    | P-521     | secp521r1 — also accepted as "secp521r1"                     |
    | K-160     | secp160k1                                                    |
    | K-192     | secp192k1                                                    |
    | K-224     | secp224k1                                                    |
    | K-256     | secp256k1                                                    |

    Brainpool curves (require HAVE_ECC plus WOLFSSL_CUSTOM_CURVES and
    HAVE_ECC_BRAINPOOL — typically enabled by --enable-ecccustcurves=all):

    | Name  | Curve              |
    | ----- | ------------------ |
    | B-256 | brainpoolP256r1    |
    | B-384 | brainpoolP384r1    |
    | B-512 | brainpoolP512r1    |

    Edwards / Montgomery curves:

    | Name   | Required build option |
    | ------ | --------------------- |
    | X25519 | HAVE_CURVE25519       |
    | X448   | HAVE_CURVE448         |

    SM2 (requires WOLFSSL_SM2):

    | Name      | Group           |
    | --------- | --------------- |
    | SM2       | sm2p256v1       |
    | sm2p256v1 | sm2p256v1 (alias) |

    ML-KEM (post-quantum) groups (require WOLFSSL_HAVE_MLKEM and
    !WOLFSSL_NO_ML_KEM):

    | Name        |
    | ----------- |
    | ML_KEM_512  |
    | ML_KEM_768  |
    | ML_KEM_1024 |

    ML-KEM hybrid groups additionally require HAVE_ECC together with either
    WOLFSSL_WC_MLKEM or HAVE_LIBOQS, and WOLFSSL_PQC_HYBRIDS (or
    WOLFSSL_EXTRA_PQC_HYBRIDS for the "extra" set):

    | Name                | Hybrid flag set            |
    | ------------------- | -------------------------- |
    | SecP256r1MLKEM768   | WOLFSSL_PQC_HYBRIDS        |
    | SecP384r1MLKEM1024  | WOLFSSL_PQC_HYBRIDS        |
    | X25519MLKEM768      | WOLFSSL_PQC_HYBRIDS        |
    | SecP256r1MLKEM512   | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | SecP384r1MLKEM768   | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | SecP521r1MLKEM1024  | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | X25519MLKEM512      | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | X448MLKEM768        | WOLFSSL_EXTRA_PQC_HYBRIDS  |

    Legacy Kyber groups (require WOLFSSL_MLKEM_KYBER; hybrids additionally
    require HAVE_ECC together with WOLFSSL_WC_MLKEM or HAVE_LIBOQS):

    | Name                  |
    | --------------------- |
    | KYBER_LEVEL1          |
    | KYBER_LEVEL3          |
    | KYBER_LEVEL5          |
    | P256_KYBER_LEVEL1     |
    | P256_KYBER_LEVEL3     |
    | P384_KYBER_LEVEL3     |
    | P521_KYBER_LEVEL5     |
    | X25519_KYBER_LEVEL1   |
    | X25519_KYBER_LEVEL3   |
    | X448_KYBER_LEVEL3     |

    In addition to the names above, when HAVE_FIPS and HAVE_SELFTEST are not
    defined, any curve name registered with wolfCrypt (looked up via
    wc_ecc_get_curve_idx_from_name(), e.g. "brainpoolP256r1") is also
    accepted.

    The order of the names in the list is preserved and used as the local
    preference order for KeyShare selection in TLS 1.3.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] list a string that is a colon-delimited list of key-exchange
    group names.

    \return WOLFSSL_FAILURE if pointer parameters are NULL, there are more than
    WOLFSSL_MAX_GROUP_COUNT groups, a group name is not recognized or not
    using TLS v1.3.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ctx, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_CTX_set1_groups_list(WOLFSSL_CTX *ctx, const char *list);

/*!
    \ingroup Setup

    \brief This function sets the list of key-exchange groups (named elliptic
    curves and KEMs) to allow on a wolfSSL session in order of preference. The
    list format and the set of recognized group names are identical to those
    documented for wolfSSL_CTX_set1_groups_list(); refer to that function for
    the full token tables and required build options.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] list a string that is a colon separated list of key exchange
    groups.

    \return WOLFSSL_FAILURE if pointer parameters are NULL, there are more than
    WOLFSSL_MAX_GROUP_COUNT groups, a group name is not recognized or not
    using TLS v1.3.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    const char* list = "P-384:P-256";
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl, list);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_set1_groups_list(WOLFSSL *ssl, const char *list);

/*!
    \ingroup TLS

    \brief This function returns the key exchange group the client prefers to
    use in the TLS v1.3 handshake.
    Call this function to after a handshake is complete to determine which
    group the server prefers so that this information can be used in future
    connections to pre-generate a key pair for key exchange.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return SIDE_ERROR if called with a server.
    \return NOT_READY_ERROR if called before handshake is complete.
    \return Group identifier if successful.

    _Example_
    \code
    int ret;
    int group;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_CTX_set1_groups_list(ssl)
    if (ret < 0) {
        // failed to get group
    }
    group = ret;
    \endcode

    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
*/
int  wolfSSL_preferred_group(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the list of key-exchange groups (named elliptic
    curves and KEMs) to allow on a wolfSSL context in order of preference. The
    list is an array of named-group identifiers (see the table below) and
    \p count is the number of identifiers in the array. Use this function to
    set the key-exchange parameters used by TLS v1.3 connections; the order
    of the array becomes the local KeyShare preference order.

    Recognized identifiers and the build options each one requires are listed
    below. The identifiers are defined in the anonymous enum in
    \<wolfssl/ssl.h\>.

    NIST / SEC curves (require HAVE_ECC):

    | Identifier                | Curve / Group                        |
    | ------------------------- | ------------------------------------ |
    | WOLFSSL_ECC_SECP160K1     | secp160k1                            |
    | WOLFSSL_ECC_SECP160R1     | secp160r1                            |
    | WOLFSSL_ECC_SECP160R2     | secp160r2                            |
    | WOLFSSL_ECC_SECP192K1     | secp192k1                            |
    | WOLFSSL_ECC_SECP192R1     | secp192r1 (prime192v1)               |
    | WOLFSSL_ECC_SECP224K1     | secp224k1                            |
    | WOLFSSL_ECC_SECP224R1     | secp224r1                            |
    | WOLFSSL_ECC_SECP256K1     | secp256k1                            |
    | WOLFSSL_ECC_SECP256R1     | secp256r1 (prime256v1)               |
    | WOLFSSL_ECC_SECP384R1     | secp384r1                            |
    | WOLFSSL_ECC_SECP521R1     | secp521r1                            |

    Brainpool curves (require HAVE_ECC plus WOLFSSL_CUSTOM_CURVES and
    HAVE_ECC_BRAINPOOL — typically enabled by --enable-ecccustcurves=all):

    | Identifier                          | Curve            | Notes |
    | ----------------------------------- | ---------------- | ----- |
    | WOLFSSL_ECC_BRAINPOOLP256R1         | brainpoolP256r1  | TLS 1.2 group ID 26 |
    | WOLFSSL_ECC_BRAINPOOLP384R1         | brainpoolP384r1  | TLS 1.2 group ID 27 |
    | WOLFSSL_ECC_BRAINPOOLP512R1         | brainpoolP512r1  | TLS 1.2 group ID 28 |
    | WOLFSSL_ECC_BRAINPOOLP256R1TLS13    | brainpoolP256r1  | RFC 8734 TLS 1.3 ID |
    | WOLFSSL_ECC_BRAINPOOLP384R1TLS13    | brainpoolP384r1  | RFC 8734 TLS 1.3 ID |
    | WOLFSSL_ECC_BRAINPOOLP512R1TLS13    | brainpoolP512r1  | RFC 8734 TLS 1.3 ID |

    Edwards / Montgomery curves:

    | Identifier        | Required build option |
    | ----------------- | --------------------- |
    | WOLFSSL_ECC_X25519| HAVE_CURVE25519       |
    | WOLFSSL_ECC_X448  | HAVE_CURVE448         |

    SM2 (requires WOLFSSL_SM2):

    | Identifier             | Group     |
    | ---------------------- | --------- |
    | WOLFSSL_ECC_SM2P256V1  | sm2p256v1 |

    Finite-field DH (RFC 7919) groups (require HAVE_FFDHE and the matching
    HAVE_FFDHE_NNNN macro for each size):

    | Identifier         | Group       |
    | ------------------ | ----------- |
    | WOLFSSL_FFDHE_2048 | ffdhe2048   |
    | WOLFSSL_FFDHE_3072 | ffdhe3072   |
    | WOLFSSL_FFDHE_4096 | ffdhe4096   |
    | WOLFSSL_FFDHE_6144 | ffdhe6144   |
    | WOLFSSL_FFDHE_8192 | ffdhe8192   |

    ML-KEM (post-quantum) groups (require HAVE_PQC, WOLFSSL_HAVE_MLKEM and
    !WOLFSSL_NO_ML_KEM):

    | Identifier         |
    | ------------------ |
    | WOLFSSL_ML_KEM_512 |
    | WOLFSSL_ML_KEM_768 |
    | WOLFSSL_ML_KEM_1024|

    ML-KEM hybrid groups additionally require HAVE_ECC together with either
    WOLFSSL_WC_MLKEM or HAVE_LIBOQS, and WOLFSSL_PQC_HYBRIDS (or
    WOLFSSL_EXTRA_PQC_HYBRIDS for the "extra" set):

    | Identifier                       | Hybrid flag set            |
    | -------------------------------- | -------------------------- |
    | WOLFSSL_SECP256R1MLKEM768        | WOLFSSL_PQC_HYBRIDS        |
    | WOLFSSL_X25519MLKEM768           | WOLFSSL_PQC_HYBRIDS        |
    | WOLFSSL_SECP384R1MLKEM1024       | WOLFSSL_PQC_HYBRIDS        |
    | WOLFSSL_SECP256R1MLKEM512        | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | WOLFSSL_SECP384R1MLKEM768        | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | WOLFSSL_SECP521R1MLKEM1024       | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | WOLFSSL_X25519MLKEM512           | WOLFSSL_EXTRA_PQC_HYBRIDS  |
    | WOLFSSL_X448MLKEM768             | WOLFSSL_EXTRA_PQC_HYBRIDS  |

    Legacy Kyber groups (require HAVE_PQC and WOLFSSL_MLKEM_KYBER; hybrids
    additionally require HAVE_ECC together with WOLFSSL_WC_MLKEM or
    HAVE_LIBOQS):

    | Identifier                  |
    | --------------------------- |
    | WOLFSSL_KYBER_LEVEL1        |
    | WOLFSSL_KYBER_LEVEL3        |
    | WOLFSSL_KYBER_LEVEL5        |
    | WOLFSSL_P256_KYBER_LEVEL1   |
    | WOLFSSL_P256_KYBER_LEVEL3   |
    | WOLFSSL_P384_KYBER_LEVEL3   |
    | WOLFSSL_P521_KYBER_LEVEL5   |
    | WOLFSSL_X25519_KYBER_LEVEL1 |
    | WOLFSSL_X25519_KYBER_LEVEL3 |
    | WOLFSSL_X448_KYBER_LEVEL3   |

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] groups a list of key-exchange groups by identifier.
    \param [in] count the number of identifiers in \p groups (must not exceed
    WOLFSSL_MAX_GROUP_COUNT).

    \return BAD_FUNC_ARG if a pointer parameter is NULL, \p count exceeds
    WOLFSSL_MAX_GROUP_COUNT, or the underlying method is not a TLS method.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    int groups[] = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = sizeof(groups) / sizeof(groups[0]);
    ...
    ret = wolfSSL_CTX_set_groups(ctx, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_CTX_set_groups(WOLFSSL_CTX* ctx, int* groups,
    int count);

/*!
    \ingroup Setup

    \brief This function sets the list of key-exchange groups (named elliptic
    curves and KEMs) to allow on a wolfSSL session in order of preference. The
    array format and the set of recognized identifiers are identical to those
    documented for wolfSSL_CTX_set_groups(); refer to that function for the
    full identifier table and required build options.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] groups a list of key-exchange groups by identifier.
    \param [in] count the number of identifiers in \p groups (must not exceed
    WOLFSSL_MAX_GROUP_COUNT).

    \return BAD_FUNC_ARG if a pointer parameter is NULL, \p count exceeds
    WOLFSSL_MAX_GROUP_COUNT, any of the identifiers are unrecognized, or the
    underlying method is not a TLS method.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    int groups[] = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    int count = sizeof(groups) / sizeof(groups[0]);
    ...
    ret = wolfSSL_set_groups(ssl, groups, count);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_UseKeyShare
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_preferred_group
*/
int  wolfSSL_set_groups(WOLFSSL* ssl, int* groups, int count);

/*!
    \ingroup IO

    \brief This function is called on the client side and initiates a
    TLS v1.3 handshake with a server.  When this function is called, the
    underlying communication channel has already been set up.
    wolfSSL_connect() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_connect() will return
    when the underlying I/O could not satisfy the needs of wolfSSL_connect
    to continue the handshake.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE. The
    calling process must then repeat the call to wolfSSL_connect() when
    the underlying I/O is ready and wolfSSL will pick up where it left off.
    When using a non-blocking socket, nothing needs to be done, but select()
    can be used to check for the required condition. If the underlying I/O is
    blocking, wolfSSL_connect() will only return once the handshake has been
    finished or an error occurred. wolfSSL takes a different approach to
    certificate verification than OpenSSL does.  The default policy for the
    client is to verify the server, this means that if you don't load CAs to
    verify the server you'll get a connect error, unable to verify (-155). It
    you want to mimic OpenSSL behavior of having SSL_connect succeed even if
    verifying the server fails and reducing security you can do this by
    calling: SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0); before calling
    SSL_new();  Though it's not recommended.

    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred.  To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_connect_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect
    \sa wolfSSL_accept_TLSv13
    \sa wolfSSL_accept
*/
int  wolfSSL_connect_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup IO

    \brief This function is called on the server side and waits for a SSL/TLS
    client to initiate the SSL/TLS handshake.  When this function is called,
    the underlying communication channel has already been set up.
    wolfSSL_accept() works with both blocking and non-blocking I/O.
    When the underlying I/O is non-blocking, wolfSSL_accept() will return
    when the underlying I/O could not satisfy the needs of wolfSSL_accept
    to continue the handshake.  In this case, a call to wolfSSL_get_error()
    will yield either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
    The calling process must then repeat the call to wolfSSL_accept when
    data is available to read and wolfSSL will pick up where it left off.
    When using a non-blocking socket, nothing needs to be done, but select()
    can be used to check for the required condition. If the underlying I/O
    is blocking, wolfSSL_accept() will only return once the handshake has
    been finished or an error occurred.
    Call this function when expecting a TLS v1.3 connection though older
    version ClientHello messages are supported.

    \return SSL_SUCCESS upon success.
    \return SSL_FATAL_ERROR will be returned if an error occurred. To get a
    more detailed error code, call wolfSSL_get_error().

    \param ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    char buffer[80];
    ...

    ret = wolfSSL_accept_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_get_error
    \sa wolfSSL_connect_TLSv13
    \sa wolfSSL_connect
    \sa wolfSSL_accept_TLSv13
    \sa wolfSSL_accept
*/
wolfSSL_accept_TLSv13(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function sets the maximum amount of early data that a
    TLS v1.3 client or server is willing to exchange using the wolfSSL context.
    Call this function to limit the amount of early data to process to mitigate
    replay attacks. Early data is protected by keys derived from those of the
    connection that the session ticket was sent and therefore will be the same
    every time a session ticket is used in resumption.
    The value is included in the session ticket for resumption.
    A server value of zero indicates no early data is to be sent by client using
    session tickets. A client value of zero indicates that the client will
    not send any early data.
    The default value is zero: per RFC 8446 Appendix E.5, TLS implementations
    "MUST NOT enable 0-RTT (either sending or accepting) unless specifically
    requested by the application." Servers must call this function (or the
    per-SSL equivalent) with a non-zero value to opt in.
    It is recommended that the number of early data bytes be kept as low as
    practically possible in the application.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] sz the amount of early data to accept in bytes.

    \return BAD_FUNC_ARG if ctx is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL_CTX* ctx;
    ...
    ret = wolfSSL_CTX_set_max_early_data(ctx, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_CTX_set_max_early_data(WOLFSSL_CTX* ctx,
    unsigned int sz);

/*!
    \ingroup Setup

    \brief This function sets the maximum amount of early data that a
    TLS v1.3 client or server is willing to exchange.
    Call this function to limit the amount of early data to process to mitigate
    replay attacks. Early data is protected by keys derived from those of the
    connection that the session ticket was sent and therefore will be the same
    every time a session ticket is used in resumption.
    The value is included in the session ticket for resumption.
    A server value of zero indicates no early data is to be sent by client using
    session tickets. A client value of zero indicates that the client will
    not send any early data.
    It is recommended that the number of early data bytes be kept as low as
    practically possible in the application.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] sz the amount of early data to accept from client in bytes.

    \return BAD_FUNC_ARG if ssl is NULL or not using TLS v1.3.
    \return 0 if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_set_max_early_data(ssl, 128);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set group list
    }
    \endcode

    \sa wolfSSL_CTX_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_set_max_early_data(WOLFSSL* ssl, unsigned int sz);

/*!
    \ingroup IO

    \brief This function writes early data to the server on resumption.
    Call this function before wolfSSL_connect() or wolfSSL_connect_TLSv13().
    This function is only used with clients.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] data the buffer holding the early data to write to server.
    \param [in] sz the amount of early data to write in bytes.
    \param [out] outSz the amount of early data written in bytes.

    \return BAD_FUNC_ARG if a pointer parameter is NULL, sz is less than 0 or
    not using TLSv1.3.
    \return SIDE_ERROR if called with a server.
    \return BAD_STATE_E if invoked without a valid session or without a valid
    PSK cb
    \return WOLFSSL_FATAL_ERROR if the connection is not made.
    \return the amount of early data written in bytes if successful.

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    byte earlyData[] = { early data };
    int outSz;
    char buffer[80];
    ...

    ret = wolfSSL_write_early_data(ssl, earlyData, sizeof(earlyData), &outSz);
    if (ret < 0) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
        goto err_label;
    }
    if (outSz < sizeof(earlyData)) {
        // not all early data was sent
    }
    ret = wolfSSL_connect_TLSv13(ssl);
    if (ret != SSL_SUCCESS) {
        err = wolfSSL_get_error(ssl, ret);
        printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
    }
    \endcode

    \sa wolfSSL_read_early_data
    \sa wolfSSL_connect
    \sa wolfSSL_connect_TLSv13
*/
int  wolfSSL_write_early_data(WOLFSSL* ssl, const void* data,
    int sz, int* outSz);

/*!
    \ingroup IO

    \brief This function reads any early data from a client on resumption.
    Call this function instead of wolfSSL_accept() or wolfSSL_accept_TLSv13()
    to accept a client and read any early data in the handshake. The function
    should be invoked until wolfSSL_is_init_finished() returns true. Early data
    may be sent by the client in multiple messages. If there is no early data
    then the handshake will be processed as normal. This function is only used
    with servers.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [out] data a buffer to hold the early data read from client.
    \param [in] sz size of the buffer in bytes.
    \param [out] outSz number of bytes of early data read.

    \return BAD_FUNC_ARG if a pointer parameter is NULL, sz is less than 0 or
    not using TLSv1.3.
    \return SIDE_ERROR if called with a client.
    \return WOLFSSL_FATAL_ERROR if accepting a connection fails.
    \return Number of early data bytes read (may be zero).

    _Example_
    \code
    int ret = 0;
    int err = 0;
    WOLFSSL* ssl;
    byte earlyData[128];
    int outSz;
    char buffer[80];
    ...

    do {
        ret = wolfSSL_read_early_data(ssl, earlyData, sizeof(earlyData), &outSz);
        if (ret < 0) {
            err = wolfSSL_get_error(ssl, ret);
            printf(“error = %d, %s\n”, err, wolfSSL_ERR_error_string(err, buffer));
        }
        if (outSz > 0) {
            // early data available
        }
    } while (!wolfSSL_is_init_finished(ssl));
    \endcode

    \sa wolfSSL_write_early_data
    \sa wolfSSL_accept
    \sa wolfSSL_accept_TLSv13
*/
int  wolfSSL_read_early_data(WOLFSSL* ssl, void* data, int sz,
    int* outSz);

/*!
    \ingroup IO

    \brief This function is called to inject data into the WOLFSSL object. This
    is useful when data needs to be read from a single place and demultiplexed
    into multiple connections. The caller should then call wolfSSL_read() to
    extract the plaintext data from the WOLFSSL object.

    \param [in] ssl a pointer to a WOLFSSL structure, created using
                    wolfSSL_new().
    \param [in] data data to inject into the ssl object.
    \param [in] sz number of bytes of data to inject.

    \return BAD_FUNC_ARG if any pointer parameter is NULL or sz <= 0
    \return APP_DATA_READY if there is application data left to read
    \return MEMORY_E if allocation fails
    \return WOLFSSL_SUCCESS on success

    _Example_
    \code
    byte buf[2000]
    sz = recv(fd, buf, sizeof(buf), 0);
    if (sz <= 0)
        // error
    if (wolfSSL_inject(ssl, buf, sz) != WOLFSSL_SUCCESS)
        // error
    sz = wolfSSL_read(ssl, buf, sizeof(buf);
    \endcode

    \sa wolfSSL_read
*/
int wolfSSL_inject(WOLFSSL* ssl, const void* data, int sz);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) client side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the client_psk_tls13_cb member of the
    WOLFSSL_CTX structure.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 client.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    ...
    wolfSSL_CTX_set_psk_client_tls13_callback(ctx, my_psk_client_tls13_cb);
    \endcode

    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_CTX_set_psk_client_tls13_callback(WOLFSSL_CTX* ctx,
    wc_psk_client_tls13_callback cb);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) client side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the client_psk_tls13_cb member of the options field in
    WOLFSSL structure.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 client.

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_set_psk_client_tls13_callback(ssl, my_psk_client_tls13_cb);
    \endcode

    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_set_psk_client_tls13_callback(WOLFSSL* ssl,
    wc_psk_client_tls13_callback cb);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) server side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the server_psk_tls13_cb member of the
    WOLFSSL_CTX structure.

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created
    with wolfSSL_CTX_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 server.

    _Example_
    \code
    WOLFSSL_CTX* ctx;
    ...
    wolfSSL_CTX_set_psk_server_tls13_callback(ctx, my_psk_client_tls13_cb);
    \endcode

    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
void wolfSSL_CTX_set_psk_server_tls13_callback(WOLFSSL_CTX* ctx,
    wc_psk_server_tls13_callback cb);

/*!
    \ingroup Setup

    \brief This function sets the Pre-Shared Key (PSK) server side callback
    for TLS v1.3 connections.
    The callback is used to find a PSK identity and return its key and
    the name of the cipher to use for the handshake.
    The function sets the server_psk_tls13_cb member of the options field in
    WOLFSSL structure.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] cb a Pre-Shared Key (PSK) callback for a TLS 1.3 server.

    _Example_
    \code
    WOLFSSL* ssl;
    ...
    wolfSSL_set_psk_server_tls13_callback(ssl, my_psk_server_tls13_cb);
    \endcode

    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
*/
void wolfSSL_set_psk_server_tls13_callback(WOLFSSL* ssl,
    wc_psk_server_tls13_callback cb);

/*!
    \ingroup Setup

    \brief Enable or disable TLS 1.3 certificate authentication with external
    PSK (RFC8773bis) on a context.

    When enabled, wolfSSL advertises and accepts the
    `tls_cert_with_extern_psk` extension for TLS 1.3 handshakes using external
    PSKs. Any non-zero \p state value enables the feature and zero disables it.

    Availability:
      - Built with `--enable-tls13 --enable-psk --enable-cert-with-extern-psk`
      - Or with `WOLFSSL_TLS13` and `WOLFSSL_CERT_WITH_EXTERN_PSK` defined

    \param [in,out] ctx a pointer to a WOLFSSL_CTX structure, created with
                        wolfSSL_CTX_new().
    \param [in] state 0 to disable, non-zero to enable.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE when \p ctx is NULL.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (wolfSSL_CTX_set_cert_with_extern_psk(ctx, 1) != WOLFSSL_SUCCESS) {
        /* handle error */
    }
    \endcode

    \sa wolfSSL_set_cert_with_extern_psk
    \sa wolfSSL_CTX_set_psk_client_tls13_callback
    \sa wolfSSL_CTX_set_psk_server_tls13_callback
*/
int wolfSSL_CTX_set_cert_with_extern_psk(WOLFSSL_CTX* ctx, int state);

/*!
    \ingroup Setup

    \brief Enable or disable TLS 1.3 certificate authentication with external
    PSK (RFC8773bis) on a connection.

    This call applies to a single WOLFSSL object. Any non-zero \p state value
    enables the feature and zero disables it.

    Availability:
      - Built with `--enable-tls13 --enable-psk --enable-cert-with-extern-psk`
      - Or with `WOLFSSL_TLS13` and `WOLFSSL_CERT_WITH_EXTERN_PSK` defined

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using
                        wolfSSL_new().
    \param [in] state 0 to disable, non-zero to enable.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE when \p ssl is NULL.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (wolfSSL_set_cert_with_extern_psk(ssl, 1) != WOLFSSL_SUCCESS) {
        /* handle error */
    }
    \endcode

    \sa wolfSSL_CTX_set_cert_with_extern_psk
    \sa wolfSSL_set_psk_client_tls13_callback
    \sa wolfSSL_set_psk_server_tls13_callback
*/
int wolfSSL_set_cert_with_extern_psk(WOLFSSL* ssl, int state);

/*!
    \ingroup Setup

    \brief This function creates a key share entry from the group including
    generating a key pair.
    The KeyShare extension contains all the generated public keys for key
    exchange. If this function is called, then only the groups specified will
    be included.
    Call this function when a preferred group has been previously established
    for the server.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().
    \param [in] group a key exchange group identifier.

    \return BAD_FUNC_ARG if ssl is NULL.
    \return MEMORY_E when dynamic memory allocation fails.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set key share
    }
    \endcode

    \sa wolfSSL_preferred_group
    \sa wolfSSL_CTX_set1_groups_list
    \sa wolfSSL_set1_groups_list
    \sa wolfSSL_CTX_set_groups
    \sa wolfSSL_set_groups
    \sa wolfSSL_NoKeyShares
*/
int wolfSSL_UseKeyShare(WOLFSSL* ssl, word16 group);

/*!
    \ingroup Setup

    \brief This function is called to ensure no key shares are sent in the
    ClientHello. This will force the server to respond with a HelloRetryRequest
    if a key exchange is required in the handshake.
    Call this function when the expected key exchange group is not known and
    to avoid the generation of keys unnecessarily.
    Note that an extra round-trip will be required to complete the handshake
    when a key exchange is required.

    \param [in,out] ssl a pointer to a WOLFSSL structure, created using wolfSSL_new().

    \return BAD_FUNC_ARG if ssl is NULL.
    \return SIDE_ERROR if called with a server.
    \return WOLFSSL_SUCCESS if successful.

    _Example_
    \code
    int ret;
    WOLFSSL* ssl;
    ...
    ret = wolfSSL_NoKeyShares(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        // failed to set no key shares
    }
    \endcode

    \sa wolfSSL_UseKeyShare
*/
int wolfSSL_NoKeyShares(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a server and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \param [in] heap a pointer to a buffer that the static memory allocator will use during dynamic memory allocation.

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method_ex(NULL);
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_server_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a client and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \param [in] heap a pointer to a buffer that the static memory allocator will use during dynamic memory allocation.

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_client_method_ex(NULL);
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_client_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a server and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_server_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_server_method
    \sa wolfTLSv1_server_method
    \sa wolfTLSv1_1_server_method
    \sa wolfTLSv1_2_server_method
    \sa wolfTLSv1_3_server_method_ex
    \sa wolfDTLSv1_server_method
    \sa wolfSSLv23_server_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_server_method(void);

/*!
    \ingroup Setup

    \brief This function is used to indicate
    that the application is a client and will only support the TLS 1.3
    protocol. This function allocates memory for and initializes a new
    wolfSSL_METHOD structure to be used when creating the SSL/TLS context
    with wolfSSL_CTX_new().

    \return If successful, the call will return a pointer to the newly
    created WOLFSSL_METHOD structure.
    \return FAIL If memory allocation fails when calling XMALLOC, the failure
    value of the underlying malloc() implementation will be returned
    (typically NULL with errno will be set to ENOMEM).

    _Example_
    \code
    #include <wolfssl/ssl.h>

    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx;

    method = wolfTLSv1_3_client_method();
    if (method == NULL) {
        // unable to get method
    }

    ctx = wolfSSL_CTX_new(method);
    ...
    \endcode

    \sa wolfSSLv3_client_method
    \sa wolfTLSv1_client_method
    \sa wolfTLSv1_1_client_method
    \sa wolfTLSv1_2_client_method
    \sa wolfTLSv1_3_client_method_ex
    \sa wolfDTLSv1_client_method
    \sa wolfSSLv23_client_method
    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_3_client_method(void);

/*!
    \ingroup Setup

    \brief This function returns a WOLFSSL_METHOD similar to
    wolfTLSv1_3_client_method except that it is not determined
    which side yet (server/client).

    \param [in] heap a pointer to a buffer that the static memory allocator will use during dynamic memory allocation.

    \return WOLFSSL_METHOD On successful creations returns a WOLFSSL_METHOD
    pointer
    \return NULL Null if memory allocation error or failure to create method

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method_ex(NULL));
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method_ex(void* heap);

/*!
    \ingroup Setup

    \brief This function returns a WOLFSSL_METHOD similar to
    wolfTLSv1_3_client_method except that it is not determined
    which side yet (server/client).

    \return WOLFSSL_METHOD On successful creations returns a WOLFSSL_METHOD
    pointer
    \return NULL Null if memory allocation error or failure to create method

    _Example_
    \code
    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method());
    // check ret value
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL_METHOD *wolfTLSv1_3_method(void);

/*!
 \ingroup SSL
 \brief This function sets a fixed / static ephemeral key for testing only
 \return 0 Key loaded successfully
 \param ctx A WOLFSSL_CTX context pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key file path (if keySz == 0) or actual key buffer (PEM or ASN.1)
 \param keySz key size (should be 0 for "key" arg is file path)
 \param format WOLFSSL_FILETYPE_ASN1 or WOLFSSL_FILETYPE_PEM
 \sa wolfSSL_CTX_get_ephemeral_key
 */
int wolfSSL_CTX_set_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief This function sets a fixed / static ephemeral key for testing only
 \return 0 Key loaded successfully
 \param ssl A WOLFSSL object pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key file path (if keySz == 0) or actual key buffer (PEM or ASN.1)
 \param keySz key size (should be 0 for "key" arg is file path)
 \param format WOLFSSL_FILETYPE_ASN1 or WOLFSSL_FILETYPE_PEM
 \sa wolfSSL_get_ephemeral_key
 */
int wolfSSL_set_ephemeral_key(WOLFSSL* ssl, int keyAlgo, const char* key, unsigned int keySz, int format);

/*!
 \ingroup SSL
 \brief This function returns pointer to loaded key as ASN.1/DER
 \return 0 Key returned successfully
 \param ctx A WOLFSSL_CTX context pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key buffer pointer
 \param keySz key size pointer
 \sa wolfSSL_CTX_set_ephemeral_key
 */
int wolfSSL_CTX_get_ephemeral_key(WOLFSSL_CTX* ctx, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief This function returns pointer to loaded key as ASN.1/DER
 \return 0 Key returned successfully
 \param ssl A WOLFSSL object pointer
 \param keyAlgo enum wc_PkType like WC_PK_TYPE_DH and WC_PK_TYPE_ECDH
 \param key key buffer pointer
 \param keySz key size pointer
 \sa wolfSSL_set_ephemeral_key
 */
int wolfSSL_get_ephemeral_key(WOLFSSL* ssl, int keyAlgo,
    const unsigned char** key, unsigned int* keySz);

/*!
 \ingroup SSL
 \brief Sign a message with the chosen message digest, padding, and RSA key
 \return WOLFSSL_SUCCESS on success and c on error
 \param type      Hash NID
 \param m         Message to sign. Most likely this will be the digest of
                  the message to sign
 \param mLen      Length of message to sign
 \param sigRet    Output buffer
 \param sigLen    On Input: length of sigRet buffer
                  On Output: length of data written to sigRet
 \param rsa       RSA key used to sign the input
 \param flag      1: Output the signature
                  0: Output the value that the unpadded signature should be
                     compared to. Note: for RSA_PKCS1_PSS_PADDING the
                     wc_RsaPSS_CheckPadding_ex function should be used to check
                     the output of a *Verify* function.
 \param padding   Padding to use. Only RSA_PKCS1_PSS_PADDING and
                  RSA_PKCS1_PADDING are currently supported for signing.
 */
int wolfSSL_RSA_sign_generic_padding(int hashAlg, const unsigned char* hash,
                               unsigned int hLen, unsigned char* sigRet,
                               unsigned int* sigLen, WOLFSSL_RSA* rsa,
                               int flag, int padding);
/*!

\brief checks if DTLSv1.3 stack has some messages sent but not yet acknowledged
 by the other peer

 \return 1 if there are pending messages, 0 otherwise
 \param ssl A WOLFSSL object pointer
*/
int wolfSSL_dtls13_has_pending_msg(WOLFSSL *ssl);

/*!
    \ingroup SSL
    \brief Get the maximum size of Early Data from a session.

    \param [in] s  the WOLFSSL_SESSION instance.

    \return the value of max_early_data that was configured in the WOLFSSL* the session
    was derived from.

    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
 */
unsigned int wolfSSL_SESSION_get_max_early_data(const WOLFSSL_SESSION *s);

/*!
    \ingroup SSL
    \brief Get a new index for external data. This entry applies also for the
           following API:
           - wolfSSL_CTX_get_ex_new_index
           - wolfSSL_get_ex_new_index
           - wolfSSL_SESSION_get_ex_new_index
           - wolfSSL_X509_get_ex_new_index

    \param [in] class_index Identifier for the object class the external data
                 index applies to. Ignored by wolfSSL.
    \param [in] argl Optional long argument passed through for compatibility.
                 Ignored by wolfSSL.
    \param [in] argp Optional pointer argument passed through for compatibility.
                 Ignored by wolfSSL.
    \param [in] new_func Pointer to an external data constructor callback.
                 Ignored by wolfSSL.
    \param [in] dup_func Pointer to an external data duplicate callback.
                 Ignored by wolfSSL.
    \param [in] free_func Pointer to an external data destructor callback.
                 Ignored by wolfSSL.

    \return The new index value to be used with the external data API for this
            object class.
*/
int wolfSSL_CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
                                    WOLFSSL_CRYPTO_EX_new* new_func,
                                    WOLFSSL_CRYPTO_EX_dup* dup_func,
                                    WOLFSSL_CRYPTO_EX_free* free_func);

/*!
 \ingroup Setup
 \brief  In case this function is called in a client side, set certificate types
 that can be sent to its peer. In case called in a server side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_CLIENT_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ctx  WOLFSSL_CTX object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_CTX_set_client_cert_type(ctx, buf, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_CTX_set_client_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  In case this function is called in a server side, set certificate types
 that can be sent to its peer. In case called in a client side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_SERVER_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ctx  WOLFSSL_CTX object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL_CTX* ctx;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_CTX_set_server_cert_type(ctx, buf, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_CTX_set_server_cert_type(WOLFSSL_CTX* ctx, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  In case this function is called in a client side, set certificate types
 that can be sent to its peer. In case called in a server side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_CLIENT_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ssl  WOLFSSL object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_set_client_cert_type(ssl, buf, len);
 \endcode
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_set_client_cert_type(WOLFSSL* ssl, const char* buf, int len);

/*!
 \ingroup Setup
 \brief  In case this function is called in a server side, set certificate types
 that can be sent to its peer. In case called in a client side,
 set certificate types that can be acceptable from its peer. Put cert types in the
 buffer with prioritised order. To reset the settings to default, pass NULL
 for the buffer or pass zero for len. By default, certificate type is only X509.
 In case both side intend to send or accept "Raw public key" cert,
 WOLFSSL_CERT_TYPE_RPK should be included in the buffer to set.

 \return WOLFSSL_SUCCESS if cert types set successfully
 \return BAD_FUNC_ARG if NULL was passed for ctx, illegal value was specified as
  cert type, buf size exceed MAX_SERVER_CERT_TYPE_CNT was specified or
  a duplicate value is found in buf.

 \param ctx  WOLFSSL_CTX object pointer
 \param buf  A buffer where certificate types are stored
 \param len  buf size in bytes (same as number of certificate types included)
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  char buf[] = {WOLFSSL_CERT_TYPE_RPK, WOLFSSL_CERT_TYPE_X509};
  int len = sizeof(buf)/sizeof(char);
  ...

  ret = wolfSSL_set_server_cert_type(ssl, buf, len);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_set_server_cert_type(WOLFSSL* ssl, const char* buf, int len);

/*!
    \ingroup Setup

    \brief Enables handshake message grouping for the given WOLFSSL_CTX context.

    This function turns on handshake message grouping for all SSL objects created from the specified context.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ctx is NULL.

    \param ctx Pointer to the WOLFSSL_CTX structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_set_group_messages(ctx);
    \endcode

    \sa wolfSSL_CTX_clear_group_messages
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_clear_group_messages
*/
int wolfSSL_CTX_set_group_messages(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Disables handshake message grouping for the given WOLFSSL_CTX context.

    This function turns off handshake message grouping for all SSL objects created from the specified context.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ctx is NULL.

    \param ctx Pointer to the WOLFSSL_CTX structure.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    wolfSSL_CTX_clear_group_messages(ctx);
    \endcode

    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_set_group_messages
    \sa wolfSSL_clear_group_messages
*/
int wolfSSL_CTX_clear_group_messages(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup

    \brief Enables handshake message grouping for the given WOLFSSL object.

    This function turns on handshake message grouping for the specified SSL object.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl Pointer to the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_set_group_messages(ssl);
    \endcode

    \sa wolfSSL_clear_group_messages
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_CTX_clear_group_messages
*/
int wolfSSL_set_group_messages(WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Disables handshake message grouping for the given WOLFSSL object.

    This function turns off handshake message grouping for the specified SSL object.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl Pointer to the WOLFSSL structure.

    _Example_
    \code
    WOLFSSL* ssl = wolfSSL_new(ctx);
    wolfSSL_clear_group_messages(ssl);
    \endcode

    \sa wolfSSL_set_group_messages
    \sa wolfSSL_CTX_set_group_messages
    \sa wolfSSL_CTX_clear_group_messages
*/
int wolfSSL_clear_group_messages(WOLFSSL* ssl);

/*!
 \ingroup SSL
 \brief  This function returns the result of the client certificate type
 negotiation done in ClientHello and ServerHello. WOLFSSL_SUCCESS is returned as
  a return value if no negotiation occurs and WOLFSSL_CERT_TYPE_UNKNOWN is
  returned as the certificate type.

 \return WOLFSSL_SUCCESS if a negotiated certificate type could be got
 \return BAD_FUNC_ARG if NULL was passed for ctx or tp
 \param ssl  WOLFSSL object pointer
 \param tp  A buffer where a certificate type is to be returned. One of three
 certificate types will be returned: WOLFSSL_CERT_TYPE_RPK,
 WOLFSSL_CERT_TYPE_X509 or WOLFSSL_CERT_TYPE_UNKNOWN.

    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  int tp;
  ...

  ret = wolfSSL_get_negotiated_client_cert_type(ssl, &tp);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_get_negotiated_server_cert_type
 */
int wolfSSL_get_negotiated_client_cert_type(WOLFSSL* ssl, int* tp);

/*!
 \ingroup SSL
 \brief  This function returns the result of the server certificate type
 negotiation done in ClientHello and ServerHello. WOLFSSL_SUCCESS is returned as
  a return value if no negotiation occurs and WOLFSSL_CERT_TYPE_UNKNOWN is
  returned as the certificate type.

 \return WOLFSSL_SUCCESS if a negotiated certificate type could be got
 \return BAD_FUNC_ARG if NULL was passed for ctx or tp
 \param ssl  WOLFSSL object pointer
 \param tp  A buffer where a certificate type is to be returned. One of three
 certificate types will be returned: WOLFSSL_CERT_TYPE_RPK,
 WOLFSSL_CERT_TYPE_X509 or WOLFSSL_CERT_TYPE_UNKNOWN.
    _Example_
 \code
  int ret;
  WOLFSSL* ssl;
  int tp;
　...

  ret = wolfSSL_get_negotiated_server_cert_type(ssl, &tp);
 \endcode
 \sa wolfSSL_set_client_cert_type
 \sa wolfSSL_CTX_set_client_cert_type
 \sa wolfSSL_set_server_cert_type
 \sa wolfSSL_CTX_set_server_cert_type
 \sa wolfSSL_get_negotiated_client_cert_type
 */
int wolfSSL_get_negotiated_server_cert_type(WOLFSSL* ssl, int* tp);

/*!

\brief Enable use of ConnectionID extensions for the SSL object. See RFC 9146
and RFC 9147

 \return WOLFSSL_SUCCESS on success, error code otherwise

 \param ssl A WOLFSSL object pointer

 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_use(WOLFSSL* ssl);

/*!

\brief If invoked after the handshake is complete it checks if ConnectionID was
successfully negotiated for the SSL object. See RFC 9146 and RFC 9147

 \return 1 if ConnectionID was correctly negotiated, 0 otherwise

 \param ssl A WOLFSSL object pointer

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_is_enabled(WOLFSSL* ssl);

/*!

\brief Set the ConnectionID used by the other peer to send records in this
connection. See RFC 9146 and RFC 9147. The ConnectionID must be at maximum
DTLS_CID_MAX_SIZE, that is an tunable compile time define, and it can't
never be bigger than 255 bytes.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly set, error code otherwise

 \param ssl A WOLFSSL object pointern
 \param cid the ConnectionID to be used
 \param size of the ConnectionID provided

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid,
    unsigned int size);

/*!

\brief Get the size of the ConnectionID used by the other peer to send records
in this connection. See RFC 9146 and RFC 9147. The size is stored in the
parameter size.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly negotiated, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param size a pointer to an unsigned int where the size will be stored

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_rx_size(WOLFSSL* ssl,
    unsigned int* size);

/*!

\brief Copy the ConnectionID used by the other peer to send records in this
connection into the buffer pointed by the parameter buffer. See RFC 9146 and RFC
9147. The available space in the buffer need to be provided in bufferSz.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly copied, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param buffer A buffer where the ConnectionID will be copied
 \param bufferSz available space in buffer

 \sa wolfSSL_dtls_cid_get0_rx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_rx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);

/*!

\brief Get the ConnectionID used by the other peer. See RFC 9146 and RFC
9147.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly set in cid.

 \param ssl A WOLFSSL object pointern
 \param cid Pointer that will be set to the internal memory that holds the CID

 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_tx_size
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get0_rx(WOLFSSL* ssl, unsigned char** cid);

/*!

\brief Get the size of the ConnectionID used to send records in this
connection. See RFC 9146 and RFC 9147. The size is stored in the parameter size.

 \return WOLFSSL_SUCCESS if ConnectionID size was correctly stored, error
 code otherwise

 \param ssl A WOLFSSL object pointern
 \param size a pointer to an unsigned int where the size will be stored

 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx
*/
int wolfSSL_dtls_cid_get_tx_size(WOLFSSL* ssl, unsigned int* size);

/*!

\brief Copy the ConnectionID used when sending records in this connection into
the buffer pointer by the parameter buffer. See RFC 9146 and RFC 9147. The
available size need to be provided in bufferSz.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly copied, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param buffer A buffer where the ConnectionID will be copied
 \param bufferSz available space in buffer

 \sa wolfSSL_dtls_cid_get0_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
int wolfSSL_dtls_cid_get_tx(WOLFSSL* ssl, unsigned char* buffer,
    unsigned int bufferSz);

/*!

\brief Get the ConnectionID used when sending records in this connection. See
RFC 9146 and RFC 9147.

 \return WOLFSSL_SUCCESS if ConnectionID was correctly retrieved, error code
 otherwise

 \param ssl A WOLFSSL object pointern
 \param cid Pointer that will be set to the internal memory that holds the CID

 \sa wolfSSL_dtls_cid_get_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
int wolfSSL_dtls_cid_get0_tx(WOLFSSL* ssl, unsigned char** cid);

/*!

\brief Extract the ConnectionID from a record datagram/message. See
RFC 9146 and RFC 9147.

 \param msg buffer holding the datagram read from the network
 \param msgSz size of msg in bytes
 \param cid pointer to the start of the CID inside the msg buffer
 \param cidSz the expected size of the CID. The record layer does not have a CID
 size field so we have to know beforehand the size of the CID. It is recommended
 to use a constant CID for all connections.

 \sa wolfSSL_dtls_cid_get_tx
 \sa wolfSSL_dtls_cid_use
 \sa wolfSSL_dtls_cid_is_enabled
 \sa wolfSSL_dtls_cid_set
 \sa wolfSSL_dtls_cid_get_rx_size
 \sa wolfSSL_dtls_cid_get_rx
 \sa wolfSSL_dtls_cid_get_tx_size
*/
const unsigned char* wolfSSL_dtls_cid_parse(const unsigned char* msg,
        unsigned int msgSz, unsigned int cidSz);

/*!
    \ingroup TLS
    \brief On the server, this sets a list of CA names to be sent to clients in
    certificate requests as a hint for which CA's are supported by the server.

    On the client, this function has no effect.

    \param [in] ctx Pointer to the wolfSSL context
    \param [in] names List of names to be set

    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_CTX_set_client_CA_list(WOLFSSL_CTX* ctx,
                                    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief This retrieves the list previously set via
     wolfSSL_CTX_set_client_CA_list, or NULL if no list has been set.

    \param [in] ctx Pointer to the wolfSSL context
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_CTX_get_client_CA_list(
        const WOLFSSL_CTX *ctx);

/*!
    \ingroup TLS
    \brief Same as wolfSSL_CTX_set_client_CA_list, but specific to a session.
    If a CA list is set on both the context and the session, the list on the
    session is used.

    \param [in] ssl Pointer to the WOLFSSL object
    \param [in] names List of names to be set.

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_set_client_CA_list(WOLFSSL* ssl,
                                    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief On the server, this retrieves the list previously set via
    wolfSSL_set_client_CA_list. If none was set, returns the list previously
    set via wolfSSL_CTX_set_client_CA_list. If no list at all was set, returns
    NULL.

    On the client, this retrieves the list that was received from the server,
    or NULL if none was received. wolfSSL_CTX_set_cert_cb can be used to
    register a callback to dynamically load certificates when a certificate
    request is received from the server.

    \param [in] ssl Pointer to the WOLFSSL object
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_cert_cb
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK* wolfSSL_get_client_CA_list(
            const WOLFSSL* ssl);

/*!
    \ingroup TLS
    \brief This function sets a list of CA names to be sent to the peer as a
    hint for which CA's are supported for its authentication.

    In TLS >= 1.3, this is supported in both directions between the client and
    the server. On the server, the CA names will be sent as part of a
    CertificateRequest, making this function an equivalent of *_set_client_CA_list;
    on the client, these are sent as part of ClientHello.

    In TLS < 1.3, sending CA names from the client to the server is not
    supported, therefore this function is equivalent to
    wolfSSL_CTX_set_client_CA_list.

    Note that the lists set via *_set_client_CA_list and *_set0_CA_list are
    separate internally, i.e. calling *_get_client_CA_list will not retrieve a
    list set via *_set0_CA_list and vice versa. If both are set, the server will
    ignore *_set0_CA_list when sending CA names to the client.

    \param [in] ctx Pointer to the wolfSSL context
    \param [in] names List of names to be set

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_CTX_set0_CA_list(WOLFSSL_CTX *ctx,
        WOLF_STACK_OF(WOLFSSL_X509_NAME)* names);

/*!
    \ingroup TLS
    \brief This retrieves the list previously set via
    wolfSSL_CTX_set0_CA_list, or NULL if no list has been set.

    \param [in] ctx Pointer to the wolfSSL context
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_CTX_get0_CA_list(
        const WOLFSSL_CTX *ctx);

/*!
    \ingroup TLS
    \brief Same as wolfSSL_CTX_set0_CA_list, but specific to a session.
    If a CA list is set on both the context and the session, the list on the
    session is used.

    \param [in] ssl Pointer to the WOLFSSL object
    \param [in] names List of names to be set.

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
void wolfSSL_set0_CA_list(WOLFSSL *ssl,
        WOLF_STACK_OF(WOLFSSL_X509_NAME) *names);

/*!
    \ingroup TLS
    \brief This retrieves the list previously set via wolfSSL_set0_CA_list. If
    none was set, returns the list previously set via
    wolfSSL_CTX_set0_CA_list. If no list at all was set, returns NULL.

    \param [in] ssl Pointer to the WOLFSSL object
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_peer_CA_list
*/
WOLFSSL_STACK *wolfSSL_get0_CA_list(
        const WOLFSSL *ssl);

/*!
    \ingroup TLS
    \brief This returns the CA list received from the peer.

    On the client, this is the list sent by the server in a CertificateRequest,
    and this function is equivalent to wolfSSL_get_client_CA_list.

    On the server, this is the list sent by the client in the ClientHello message
    in TLS >= 1.3; in TLS < 1.3, the function always returns NULL on the server
    side.

    wolfSSL_CTX_set_cert_cb can be used to register a callback to dynamically
    load certificates when a CA list is received from the peer.

    \param [in] ssl Pointer to the WOLFSSL object
    \return A stack of WOLFSSL_X509_NAMEs containing the CA names

    \sa wolfSSL_CTX_set_cert_cb
    \sa wolfSSL_CTX_set_client_CA_list
    \sa wolfSSL_set_client_CA_list
    \sa wolfSSL_CTX_get_client_CA_list
    \sa wolfSSL_get_client_CA_list
    \sa wolfSSL_CTX_set0_CA_list
    \sa wolfSSL_set0_CA_list
    \sa wolfSSL_CTX_get0_CA_list
    \sa wolfSSL_get0_CA_list
*/
WOLFSSL_STACK *wolfSSL_get0_peer_CA_list(const WOLFSSL *ssl);

/*!
    \ingroup TLS
    \brief This function sets a callback that will be called whenever a
    certificate is about to be used, to allow the application to inspect, set
    or clear any certificates, for example to react to a CA list sent from the
    peer.

    \param [in] ctx Pointer to the wolfSSL context
    \param [in] cb Function pointer to the callback
    \param [in] arg Pointer that will be passed to the callback

    \sa wolfSSL_get0_peer_CA_list
    \sa wolfSSL_get_client_CA_list
*/
void wolfSSL_CTX_set_cert_cb(WOLFSSL_CTX* ctx,
    int (*cb)(WOLFSSL *, void *), void *arg);

/*!
    \ingroup TLS

    \brief This function returns the raw list of ciphersuites and signature
    algorithms offered by the client. The lists are only stored and returned
    inside a callback setup with wolfSSL_CTX_set_cert_cb(). This is useful to
    be able to dynamically load certificates and keys based on the available
    ciphersuites and signature algorithms.

    \param [in] ssl The WOLFSSL object to extract the lists from.
    \param [out] suites Raw and unfiltered list of client ciphersuites.
                        May be NULL if no suites are available.
    \param [out] suiteSz Size of suites in bytes.
    \param [out] hashSigAlgo Raw and unfiltered list of client signature
                        algorithms. May be NULL if not provided.
    \param [out] hashSigAlgoSz Size of hashSigAlgo in bytes.
    \return WOLFSSL_SUCCESS when suites available
    \return WOLFSSL_FAILURE when suites not available

    _Example_
    \code
    int certCB(WOLFSSL* ssl, void* arg)
    {
        const byte* suites = NULL;
        word16 suiteSz = 0;
        const byte* hashSigAlgo = NULL;
        word16 hashSigAlgoSz = 0;

        wolfSSL_get_client_suites_sigalgs(ssl, &suites, &suiteSz, &hashSigAlgo,
                &hashSigAlgoSz);

        // Choose certificate to load based on ciphersuites and sigalgs
    }

    WOLFSSL* ctx;
    ctx  = wolfSSL_CTX_new(wolfTLSv1_3_method_ex(NULL));
    wolfSSL_CTX_set_cert_cb(ctx, certCB, NULL);
    \endcode

    \sa wolfSSL_get_ciphersuite_info
    \sa wolfSSL_get_sigalg_info
*/
int wolfSSL_get_client_suites_sigalgs(const WOLFSSL* ssl,
        const byte** suites, word16* suiteSz,
        const byte** hashSigAlgo, word16* hashSigAlgoSz);

/*!
    \ingroup TLS

    \brief This returns information about the ciphersuite directly from the
    raw ciphersuite bytes.

    \param [in] first First byte of the ciphersuite
    \param [in] second Second byte of the ciphersuite

    \return WOLFSSL_CIPHERSUITE_INFO A struct containing information about the
    type of authentication used in the ciphersuite.

    _Example_
    \code
    WOLFSSL_CIPHERSUITE_INFO info =
            wolfSSL_get_ciphersuite_info(suites[0], suites[1]);
    if (info.rsaAuth)
        haveRSA = 1;
    else if (info.eccAuth)
        haveECC = 1;
    \endcode

    \sa wolfSSL_get_client_suites_sigalgs
    \sa wolfSSL_get_sigalg_info
*/
WOLFSSL_CIPHERSUITE_INFO wolfSSL_get_ciphersuite_info(byte first,
        byte second);

/*!
    \ingroup TLS

    \brief This returns information about the hash and signature algorithm
    directly from the raw ciphersuite bytes.

    \param [in] first First byte of the hash and signature algorithm
    \param [in] second Second byte of the hash and signature algorithm
    \param [out] hashAlgo The enum wc_HashType of the MAC algorithm
    \param [out] sigAlgo The enum Key_Sum of the authentication algorithm

    \return 0            when info was correctly set
    \return BAD_FUNC_ARG when either input parameters are NULL or the bytes
                         are not a recognized sigalg suite

    _Example_
    \code
    enum wc_HashType hashAlgo;
    enum Key_Sum sigAlgo;

    wolfSSL_get_sigalg_info(hashSigAlgo[idx+0], hashSigAlgo[idx+1],
            &hashAlgo, &sigAlgo);

    if (sigAlgo == RSAk || sigAlgo == RSAPSSk)
        haveRSA = 1;
    else if (sigAlgo == ECDSAk)
        haveECC = 1;
    \endcode

    \sa wolfSSL_get_client_suites_sigalgs
    \sa wolfSSL_get_ciphersuite_info
*/
int wolfSSL_get_sigalg_info(byte first, byte second,
        int* hashAlgo, int* sigAlgo);

/*!
    \brief This function will set the password callback in the provided CTX.
    This callback is used when loading an encrypted cert or key which requires
    a password.

    \param ctx a pointer to a WOLFSSL_CTX structure, created with
    wolfSSL_CTX_new().
    \param cb a function pointer to (*wc_pem_password_cb) that is set to the
    passwd_cb member of the WOLFSSL_CTX.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    int PasswordCallBack(char* passwd, int sz, int rw, void* userdata) {

    }
    …
    wolfSSL_CTX_set_default_passwd_cb(ctx, PasswordCallBack);
    \endcode

    \sa wolfSSL_CTX_set_default_passwd_cb_userdata
*/
void wolfSSL_CTX_set_default_passwd_cb(WOLFSSL_CTX* ctx,
                                        wc_pem_password_cb* cb);

/*!
    \brief This function will set the userdata argument to the passwd_userdata
    member of the WOLFSSL_CTX structure.
    This member is passed into the CTX's password callback when called.

    \param ctx a pointer to a WOLFSSL_CTX structure, created with
    wolfSSL_CTX_new().
    \param userdata a pointer to userdata which is passed into the
    password callback.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new( protocol method );
    int data;
    …
    wolfSSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)&data);
    \endcode

    \sa wolfSSL_CTX_set_default_passwd_cb
*/
void wolfSSL_CTX_set_default_passwd_cb_userdata(WOLFSSL_CTX* ctx,
                                                   void* userdata);

/*!
    \ingroup Setup

    \brief Gets the state of the secure renegotiation (SCR) check requirement.

    This function returns whether the client requires the server to acknowledge
    the secure renegotiation extension and enable secure renegotiation when
    sending it from the client. When enabled, the client will generate a fatal
    handshake_failure alert if the server does not acknowledge the extension
    in the ServerHello message, as required by RFC 9325.

    \return 1 if the SCR check is enabled.
    \return 0 if the SCR check is disabled.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl Pointer to the WOLFSSL structure, created with wolfSSL_new().

    _Example_
    \code
    WOLFSSL* ssl;
    int enabled;

    ssl = wolfSSL_new(ctx);
    enabled = wolfSSL_get_scr_check_enabled(ssl);
    if (enabled) {
        // SCR check is enabled
    }
    \endcode

    \sa wolfSSL_set_scr_check_enabled
*/
int wolfSSL_get_scr_check_enabled(const WOLFSSL* ssl);

/*!
    \ingroup Setup

    \brief Sets the state of the secure renegotiation (SCR) check requirement.

    This function enables or disables the requirement for the server to
    acknowledge the secure renegotiation extension and enable secure
    renegotiation when sending it from the client. When enabled, the client
    will generate a fatal handshake_failure alert if the server does not
    acknowledge the extension in the ServerHello message, as required by
    RFC 9325.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG if ssl is NULL.

    \param ssl Pointer to the WOLFSSL structure, created with wolfSSL_new().
    \param enabled Non-zero to enable the SCR check, zero to disable it.

    _Example_
    \code
    WOLFSSL* ssl;
    int ret;

    ssl = wolfSSL_new(ctx);
    ret = wolfSSL_set_scr_check_enabled(ssl, 1);
    if (ret != WOLFSSL_SUCCESS) {
        // Error setting SCR check
    }
    \endcode

    \sa wolfSSL_get_scr_check_enabled
*/
int wolfSSL_set_scr_check_enabled(WOLFSSL* ssl, byte enabled);

/*!
    \ingroup ASN
    \brief Allocates and initializes a new WOLFSSL_ASN1_OBJECT structure.
    The returned object has its OID buffer pointer set to NULL and must
    be freed with wolfSSL_ASN1_OBJECT_free().

    \return pointer Pointer to a freshly allocated WOLFSSL_ASN1_OBJECT.
    \return NULL on allocation failure.

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_ASN1_OBJECT_new();
    if (obj == NULL) {
        // handle error
    }
    wolfSSL_ASN1_OBJECT_free(obj);
    \endcode

    \sa wolfSSL_ASN1_OBJECT_free
    \sa wolfSSL_ASN1_OBJECT_dup
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_new(void);

/*!
    \ingroup ASN
    \brief Creates a deep copy of the given WOLFSSL_ASN1_OBJECT,
    duplicating the OID data buffer.

    \return pointer Pointer to a newly allocated duplicate WOLFSSL_ASN1_OBJECT.
    \return NULL on allocation failure or if obj is NULL.

    \param obj WOLFSSL_ASN1_OBJECT to duplicate.

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* dup = wolfSSL_ASN1_OBJECT_dup(orig);
    if (dup == NULL) {
        // handle error
    }
    wolfSSL_ASN1_OBJECT_free(dup);
    \endcode

    \sa wolfSSL_ASN1_OBJECT_new
    \sa wolfSSL_ASN1_OBJECT_free
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_ASN1_OBJECT_dup(WOLFSSL_ASN1_OBJECT* obj);

/*!
    \ingroup ASN
    \brief Frees the WOLFSSL_ASN1_OBJECT and any owned dynamic data.
    Has no effect when obj is NULL.

    \return none No return value.

    \param obj WOLFSSL_ASN1_OBJECT to free.

    _Example_
    \code
    WOLFSSL_ASN1_OBJECT* obj = wolfSSL_ASN1_OBJECT_new();
    // ... use obj ...
    wolfSSL_ASN1_OBJECT_free(obj);
    \endcode

    \sa wolfSSL_ASN1_OBJECT_new
    \sa wolfSSL_ASN1_OBJECT_dup
*/
void wolfSSL_ASN1_OBJECT_free(WOLFSSL_ASN1_OBJECT* obj);

/*!
    \ingroup ASN
    \brief Converts the data in a WOLFSSL_ASN1_STRING to a UTF-8 encoded
    string. Memory for the output buffer is allocated by the function and
    must be released by the caller using OPENSSL_free().

    \return length Length in bytes of the UTF-8 string written to *out on
    success.
    \return negative On error.

    \param out Address of a pointer that will be set to the newly
    allocated UTF-8 buffer.
    \param in WOLFSSL_ASN1_STRING to convert.

    _Example_
    \code
    unsigned char* utf8 = NULL;
    int len = wolfSSL_ASN1_STRING_to_UTF8(&utf8, str);
    if (len > 0) {
        // use utf8
        OPENSSL_free(utf8);
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_data
    \sa wolfSSL_ASN1_STRING_length
*/
int wolfSSL_ASN1_STRING_to_UTF8(unsigned char **out, WOLFSSL_ASN1_STRING *in);

/*!
    \ingroup ASN
    \brief Converts a UniversalString (4-byte-per-character) ASN.1 string
    to a plain string in place when all characters lie in the ASCII range.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if s is NULL, not a UniversalString, or the
    contents cannot be converted.

    \param s WOLFSSL_ASN1_STRING of type V_ASN1_UNIVERSALSTRING to convert.

    _Example_
    \code
    if (wolfSSL_ASN1_UNIVERSALSTRING_to_string(s) != WOLFSSL_SUCCESS) {
        // handle error
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_to_UTF8
*/
int wolfSSL_ASN1_UNIVERSALSTRING_to_string(WOLFSSL_ASN1_STRING *s);

/*!
    \ingroup ASN
    \brief Allocates and initializes a new empty WOLFSSL_ASN1_STRING.
    The string must be freed with wolfSSL_ASN1_STRING_free().

    \return pointer Newly allocated WOLFSSL_ASN1_STRING.
    \return NULL on allocation failure.

    _Example_
    \code
    WOLFSSL_ASN1_STRING* s = wolfSSL_ASN1_STRING_new();
    if (s == NULL) {
        // handle error
    }
    wolfSSL_ASN1_STRING_free(s);
    \endcode

    \sa wolfSSL_ASN1_STRING_free
    \sa wolfSSL_ASN1_STRING_type_new
*/
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_new(void);

/*!
    \ingroup ASN
    \brief Creates a deep copy of an existing WOLFSSL_ASN1_STRING,
    including its data buffer and type.

    \return pointer Newly allocated duplicate WOLFSSL_ASN1_STRING.
    \return NULL if asn1 is NULL or on allocation failure.

    \param asn1 WOLFSSL_ASN1_STRING to duplicate.

    _Example_
    \code
    WOLFSSL_ASN1_STRING* copy = wolfSSL_ASN1_STRING_dup(orig);
    // ...
    wolfSSL_ASN1_STRING_free(copy);
    \endcode

    \sa wolfSSL_ASN1_STRING_new
    \sa wolfSSL_ASN1_STRING_free
*/
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_dup(WOLFSSL_ASN1_STRING* asn1);

/*!
    \ingroup ASN
    \brief Allocates a new WOLFSSL_ASN1_STRING and sets its ASN.1 string
    type (for example V_ASN1_UTF8STRING, V_ASN1_IA5STRING).

    \return pointer Newly allocated WOLFSSL_ASN1_STRING with the requested
    type.
    \return NULL on allocation failure.

    \param type ASN.1 string type tag.

    _Example_
    \code
    WOLFSSL_ASN1_STRING* s =
        wolfSSL_ASN1_STRING_type_new(V_ASN1_UTF8STRING);
    \endcode

    \sa wolfSSL_ASN1_STRING_new
    \sa wolfSSL_ASN1_STRING_type
*/
WOLFSSL_ASN1_STRING* wolfSSL_ASN1_STRING_type_new(int type);

/*!
    \ingroup ASN
    \brief Returns the ASN.1 string type code stored in a
    WOLFSSL_ASN1_STRING (e.g. V_ASN1_PRINTABLESTRING).

    \return type Non-negative ASN.1 type tag on success.
    \return negative On error or if asn1 is NULL.

    \param asn1 WOLFSSL_ASN1_STRING to query.

    _Example_
    \code
    int type = wolfSSL_ASN1_STRING_type(s);
    \endcode

    \sa wolfSSL_ASN1_STRING_type_new
*/
int wolfSSL_ASN1_STRING_type(const WOLFSSL_ASN1_STRING* asn1);

/*!
    \ingroup ASN
    \brief Compares two WOLFSSL_ASN1_STRING structures by length first,
    then by byte content. Mirrors OpenSSL's ASN1_STRING_cmp().

    \return 0 If the two strings are equal.
    \return non-zero If the strings differ; the sign indicates ordering.
    \return -1 If either argument is NULL.

    \param a First WOLFSSL_ASN1_STRING.
    \param b Second WOLFSSL_ASN1_STRING.

    _Example_
    \code
    if (wolfSSL_ASN1_STRING_cmp(a, b) == 0) {
        // strings match
    }
    \endcode

    \sa wolfSSL_ASN1_STRING_data
    \sa wolfSSL_ASN1_STRING_length
*/
int wolfSSL_ASN1_STRING_cmp(const WOLFSSL_ASN1_STRING *a, const WOLFSSL_ASN1_STRING *b);

/*!
    \ingroup ASN
    \brief Frees a WOLFSSL_ASN1_STRING previously allocated with
    wolfSSL_ASN1_STRING_new() or related constructors. Has no effect
    when asn1 is NULL.

    \return none No return value.

    \param asn1 WOLFSSL_ASN1_STRING to free.

    _Example_
    \code
    wolfSSL_ASN1_STRING_free(s);
    \endcode

    \sa wolfSSL_ASN1_STRING_new
*/
void wolfSSL_ASN1_STRING_free(WOLFSSL_ASN1_STRING* asn1);

/*!
    \ingroup ASN
    \brief Returns a pointer to the internal data buffer of a
    WOLFSSL_ASN1_STRING. The data is not null-terminated; use
    wolfSSL_ASN1_STRING_length() to obtain its size.

    \return pointer Pointer to the string's internal data buffer.
    \return NULL if asn is NULL.

    \param asn WOLFSSL_ASN1_STRING to query.

    _Example_
    \code
    unsigned char* data = wolfSSL_ASN1_STRING_data(s);
    int len = wolfSSL_ASN1_STRING_length(s);
    \endcode

    \sa wolfSSL_ASN1_STRING_length
    \sa wolfSSL_ASN1_STRING_to_UTF8
*/
unsigned char* wolfSSL_ASN1_STRING_data(WOLFSSL_ASN1_STRING* asn);

/*!
    \ingroup ASN
    \brief Returns the length in bytes of the data stored in a
    WOLFSSL_ASN1_STRING.

    \return length Length of the string's data buffer in bytes.
    \return 0 If asn is NULL.

    \param asn WOLFSSL_ASN1_STRING to query.

    _Example_
    \code
    int len = wolfSSL_ASN1_STRING_length(s);
    \endcode

    \sa wolfSSL_ASN1_STRING_data
*/
int wolfSSL_ASN1_STRING_length(const WOLFSSL_ASN1_STRING* asn);

/*!
    \ingroup ASN
    \brief Prints the contents of an ASN.1 string to a BIO, replacing
    non-printable bytes with '.'. Mirrors OpenSSL's ASN1_STRING_print().

    \return length Number of characters written on success.
    \return WOLFSSL_FAILURE on error.

    \param out BIO to write to.
    \param str WOLFSSL_ASN1_STRING to print.

    _Example_
    \code
    wolfSSL_ASN1_STRING_print(bio, s);
    \endcode

    \sa wolfSSL_ASN1_STRING_print_ex
*/
int wolfSSL_ASN1_STRING_print(WOLFSSL_BIO *out, WOLFSSL_ASN1_STRING *str);

/*!
    \ingroup ASN
    \brief Prints the contents of an ASN.1 string to a BIO using a set
    of flags that control formatting, escaping, and whether the string
    type is shown. Mirrors OpenSSL's ASN1_STRING_print_ex().

    \return length Number of characters written on success.
    \return WOLFSSL_FAILURE on error.

    \param out BIO to write the output to.
    \param str WOLFSSL_ASN1_STRING to print.
    \param flags Bitwise OR of ASN1_STRFLGS_* values controlling output.

    _Example_
    \code
    wolfSSL_ASN1_STRING_print_ex(bio, s, ASN1_STRFLGS_RFC2253);
    \endcode

    \sa wolfSSL_ASN1_STRING_print
*/
int wolfSSL_ASN1_STRING_print_ex(WOLFSSL_BIO *out, WOLFSSL_ASN1_STRING *str, unsigned long flags);

/*!
    \ingroup ASN
    \brief Allocates and initializes a new WOLFSSL_ASN1_INTEGER set to 0.
    Must be released with wolfSSL_ASN1_INTEGER_free().

    \return pointer Newly allocated WOLFSSL_ASN1_INTEGER.
    \return NULL on allocation failure.

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* i = wolfSSL_ASN1_INTEGER_new();
    wolfSSL_ASN1_INTEGER_free(i);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_free
    \sa wolfSSL_ASN1_INTEGER_set
*/
WOLFSSL_ASN1_INTEGER* wolfSSL_ASN1_INTEGER_new(void);

/*!
    \ingroup ASN
    \brief Frees a WOLFSSL_ASN1_INTEGER and any data it owns. Has no
    effect when in is NULL.

    \return none No return value.

    \param in WOLFSSL_ASN1_INTEGER to free.

    _Example_
    \code
    wolfSSL_ASN1_INTEGER_free(i);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_new
*/
void wolfSSL_ASN1_INTEGER_free(WOLFSSL_ASN1_INTEGER* in);

/*!
    \ingroup ASN
    \brief Sets the value of a WOLFSSL_ASN1_INTEGER to the signed long v,
    encoding the value into the structure's internal DER buffer.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if a is NULL or on encoding error.

    \param a WOLFSSL_ASN1_INTEGER to update.
    \param v Signed long value to store.

    _Example_
    \code
    WOLFSSL_ASN1_INTEGER* i = wolfSSL_ASN1_INTEGER_new();
    wolfSSL_ASN1_INTEGER_set(i, 12345);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_get
    \sa wolfSSL_ASN1_INTEGER_new
*/
int wolfSSL_ASN1_INTEGER_set(WOLFSSL_ASN1_INTEGER *a, long v);

/*!
    \ingroup ASN
    \brief Returns the value stored in a WOLFSSL_ASN1_INTEGER as a signed
    long. Mirrors OpenSSL's ASN1_INTEGER_get().

    \return value The decoded signed long value on success.
    \return 0 If a is NULL (matches OpenSSL behaviour for the NULL case).
    \return -1 If the value cannot be represented as a long.

    \param a WOLFSSL_ASN1_INTEGER to read.

    _Example_
    \code
    long v = wolfSSL_ASN1_INTEGER_get(i);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_set
    \sa wolfSSL_ASN1_INTEGER_to_BN
*/
long wolfSSL_ASN1_INTEGER_get(const WOLFSSL_ASN1_INTEGER* a);

/*!
    \ingroup ASN
    \brief Returns the length in bytes of the encoded integer data held
    in a WOLFSSL_ASN1_INTEGER.

    \return length Number of bytes of integer data.
    \return 0 If ai is NULL.

    \param ai WOLFSSL_ASN1_INTEGER to query.

    _Example_
    \code
    int len = wolfSSL_ASN1_INTEGER_get_length(i);
    \endcode

    \sa wolfSSL_ASN1_INTEGER_get
    \sa wolfSSL_ASN1_INTEGER_get0_data
*/
int wolfSSL_ASN1_INTEGER_get_length(const WOLFSSL_ASN1_INTEGER* ai);

/*!
    \ingroup ASN
    \brief Allocates and initializes a new empty WOLFSSL_ASN1_TIME
    structure. Must be released with wolfSSL_ASN1_TIME_free().

    \return pointer Newly allocated WOLFSSL_ASN1_TIME.
    \return NULL on allocation failure.

    _Example_
    \code
    WOLFSSL_ASN1_TIME* t = wolfSSL_ASN1_TIME_new();
    wolfSSL_ASN1_TIME_free(t);
    \endcode

    \sa wolfSSL_ASN1_TIME_free
    \sa wolfSSL_ASN1_TIME_set
*/
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_TIME_new(void);

/*!
    \ingroup ASN
    \brief Frees a WOLFSSL_ASN1_TIME structure. Has no effect when t is
    NULL.

    \return none No return value.

    \param t WOLFSSL_ASN1_TIME to free.

    _Example_
    \code
    wolfSSL_ASN1_TIME_free(t);
    \endcode

    \sa wolfSSL_ASN1_TIME_new
*/
void wolfSSL_ASN1_TIME_free(WOLFSSL_ASN1_TIME* t);

/*!
    \ingroup ASN
    \brief Sets a WOLFSSL_ASN1_TIME to the time value t (in seconds since
    the Unix epoch). If s is NULL a new structure is allocated. The
    resulting object encodes either UTCTime or GeneralizedTime depending
    on the year.

    \return pointer Pointer to the populated WOLFSSL_ASN1_TIME (s if
    non-NULL, otherwise a newly allocated one).
    \return NULL on error.

    \param s Existing WOLFSSL_ASN1_TIME to update, or NULL to allocate.
    \param t time_t value to encode.

    _Example_
    \code
    WOLFSSL_ASN1_TIME* t = wolfSSL_ASN1_TIME_set(NULL, time(NULL));
    \endcode

    \sa wolfSSL_ASN1_TIME_new
    \sa wolfSSL_ASN1_TIME_set_string
    \sa wolfSSL_ASN1_UTCTIME_set
*/
WOLFSSL_ASN1_TIME *wolfSSL_ASN1_TIME_set(WOLFSSL_ASN1_TIME *s, time_t t);

/*!
    \ingroup ASN
    \brief Parses an ASCII time string in either UTCTime ("YYMMDDHHMMSSZ")
    or GeneralizedTime ("YYYYMMDDHHMMSSZ") form and stores it in s.
    If s is NULL the function only validates the string format.

    \return WOLFSSL_SUCCESS If the string is a valid ASN.1 time.
    \return WOLFSSL_FAILURE If the string is malformed.

    \param s WOLFSSL_ASN1_TIME to populate, or NULL to validate only.
    \param str NUL-terminated time string.

    _Example_
    \code
    WOLFSSL_ASN1_TIME* t = wolfSSL_ASN1_TIME_new();
    wolfSSL_ASN1_TIME_set_string(t, "230101000000Z");
    \endcode

    \sa wolfSSL_ASN1_TIME_set
    \sa wolfSSL_ASN1_TIME_check
*/
int wolfSSL_ASN1_TIME_set_string(WOLFSSL_ASN1_TIME *s, const char *str);

/*!
    \ingroup ASN
    \brief Validates that the WOLFSSL_ASN1_TIME structure contains a
    well-formed UTCTime or GeneralizedTime value.

    \return WOLFSSL_SUCCESS If the value is a valid ASN.1 time.
    \return WOLFSSL_FAILURE If the value is invalid or a is NULL.

    \param a WOLFSSL_ASN1_TIME to validate.

    _Example_
    \code
    if (wolfSSL_ASN1_TIME_check(t) != WOLFSSL_SUCCESS) {
        // not a valid time
    }
    \endcode

    \sa wolfSSL_ASN1_TIME_set
    \sa wolfSSL_ASN1_TIME_set_string
*/
int wolfSSL_ASN1_TIME_check(const WOLFSSL_ASN1_TIME* a);

/*!
    \ingroup ASN
    \brief Prints a human-readable representation of a WOLFSSL_ASN1_TIME
    value to the given BIO (e.g. "Mar 13 00:00:00 2024 GMT").

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio BIO to write the formatted time to.
    \param asnTime WOLFSSL_ASN1_TIME to print.

    _Example_
    \code
    wolfSSL_ASN1_TIME_print(bio, t);
    \endcode

    \sa wolfSSL_ASN1_TIME_to_string
    \sa wolfSSL_ASN1_TIME_to_tm
*/
int wolfSSL_ASN1_TIME_print(WOLFSSL_BIO* bio, const WOLFSSL_ASN1_TIME* asnTime);

/*!
    \ingroup ASN
    \brief Converts a WOLFSSL_ASN1_TIME value into a broken-down struct
    tm in UTC. If tm is NULL the call only validates asnTime.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error or invalid asnTime.

    \param asnTime WOLFSSL_ASN1_TIME to convert.
    \param tm Destination struct tm, or NULL to validate only.

    _Example_
    \code
    struct tm out;
    wolfSSL_ASN1_TIME_to_tm(t, &out);
    \endcode

    \sa wolfSSL_ASN1_TIME_print
    \sa wolfSSL_ASN1_TIME_set
*/
int wolfSSL_ASN1_TIME_to_tm(const WOLFSSL_ASN1_TIME* asnTime, struct tm* tm);

/*!
    \ingroup ASN
    \brief Returns the length in bytes of the encoded data portion of a
    WOLFSSL_ASN1_TIME structure.

    \return length Number of bytes of time data.
    \return 0 If t is NULL.

    \param t WOLFSSL_ASN1_TIME to query.

    _Example_
    \code
    int len = wolfSSL_ASN1_TIME_get_length(t);
    \endcode

    \sa wolfSSL_ASN1_TIME_get_data
*/
int wolfSSL_ASN1_TIME_get_length(const WOLFSSL_ASN1_TIME *t);

/*!
    \ingroup ASN
    \brief Returns a pointer to the internal encoded data buffer of a
    WOLFSSL_ASN1_TIME structure.

    \return pointer Pointer to the encoded time data.
    \return NULL If t is NULL.

    \param t WOLFSSL_ASN1_TIME to query.

    _Example_
    \code
    unsigned char* data = wolfSSL_ASN1_TIME_get_data(t);
    int len = wolfSSL_ASN1_TIME_get_length(t);
    \endcode

    \sa wolfSSL_ASN1_TIME_get_length
*/
unsigned char* wolfSSL_ASN1_TIME_get_data(const WOLFSSL_ASN1_TIME *t);

/*!
    \ingroup ASN
    \brief Sets a WOLFSSL_ASN1_TIME to the time value t encoded as
    UTCTime. If s is NULL a new structure is allocated. Mirrors
    OpenSSL's ASN1_UTCTIME_set().

    \return pointer Pointer to the populated WOLFSSL_ASN1_TIME.
    \return NULL on error.

    \param s Existing WOLFSSL_ASN1_TIME to update, or NULL to allocate.
    \param t time_t value to encode.

    _Example_
    \code
    WOLFSSL_ASN1_TIME* t = wolfSSL_ASN1_UTCTIME_set(NULL, time(NULL));
    \endcode

    \sa wolfSSL_ASN1_TIME_set
    \sa wolfSSL_ASN1_TIME_free
*/
WOLFSSL_ASN1_TIME* wolfSSL_ASN1_UTCTIME_set(WOLFSSL_ASN1_TIME *s, time_t t);

/*!
    \ingroup ASN
    \brief Frees a WOLFSSL_ASN1_GENERALIZEDTIME structure. Has no effect
    when the argument is NULL.

    \return none No return value.

    \param asn1Time WOLFSSL_ASN1_GENERALIZEDTIME to free.

    _Example_
    \code
    wolfSSL_ASN1_GENERALIZEDTIME_free(gt);
    \endcode

    \sa wolfSSL_ASN1_TIME_free
*/
void wolfSSL_ASN1_GENERALIZEDTIME_free(WOLFSSL_ASN1_GENERALIZEDTIME*);

/*!
    \ingroup ASN
    \brief Allocates and initializes a new WOLFSSL_ASN1_BIT_STRING.
    Must be released with wolfSSL_ASN1_BIT_STRING_free().

    \return pointer Newly allocated WOLFSSL_ASN1_BIT_STRING.
    \return NULL on allocation failure.

    _Example_
    \code
    WOLFSSL_ASN1_BIT_STRING* bs = wolfSSL_ASN1_BIT_STRING_new();
    wolfSSL_ASN1_BIT_STRING_free(bs);
    \endcode

    \sa wolfSSL_ASN1_BIT_STRING_free
    \sa wolfSSL_ASN1_BIT_STRING_set_bit
*/
WOLFSSL_ASN1_BIT_STRING* wolfSSL_ASN1_BIT_STRING_new(void);

/*!
    \ingroup ASN
    \brief Frees a WOLFSSL_ASN1_BIT_STRING and its data. Has no effect
    when str is NULL.

    \return none No return value.

    \param str WOLFSSL_ASN1_BIT_STRING to free.

    _Example_
    \code
    wolfSSL_ASN1_BIT_STRING_free(bs);
    \endcode

    \sa wolfSSL_ASN1_BIT_STRING_new
*/
void wolfSSL_ASN1_BIT_STRING_free(WOLFSSL_ASN1_BIT_STRING* str);

/*!
    \ingroup ASN
    \brief Allocates and initializes a new WOLFSSL_ASN1_TYPE wrapper.
    The structure represents an ASN.1 ANY value and must be released
    with wolfSSL_ASN1_TYPE_free().

    \return pointer Newly allocated WOLFSSL_ASN1_TYPE.
    \return NULL on allocation failure.

    _Example_
    \code
    WOLFSSL_ASN1_TYPE* at = wolfSSL_ASN1_TYPE_new();
    wolfSSL_ASN1_TYPE_free(at);
    \endcode

    \sa wolfSSL_ASN1_TYPE_free
*/
WOLFSSL_ASN1_TYPE* wolfSSL_ASN1_TYPE_new(void);

/*!
    \ingroup ASN
    \brief Frees a WOLFSSL_ASN1_TYPE wrapper, releasing the inner value
    appropriate to its type. Has no effect when at is NULL.

    \return none No return value.

    \param at WOLFSSL_ASN1_TYPE to free.

    _Example_
    \code
    wolfSSL_ASN1_TYPE_free(at);
    \endcode

    \sa wolfSSL_ASN1_TYPE_new
*/
void wolfSSL_ASN1_TYPE_free(WOLFSSL_ASN1_TYPE* at);

/*!
    \ingroup ASN
    \brief Returns the short textual name of an ASN.1 universal tag
    (e.g. "UTF8STRING", "INTEGER", "BIT STRING"). Returns NULL for
    unknown tag values.

    \return pointer Constant string naming the tag.
    \return NULL If the tag value is not recognised.

    \param tag ASN.1 universal tag number.

    _Example_
    \code
    const char* name = wolfSSL_ASN1_tag2str(V_ASN1_UTF8STRING);
    \endcode

    \sa wolfSSL_ASN1_STRING_type
*/
const char *wolfSSL_ASN1_tag2str(int tag);

/*!
    \ingroup Setup
    \brief Equivalent to wolfSSL_CTX_new() but allows a custom heap hint
    to be passed in for static memory or custom allocator use. The heap
    pointer is stored in the context and used for subsequent allocations.

    \return WOLFSSL_CTX* On success, returns a pointer to a newly created
    WOLFSSL_CTX structure.
    \return NULL on failure.

    \param method pointer to the desired WOLFSSL_METHOD.
    \param heap heap hint pointer used for memory allocations.

    _Example_
    \code
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new_ex(wolfTLSv1_3_client_method(), myHeap);
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
WOLFSSL_CTX* wolfSSL_CTX_new_ex(WOLFSSL_METHOD* method, void* heap);

/*!
    \ingroup Setup
    \brief Increments the reference count of the WOLFSSL_CTX so it is
    not freed until matching wolfSSL_CTX_free() calls have been made.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    if (wolfSSL_CTX_up_ref(ctx) != WOLFSSL_SUCCESS) {
        // error
    }
    \endcode

    \sa wolfSSL_CTX_new
    \sa wolfSSL_CTX_free
*/
int wolfSSL_CTX_up_ref(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the size in bytes of the internal WOLFSSL_CTX structure.
    Useful for static memory builds when allocating buffers up front.

    \return int Size in bytes of the WOLFSSL_CTX structure.

    _Example_
    \code
    int size = wolfSSL_CTX_GetObjectSize();
    \endcode

    \sa wolfSSL_GetObjectSize
    \sa wolfSSL_METHOD_GetObjectSize
*/
int wolfSSL_CTX_GetObjectSize(void);

/*!
    \ingroup Setup
    \brief Returns the heap hint that was associated with the
    WOLFSSL_CTX when it was created (or with the WOLFSSL when one
    is provided). Used internally for custom allocator support.

    \return void* The heap hint pointer.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param ssl optional pointer to a WOLFSSL session; when non-NULL its
    heap hint is returned, otherwise the ctx heap is returned.

    _Example_
    \code
    void* heap = wolfSSL_CTX_GetHeap(ctx, NULL);
    \endcode

    \sa wolfSSL_CTX_new_ex
*/
void* wolfSSL_CTX_GetHeap(WOLFSSL_CTX* ctx, WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Indicates whether any of the private key callbacks (PK)
    such as ECC sign, RSA sign, or DH agree are registered with the
    context.

    \return 1 If at least one private key callback is set.
    \return 0 Otherwise.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    if (wolfSSL_CTX_IsPrivatePkSet(ctx)) { ... }
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_SetRsaSignCb
*/
int wolfSSL_CTX_IsPrivatePkSet(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Allocates and seeds a new random number generator inside
    the WOLFSSL_CTX. Used so that internal RNG operations can be
    shared by sessions created from the context.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_new_rng(ctx);
    \endcode

    \sa wolfSSL_CTX_new
*/
int wolfSSL_CTX_new_rng(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Enables or disables the Encrypt-Then-MAC extension (RFC 7366)
    for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param set non-zero to allow Encrypt-Then-MAC, 0 to disallow.

    _Example_
    \code
    wolfSSL_CTX_AllowEncryptThenMac(ctx, 1);
    \endcode

    \sa wolfSSL_AllowEncryptThenMac
*/
int wolfSSL_CTX_AllowEncryptThenMac(WOLFSSL_CTX* ctx, int set);

/*!
    \ingroup Setup
    \brief Disables the TLS Extended Master Secret extension (RFC 7627)
    for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_DisableExtendedMasterSecret(ctx);
    \endcode

    \sa wolfSSL_DisableExtendedMasterSecret
*/
int wolfSSL_CTX_DisableExtendedMasterSecret(WOLFSSL_CTX* ctx);

/*!
    \ingroup OCSP
    \brief Disables OCSP stapling (TLS Certificate Status Request extension)
    for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_DisableOCSPStapling(ctx);
    \endcode

    \sa wolfSSL_CTX_EnableOCSPStapling
*/
int wolfSSL_CTX_DisableOCSPStapling(WOLFSSL_CTX* ctx);

/*!
    \ingroup OCSP
    \brief Enables the OCSP must-staple TLS extension on sessions
    created from this context. When set, the peer is required to
    provide a stapled OCSP response.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_EnableOCSPMustStaple(ctx);
    \endcode

    \sa wolfSSL_CTX_DisableOCSPMustStaple
*/
int wolfSSL_CTX_EnableOCSPMustStaple(WOLFSSL_CTX* ctx);

/*!
    \ingroup OCSP
    \brief Disables the OCSP must-staple extension on sessions
    created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_DisableOCSPMustStaple(ctx);
    \endcode

    \sa wolfSSL_CTX_EnableOCSPMustStaple
*/
int wolfSSL_CTX_DisableOCSPMustStaple(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertManager
    \brief Returns the internal WOLFSSL_CERT_MANAGER associated with
    the given context. Use this to share CA data, CRLs, and OCSP state
    with code that takes a cert manager.

    \return WOLFSSL_CERT_MANAGER* On success.
    \return NULL If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_CERT_MANAGER* cm = wolfSSL_CTX_GetCertManager(ctx);
    \endcode

    \sa wolfSSL_CertManagerNew
*/
WOLFSSL_CERT_MANAGER* wolfSSL_CTX_GetCertManager(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Loads a CRL file (PEM or DER) into the context's cert
    manager. The file may be monitored for changes when supported.

    \return WOLFSSL_SUCCESS On success.
    \return < 0 On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param path path to the CRL file.
    \param type WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.

    _Example_
    \code
    wolfSSL_CTX_LoadCRLFile(ctx, "./crl.pem", WOLFSSL_FILETYPE_PEM);
    \endcode

    \sa wolfSSL_CTX_LoadCRL
    \sa wolfSSL_CTX_EnableCRL
*/
int wolfSSL_CTX_LoadCRLFile(WOLFSSL_CTX* ctx, const char* path, int type);

/*!
    \ingroup Setup
    \brief Disables session tickets for TLS 1.2 sessions created from
    the context. TLS 1.3 ticket handling is unaffected.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_NoTicketTLSv12(ctx);
    \endcode

    \sa wolfSSL_NoTicketTLSv12
*/
int wolfSSL_CTX_NoTicketTLSv12(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertManager
    \brief Registers an application callback used to fetch a CRL when
    it is not available locally. The callback receives the issuer URL
    and provides the CRL contents back to wolfSSL.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CbCrlIO callback used to retrieve CRLs.

    _Example_
    \code
    wolfSSL_CTX_SetCRL_IOCb(ctx, myCrlIoCb);
    \endcode

    \sa wolfSSL_CTX_EnableCRL
    \sa wolfSSL_CTX_LoadCRL
*/
int wolfSSL_CTX_SetCRL_IOCb(WOLFSSL_CTX* ctx, CbCrlIO cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to perform ECC key generation
    on behalf of wolfSSL (PK callback). The callback signature is
    typedef int (*CallbackEccKeyGen)(WOLFSSL* ssl, ecc_key* key,
    unsigned int keySz, int ecc_curve, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackEccKeyGen callback to register.

    _Example_
    \code
    wolfSSL_CTX_SetEccKeyGenCb(ctx, myEccKeyGenCb);
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_SetEccSharedSecretCb
*/
void wolfSSL_CTX_SetEccKeyGenCb(WOLFSSL_CTX* ctx, CallbackEccKeyGen cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to perform ECC shared secret
    derivation. The callback signature is
    typedef int (*CallbackEccSharedSecret)(WOLFSSL* ssl, ecc_key* otherKey,
    unsigned char* pubKeyDer, word32* pubKeySz, unsigned char* out,
    word32* outlen, int side, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackEccSharedSecret to register.

    _Example_
    \code
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, myEccSharedSecretCb);
    \endcode

    \sa wolfSSL_CTX_SetEccSignCb
    \sa wolfSSL_CTX_SetEccKeyGenCb
*/
void wolfSSL_CTX_SetEccSharedSecretCb(WOLFSSL_CTX* ctx, CallbackEccSharedSecret cb);

/*!
    \ingroup Setup
    \brief Enables or disables the Encrypted Client Hello (ECH) extension
    on sessions created from the context.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param enable non-zero to enable ECH, 0 to disable.

    _Example_
    \code
    wolfSSL_CTX_SetEchEnable(ctx, 1);
    \endcode

    \sa wolfSSL_SetEchConfigs
*/
void wolfSSL_CTX_SetEchEnable(WOLFSSL_CTX* ctx, byte enable);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to perform combined MAC + encrypt
    in a single operation. The callback signature is
    typedef int (*CallbackEncryptMac)(WOLFSSL* ssl, unsigned char* macOut,
    int content, int macVerify, unsigned char* encOut,
    const unsigned char* encIn, unsigned int encSz, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackEncryptMac to register.

    _Example_
    \code
    wolfSSL_CTX_SetEncryptMacCb(ctx, myEncMacCb);
    \endcode

    \sa wolfSSL_CTX_SetMacEncryptCb
    \sa wolfSSL_CTX_SetVerifyMacCb
*/
void wolfSSL_CTX_SetEncryptMacCb(WOLFSSL_CTX* ctx, CallbackEncryptMac cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to perform HKDF-Extract for TLS 1.3
    key schedule derivations. The callback signature is
    typedef int (*CallbackHKDFExtract)(byte* prk, const byte* salt,
    word32 saltLen, byte* ikm, word32 ikmLen, int digest, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackHKDFExtract to register.

    _Example_
    \code
    wolfSSL_CTX_SetHKDFExtractCb(ctx, myHkdfExtractCb);
    \endcode

    \sa wolfSSL_CTX_SetTlsFinishedCb
*/
void wolfSSL_CTX_SetHKDFExtractCb(WOLFSSL_CTX* ctx, CallbackHKDFExtract cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to perform RSA-PSS signing. The
    callback signature is
    typedef int (*CallbackRsaPssSign)(WOLFSSL* ssl, const unsigned char* in,
    unsigned int inSz, unsigned char* out, unsigned int* outSz,
    int hash, int mgf, const unsigned char* keyDer, unsigned int keySz,
    void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackRsaPssSign to register.

    _Example_
    \code
    wolfSSL_CTX_SetRsaPssSignCb(ctx, myPssSignCb);
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
*/
void wolfSSL_CTX_SetRsaPssSignCb(WOLFSSL_CTX* ctx, CallbackRsaPssSign cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to verify an RSA signature that
    was produced earlier by the registered RSA sign callback. Used
    for self-test of the sign operation. The callback signature is
    the same as the RSA verify callback.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackRsaVerify to register.

    _Example_
    \code
    wolfSSL_CTX_SetRsaSignCheckCb(ctx, myRsaVerifyCb);
    \endcode

    \sa wolfSSL_CTX_SetRsaSignCb
    \sa wolfSSL_CTX_SetRsaVerifyCb
*/
void wolfSSL_CTX_SetRsaSignCheckCb(WOLFSSL_CTX* ctx, CallbackRsaVerify cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback invoked when the TLS Finished message
    is being computed, allowing an external module to supply the value.
    The callback signature is
    typedef int (*CallbackTlsFinished)(WOLFSSL* ssl, const byte* side,
    const byte* handshake_hash, word32 hashSz, byte* hashes, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackTlsFinished to register.

    _Example_
    \code
    wolfSSL_CTX_SetTlsFinishedCb(ctx, myFinishedCb);
    \endcode

    \sa wolfSSL_CTX_SetHKDFExtractCb
*/
void wolfSSL_CTX_SetTlsFinishedCb(WOLFSSL_CTX* ctx, CallbackTlsFinished cb);

/*!
    \ingroup Setup
    \brief Sets the size (in bytes) of the ephemeral ECDHE key that
    will be generated for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL or sz is invalid.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param sz key size in bytes (e.g. 32 for P-256).

    _Example_
    \code
    wolfSSL_CTX_SetTmpEC_DHE_Sz(ctx, 32);
    \endcode

    \sa wolfSSL_SetTmpEC_DHE_Sz
*/
int wolfSSL_CTX_SetTmpEC_DHE_Sz(WOLFSSL_CTX* ctx, word16 sz);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to verify a MAC over received
    data when MAC and decrypt are performed in separate operations.
    The callback signature is
    typedef int (*CallbackVerifyMac)(WOLFSSL* ssl, const byte* message,
    word32 messageSz, word32 macSz, word32 content, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackVerifyMac to register.

    _Example_
    \code
    wolfSSL_CTX_SetVerifyMacCb(ctx, myVerifyMacCb);
    \endcode

    \sa wolfSSL_CTX_SetEncryptMacCb
*/
void wolfSSL_CTX_SetVerifyMacCb(WOLFSSL_CTX* ctx, CallbackVerifyMac cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to generate an X25519 key pair.
    The callback signature is
    typedef int (*CallbackX25519KeyGen)(WOLFSSL* ssl, struct curve25519_key* key,
    unsigned int keySz, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackX25519KeyGen to register.

    _Example_
    \code
    wolfSSL_CTX_SetX25519KeyGenCb(ctx, myX25519KeyGenCb);
    \endcode

    \sa wolfSSL_CTX_SetEccKeyGenCb
*/
void wolfSSL_CTX_SetX25519KeyGenCb(WOLFSSL_CTX* ctx, CallbackX25519KeyGen cb);

/*!
    \ingroup CertsKeys
    \brief Registers a callback used to generate an X448 key pair.
    The callback signature is
    typedef int (*CallbackX448KeyGen)(WOLFSSL* ssl, struct curve448_key* key,
    unsigned int keySz, void* ctx);

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb CallbackX448KeyGen to register.

    _Example_
    \code
    wolfSSL_CTX_SetX448KeyGenCb(ctx, myX448KeyGenCb);
    \endcode

    \sa wolfSSL_CTX_SetX25519KeyGenCb
*/
void wolfSSL_CTX_SetX448KeyGenCb(WOLFSSL_CTX* ctx, CallbackX448KeyGen cb);

/*!
    \ingroup Setup
    \brief Restricts a server context to only present client-side
    cipher suites. Primarily used in test harnesses.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_UseClientSuites(ctx);
    \endcode

    \sa wolfSSL_UseClientSuites
*/
int wolfSSL_CTX_UseClientSuites(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Enables support for secure renegotiation (RFC 5746) on
    sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_UseSecureRenegotiation(ctx);
    \endcode

    \sa wolfSSL_UseSecureRenegotiation
    \sa wolfSSL_Rehandshake
*/
int wolfSSL_CTX_UseSecureRenegotiation(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Adds an additional certificate to the context's extra chain
    without bumping the reference count of the X509 object. The context
    takes ownership of the reference.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param x509 the WOLFSSL_X509 to add. Ownership is transferred.

    _Example_
    \code
    wolfSSL_CTX_add0_chain_cert(ctx, x509);
    \endcode

    \sa wolfSSL_CTX_add1_chain_cert
    \sa wolfSSL_CTX_add_extra_chain_cert
*/
int wolfSSL_CTX_add0_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Adds an additional certificate to the context's extra chain,
    incrementing the X509 reference count. The caller retains ownership
    of its reference and must still free it.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param x509 the WOLFSSL_X509 to add.

    _Example_
    \code
    wolfSSL_CTX_add1_chain_cert(ctx, x509);
    \endcode

    \sa wolfSSL_CTX_add0_chain_cert
*/
int wolfSSL_CTX_add1_chain_cert(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Adds a certificate to the client CA list that will be sent
    in a CertificateRequest message to the peer. The reference count
    of the X509 is incremented.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param x509 CA certificate to add to the list.

    _Example_
    \code
    wolfSSL_CTX_add1_to_CA_list(ctx, caX509);
    \endcode

    \sa wolfSSL_CTX_add_client_CA
*/
int wolfSSL_CTX_add1_to_CA_list(WOLFSSL_CTX *ctx, WOLFSSL_X509 *x509);

/*!
    \ingroup CertsKeys
    \brief Adds a CA certificate to the list that is sent to clients
    in a TLS CertificateRequest message. Names accumulated through
    repeated calls form the client_CA_list.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param x509 CA certificate to add.

    _Example_
    \code
    wolfSSL_CTX_add_client_CA(ctx, caX509);
    \endcode

    \sa wolfSSL_CTX_add1_to_CA_list
*/
int wolfSSL_CTX_add_client_CA(WOLFSSL_CTX* ctx, WOLFSSL_X509* x509);

/*!
    \ingroup Setup
    \brief Generic callback-control entry point used by OpenSSL
    compatibility code. Forwards to the appropriate internal handler
    based on cmd. Most applications will not call this directly.

    \return long Command-specific value.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cmd command identifier.
    \param fp function pointer to install.

    _Example_
    \code
    wolfSSL_CTX_callback_ctrl(ctx, cmd, (void(*)(void))cb);
    \endcode

    \sa wolfSSL_CTX_ctrl
*/
long wolfSSL_CTX_callback_ctrl(WOLFSSL_CTX* ctx, int cmd, void (*fp)(void));

/*!
    \ingroup CertsKeys
    \brief Checks that the configured private key matches the loaded
    public certificate.

    \return WOLFSSL_SUCCESS On match.
    \return WOLFSSL_FAILURE On mismatch or if cert/key are missing.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    if (wolfSSL_CTX_check_private_key(ctx) != WOLFSSL_SUCCESS) { ... }
    \endcode

    \sa wolfSSL_check_private_key
*/
int wolfSSL_CTX_check_private_key(const WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Frees and removes any certificates previously added with
    wolfSSL_CTX_add_extra_chain_cert() or the add0/add1 variants.

    \return 1 On success.
    \return 0 On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_clear_extra_chain_certs(ctx);
    \endcode

    \sa wolfSSL_CTX_add_extra_chain_cert
*/
long wolfSSL_CTX_clear_extra_chain_certs(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Clears mode flags previously set with wolfSSL_CTX_set_mode().

    \return long The mode value after clearing.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode bitmask of mode flags to clear.

    _Example_
    \code
    wolfSSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);
    \endcode

    \sa wolfSSL_CTX_set_mode
    \sa wolfSSL_CTX_get_mode
*/
long wolfSSL_CTX_clear_mode(WOLFSSL_CTX* ctx, long mode);

/*!
    \ingroup Setup
    \brief Generic ctrl entry point providing the OpenSSL
    SSL_CTX_ctrl() interface. The cmd value selects which operation
    to perform; opt and pt provide command-specific parameters.

    \return long Command-specific result.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cmd command identifier.
    \param opt numeric option value.
    \param pt pointer option value.

    _Example_
    \code
    wolfSSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, 0, NULL);
    \endcode

    \sa wolfSSL_CTX_callback_ctrl
*/
long wolfSSL_CTX_ctrl(WOLFSSL_CTX* ctx, int cmd, long opt, void* pt);

/*!
    \ingroup Setup
    \brief Sets the maximum DTLS record size to the given value. Used
    to limit fragment size for path MTU constrained networks.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL or mtu is invalid.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mtu maximum transmission unit in bytes.

    _Example_
    \code
    wolfSSL_CTX_dtls_set_mtu(ctx, 1400);
    \endcode

    \sa wolfSSL_dtls_set_mtu
*/
int wolfSSL_CTX_dtls_set_mtu(WOLFSSL_CTX* ctx, unsigned short mtu);

/*!
    \ingroup Setup
    \brief Enables DTLS over SCTP mode on the context. When enabled,
    wolfSSL relies on SCTP's reliability and ordering and avoids its
    own retransmission timers.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_dtls_set_sctp(ctx);
    \endcode

    \sa wolfSSL_dtls_set_sctp
*/
int wolfSSL_CTX_dtls_set_sctp(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Removes expired sessions from the context's session cache.
    Sessions whose start time is older than tm are evicted.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param tm cutoff time in seconds since the epoch.

    _Example_
    \code
    wolfSSL_CTX_flush_sessions(ctx, time(NULL));
    \endcode

    \sa wolfSSL_flush_sessions
*/
void wolfSSL_CTX_flush_sessions(WOLFSSL_CTX* ctx, long tm);

/*!
    \ingroup CertsKeys
    \brief Returns the certificate that was configured on the context
    with wolfSSL_CTX_use_certificate(). Reference count is not changed.

    \return WOLFSSL_X509* On success.
    \return NULL If no certificate is set.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_X509* cert = wolfSSL_CTX_get0_certificate(ctx);
    \endcode

    \sa wolfSSL_CTX_use_certificate
*/
WOLFSSL_X509* wolfSSL_CTX_get0_certificate(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Returns a pointer to the X509 verify parameter structure
    contained in the context. The structure can be modified to adjust
    certificate verification parameters.

    \return WOLFSSL_X509_VERIFY_PARAM* On success.
    \return NULL If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_X509_VERIFY_PARAM* p = wolfSSL_CTX_get0_param(ctx);
    \endcode

    \sa wolfSSL_CTX_set1_param
*/
WOLFSSL_X509_VERIFY_PARAM* wolfSSL_CTX_get0_param(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Returns the private key configured on the context. Reference
    count is not changed.

    \return WOLFSSL_EVP_PKEY* On success.
    \return NULL If no key is set.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_CTX_get0_privatekey(ctx);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_CTX_get0_privatekey(const WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Retrieves an application-defined pointer that was previously
    stored on the context with wolfSSL_CTX_set_ex_data().

    \return void* The stored pointer, or NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param idx index returned by wolfSSL_CTX_get_ex_new_index().

    _Example_
    \code
    void* data = wolfSSL_CTX_get_ex_data(ctx, idx);
    \endcode

    \sa wolfSSL_CTX_set_ex_data
*/
void* wolfSSL_CTX_get_ex_data(const WOLFSSL_CTX* ctx, int idx);

/*!
    \ingroup Setup
    \brief Returns the maximum amount of TLS 1.3 early data (0-RTT)
    that the server will accept from a client per session.

    \return int Maximum early data size in bytes.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int sz = wolfSSL_CTX_get_max_early_data(ctx);
    \endcode

    \sa wolfSSL_CTX_set_max_early_data
*/
int wolfSSL_CTX_get_max_early_data(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the maximum TLS protocol version currently
    configured on the context.

    \return int Protocol version constant (e.g. TLS1_3_VERSION).

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int v = wolfSSL_CTX_get_max_proto_version(ctx);
    \endcode

    \sa wolfSSL_CTX_set_max_proto_version
*/
int wolfSSL_CTX_get_max_proto_version(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the minimum TLS protocol version currently
    configured on the context.

    \return int Protocol version constant (e.g. TLS1_2_VERSION).

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int v = wolfSSL_CTX_get_min_proto_version(ctx);
    \endcode

    \sa wolfSSL_CTX_set_min_proto_version
*/
int wolfSSL_CTX_get_min_proto_version(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the current bitmask of SSL_MODE_* flags configured
    on the context.

    \return long Currently set mode flags.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long m = wolfSSL_CTX_get_mode(ctx);
    \endcode

    \sa wolfSSL_CTX_set_mode
    \sa wolfSSL_CTX_clear_mode
*/
long wolfSSL_CTX_get_mode(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the maximum number of TLS 1.3 session tickets the
    server will issue per session.

    \return size_t Maximum number of tickets.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    size_t n = wolfSSL_CTX_get_num_tickets(ctx);
    \endcode

    \sa wolfSSL_CTX_set_num_tickets
*/
size_t wolfSSL_CTX_get_num_tickets(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the current bitmask of SSL_OP_* option flags
    configured on the context.

    \return long Currently set option flags.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long opts = wolfSSL_CTX_get_options(ctx);
    \endcode

    \sa wolfSSL_CTX_set_options
*/
long wolfSSL_CTX_get_options(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the OpenSSL-compatible security level configured on
    the context. Levels 0-5 select progressively stricter cryptographic
    parameter requirements.

    \return int Configured security level.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int level = wolfSSL_CTX_get_security_level(ctx);
    \endcode

    \sa wolfSSL_CTX_set_security_level
*/
int wolfSSL_CTX_get_security_level(const WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the current session-cache mode bitmask. See
    wolfSSL_CTX_set_session_cache_mode() for the possible flags.

    \return long Current cache mode flags.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long mode = wolfSSL_CTX_get_session_cache_mode(ctx);
    \endcode

    \sa wolfSSL_CTX_set_session_cache_mode
*/
long wolfSSL_CTX_get_session_cache_mode(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Returns the verify callback previously registered with
    wolfSSL_CTX_set_verify(), or NULL if none was set.

    \return VerifyCallback The registered callback, or NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    VerifyCallback cb = wolfSSL_CTX_get_verify_callback(ctx);
    \endcode

    \sa wolfSSL_CTX_set_verify
*/
VerifyCallback wolfSSL_CTX_get_verify_callback(WOLFSSL_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Returns the verify mode bitmask currently configured on
    the context (see wolfSSL_CTX_set_verify()).

    \return int Current verify mode bitmask.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    int mode = wolfSSL_CTX_get_verify_mode(ctx);
    \endcode

    \sa wolfSSL_CTX_set_verify
*/
int wolfSSL_CTX_get_verify_mode(const WOLFSSL_CTX* ctx);

/*!
    \ingroup IO
    \brief Sets the DTLS multicast member identifier on the context.
    Each member of a multicast group must have a unique ID.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL or id is invalid.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param id member id (0-255).

    _Example_
    \code
    wolfSSL_CTX_mcast_set_member_id(ctx, 1);
    \endcode

    \sa wolfSSL_mcast_set_member_id
*/
int wolfSSL_CTX_mcast_set_member_id(WOLFSSL_CTX* ctx, unsigned short id);

/*!
    \ingroup Setup
    \brief Enables or disables mutual (client) authentication. When
    set, the server requires the client to present a certificate and
    the client requires the server to verify it.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param req 1 to require mutual auth, 0 to disable.

    _Example_
    \code
    wolfSSL_CTX_mutual_auth(ctx, 1);
    \endcode

    \sa wolfSSL_mutual_auth
*/
int wolfSSL_CTX_mutual_auth(WOLFSSL_CTX* ctx, int req);

/*!
    \ingroup Setup
    \brief Restricts the context to only the DHE-PSK key exchange
    suite group, refusing plain PSK suites.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_only_dhe_psk(ctx);
    \endcode

    \sa wolfSSL_CTX_set_psk_server_callback
*/
int wolfSSL_CTX_only_dhe_psk(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of full TLS handshakes (accepts) that
    completed against this context.

    \return long Count of accept operations.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_accept(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_accept_good
*/
long wolfSSL_CTX_sess_accept(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of successful TLS handshakes that
    completed on the server side.

    \return long Count of successful accepts.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_accept_good(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_accept
*/
long wolfSSL_CTX_sess_accept_good(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of renegotiation operations performed
    on the server side.

    \return long Count of server renegotiations.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_accept_renegotiate(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_connect_renegotiate
*/
long wolfSSL_CTX_sess_accept_renegotiate(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of times the session cache had to evict
    an entry because it was full.

    \return long Count of cache-full events.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_cache_full(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_set_cache_size
*/
long wolfSSL_CTX_sess_cache_full(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of session cache hits served via the
    external get-session callback (rather than the internal cache).

    \return long Count of callback hits.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_cb_hits(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_hits
*/
long wolfSSL_CTX_sess_cb_hits(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of full TLS handshakes (connects) the
    client side performed against this context.

    \return long Count of connect operations.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_connect(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_connect_good
*/
long wolfSSL_CTX_sess_connect(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of successful TLS handshakes that
    completed on the client side.

    \return long Count of successful connects.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_connect_good(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_connect
*/
long wolfSSL_CTX_sess_connect_good(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of renegotiation operations performed
    on the client side.

    \return long Count of client renegotiations.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_connect_renegotiate(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_accept_renegotiate
*/
long wolfSSL_CTX_sess_connect_renegotiate(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the maximum number of entries the session cache
    can hold.

    \return long Configured cache size.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long sz = wolfSSL_CTX_sess_get_cache_size(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_set_cache_size
*/
long wolfSSL_CTX_sess_get_cache_size(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of session cache hits served from the
    internal cache.

    \return long Count of cache hits.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_hits(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_misses
*/
long wolfSSL_CTX_sess_hits(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of session cache misses encountered
    when looking up resumption sessions.

    \return long Count of cache misses.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_misses(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_hits
*/
long wolfSSL_CTX_sess_misses(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Returns the number of sessions stored in the internal
    session cache for this context.

    \return long Number of sessions.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_number(ctx);
    \endcode

    \sa wolfSSL_CTX_sess_get_cache_size
*/
long wolfSSL_CTX_sess_number(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Sets the maximum number of entries that the internal
    session cache will hold for this context.

    \return long The previous cache size.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param sz new maximum cache size.

    _Example_
    \code
    wolfSSL_CTX_sess_set_cache_size(ctx, 1024);
    \endcode

    \sa wolfSSL_CTX_sess_get_cache_size
*/
long wolfSSL_CTX_sess_set_cache_size(WOLFSSL_CTX* ctx, long sz);

/*!
    \ingroup Setup
    \brief Returns the number of sessions that were evicted from the
    cache because they timed out.

    \return long Count of timeouts.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    long n = wolfSSL_CTX_sess_timeouts(ctx);
    \endcode

    \sa wolfSSL_CTX_set_timeout
*/
long wolfSSL_CTX_sess_timeouts(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Sets the list of supported elliptic curves for sessions
    created from the context. names is a colon-separated list of
    curve names (e.g. "P-256:P-384:X25519").

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error or unknown curve.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param names colon-separated curve list.

    _Example_
    \code
    wolfSSL_CTX_set1_curves_list(ctx, "P-256:X25519");
    \endcode

    \sa wolfSSL_set1_curves_list
*/
int wolfSSL_CTX_set1_curves_list(WOLFSSL_CTX* ctx, const char* names);

/*!
    \ingroup CertsKeys
    \brief Copies the contents of the given X509 verify parameter
    structure into the context's internal copy.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param vpm source WOLFSSL_X509_VERIFY_PARAM.

    _Example_
    \code
    wolfSSL_CTX_set1_param(ctx, vpm);
    \endcode

    \sa wolfSSL_CTX_get0_param
*/
int wolfSSL_CTX_set1_param(WOLFSSL_CTX* ctx, WOLFSSL_X509_VERIFY_PARAM *vpm);

/*!
    \ingroup Setup
    \brief Sets the supported cipher list for the context from a
    wire-format byte array. The list and listSz arguments contain
    the encoded cipher suite identifiers.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param list buffer of cipher suite bytes.
    \param listSz length of list in bytes.

    _Example_
    \code
    wolfSSL_CTX_set_cipher_list_bytes(ctx, suites, sizeof(suites));
    \endcode

    \sa wolfSSL_CTX_set_cipher_list
*/
int wolfSSL_CTX_set_cipher_list_bytes(WOLFSSL_CTX* ctx, const byte* list, const int listSz);

/*!
    \ingroup IO
    \brief Sets the default read-ahead flag on the context. When set,
    sessions read as much as possible from the transport rather than
    only the next record.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param m non-zero to enable read-ahead, 0 to disable.

    _Example_
    \code
    wolfSSL_CTX_set_default_read_ahead(ctx, 1);
    \endcode

    \sa wolfSSL_CTX_set_read_ahead
*/
void wolfSSL_CTX_set_default_read_ahead(WOLFSSL_CTX* ctx, int m);

/*!
    \ingroup CertsKeys
    \brief Loads the default CA certificates from the locations
    configured at build time. Equivalent to OpenSSL's
    SSL_CTX_set_default_verify_paths().

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().

    _Example_
    \code
    wolfSSL_CTX_set_default_verify_paths(ctx);
    \endcode

    \sa wolfSSL_CTX_load_verify_locations
*/
int wolfSSL_CTX_set_default_verify_paths(WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief OpenSSL compatibility no-op. wolfSSL always negotiates DH
    parameters automatically when DHE suites are configured.

    \return WOLFSSL_SUCCESS Always.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param onoff ignored.

    _Example_
    \code
    wolfSSL_CTX_set_dh_auto(ctx, 1);
    \endcode

    \sa wolfSSL_CTX_SetTmpDH
*/
int wolfSSL_CTX_set_dh_auto(WOLFSSL_CTX* ctx, int onoff);

/*!
    \ingroup Setup
    \brief OpenSSL compatibility no-op. wolfSSL always negotiates
    ECDH curves automatically.

    \return WOLFSSL_SUCCESS Always.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param onoff ignored.

    _Example_
    \code
    wolfSSL_CTX_set_ecdh_auto(ctx, 1);
    \endcode

    \sa wolfSSL_CTX_set1_curves_list
*/
int wolfSSL_CTX_set_ecdh_auto(WOLFSSL_CTX* ctx, int onoff);

/*!
    \ingroup Setup
    \brief Stores an application-defined pointer in the context at the
    given index. The data can later be retrieved with
    wolfSSL_CTX_get_ex_data().

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param idx index returned by wolfSSL_CTX_get_ex_new_index().
    \param data pointer to store.

    _Example_
    \code
    wolfSSL_CTX_set_ex_data(ctx, idx, myPtr);
    \endcode

    \sa wolfSSL_CTX_get_ex_data
*/
int wolfSSL_CTX_set_ex_data(WOLFSSL_CTX* ctx, int idx, void* data);

/*!
    \ingroup Setup
    \brief Sets the maximum TLS protocol version that will be
    negotiated for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On unsupported version.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param version protocol version constant (e.g. TLS1_2_VERSION,
    TLS1_3_VERSION). 0 selects the highest supported.

    _Example_
    \code
    wolfSSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    \endcode

    \sa wolfSSL_CTX_set_min_proto_version
    \sa wolfSSL_CTX_get_max_proto_version
*/
int wolfSSL_CTX_set_max_proto_version(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup Setup
    \brief Sets the minimum TLS protocol version that will be
    negotiated for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On unsupported version.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param version protocol version constant. 0 selects the lowest
    supported.

    _Example_
    \code
    wolfSSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    \endcode

    \sa wolfSSL_CTX_set_max_proto_version
    \sa wolfSSL_CTX_get_min_proto_version
*/
int wolfSSL_CTX_set_min_proto_version(WOLFSSL_CTX* ctx, int version);

/*!
    \ingroup Setup
    \brief Sets SSL_MODE_* mode flags on the context. The new mode is
    the bitwise OR of the previous mode and the supplied value.

    \return long The mode value after the change.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode bitmask of mode flags to set.

    _Example_
    \code
    wolfSSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    \endcode

    \sa wolfSSL_CTX_get_mode
    \sa wolfSSL_CTX_clear_mode
*/
long wolfSSL_CTX_set_mode(WOLFSSL_CTX* ctx, long mode);

/*!
    \ingroup IO
    \brief Registers a message callback that is invoked for each TLS
    record sent or received. The callback signature is
    typedef void (*SSL_Msg_Cb)(int write_p, int version, int content_type,
    const void* buf, size_t len, WOLFSSL* ssl, void* arg);

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb message callback to install.

    _Example_
    \code
    wolfSSL_CTX_set_msg_callback(ctx, myMsgCb);
    \endcode

    \sa wolfSSL_CTX_set_msg_callback_arg
    \sa wolfSSL_set_msg_callback
*/
int wolfSSL_CTX_set_msg_callback(WOLFSSL_CTX *ctx, SSL_Msg_Cb cb);

/*!
    \ingroup IO
    \brief Sets the user argument passed to the message callback
    registered with wolfSSL_CTX_set_msg_callback().

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param arg user pointer passed to the callback.

    _Example_
    \code
    wolfSSL_CTX_set_msg_callback_arg(ctx, myCtx);
    \endcode

    \sa wolfSSL_CTX_set_msg_callback
*/
int wolfSSL_CTX_set_msg_callback_arg(WOLFSSL_CTX *ctx, void* arg);

/*!
    \ingroup Setup
    \brief Sets the maximum number of TLS 1.3 session tickets that
    the server will issue per session.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mxTickets maximum number of tickets.

    _Example_
    \code
    wolfSSL_CTX_set_num_tickets(ctx, 2);
    \endcode

    \sa wolfSSL_CTX_get_num_tickets
*/
int wolfSSL_CTX_set_num_tickets(WOLFSSL_CTX* ctx, size_t mxTickets);

/*!
    \ingroup Setup
    \brief Enables TLS 1.3 post-handshake client authentication for
    sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return BAD_FUNC_ARG If ctx is NULL.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param val non-zero to enable post-handshake auth, 0 to disable.

    _Example_
    \code
    wolfSSL_CTX_set_post_handshake_auth(ctx, 1);
    \endcode

    \sa wolfSSL_set_post_handshake_auth
*/
int wolfSSL_CTX_set_post_handshake_auth(WOLFSSL_CTX* ctx, int val);

/*!
    \ingroup Setup
    \brief Configures quiet shutdown mode. When enabled, wolfSSL
    treats the connection as closed without exchanging close_notify.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param mode non-zero to enable quiet shutdown.

    _Example_
    \code
    wolfSSL_CTX_set_quiet_shutdown(ctx, 1);
    \endcode

    \sa wolfSSL_set_quiet_shutdown
*/
void wolfSSL_CTX_set_quiet_shutdown(WOLFSSL_CTX* ctx, int mode);

/*!
    \ingroup Setup
    \brief Sets the OpenSSL-compatible security level for the context.
    Levels 0-5 progressively require stronger cryptographic parameters
    (e.g. minimum key sizes).

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param level security level (0-5).

    _Example_
    \code
    wolfSSL_CTX_set_security_level(ctx, 2);
    \endcode

    \sa wolfSSL_CTX_get_security_level
*/
void wolfSSL_CTX_set_security_level(WOLFSSL_CTX* ctx, int level);

/*!
    \ingroup Setup
    \brief Sets the user argument passed to the SNI servername
    callback registered with wolfSSL_CTX_set_servername_callback().

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param arg user pointer.

    _Example_
    \code
    wolfSSL_CTX_set_servername_arg(ctx, myCtx);
    \endcode

    \sa wolfSSL_CTX_set_servername_callback
*/
int wolfSSL_CTX_set_servername_arg(WOLFSSL_CTX* ctx, void* arg);

/*!
    \ingroup Setup
    \brief Sets the SRP password used during the TLS-SRP handshake
    for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param password null-terminated SRP password.

    _Example_
    \code
    wolfSSL_CTX_set_srp_password(ctx, "password");
    \endcode

    \sa wolfSSL_CTX_set_srp_username
*/
int wolfSSL_CTX_set_srp_password(WOLFSSL_CTX* ctx, char* password);

/*!
    \ingroup Setup
    \brief Sets the SRP group strength (in bits) used during the
    TLS-SRP handshake.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param strength SRP group strength in bits (e.g. 2048).

    _Example_
    \code
    wolfSSL_CTX_set_srp_strength(ctx, 2048);
    \endcode

    \sa wolfSSL_CTX_set_srp_username
*/
int wolfSSL_CTX_set_srp_strength(WOLFSSL_CTX *ctx, int strength);

/*!
    \ingroup Setup
    \brief Sets the SRP username used during the TLS-SRP handshake
    for sessions created from this context.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param username null-terminated SRP username.

    _Example_
    \code
    wolfSSL_CTX_set_srp_username(ctx, "user");
    \endcode

    \sa wolfSSL_CTX_set_srp_password
*/
int wolfSSL_CTX_set_srp_username(WOLFSSL_CTX* ctx, char* username);

/*!
    \ingroup Setup
    \brief Registers the session ticket encryption callback (OpenSSL
    compatibility form). The callback is invoked when a ticket is
    issued or received and is responsible for encrypting or decrypting
    the ticket payload.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param cb ticketCompatCb callback to register.

    _Example_
    \code
    wolfSSL_CTX_set_tlsext_ticket_key_cb(ctx, myTicketCb);
    \endcode

    \sa wolfSSL_CTX_NoTicketTLSv12
*/
int wolfSSL_CTX_set_tlsext_ticket_key_cb(WOLFSSL_CTX* ctx, ticketCompatCb cb);

/*!
    \ingroup CertsKeys
    \brief Sets the maximum depth of the certificate chain that will
    be accepted during peer verification.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param depth maximum chain depth (excluding the leaf certificate).

    _Example_
    \code
    wolfSSL_CTX_set_verify_depth(ctx, 4);
    \endcode

    \sa wolfSSL_CTX_get_verify_depth
*/
void wolfSSL_CTX_set_verify_depth(WOLFSSL_CTX *ctx, int depth);

/*!
    \ingroup CertsKeys
    \brief Configures an RSA private key on the context from a
    WOLFSSL_RSA structure.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param rsa RSA key to load.

    _Example_
    \code
    wolfSSL_CTX_use_RSAPrivateKey(ctx, rsa);
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey
*/
int wolfSSL_CTX_use_RSAPrivateKey(WOLFSSL_CTX* ctx, WOLFSSL_RSA* rsa);

/*!
    \ingroup CertsKeys
    \brief Loads the given X509 certificate as the context's
    certificate. The reference count of the X509 is increased.

    \return WOLFSSL_SUCCESS On success.
    \return WOLFSSL_FAILURE On error.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param x certificate to use.

    _Example_
    \code
    wolfSSL_CTX_use_certificate(ctx, x509);
    \endcode

    \sa wolfSSL_CTX_use_certificate_file
    \sa wolfSSL_CTX_use_certificate_buffer
*/
int wolfSSL_CTX_use_certificate(WOLFSSL_CTX* ctx, WOLFSSL_X509* x);

/*!
    \ingroup Setup
    \brief OpenSSL compatibility callback registration for installing
    a Diffie-Hellman parameter generation callback. The callback has
    the signature
    WOLFSSL_DH* (*dh)(WOLFSSL* ssl, int is_export, int keylength);
    and should return DH parameters of the requested size. wolfSSL
    invokes the callback when DH parameters are required.

    \param ctx pointer to the SSL context, created with wolfSSL_CTX_new().
    \param dh callback used to provide DH parameters.

    _Example_
    \code
    WOLFSSL_CTX_set_tmp_dh_callback(ctx, myDhCb);
    \endcode

    \sa wolfSSL_CTX_SetTmpDH
*/
void WOLFSSL_CTX_set_tmp_dh_callback(WOLFSSL_CTX *ctx, WOLFSSL_DH *(*dh) (WOLFSSL *ssl, int is_export, int keylength));
/*!
    \ingroup CertsKeys
    \brief OpenSSL compatibility wrapper that initializes a WOLFSSL_X509V3_CTX without an associated configuration database. Used together with wolfSSL_X509V3_set_ctx() when X509 extensions are added programmatically rather than read from a configuration file.

    \return no value, this function does not return.

    \param ctx pointer to the X509V3 context to be initialized.

    _Example_
    \code
    // see wolfSSL_X509V3_set_ctx_nodb usage
    \endcode
*/
void wolfSSL_X509V3_set_ctx_nodb(WOLFSSL_X509V3_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_ACERT (attribute certificate) structure previously allocated by wolfSSL_X509_ACERT_new() or wolfSSL_X509_ACERT_new_ex(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param x509 pointer to the WOLFSSL_X509_ACERT structure to free.

    _Example_
    \code
    // see wolfSSL_X509_ACERT_free usage
    \endcode

    \sa wolfSSL_X509_ACERT_new
    \sa wolfSSL_X509_ACERT_new_ex
*/
void wolfSSL_X509_ACERT_free(WOLFSSL_X509_ACERT* x509);

/*!
    \ingroup CertsKeys
    \brief Returns the certificate-version field of a WOLFSSL_X509_ACERT attribute certificate (zero-based, i.e. v2 returns 1).

    \return version value (>=0) on success.
    \return WOLFSSL_FAILURE if x is NULL.

    \param x pointer to the attribute certificate.

    _Example_
    \code
    // see wolfSSL_X509_ACERT_get_version usage
    \endcode

    \sa wolfSSL_X509_ACERT_version
*/
long wolfSSL_X509_ACERT_get_version(const WOLFSSL_X509_ACERT *x);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_ACERT (attribute certificate) structure using the default heap.

    \return pointer to a newly allocated WOLFSSL_X509_ACERT on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_ACERT_new usage
    \endcode

    \sa wolfSSL_X509_ACERT_new_ex
    \sa wolfSSL_X509_ACERT_free
*/
WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_new(void);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_ACERT (attribute certificate) structure using the supplied heap hint.

    \return pointer to a newly allocated WOLFSSL_X509_ACERT on success.
    \return NULL on failure.

    \param heap heap hint for memory allocation, or NULL for the default heap.

    _Example_
    \code
    // see wolfSSL_X509_ACERT_new_ex usage
    \endcode

    \sa wolfSSL_X509_ACERT_new
    \sa wolfSSL_X509_ACERT_free
*/
WOLFSSL_X509_ACERT * wolfSSL_X509_ACERT_new_ex(void * heap);

/*!
    \ingroup CertsKeys
    \brief Returns the version number of an attribute certificate (e.g. 1 for v1, 2 for v2).

    \return version number on success.
    \return 0 on failure.

    \param x509 pointer to the attribute certificate.

    _Example_
    \code
    // see wolfSSL_X509_ACERT_version usage
    \endcode

    \sa wolfSSL_X509_ACERT_get_version
*/
int  wolfSSL_X509_ACERT_version(WOLFSSL_X509_ACERT* x509);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_ALGOR (AlgorithmIdentifier) structure previously allocated by wolfSSL_X509_ALGOR_new(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param alg pointer to the WOLFSSL_X509_ALGOR structure to free.

    _Example_
    \code
    // see wolfSSL_X509_ALGOR_free usage
    \endcode

    \sa wolfSSL_X509_ALGOR_new
*/
void wolfSSL_X509_ALGOR_free(WOLFSSL_X509_ALGOR *alg);

/*!
    \ingroup CertsKeys
    \brief OpenSSL-compatible accessor that retrieves the algorithm OID and optional parameter from a WOLFSSL_X509_ALGOR. Any of the output pointers may be NULL if that particular component is not required.

    \return no value, this function does not return.

    \param paobj if non-NULL, receives a pointer to the algorithm's ASN1_OBJECT.
    \param pptype if non-NULL, receives the ASN.1 tag of the parameter (e.g. V_ASN1_NULL, V_ASN1_OBJECT).
    \param ppval if non-NULL, receives a pointer to the algorithm parameter value.
    \param algor pointer to the WOLFSSL_X509_ALGOR to inspect.

    _Example_
    \code
    // see wolfSSL_X509_ALGOR_get0 usage
    \endcode

    \sa wolfSSL_X509_ALGOR_set0
*/
void wolfSSL_X509_ALGOR_get0(const WOLFSSL_ASN1_OBJECT **paobj, int *pptype, const void **ppval, const WOLFSSL_X509_ALGOR *algor);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_ALGOR (AlgorithmIdentifier) structure.

    \return pointer to a new WOLFSSL_X509_ALGOR on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_ALGOR_new usage
    \endcode

    \sa wolfSSL_X509_ALGOR_free
*/
WOLFSSL_X509_ALGOR* wolfSSL_X509_ALGOR_new(void);

/*!
    \ingroup CertsKeys
    \brief Sets the algorithm OID and parameter of a WOLFSSL_X509_ALGOR. Takes ownership of aobj and pval on success.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param algor the WOLFSSL_X509_ALGOR to populate.
    \param aobj the algorithm OID; the structure takes ownership.
    \param ptype ASN.1 tag describing pval (e.g. V_ASN1_NULL).
    \param pval pointer to the algorithm parameter or NULL.

    _Example_
    \code
    // see wolfSSL_X509_ALGOR_set0 usage
    \endcode

    \sa wolfSSL_X509_ALGOR_get0
*/
int wolfSSL_X509_ALGOR_set0(WOLFSSL_X509_ALGOR *algor, WOLFSSL_ASN1_OBJECT *aobj, int ptype, void *pval);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_ATTRIBUTE structure previously allocated with wolfSSL_X509_ATTRIBUTE_new(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param attr pointer to the X509 attribute structure to free.

    _Example_
    \code
    // see wolfSSL_X509_ATTRIBUTE_free usage
    \endcode

    \sa wolfSSL_X509_ATTRIBUTE_new
*/
void wolfSSL_X509_ATTRIBUTE_free(WOLFSSL_X509_ATTRIBUTE* attr);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_ATTRIBUTE structure (used for PKCS#10 / X.509 attributes).

    \return pointer to a new WOLFSSL_X509_ATTRIBUTE on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_ATTRIBUTE_new usage
    \endcode

    \sa wolfSSL_X509_ATTRIBUTE_free
*/
WOLFSSL_X509_ATTRIBUTE* wolfSSL_X509_ATTRIBUTE_new(void);

/*!
    \ingroup CertsKeys
    \brief Returns the number of CA certificates currently loaded in a WOLFSSL_X509_STORE.

    \return count of CA certificates in the store on success.
    \return WOLFSSL_FAILURE if store is NULL or unavailable.

    \param store pointer to the certificate store to query.

    _Example_
    \code
    // see wolfSSL_X509_CA_num usage
    \endcode

    \sa wolfSSL_X509_STORE_new
    \sa wolfSSL_X509_STORE_add_cert
*/
int wolfSSL_X509_CA_num(WOLFSSL_X509_STORE *store);

/*!
    \ingroup CertsKeys
    \brief Creates an independent deep copy of a WOLFSSL_X509_CRL structure. The returned CRL must be released with wolfSSL_X509_CRL_free().

    \return pointer to a newly allocated CRL on success.
    \return NULL on failure.

    \param crl pointer to the CRL to duplicate.

    _Example_
    \code
    // see wolfSSL_X509_CRL_dup usage
    \endcode

    \sa wolfSSL_X509_CRL_new
    \sa wolfSSL_X509_CRL_free
*/
WOLFSSL_X509_CRL* wolfSSL_X509_CRL_dup(const WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_CRL structure and any storage owned by it. Passing NULL is a no-op.

    \return no value, this function does not return.

    \param crl pointer to the CRL to free.

    _Example_
    \code
    // see wolfSSL_X509_CRL_free usage
    \endcode

    \sa wolfSSL_X509_CRL_new
    \sa wolfSSL_X509_CRL_dup
*/
void wolfSSL_X509_CRL_free(WOLFSSL_X509_CRL *crl);

/*!
    \ingroup CertsKeys
    \brief Returns the stack of revoked-certificate entries contained in the given CRL. Mirrors OpenSSL's X509_CRL_get_REVOKED().

    \return pointer to a WOLFSSL_STACK of WOLFSSL_X509_REVOKED entries on success.
    \return NULL on failure.

    \param crl pointer to the CRL whose revoked entries should be returned.

    _Example_
    \code
    // see wolfSSL_X509_CRL_get_REVOKED usage
    \endcode

    \sa wolfSSL_X509_CRL_get_lastUpdate
    \sa wolfSSL_X509_CRL_get_nextUpdate
*/
WOLFSSL_STACK* wolfSSL_X509_CRL_get_REVOKED(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys
    \brief Returns the thisUpdate (lastUpdate) field of a CRL as a WOLFSSL_ASN1_TIME pointer.

    \return pointer to the lastUpdate ASN1_TIME on success.
    \return NULL on failure.

    \param crl pointer to the CRL.

    _Example_
    \code
    // see wolfSSL_X509_CRL_get_lastUpdate usage
    \endcode

    \sa wolfSSL_X509_CRL_get_nextUpdate
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_lastUpdate(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys
    \brief Returns the nextUpdate field of a CRL as a WOLFSSL_ASN1_TIME pointer.

    \return pointer to the nextUpdate ASN1_TIME on success.
    \return NULL on failure.

    \param crl pointer to the CRL.

    _Example_
    \code
    // see wolfSSL_X509_CRL_get_nextUpdate usage
    \endcode

    \sa wolfSSL_X509_CRL_get_lastUpdate
*/
WOLFSSL_ASN1_TIME* wolfSSL_X509_CRL_get_nextUpdate(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys
    \brief Returns the signature OID (algorithm identifier) used to sign the given CRL.

    \return signature algorithm identifier on success.
    \return WOLFSSL_FAILURE if crl is NULL.

    \param crl pointer to the CRL.

    _Example_
    \code
    // see wolfSSL_X509_CRL_get_signature_type usage
    \endcode

    \sa wolfSSL_X509_CRL_verify
*/
int wolfSSL_X509_CRL_get_signature_type(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_CRL structure.

    \return pointer to a new WOLFSSL_X509_CRL on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_CRL_new usage
    \endcode

    \sa wolfSSL_X509_CRL_free
    \sa wolfSSL_X509_CRL_dup
*/
WOLFSSL_X509_CRL* wolfSSL_X509_CRL_new(void);

/*!
    \ingroup CertsKeys
    \brief Increments the reference count on a WOLFSSL_X509_CRL so that multiple owners can share the same CRL safely. Each successful call must be paired with a wolfSSL_X509_CRL_free().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if crl is NULL or the reference count could not be incremented.

    \param crl pointer to the CRL whose reference count is incremented.

    _Example_
    \code
    // see wolfSSL_X509_CRL_up_ref usage
    \endcode

    \sa wolfSSL_X509_CRL_free
*/
int wolfSSL_X509_CRL_up_ref(WOLFSSL_X509_CRL* crl);

/*!
    \ingroup CertsKeys
    \brief Verifies the signature on a CRL using the supplied public key (typically the issuer's).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on signature mismatch or other error.

    \param crl pointer to the CRL to verify.
    \param pkey issuer public key.

    _Example_
    \code
    // see wolfSSL_X509_CRL_verify usage
    \endcode

    \sa wolfSSL_X509_verify
*/
int       wolfSSL_X509_CRL_verify(WOLFSSL_X509_CRL* crl, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys
    \brief Returns the version field of a CRL (1 for v1, 2 for v2).

    \return CRL version on success.
    \return 0 on failure.

    \param crl pointer to the CRL.

    _Example_
    \code
    // see wolfSSL_X509_CRL_version usage
    \endcode
*/
int wolfSSL_X509_CRL_version(WOLFSSL_X509_CRL *crl);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_EXTENSION structure previously allocated by wolfSSL_X509_EXTENSION_new(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param ext_to_free extension structure to free.

    _Example_
    \code
    // see wolfSSL_X509_EXTENSION_free usage
    \endcode

    \sa wolfSSL_X509_EXTENSION_new
*/
void wolfSSL_X509_EXTENSION_free(WOLFSSL_X509_EXTENSION* ext_to_free);

/*!
    \ingroup CertsKeys
    \brief Returns the critical flag of an X509 extension.

    \return 1 if the extension is marked critical.
    \return 0 if it is not.
    \return Negative value on error.

    \param ex extension to inspect.

    _Example_
    \code
    // see wolfSSL_X509_EXTENSION_get_critical usage
    \endcode

    \sa wolfSSL_X509_EXTENSION_set_critical
*/
int wolfSSL_X509_EXTENSION_get_critical(const WOLFSSL_X509_EXTENSION* ex);

/*!
    \ingroup CertsKeys
    \brief Returns the DER-encoded value (extnValue) of an X509 extension as a WOLFSSL_ASN1_STRING.

    \return pointer to the extension value on success.
    \return NULL on failure.

    \param ext extension to inspect.

    _Example_
    \code
    // see wolfSSL_X509_EXTENSION_get_data usage
    \endcode

    \sa wolfSSL_X509_EXTENSION_get_object
*/
WOLFSSL_ASN1_STRING* wolfSSL_X509_EXTENSION_get_data(WOLFSSL_X509_EXTENSION* ext);

/*!
    \ingroup CertsKeys
    \brief Returns the OID (extnID) of an X509 extension as a WOLFSSL_ASN1_OBJECT.

    \return pointer to the extension's OBJECT on success.
    \return NULL on failure.

    \param ext extension to inspect.

    _Example_
    \code
    // see wolfSSL_X509_EXTENSION_get_object usage
    \endcode

    \sa wolfSSL_X509_EXTENSION_get_data
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_X509_EXTENSION_get_object(WOLFSSL_X509_EXTENSION* ext);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_EXTENSION structure.

    \return pointer to a new WOLFSSL_X509_EXTENSION on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_EXTENSION_new usage
    \endcode

    \sa wolfSSL_X509_EXTENSION_free
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_EXTENSION_new(void);

/*!
    \ingroup CertsKeys
    \brief Sets or clears the critical flag on an X509 extension.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if ex is NULL.

    \param ex extension to modify.
    \param crit non-zero to mark the extension critical, zero otherwise.

    _Example_
    \code
    // see wolfSSL_X509_EXTENSION_set_critical usage
    \endcode

    \sa wolfSSL_X509_EXTENSION_get_critical
*/
int wolfSSL_X509_EXTENSION_set_critical(WOLFSSL_X509_EXTENSION* ex, int crit);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_INFO structure (and any certificate/CRL/key contents it owns) previously allocated by wolfSSL_X509_INFO_new(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param info pointer to the WOLFSSL_X509_INFO to free.

    _Example_
    \code
    // see wolfSSL_X509_INFO_free usage
    \endcode

    \sa wolfSSL_X509_INFO_new
*/
void wolfSSL_X509_INFO_free(WOLFSSL_X509_INFO* info);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_INFO structure, typically used when reading combined PEM bundles via PEM_X509_INFO_read_bio().

    \return pointer to a new WOLFSSL_X509_INFO on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_INFO_new usage
    \endcode

    \sa wolfSSL_X509_INFO_free
*/
WOLFSSL_X509_INFO *wolfSSL_X509_INFO_new(void);

/*!
    \ingroup CertsKeys
    \brief Adds a hashed-directory lookup entry to a WOLFSSL_X509_LOOKUP. Certificates in dir must follow the OpenSSL hashed-directory naming convention (subject_hash.NN, crl_hash.rNN).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param lookup X509 lookup handle (obtained from wolfSSL_X509_STORE_add_lookup).
    \param dir path to the directory of hashed certificates and CRLs.
    \param type file type, e.g. X509_FILETYPE_PEM.

    _Example_
    \code
    // see wolfSSL_X509_LOOKUP_add_dir usage
    \endcode

    \sa wolfSSL_X509_LOOKUP_hash_dir
    \sa wolfSSL_X509_LOOKUP_load_file
*/
int wolfSSL_X509_LOOKUP_add_dir(WOLFSSL_X509_LOOKUP* lookup,const char* dir,long type);

/*!
    \ingroup CertsKeys
    \brief Returns the built-in X509_LOOKUP method that loads certificates and CRLs from a single file. Used with wolfSSL_X509_STORE_add_lookup().

    \return pointer to the file-lookup method (always non-NULL).

    _Example_
    \code
    // see wolfSSL_X509_LOOKUP_file usage
    \endcode

    \sa wolfSSL_X509_LOOKUP_hash_dir
    \sa wolfSSL_X509_LOOKUP_add_dir
*/
WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_file(void);

/*!
    \ingroup CertsKeys
    \brief Returns the built-in X509_LOOKUP method that loads certificates and CRLs by subject-hash from a directory. Used with wolfSSL_X509_STORE_add_lookup().

    \return pointer to the hashed-directory lookup method (always non-NULL).

    _Example_
    \code
    // see wolfSSL_X509_LOOKUP_hash_dir usage
    \endcode

    \sa wolfSSL_X509_LOOKUP_file
    \sa wolfSSL_X509_LOOKUP_add_dir
*/
WOLFSSL_X509_LOOKUP_METHOD* wolfSSL_X509_LOOKUP_hash_dir(void);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_NAME_ENTRY allocated by wolfSSL_X509_NAME_ENTRY_new() or wolfSSL_X509_NAME_ENTRY_create_by_*(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param ne name entry to free.

    _Example_
    \code
    // see wolfSSL_X509_NAME_ENTRY_free usage
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_new
*/
void wolfSSL_X509_NAME_ENTRY_free(WOLFSSL_X509_NAME_ENTRY* ne);

/*!
    \ingroup CertsKeys
    \brief Returns the ASN1_STRING value of an X509_NAME entry (e.g. the actual UTF8String/PrintableString bytes).

    \return pointer to the entry's value on success.
    \return NULL on failure.

    \param in name entry to inspect.

    _Example_
    \code
    // see wolfSSL_X509_NAME_ENTRY_get_data usage
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_get_object
*/
WOLFSSL_ASN1_STRING* wolfSSL_X509_NAME_ENTRY_get_data(WOLFSSL_X509_NAME_ENTRY* in);

/*!
    \ingroup CertsKeys
    \brief Returns the ASN.1 OID identifying the field of an X509_NAME entry (e.g. CN, O).

    \return pointer to the OID object on success.
    \return NULL on failure.

    \param ne name entry to inspect.

    _Example_
    \code
    // see wolfSSL_X509_NAME_ENTRY_get_object usage
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_get_data
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_X509_NAME_ENTRY_get_object(WOLFSSL_X509_NAME_ENTRY *ne);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509_NAME_ENTRY.

    \return pointer to a new WOLFSSL_X509_NAME_ENTRY on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_NAME_ENTRY_new usage
    \endcode

    \sa wolfSSL_X509_NAME_ENTRY_free
*/
WOLFSSL_X509_NAME_ENTRY* wolfSSL_X509_NAME_ENTRY_new(void);

/*!
    \ingroup CertsKeys
    \brief Returns the set/RDN index of a name entry (i.e. the multi-valued RDN grouping field).

    \return set index on success.
    \return WOLFSSL_FAILURE on error.

    \param ne name entry to inspect.

    _Example_
    \code
    // see wolfSSL_X509_NAME_ENTRY_set usage
    \endcode
*/
int wolfSSL_X509_NAME_ENTRY_set(const WOLFSSL_X509_NAME_ENTRY *ne);

/*!
    \ingroup CertsKeys
    \brief Returns the number of entries (RDNs) in a WOLFSSL_X509_NAME.

    \return number of entries on success.
    \return 0 if name is NULL.

    \param name X509_NAME to inspect.

    _Example_
    \code
    // see wolfSSL_X509_NAME_entry_count usage
    \endcode
*/
int wolfSSL_X509_NAME_entry_count(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_NAME structure and all its entries. Passing NULL is a no-op.

    \return no value, this function does not return.

    \param name X509_NAME to free.

    _Example_
    \code
    // see wolfSSL_X509_NAME_free usage
    \endcode

    \sa wolfSSL_X509_NAME_new
*/
void wolfSSL_X509_NAME_free(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys
    \brief Returns the size in bytes of the DER-encoded form of a WOLFSSL_X509_NAME.

    \return encoded size on success.
    \return Negative or 0 on failure.

    \param name X509_NAME to inspect.

    _Example_
    \code
    // see wolfSSL_X509_NAME_get_sz usage
    \endcode

    \sa wolfSSL_X509_NAME_oneline
*/
int wolfSSL_X509_NAME_get_sz(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys
    \brief Computes the OpenSSL-compatible 32-bit hash of a WOLFSSL_X509_NAME (first four bytes of the SHA-1 of the DER encoding, in little-endian order). Used as a key for hashed CA directories.

    \return 32-bit hash value on success.
    \return 0 on failure.

    \param name X509_NAME to hash.

    _Example_
    \code
    // see wolfSSL_X509_NAME_hash usage
    \endcode

    \sa wolfSSL_X509_subject_name_hash
    \sa wolfSSL_X509_issuer_name_hash
*/
unsigned long wolfSSL_X509_NAME_hash(WOLFSSL_X509_NAME* name);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509_NAME.

    \return pointer to a new WOLFSSL_X509_NAME on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_NAME_new usage
    \endcode

    \sa wolfSSL_X509_NAME_new_ex
    \sa wolfSSL_X509_NAME_free
*/
WOLFSSL_X509_NAME* wolfSSL_X509_NAME_new(void);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509_NAME using the supplied heap hint.

    \return pointer to a new WOLFSSL_X509_NAME on success.
    \return NULL on failure.

    \param heap heap hint for the allocation, or NULL.

    _Example_
    \code
    // see wolfSSL_X509_NAME_new_ex usage
    \endcode

    \sa wolfSSL_X509_NAME_new
    \sa wolfSSL_X509_NAME_free
*/
WOLFSSL_X509_NAME* wolfSSL_X509_NAME_new_ex(void *heap);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_OBJECT (a tagged union over a certificate or CRL) previously allocated by wolfSSL_X509_OBJECT_new(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param obj X509 object to free.

    _Example_
    \code
    // see wolfSSL_X509_OBJECT_free usage
    \endcode

    \sa wolfSSL_X509_OBJECT_new
    \sa wolfSSL_X509_OBJECT_free_contents
*/
void wolfSSL_X509_OBJECT_free(WOLFSSL_X509_OBJECT *obj);

/*!
    \ingroup CertsKeys
    \brief Frees the contents held by a WOLFSSL_X509_OBJECT without freeing the object itself. Useful when the object is stack-allocated.

    \return no value, this function does not return.

    \param obj object whose contents should be released.

    _Example_
    \code
    // see wolfSSL_X509_OBJECT_free_contents usage
    \endcode

    \sa wolfSSL_X509_OBJECT_free
*/
void      wolfSSL_X509_OBJECT_free_contents(WOLFSSL_X509_OBJECT* obj);

/*!
    \ingroup CertsKeys
    \brief Returns the X509 certificate contained in a WOLFSSL_X509_OBJECT when its type is X509_LU_X509. Returns NULL otherwise.

    \return pointer to the contained WOLFSSL_X509 on success.
    \return NULL otherwise.

    \param obj X509 object to inspect.

    _Example_
    \code
    // see wolfSSL_X509_OBJECT_get0_X509 usage
    \endcode

    \sa wolfSSL_X509_OBJECT_get0_X509_CRL
*/
WOLFSSL_X509 *wolfSSL_X509_OBJECT_get0_X509(const WOLFSSL_X509_OBJECT *obj);

/*!
    \ingroup CertsKeys
    \brief Returns the X509 CRL contained in a WOLFSSL_X509_OBJECT when its type is X509_LU_CRL. Returns NULL otherwise.

    \return pointer to the contained WOLFSSL_X509_CRL on success.
    \return NULL otherwise.

    \param obj X509 object to inspect.

    _Example_
    \code
    // see wolfSSL_X509_OBJECT_get0_X509_CRL usage
    \endcode

    \sa wolfSSL_X509_OBJECT_get0_X509
*/
WOLFSSL_X509_CRL *wolfSSL_X509_OBJECT_get0_X509_CRL(WOLFSSL_X509_OBJECT *obj);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509_OBJECT.

    \return pointer to a new WOLFSSL_X509_OBJECT on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_OBJECT_new usage
    \endcode

    \sa wolfSSL_X509_OBJECT_free
*/
WOLFSSL_X509_OBJECT* wolfSSL_X509_OBJECT_new(void);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_PUBKEY structure previously allocated by wolfSSL_X509_PUBKEY_new() or returned by wolfSSL_X509_get_X509_PUBKEY(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param x X509_PUBKEY to free.

    _Example_
    \code
    // see wolfSSL_X509_PUBKEY_free usage
    \endcode

    \sa wolfSSL_X509_PUBKEY_new
*/
void wolfSSL_X509_PUBKEY_free(WOLFSSL_X509_PUBKEY *x);

/*!
    \ingroup CertsKeys
    \brief Decodes a WOLFSSL_X509_PUBKEY into a freshly allocated WOLFSSL_EVP_PKEY. The returned key must be freed with wolfSSL_EVP_PKEY_free().

    \return pointer to a new EVP_PKEY on success.
    \return NULL on failure.

    \param key X509_PUBKEY to decode.

    _Example_
    \code
    // see wolfSSL_X509_PUBKEY_get usage
    \endcode

    \sa wolfSSL_X509_PUBKEY_set
*/
WOLFSSL_EVP_PKEY* wolfSSL_X509_PUBKEY_get(WOLFSSL_X509_PUBKEY* key);

/*!
    \ingroup CertsKeys
    \brief OpenSSL-compatible accessor that returns the algorithm OID, raw public key bytes and full X509_ALGOR of a SubjectPublicKeyInfo. Any of the output pointers may be NULL.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ppkalg if non-NULL, receives the algorithm OID.
    \param pk if non-NULL, receives a pointer to the raw public-key bytes.
    \param ppklen if non-NULL, receives the length of the raw key bytes.
    \param pa if non-NULL, receives the WOLFSSL_X509_ALGOR describing the key.
    \param pub the WOLFSSL_X509_PUBKEY to inspect.

    _Example_
    \code
    // see wolfSSL_X509_PUBKEY_get0_param usage
    \endcode

    \sa wolfSSL_X509_PUBKEY_get
*/
int wolfSSL_X509_PUBKEY_get0_param(WOLFSSL_ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, WOLFSSL_X509_ALGOR **pa, WOLFSSL_X509_PUBKEY *pub);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509_PUBKEY structure.

    \return pointer to a new WOLFSSL_X509_PUBKEY on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_PUBKEY_new usage
    \endcode

    \sa wolfSSL_X509_PUBKEY_free
*/
WOLFSSL_X509_PUBKEY *wolfSSL_X509_PUBKEY_new(void);

/*!
    \ingroup CertsKeys
    \brief Encodes a WOLFSSL_EVP_PKEY into a WOLFSSL_X509_PUBKEY (SubjectPublicKeyInfo), allocating a new structure at *x and freeing any previous value.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x address of the X509_PUBKEY pointer to populate.
    \param key EVP_PKEY containing the public key.

    _Example_
    \code
    // see wolfSSL_X509_PUBKEY_set usage
    \endcode

    \sa wolfSSL_X509_PUBKEY_get
*/
int wolfSSL_X509_PUBKEY_set(WOLFSSL_X509_PUBKEY **x, WOLFSSL_EVP_PKEY *key);

/*!
    \ingroup CertsKeys
    \brief Frees a certificate-signing-request structure (a WOLFSSL_X509 used as a PKCS#10 CSR). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param req CSR to free.

    _Example_
    \code
    // see wolfSSL_X509_REQ_free usage
    \endcode

    \sa wolfSSL_X509_REQ_new
*/
void wolfSSL_X509_REQ_free(WOLFSSL_X509* req);

/*!
    \ingroup CertsKeys
    \brief Returns the number of attributes attached to a PKCS#10 CSR.

    \return attribute count on success.
    \return 0 if req is NULL or has no attributes.

    \param req CSR to inspect.

    _Example_
    \code
    // see wolfSSL_X509_REQ_get_attr_count usage
    \endcode
*/
int wolfSSL_X509_REQ_get_attr_count(const WOLFSSL_X509 *req);

/*!
    \ingroup CertsKeys
    \brief Returns the stack of X509 extensions requested in a PKCS#10 CSR.

    \return pointer to a stack of WOLFSSL_X509_EXTENSION on success.
    \return NULL if no extensions are present.

    \param x CSR to inspect.

    _Example_
    \code
    // see wolfSSL_X509_REQ_get_extensions usage
    \endcode
*/
const WOLFSSL_STACK *wolfSSL_X509_REQ_get_extensions(const WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys
    \brief Returns the version field of a PKCS#10 CSR.

    \return version value on success.
    \return WOLFSSL_FAILURE on error.

    \param req CSR to inspect.

    _Example_
    \code
    // see wolfSSL_X509_REQ_get_version usage
    \endcode

    \sa wolfSSL_X509_REQ_set_version
*/
long wolfSSL_X509_REQ_get_version(const WOLFSSL_X509 *req);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty PKCS#10 CSR (returned as a WOLFSSL_X509 to match OpenSSL's X509_REQ alias).

    \return pointer to a new CSR on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_REQ_new usage
    \endcode

    \sa wolfSSL_X509_REQ_free
*/
WOLFSSL_X509* wolfSSL_X509_REQ_new(void);

/*!
    \ingroup CertsKeys
    \brief Writes a human-readable text rendering of a PKCS#10 CSR to the supplied BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio output BIO.
    \param x509 CSR to print.

    _Example_
    \code
    // see wolfSSL_X509_REQ_print usage
    \endcode

    \sa wolfSSL_X509_print
*/
int wolfSSL_X509_REQ_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Sets the version field of a PKCS#10 CSR.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x CSR to modify.
    \param version new version value.

    _Example_
    \code
    // see wolfSSL_X509_REQ_set_version usage
    \endcode

    \sa wolfSSL_X509_REQ_get_version
*/
int wolfSSL_X509_REQ_set_version(WOLFSSL_X509 *x, long version);

/*!
    \ingroup CertsKeys
    \brief Verifies the signature on a PKCS#10 CSR using the supplied public key (typically the public key embedded in the request itself, demonstrating proof of possession).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if the signature does not verify.

    \param x509 CSR to verify.
    \param pkey public key for verification.

    _Example_
    \code
    // see wolfSSL_X509_REQ_verify usage
    \endcode

    \sa wolfSSL_X509_verify
*/
int wolfSSL_X509_REQ_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_REVOKED structure. Passing NULL is a no-op.

    \return no value, this function does not return.

    \param rev revoked entry to free.

    _Example_
    \code
    // see wolfSSL_X509_REVOKED_free usage
    \endcode
*/
void wolfSSL_X509_REVOKED_free(WOLFSSL_X509_REVOKED* rev);

/*!
    \ingroup CertsKeys
    \brief Resets a WOLFSSL_X509_STORE_CTX, releasing any per-verification state but leaving the structure itself usable. Mirrors OpenSSL's X509_STORE_CTX_cleanup().

    \return no value, this function does not return.

    \param ctx context to clean up.

    _Example_
    \code
    // see wolfSSL_X509_STORE_CTX_cleanup usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_free
*/
void wolfSSL_X509_STORE_CTX_cleanup(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_STORE_CTX previously allocated with wolfSSL_X509_STORE_CTX_new(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param ctx context to free.

    _Example_
    \code
    // see wolfSSL_X509_STORE_CTX_free usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_new
*/
void wolfSSL_X509_STORE_CTX_free(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Returns the error code recorded on a store context, e.g. during certificate-chain verification.

    \return error code (0 if no error).

    \param ctx store context to query.

    _Example_
    \code
    // see wolfSSL_X509_STORE_CTX_get_error usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error_depth
    \sa wolfSSL_X509_verify_cert_error_string
*/
int   wolfSSL_X509_STORE_CTX_get_error(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Returns the chain depth at which the most recent verification error occurred. Depth 0 is the peer certificate.

    \return non-negative depth on success.
    \return Negative value on error.

    \param ctx store context to query.

    _Example_
    \code
    // see wolfSSL_X509_STORE_CTX_get_error_depth usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error
*/
int   wolfSSL_X509_STORE_CTX_get_error_depth(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_STORE_CTX used to drive certificate-chain verification.

    \return pointer to a new WOLFSSL_X509_STORE_CTX on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_STORE_CTX_new usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_new_ex
    \sa wolfSSL_X509_STORE_CTX_free
*/
WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new(void);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_STORE_CTX using the supplied heap hint.

    \return pointer to a new WOLFSSL_X509_STORE_CTX on success.
    \return NULL on failure.

    \param heap heap hint, or NULL.

    _Example_
    \code
    // see wolfSSL_X509_STORE_CTX_new_ex usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_new
*/
WOLFSSL_X509_STORE_CTX* wolfSSL_X509_STORE_CTX_new_ex(void* heap);

/*!
    \ingroup CertsKeys
    \brief Returns a stack of certificates held by the given store context, including the peer chain and any intermediates accumulated during verification. The returned stack must be freed by the caller with wolfSSL_sk_X509_pop_free().

    \return pointer to a new stack of WOLFSSL_X509 on success.
    \return NULL on failure.

    \param s store context to query.

    _Example_
    \code
    // see wolfSSL_X509_STORE_GetCerts usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_chain
*/
WOLFSSL_STACK* wolfSSL_X509_STORE_GetCerts(WOLFSSL_X509_STORE_CTX* s);

/*!
    \ingroup CertsKeys
    \brief Adds a CRL to a certificate store. Subsequent verifications using the store will check the certificate against this CRL.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ctx certificate store to update.
    \param x CRL to add.

    _Example_
    \code
    // see wolfSSL_X509_STORE_add_crl usage
    \endcode

    \sa wolfSSL_X509_STORE_add_cert
*/
int wolfSSL_X509_STORE_add_crl(WOLFSSL_X509_STORE *ctx, WOLFSSL_X509_CRL *x);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_STORE allocated by wolfSSL_X509_STORE_new(). Passing NULL is a no-op.

    \return no value, this function does not return.

    \param store store to free.

    _Example_
    \code
    // see wolfSSL_X509_STORE_free usage
    \endcode

    \sa wolfSSL_X509_STORE_new
*/
void         wolfSSL_X509_STORE_free(WOLFSSL_X509_STORE* store);

/*!
    \ingroup CertsKeys
    \brief Loads trust anchors into an X509 store from a file and/or a hashed directory. Either path may be NULL to skip that source. Mirrors OpenSSL's X509_STORE_load_locations().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param str store to populate.
    \param file path to a PEM file of CA certificates, or NULL.
    \param dir path to a hashed CA directory, or NULL.

    _Example_
    \code
    // see wolfSSL_X509_STORE_load_locations usage
    \endcode

    \sa wolfSSL_X509_STORE_set_default_paths
*/
int wolfSSL_X509_STORE_load_locations(WOLFSSL_X509_STORE *str, const char *file, const char *dir);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509_STORE used to hold trusted CA certificates and CRLs.

    \return pointer to a new WOLFSSL_X509_STORE on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_STORE_new usage
    \endcode

    \sa wolfSSL_X509_STORE_free
*/
WOLFSSL_X509_STORE*  wolfSSL_X509_STORE_new(void);

/*!
    \ingroup CertsKeys
    \brief Loads the system's default CA file and CA directory into the supplied store. Equivalent to wolfSSL_X509_STORE_load_locations(str, default_file, default_dir).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param str store to populate.

    _Example_
    \code
    // see wolfSSL_X509_STORE_set_default_paths usage
    \endcode

    \sa wolfSSL_X509_STORE_load_locations
    \sa wolfSSL_X509_get_default_cert_file
*/
int wolfSSL_X509_STORE_set_default_paths(WOLFSSL_X509_STORE *str);

/*!
    \ingroup CertsKeys
    \brief Increments the reference count on a WOLFSSL_X509_STORE so it can be shared safely. Each successful call must be paired with a wolfSSL_X509_STORE_free().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if store is NULL.

    \param store store whose reference count is incremented.

    _Example_
    \code
    // see wolfSSL_X509_STORE_up_ref usage
    \endcode

    \sa wolfSSL_X509_STORE_free
*/
int          wolfSSL_X509_STORE_up_ref(WOLFSSL_X509_STORE* store);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_X509_VERIFY_PARAM structure. Passing NULL is a no-op.

    \return no value, this function does not return.

    \param param verify-param to free.

    _Example_
    \code
    // see wolfSSL_X509_VERIFY_PARAM_free usage
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_new
*/
void wolfSSL_X509_VERIFY_PARAM_free(WOLFSSL_X509_VERIFY_PARAM *param);

/*!
    \ingroup CertsKeys
    \brief Returns the verification flags currently set on a WOLFSSL_X509_VERIFY_PARAM (e.g. X509_V_FLAG_CRL_CHECK).

    \return flag bitmask on success.
    \return 0 if param is NULL.

    \param param verify-param to inspect.

    _Example_
    \code
    // see wolfSSL_X509_VERIFY_PARAM_get_flags usage
    \endcode
*/
int wolfSSL_X509_VERIFY_PARAM_get_flags(WOLFSSL_X509_VERIFY_PARAM *param);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new WOLFSSL_X509_VERIFY_PARAM with default settings.

    \return pointer to a new verify-param on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_VERIFY_PARAM_new usage
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_free
*/
WOLFSSL_X509_VERIFY_PARAM* wolfSSL_X509_VERIFY_PARAM_new(void);

/*!
    \ingroup CertsKeys
    \brief Adds a Subject Alternative Name to a WOLFSSL_X509. The string in name is a NUL-terminated value whose interpretation depends on type (e.g. ASN_DNS_TYPE, ASN_IP_TYPE, ASN_RFC822_TYPE).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to modify.
    \param name alt-name string (NUL-terminated).
    \param type SAN type (one of the ASN_*_TYPE constants).

    _Example_
    \code
    // see wolfSSL_X509_add_altname usage
    \endcode

    \sa wolfSSL_X509_add_altname_ex
*/
int wolfSSL_X509_add_altname(WOLFSSL_X509* x509, const char* name, int type);

/*!
    \ingroup CertsKeys
    \brief Adds a Subject Alternative Name to a WOLFSSL_X509 with an explicit length, supporting binary SAN values (e.g. IP addresses).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to modify.
    \param name alt-name bytes.
    \param nameSz length of name in bytes.
    \param type SAN type (one of the ASN_*_TYPE constants).

    _Example_
    \code
    // see wolfSSL_X509_add_altname_ex usage
    \endcode

    \sa wolfSSL_X509_add_altname
*/
int wolfSSL_X509_add_altname_ex(WOLFSSL_X509* x509, const char* name, word32 nameSz, int type);

/*!
    \ingroup CertsKeys
    \brief Adds an X509 extension to a certificate at the given position. loc of -1 appends the extension.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x certificate to modify.
    \param ex extension to add (copied).
    \param loc insertion index, or -1 to append.

    _Example_
    \code
    // see wolfSSL_X509_add_ext usage
    \endcode

    \sa wolfSSL_X509_delete_ext
    \sa wolfSSL_X509_get_ext
*/
int wolfSSL_X509_add_ext(WOLFSSL_X509 *x, WOLFSSL_X509_EXTENSION *ex, int loc);

/*!
    \ingroup CertsKeys
    \brief Determines whether the given certificate is a CA. Checks Basic Constraints and, where relevant, Netscape Cert-Type and Key Usage. Mirrors OpenSSL's X509_check_ca().

    \return 1 if x509 is a CA.
    \return 0 if it is not.
    \return Other values per OpenSSL semantics for older / Netscape-style CAs.

    \param x509 certificate to test.

    _Example_
    \code
    // see wolfSSL_X509_check_ca usage
    \endcode

    \sa wolfSSL_X509_get_isCA
*/
int wolfSSL_X509_check_ca(WOLFSSL_X509 *x509);

/*!
    \ingroup CertsKeys
    \brief Checks that the public key embedded in x509 matches the supplied private key.

    \return WOLFSSL_SUCCESS if the keys match.
    \return WOLFSSL_FAILURE otherwise.

    \param x509 certificate whose public key is checked.
    \param pkey private key to test.

    _Example_
    \code
    // see wolfSSL_X509_check_private_key usage
    \endcode

    \sa wolfSSL_CTX_check_private_key
*/
int wolfSSL_X509_check_private_key(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys
    \brief Lexicographically compares two certificates by hashing their DER encodings. Returns 0 if equal.

    \return 0 if the two certificates are byte-identical.
    \return Non-zero value otherwise.

    \param a first certificate.
    \param b second certificate.

    _Example_
    \code
    // see wolfSSL_X509_cmp usage
    \endcode
*/
int wolfSSL_X509_cmp(const WOLFSSL_X509* a, const WOLFSSL_X509* b);

/*!
    \ingroup CertsKeys
    \brief Compares asnTime against the current system time.

    \return -1 if asnTime is in the past.
    \return 1 if asnTime is in the future.
    \return 0 on error.

    \param asnTime ASN1_TIME value to compare.

    _Example_
    \code
    // see wolfSSL_X509_cmp_current_time usage
    \endcode
*/
int       wolfSSL_X509_cmp_current_time(const WOLFSSL_ASN1_TIME* asnTime);

/*!
    \ingroup CertsKeys
    \brief Removes the X509 extension at the given index and returns it. Caller takes ownership and must free with wolfSSL_X509_EXTENSION_free().

    \return pointer to the removed extension on success.
    \return NULL on error or invalid index.

    \param x509 certificate to modify.
    \param loc index of the extension to remove.

    _Example_
    \code
    // see wolfSSL_X509_delete_ext usage
    \endcode

    \sa wolfSSL_X509_add_ext
*/
WOLFSSL_X509_EXTENSION *wolfSSL_X509_delete_ext(WOLFSSL_X509 *x509, int loc);

/*!
    \ingroup CertsKeys
    \brief Creates an independent deep copy of a WOLFSSL_X509. The returned certificate must be freed with wolfSSL_X509_free().

    \return pointer to a new certificate on success.
    \return NULL on failure.

    \param x certificate to duplicate.

    _Example_
    \code
    // see wolfSSL_X509_dup usage
    \endcode

    \sa wolfSSL_X509_new
    \sa wolfSSL_X509_free
*/
WOLFSSL_X509* wolfSSL_X509_dup(WOLFSSL_X509* x);

/*!
    \ingroup CertsKeys
    \brief Frees a stack of email strings returned by wolfSSL_X509_get1_email().

    \return no value, this function does not return.

    \param sk stack of email strings to free.

    _Example_
    \code
    // see wolfSSL_X509_email_free usage
    \endcode
*/
void wolfSSL_X509_email_free(WOLF_STACK_OF(WOLFSSL_STRING) *sk);

/*!
    \ingroup CertsKeys
    \brief Returns whether the extension identified by nid in x509 is marked critical.

    \return 1 if the extension is critical.
    \return 0 if not.
    \return Negative value if the extension is not present.

    \param x509 certificate to inspect.
    \param nid NID of the extension.

    _Example_
    \code
    // see wolfSSL_X509_ext_get_critical_by_NID usage
    \endcode

    \sa wolfSSL_X509_ext_isSet_by_NID
*/
int  wolfSSL_X509_ext_get_critical_by_NID(WOLFSSL_X509* x509, int nid);

/*!
    \ingroup CertsKeys
    \brief Returns whether the extension identified by nid is present in x509.

    \return 1 if the extension is present.
    \return 0 otherwise.

    \param x509 certificate to inspect.
    \param nid NID of the extension.

    _Example_
    \code
    // see wolfSSL_X509_ext_isSet_by_NID usage
    \endcode

    \sa wolfSSL_X509_ext_get_critical_by_NID
*/
int  wolfSSL_X509_ext_isSet_by_NID(WOLFSSL_X509* x509, int nid);

/*!
    \ingroup CertsKeys
    \brief Returns the stack of X509 extensions held by x without transferring ownership.

    \return pointer to a stack of WOLFSSL_X509_EXTENSION on success.
    \return NULL if x has no extensions.

    \param x certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get0_extensions usage
    \endcode

    \sa wolfSSL_X509_get_ext
*/
const WOLFSSL_STACK *wolfSSL_X509_get0_extensions(const WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys
    \brief Returns the AlgorithmIdentifier from the to-be-signed portion of the certificate (i.e. the signatureAlgorithm field within tbsCertificate).

    \return pointer to a const WOLFSSL_X509_ALGOR on success.
    \return NULL on failure.

    \param x certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get0_tbs_sigalg usage
    \endcode
*/
const WOLFSSL_X509_ALGOR* wolfSSL_X509_get0_tbs_sigalg(const WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys
    \brief Returns a pointer to the WOLFSSL_X509_PUBKEY (SubjectPublicKeyInfo) embedded in x509. The returned pointer is owned by the certificate and must not be freed by the caller.

    \return pointer to the certificate's X509_PUBKEY on success.
    \return NULL on failure.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_X509_PUBKEY usage
    \endcode

    \sa wolfSSL_X509_get_pubkey
*/
WOLFSSL_X509_PUBKEY *wolfSSL_X509_get_X509_PUBKEY(const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Indicates whether the Authority Information Access extension contained more entries than wolfSSL stored internally (i.e. parsing was truncated).

    \return non-zero if AIA was truncated.
    \return 0 if the full AIA was retained.

    \param x certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_aia_overflow usage
    \endcode
*/
int wolfSSL_X509_get_aia_overflow(WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys
    \brief Returns the compiled-in default trusted-CA directory path used by wolfSSL_X509_STORE_set_default_paths().

    \return pointer to a NUL-terminated path string.

    _Example_
    \code
    // see wolfSSL_X509_get_default_cert_dir usage
    \endcode

    \sa wolfSSL_X509_get_default_cert_dir_env
    \sa wolfSSL_X509_STORE_set_default_paths
*/
const char* wolfSSL_X509_get_default_cert_dir(void);

/*!
    \ingroup CertsKeys
    \brief Returns the name of the environment variable that, if set, overrides the compiled-in default trusted-CA directory (typically "SSL_CERT_DIR").

    \return pointer to a NUL-terminated environment-variable name.

    _Example_
    \code
    // see wolfSSL_X509_get_default_cert_dir_env usage
    \endcode

    \sa wolfSSL_X509_get_default_cert_dir
*/
const char* wolfSSL_X509_get_default_cert_dir_env(void);

/*!
    \ingroup CertsKeys
    \brief Returns the compiled-in default trusted-CA file path used by wolfSSL_X509_STORE_set_default_paths().

    \return pointer to a NUL-terminated path string.

    _Example_
    \code
    // see wolfSSL_X509_get_default_cert_file usage
    \endcode

    \sa wolfSSL_X509_get_default_cert_file_env
    \sa wolfSSL_X509_STORE_set_default_paths
*/
const char* wolfSSL_X509_get_default_cert_file(void);

/*!
    \ingroup CertsKeys
    \brief Returns the name of the environment variable that, if set, overrides the compiled-in default trusted-CA file (typically "SSL_CERT_FILE").

    \return pointer to a NUL-terminated environment-variable name.

    _Example_
    \code
    // see wolfSSL_X509_get_default_cert_file_env usage
    \endcode

    \sa wolfSSL_X509_get_default_cert_file
*/
const char* wolfSSL_X509_get_default_cert_file_env(void);

/*!
    \ingroup CertsKeys
    \brief Retrieves application data previously stored on a WOLFSSL_X509 via wolfSSL_X509_set_ex_data() at slot idx.

    \return the stored pointer on success.
    \return NULL if no value is stored or on error.

    \param x509 certificate to query.
    \param idx ex_data slot index returned by wolfSSL_X509_get_ex_new_index().

    _Example_
    \code
    // see wolfSSL_X509_get_ex_data usage
    \endcode

    \sa wolfSSL_X509_set_ex_data
*/
void *wolfSSL_X509_get_ex_data(WOLFSSL_X509 *x509, int idx);

/*!
    \ingroup CertsKeys
    \brief Returns the X509 extension at index loc within x. The returned pointer is owned by x.

    \return pointer to the extension on success.
    \return NULL on invalid index or error.

    \param x certificate to inspect.
    \param loc zero-based extension index.

    _Example_
    \code
    // see wolfSSL_X509_get_ext usage
    \endcode

    \sa wolfSSL_X509_get_ext_count
    \sa wolfSSL_X509_set_ext
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_get_ext(const WOLFSSL_X509* x, int loc);

/*!
    \ingroup CertsKeys
    \brief Returns the number of X509 extensions present in the certificate.

    \return extension count (>=0) on success.
    \return WOLFSSL_FAILURE on error.

    \param passedCert certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_ext_count usage
    \endcode

    \sa wolfSSL_X509_get_ext
*/
int wolfSSL_X509_get_ext_count(const WOLFSSL_X509* passedCert);

/*!
    \ingroup CertsKeys
    \brief Returns the Extended Key Usage bitmask (e.g. XKU_SSL_SERVER | XKU_SSL_CLIENT) parsed from the EKU extension.

    \return EKU bitmask on success.
    \return 0 if the certificate has no EKU.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_extended_key_usage usage
    \endcode

    \sa wolfSSL_X509_get_key_usage
*/
unsigned int wolfSSL_X509_get_extended_key_usage(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Returns the per-certificate extension-flag bitmask (e.g. EXFLAG_CA, EXFLAG_KUSAGE) computed from the parsed extensions.

    \return bitmask of EXFLAG_* values.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_extension_flags usage
    \endcode

    \sa wolfSSL_X509_get_key_usage
    \sa wolfSSL_X509_get_extended_key_usage
*/
unsigned int wolfSSL_X509_get_extension_flags(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Indicates whether the certificate's BasicConstraints extension explicitly sets pathLenConstraint.

    \return non-zero if pathLenConstraint is set.
    \return 0 otherwise.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_isSet_pathLength usage
    \endcode

    \sa wolfSSL_X509_get_pathLength
*/
int  wolfSSL_X509_get_isSet_pathLength(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Returns the parsed Key Usage extension bitmask (legacy wolfSSL-style accessor; see also wolfSSL_X509_get_key_usage()).

    \return Key Usage bitmask on success.
    \return 0 if the extension is not present.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_keyUsage usage
    \endcode

    \sa wolfSSL_X509_get_key_usage
*/
unsigned int wolfSSL_X509_get_keyUsage(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief OpenSSL-compatible alias returning the Key Usage extension bitmask (e.g. KEYUSE_DIGITAL_SIG | KEYUSE_KEY_ENCIPHER).

    \return Key Usage bitmask on success.
    \return 0 if the extension is not present.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_key_usage usage
    \endcode

    \sa wolfSSL_X509_get_keyUsage
*/
unsigned int wolfSSL_X509_get_key_usage(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Formats a WOLFSSL_X509_NAME as a single line of text. If in is NULL a new buffer is allocated; otherwise up to sz bytes are written to in.

    \return pointer to the formatted string on success.
    \return NULL on error.

    \param name X509_NAME to render.
    \param in destination buffer or NULL to have one allocated.
    \param sz size of in in bytes (ignored when in is NULL).

    _Example_
    \code
    // see wolfSSL_X509_get_name_oneline usage
    \endcode

    \sa wolfSSL_X509_NAME_oneline
*/
char* wolfSSL_X509_get_name_oneline(WOLFSSL_X509_NAME* name, char* in, int sz);

/*!
    \ingroup CertsKeys
    \brief Returns the pathLenConstraint value from the BasicConstraints extension.

    \return pathLen value on success.
    \return 0 if the extension is not set.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_pathLength usage
    \endcode

    \sa wolfSSL_X509_get_isSet_pathLength
*/
unsigned int wolfSSL_X509_get_pathLength(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Returns the public key contained in the certificate as a newly allocated WOLFSSL_EVP_PKEY. The caller must free the returned key with wolfSSL_EVP_PKEY_free().

    \return pointer to a new EVP_PKEY on success.
    \return NULL on failure.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_pubkey usage
    \endcode

    \sa wolfSSL_X509_get_X509_PUBKEY
*/
WOLFSSL_EVP_PKEY* wolfSSL_X509_get_pubkey(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Returns an integer identifying the algorithm of the certificate's public key (e.g. RSAk, ECDSAk).

    \return public-key type on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_pubkey_type usage
    \endcode

    \sa wolfSSL_X509_get_pubkey
*/
int wolfSSL_X509_get_pubkey_type(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Returns the certificate's serial number as a newly allocated WOLFSSL_ASN1_INTEGER. The caller must free it with wolfSSL_ASN1_INTEGER_free().

    \return pointer to a new ASN1_INTEGER on success.
    \return NULL on failure.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_serialNumber usage
    \endcode

    \sa wolfSSL_X509_get_serial_number
*/
WOLFSSL_ASN1_INTEGER* wolfSSL_X509_get_serialNumber(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Returns the NID identifying the algorithm used to sign x (e.g. NID_sha256WithRSAEncryption).

    \return NID on success.
    \return 0 on error.

    \param x certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_signature_nid usage
    \endcode

    \sa wolfSSL_X509_get_signature_type
*/
int wolfSSL_X509_get_signature_nid(const WOLFSSL_X509* x);

/*!
    \ingroup CertsKeys
    \brief Returns a pointer to the raw DER encoding of the to-be-signed (tbsCertificate) portion of the certificate. The returned buffer is owned by x509.

    \return pointer to the TBS bytes on success.
    \return NULL on failure.

    \param x509 certificate to inspect.
    \param outSz out-parameter receiving the length of the TBS bytes.

    _Example_
    \code
    // see wolfSSL_X509_get_tbs usage
    \endcode

    \sa wolfSSL_X509_get_der
*/
const unsigned char* wolfSSL_X509_get_tbs(WOLFSSL_X509* x509, int* outSz);

/*!
    \ingroup CertsKeys
    \brief Returns the version field of a certificate as a zero-based number (i.e. v3 returns 2).

    \return version value on success.
    \return WOLFSSL_FAILURE on error.

    \param x certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_get_version usage
    \endcode

    \sa wolfSSL_X509_version
*/
long wolfSSL_X509_get_version(const WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys
    \brief Computes the OpenSSL-compatible 32-bit hash of the certificate's issuer name.

    \return 32-bit issuer-name hash on success.
    \return 0 on failure.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_issuer_name_hash usage
    \endcode

    \sa wolfSSL_X509_subject_name_hash
    \sa wolfSSL_X509_NAME_hash
*/
unsigned long  wolfSSL_X509_issuer_name_hash(const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509 structure.

    \return pointer to a new WOLFSSL_X509 on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_X509_new usage
    \endcode

    \sa wolfSSL_X509_new_ex
    \sa wolfSSL_X509_free
*/
WOLFSSL_X509* wolfSSL_X509_new(void);

/*!
    \ingroup CertsKeys
    \brief Allocates and initializes a new empty WOLFSSL_X509 structure using the supplied heap hint.

    \return pointer to a new WOLFSSL_X509 on success.
    \return NULL on failure.

    \param heap heap hint, or NULL for the default heap.

    _Example_
    \code
    // see wolfSSL_X509_new_ex usage
    \endcode

    \sa wolfSSL_X509_new
    \sa wolfSSL_X509_free
*/
WOLFSSL_X509* wolfSSL_X509_new_ex(void* heap);

/*!
    \ingroup CertsKeys
    \brief Writes a human-readable text dump of a certificate to the supplied BIO. Mirrors OpenSSL's X509_print().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio destination BIO.
    \param x509 certificate to print.

    _Example_
    \code
    // see wolfSSL_X509_print usage
    \endcode

    \sa wolfSSL_X509_print_fp
    \sa wolfSSL_X509_REQ_print
*/
int wolfSSL_X509_print(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Writes a human-readable text dump of a certificate to the supplied file stream.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param fp destination file stream.
    \param x509 certificate to print.

    _Example_
    \code
    // see wolfSSL_X509_print_fp usage
    \endcode

    \sa wolfSSL_X509_print
*/
int wolfSSL_X509_print_fp(XFILE fp, WOLFSSL_X509 *x509);

/*!
    \ingroup CertsKeys
    \brief Internal-style accessor that prepares the X509_EXTENSION at index loc for modification, returning a pointer to it.

    \return pointer to the extension on success.
    \return NULL on error.

    \param x certificate to operate on.
    \param loc extension index.

    _Example_
    \code
    // see wolfSSL_X509_set_ext usage
    \endcode

    \sa wolfSSL_X509_get_ext
    \sa wolfSSL_X509_add_ext
*/
WOLFSSL_X509_EXTENSION* wolfSSL_X509_set_ext(WOLFSSL_X509* x, int loc);

/*!
    \ingroup CertsKeys
    \brief Sets the (legacy) Netscape Cert-Type extension on the certificate.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to modify.
    \param nsCertType Netscape Cert-Type bitmask.

    _Example_
    \code
    // see wolfSSL_X509_set_ns_cert_type usage
    \endcode
*/
int wolfSSL_X509_set_ns_cert_type(WOLFSSL_X509* x509, int nsCertType);

/*!
    \ingroup CertsKeys
    \brief Sets the public key of a certificate from a WOLFSSL_EVP_PKEY. The key is copied into the certificate.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param cert certificate to modify.
    \param pkey public key to install.

    _Example_
    \code
    // see wolfSSL_X509_set_pubkey usage
    \endcode

    \sa wolfSSL_X509_get_pubkey
*/
int wolfSSL_X509_set_pubkey(WOLFSSL_X509* cert, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys
    \brief Computes and installs the Subject Key Identifier extension on a certificate from its public key (using the default hash).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to modify.

    _Example_
    \code
    // see wolfSSL_X509_set_subject_key_id_ex usage
    \endcode

    \sa wolfSSL_X509_set_subject_key_id
*/
int wolfSSL_X509_set_subject_key_id_ex(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Sets the version field on a certificate. v is zero-based (i.e. pass 2 for v3).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to modify.
    \param v new version value.

    _Example_
    \code
    // see wolfSSL_X509_set_version usage
    \endcode

    \sa wolfSSL_X509_get_version
*/
int wolfSSL_X509_set_version(WOLFSSL_X509* x509, long v);

/*!
    \ingroup CertsKeys
    \brief Signs a certificate using the digest/key configured in ctx (set up via wolfSSL_EVP_DigestSignInit()). The serialized DER size on success.

    \return size of the signed DER on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to sign.
    \param ctx EVP_MD_CTX configured with signing key and digest.

    _Example_
    \code
    // see wolfSSL_X509_sign_ctx usage
    \endcode

    \sa wolfSSL_X509_sign
*/
int wolfSSL_X509_sign_ctx(WOLFSSL_X509 *x509, WOLFSSL_EVP_MD_CTX *ctx);

/*!
    \ingroup CertsKeys
    \brief Computes the OpenSSL-compatible 32-bit hash of the certificate's subject name.

    \return 32-bit subject-name hash on success.
    \return 0 on failure.

    \param x509 certificate to inspect.

    _Example_
    \code
    // see wolfSSL_X509_subject_name_hash usage
    \endcode

    \sa wolfSSL_X509_issuer_name_hash
    \sa wolfSSL_X509_NAME_hash
*/
unsigned long  wolfSSL_X509_subject_name_hash(const WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Increments the reference count on a WOLFSSL_X509 so it can be shared safely between multiple owners. Each successful call must be paired with a wolfSSL_X509_free().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if x509 is NULL or the reference count could not be incremented.

    \param x509 certificate whose reference count is incremented.

    _Example_
    \code
    // see wolfSSL_X509_up_ref usage
    \endcode

    \sa wolfSSL_X509_free
*/
int wolfSSL_X509_up_ref(WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Verifies the signature of a certificate using the supplied public key (typically the issuer's).

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if the signature does not verify.

    \param x509 certificate to verify.
    \param pkey public key for verification.

    _Example_
    \code
    // see wolfSSL_X509_verify usage
    \endcode

    \sa wolfSSL_X509_verify_cert
*/
int wolfSSL_X509_verify(WOLFSSL_X509* x509, WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup CertsKeys
    \brief Builds and verifies a certificate chain using the trust anchors and CRLs configured on the supplied store context. Mirrors OpenSSL's X509_verify_cert().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if the chain cannot be built or verified; see wolfSSL_X509_STORE_CTX_get_error().

    \param ctx store context, previously initialized with wolfSSL_X509_STORE_CTX_init().

    _Example_
    \code
    // see wolfSSL_X509_verify_cert usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error
    \sa wolfSSL_X509_verify
*/
int         wolfSSL_X509_verify_cert(WOLFSSL_X509_STORE_CTX* ctx);

/*!
    \ingroup CertsKeys
    \brief Returns a static human-readable description of a chain-verification error code returned by wolfSSL_X509_STORE_CTX_get_error().

    \return pointer to a NUL-terminated description (never NULL).

    \param err error code.

    _Example_
    \code
    // see wolfSSL_X509_verify_cert_error_string usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_error
*/
const char* wolfSSL_X509_verify_cert_error_string(long err);

/*!
    \ingroup CertsKeys
    \brief Allocates a new empty WOLFSSL_STACK node used internally by the OpenSSL-compatible sk_* helpers.

    \return pointer to a newly allocated stack node on success.
    \return NULL on allocation failure.

    \param heap optional heap hint used for the underlying allocation; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_new_node usage
    \endcode

    \sa wolfSSL_sk_free_node
    \sa wolfSSL_sk_push_node
*/
WOLFSSL_STACK* wolfSSL_sk_new_node(void* heap);

/*!
    \ingroup CertsKeys
    \brief Frees a single WOLFSSL_STACK node previously allocated with wolfSSL_sk_new_node(). Does not free any data referenced by the node.

    \return none.

    \param in node to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_free_node usage
    \endcode

    \sa wolfSSL_sk_new_node
*/
void wolfSSL_sk_free_node(WOLFSSL_STACK* in);

/*!
    \ingroup CertsKeys
    \brief Returns the WOLFSSL_STACK node at the given index, walking from the head of the stack.

    \return pointer to the node at index idx on success.
    \return NULL if sk is NULL or idx is out of range.

    \param sk stack to traverse.
    \param idx zero-based index of the desired node.

    _Example_
    \code
    // see wolfSSL_sk_get_node usage
    \endcode

    \sa wolfSSL_sk_value
*/
WOLFSSL_STACK* wolfSSL_sk_get_node(WOLFSSL_STACK* sk, int idx);

/*!
    \ingroup CertsKeys
    \brief Pushes a pre-allocated WOLFSSL_STACK node onto the front of *stack, mirroring OpenSSL's internal sk_push_node helper.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if stack or in is NULL.

    \param stack address of the stack head to update.
    \param in node to push.

    _Example_
    \code
    // see wolfSSL_sk_push_node usage
    \endcode

    \sa wolfSSL_sk_push
    \sa wolfSSL_sk_new_node
*/
int wolfSSL_sk_push_node(WOLFSSL_STACK** stack, WOLFSSL_STACK* in);

/*!
    \ingroup CertsKeys
    \brief Frees the entire WOLFSSL_STACK chain. The element data held by each node is not freed; use wolfSSL_sk_pop_free()-style helpers when ownership of the elements must be released.

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_free usage
    \endcode

    \sa wolfSSL_sk_pop_free
    \sa wolfSSL_sk_X509_pop_free
*/
void wolfSSL_sk_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Returns a deep copy of the supplied WOLFSSL_STACK, duplicating each element using the type-specific copy routines. Mirrors OpenSSL's sk_dup().

    \return newly allocated stack on success.
    \return NULL on failure.

    \param sk stack to duplicate.

    _Example_
    \code
    // see wolfSSL_sk_dup usage
    \endcode

    \sa wolfSSL_shallow_sk_dup
*/
WOLFSSL_STACK* wolfSSL_sk_dup(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Returns a shallow copy of the supplied stack. The new stack references the same elements as the original; ownership of those elements is not transferred.

    \return newly allocated stack on success.
    \return NULL on failure.

    \param sk stack to duplicate.

    _Example_
    \code
    // see wolfSSL_shallow_sk_dup usage
    \endcode

    \sa wolfSSL_sk_dup
*/
WOLFSSL_STACK* wolfSSL_shallow_sk_dup(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Appends a generic data pointer to the stack. Mirrors OpenSSL's sk_push().

    \return new stack size on success.
    \return WOLFSSL_FAILURE if st is NULL or allocation fails.

    \param st stack to append to.
    \param data pointer stored in the new node (not copied).

    _Example_
    \code
    // see wolfSSL_sk_push usage
    \endcode

    \sa wolfSSL_sk_insert
    \sa wolfSSL_sk_pop
*/
int wolfSSL_sk_push(WOLFSSL_STACK *st, const void *data);

/*!
    \ingroup CertsKeys
    \brief Inserts a data pointer at the given index, shifting later entries up by one. An idx of -1 appends to the end. Mirrors OpenSSL's sk_insert().

    \return new stack size on success.
    \return WOLFSSL_FAILURE on error.

    \param sk stack to modify.
    \param data pointer stored in the new node.
    \param idx zero-based insertion index, or -1 to append.

    _Example_
    \code
    // see wolfSSL_sk_insert usage
    \endcode

    \sa wolfSSL_sk_push
*/
int wolfSSL_sk_insert(WOLFSSL_STACK *sk, const void *data, int idx);

/*!
    \ingroup CertsKeys
    \brief Removes and returns the top element of the stack. Mirrors OpenSSL's sk_pop().

    \return pointer to the popped element on success.
    \return NULL if the stack is empty or NULL.

    \param sk stack to pop from.

    _Example_
    \code
    // see wolfSSL_sk_pop usage
    \endcode

    \sa wolfSSL_sk_push
*/
void* wolfSSL_sk_pop(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of elements currently held in the stack. Mirrors OpenSSL's sk_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_num usage
    \endcode

    \sa wolfSSL_sk_value
*/
int wolfSSL_sk_num(const WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the element stored at index i without removing it. Mirrors OpenSSL's sk_value().

    \return pointer to the element on success.
    \return NULL if sk is NULL or i is out of range.

    \param sk stack to inspect.
    \param i zero-based element index.

    _Example_
    \code
    // see wolfSSL_sk_value usage
    \endcode

    \sa wolfSSL_sk_num
*/
void* wolfSSL_sk_value(const WOLFSSL_STACK* sk, int i);

/*!
    \ingroup CertsKeys
    \brief Removes and returns the top WOLFSSL_X509 of the stack. Mirrors OpenSSL's sk_X509_pop().

    \return popped WOLFSSL_X509 on success.
    \return NULL if the stack is empty or NULL.

    \param sk stack to pop from.

    _Example_
    \code
    // see wolfSSL_sk_X509_pop usage
    \endcode

    \sa wolfSSL_sk_X509_push
    \sa wolfSSL_sk_X509_free
*/
WOLFSSL_X509* wolfSSL_sk_X509_pop(WOLF_STACK_OF(WOLFSSL_X509)* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_X509 element it contains using wolfSSL_X509_free(). Mirrors OpenSSL's sk_X509_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_X509_free usage
    \endcode

    \sa wolfSSL_sk_X509_pop_free
*/
void wolfSSL_sk_X509_free(WOLF_STACK_OF(WOLFSSL_X509)* sk);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_X509_CRL elements. Mirrors OpenSSL's sk_X509_CRL_new().

    \return newly allocated stack on success.
    \return NULL on allocation failure.


    _Example_
    \code
    // see wolfSSL_sk_X509_CRL_new usage
    \endcode

    \sa wolfSSL_sk_X509_CRL_new_null
    \sa wolfSSL_sk_X509_CRL_free
*/
WOLFSSL_STACK* wolfSSL_sk_X509_CRL_new(void);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_X509_CRL elements (mirrors OpenSSL's sk_X509_CRL_new_null()).

    \return newly allocated stack on success.
    \return NULL on allocation failure.


    _Example_
    \code
    // see wolfSSL_sk_X509_CRL_new_null usage
    \endcode

    \sa wolfSSL_sk_X509_CRL_new
*/
WOLFSSL_STACK* wolfSSL_sk_X509_CRL_new_null(void);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_X509_CRL element it contains. Mirrors OpenSSL's sk_X509_CRL_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_X509_CRL_free usage
    \endcode

    \sa wolfSSL_sk_X509_CRL_new
*/
void wolfSSL_sk_X509_CRL_free(WOLF_STACK_OF(WOLFSSL_X509_CRL)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509_CRL elements held in the stack. Mirrors OpenSSL's sk_X509_CRL_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_CRL_num usage
    \endcode

    \sa wolfSSL_sk_X509_CRL_value
*/
int wolfSSL_sk_X509_CRL_num(WOLF_STACK_OF(WOLFSSL_X509)* sk);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_GENERAL_NAME elements. Mirrors OpenSSL's sk_GENERAL_NAME_new().

    \return newly allocated stack on success.
    \return NULL on allocation failure.

    \param cmpFunc optional comparison callback used for ordered insertion; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_GENERAL_NAME_new usage
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_push
    \sa wolfSSL_sk_GENERAL_NAME_free
*/
WOLFSSL_STACK* wolfSSL_sk_GENERAL_NAME_new(void *cmpFunc);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_GENERAL_NAME elements held in the stack. Mirrors OpenSSL's sk_GENERAL_NAME_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_GENERAL_NAME_num usage
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_value
*/
int wolfSSL_sk_GENERAL_NAME_num(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_GENERAL_NAME element it contains. Mirrors OpenSSL's sk_GENERAL_NAME_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_GENERAL_NAME_free usage
    \endcode

    \sa wolfSSL_sk_GENERAL_NAME_pop_free
*/
void wolfSSL_sk_GENERAL_NAME_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_GENERAL_SUBTREE elements held in the stack. Mirrors OpenSSL's sk_GENERAL_SUBTREE_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_GENERAL_SUBTREE_num usage
    \endcode

    \sa wolfSSL_sk_GENERAL_SUBTREE_value
*/
int wolfSSL_sk_GENERAL_SUBTREE_num(const WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_DIST_POINT elements held in the stack. Mirrors OpenSSL's sk_DIST_POINT_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_DIST_POINT_num usage
    \endcode

    \sa wolfSSL_sk_DIST_POINT_value
*/
int wolfSSL_sk_DIST_POINT_num(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_DIST_POINT element it contains. Mirrors OpenSSL's sk_DIST_POINT_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_DIST_POINT_free usage
    \endcode

    \sa wolfSSL_sk_DIST_POINT_pop_free
*/
void wolfSSL_sk_DIST_POINT_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_ACCESS_DESCRIPTION elements held in the stack. Mirrors OpenSSL's sk_ACCESS_DESCRIPTION_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_ACCESS_DESCRIPTION_num usage
    \endcode

    \sa wolfSSL_sk_ACCESS_DESCRIPTION_value
*/
int wolfSSL_sk_ACCESS_DESCRIPTION_num(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_ACCESS_DESCRIPTION element it contains. Mirrors OpenSSL's sk_ACCESS_DESCRIPTION_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_ACCESS_DESCRIPTION_free usage
    \endcode

    \sa wolfSSL_sk_ACCESS_DESCRIPTION_pop_free
*/
void wolfSSL_sk_ACCESS_DESCRIPTION_free(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_ASN1_OBJECT elements. Mirrors OpenSSL's sk_ASN1_OBJECT_new_null().

    \return newly allocated stack on success.
    \return NULL on allocation failure.


    _Example_
    \code
    // see wolfSSL_sk_new_asn1_obj usage
    \endcode

    \sa wolfSSL_sk_ASN1_OBJECT_push
    \sa wolfSSL_sk_ASN1_OBJECT_free
*/
WOLFSSL_STACK* wolfSSL_sk_new_asn1_obj(void);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_ASN1_OBJECT element it contains. Mirrors OpenSSL's sk_ASN1_OBJECT_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_ASN1_OBJECT_free usage
    \endcode

    \sa wolfSSL_sk_ASN1_OBJECT_pop_free
*/
void wolfSSL_sk_ASN1_OBJECT_free(WOLF_STACK_OF(WOLFSSL_ASN1_OBJECT)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509_EXTENSION elements held in the stack. Mirrors OpenSSL's sk_X509_EXTENSION_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_EXTENSION_num usage
    \endcode

    \sa wolfSSL_sk_X509_EXTENSION_value
*/
int wolfSSL_sk_X509_EXTENSION_num(WOLF_STACK_OF(WOLFSSL_X509_EXTENSION)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509_REVOKED entries in the stack. Mirrors OpenSSL's sk_X509_REVOKED_num().

    \return number of entries (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_REVOKED_num usage
    \endcode

    \sa wolfSSL_sk_X509_REVOKED_value
*/
int       wolfSSL_sk_X509_REVOKED_num(WOLFSSL_STACK* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_CIPHER reference. Mirrors OpenSSL's sk_CIPHER_free(). Cipher entries are typically owned by the SSL context so only the stack itself is released.

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_CIPHER_free usage
    \endcode

    \sa wolfSSL_sk_SSL_CIPHER_free
*/
void wolfSSL_sk_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_X509_EXTENSION elements. Mirrors OpenSSL's sk_X509_EXTENSION_new().

    \return newly allocated stack on success.
    \return NULL on allocation failure.


    _Example_
    \code
    // see wolfSSL_sk_new_x509_ext usage
    \endcode

    \sa wolfSSL_sk_X509_EXTENSION_push
    \sa wolfSSL_sk_X509_EXTENSION_free
*/
WOLFSSL_STACK* wolfSSL_sk_new_x509_ext(void);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_X509 elements (sk_X509_new_null() compatible).

    \return newly allocated stack on success.
    \return NULL on allocation failure.


    _Example_
    \code
    // see wolfSSL_sk_X509_new_null usage
    \endcode

    \sa wolfSSL_sk_X509_push
    \sa wolfSSL_sk_X509_free
*/
WOLFSSL_STACK* wolfSSL_sk_X509_new_null(void);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509 elements held in the stack. Mirrors OpenSSL's sk_X509_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if s is NULL.

    \param s stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_num usage
    \endcode

    \sa wolfSSL_sk_X509_value
*/
int wolfSSL_sk_X509_num(const WOLF_STACK_OF(WOLFSSL_X509) *s);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_X509_OBJECT elements. Mirrors OpenSSL's sk_X509_OBJECT_new().

    \return newly allocated stack on success.
    \return NULL on allocation failure.


    _Example_
    \code
    // see wolfSSL_sk_X509_OBJECT_new usage
    \endcode

    \sa wolfSSL_sk_X509_OBJECT_push
    \sa wolfSSL_sk_X509_OBJECT_free
*/
WOLFSSL_STACK* wolfSSL_sk_X509_OBJECT_new(void);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_X509_OBJECT element it contains. Mirrors OpenSSL's sk_X509_OBJECT_free().

    \return none.

    \param s stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_X509_OBJECT_free usage
    \endcode

    \sa wolfSSL_sk_X509_OBJECT_pop_free
*/
void wolfSSL_sk_X509_OBJECT_free(WOLFSSL_STACK* s);

/*!
    \ingroup CertsKeys
    \brief Pushes a WOLFSSL_X509_OBJECT onto the stack. Mirrors OpenSSL's sk_X509_OBJECT_push().

    \return new stack size on success.
    \return WOLFSSL_FAILURE if sk or obj is NULL.

    \param sk stack to push onto.
    \param obj object to append.

    _Example_
    \code
    // see wolfSSL_sk_X509_OBJECT_push usage
    \endcode

    \sa wolfSSL_sk_X509_OBJECT_pop_free
*/
int wolfSSL_sk_X509_OBJECT_push(WOLFSSL_STACK* sk, WOLFSSL_X509_OBJECT* obj);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_X509_INFO elements (sk_X509_INFO_new_null() compatible).

    \return newly allocated stack on success.
    \return NULL on allocation failure.


    _Example_
    \code
    // see wolfSSL_sk_X509_INFO_new_null usage
    \endcode

    \sa wolfSSL_sk_X509_INFO_push
    \sa wolfSSL_sk_X509_INFO_free
*/
WOLFSSL_STACK* wolfSSL_sk_X509_INFO_new_null(void);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509_INFO elements held in the stack. Mirrors OpenSSL's sk_X509_INFO_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_INFO_num usage
    \endcode

    \sa wolfSSL_sk_X509_INFO_value
*/
int wolfSSL_sk_X509_INFO_num(const WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk);

/*!
    \ingroup CertsKeys
    \brief Removes and returns the top WOLFSSL_X509_INFO of the stack. Mirrors OpenSSL's sk_X509_INFO_pop().

    \return popped WOLFSSL_X509_INFO on success.
    \return NULL if the stack is empty or NULL.

    \param sk stack to pop from.

    _Example_
    \code
    // see wolfSSL_sk_X509_INFO_pop usage
    \endcode

    \sa wolfSSL_sk_X509_INFO_push
*/
WOLFSSL_X509_INFO* wolfSSL_sk_X509_INFO_pop(WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_X509_INFO element it contains. Mirrors OpenSSL's sk_X509_INFO_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_X509_INFO_free usage
    \endcode

    \sa wolfSSL_sk_X509_INFO_pop_free
*/
void wolfSSL_sk_X509_INFO_free(WOLF_STACK_OF(WOLFSSL_X509_INFO)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the WOLFSSL_X509_NAME element at index i without removing it. Mirrors OpenSSL's sk_X509_NAME_value().

    \return pointer to the element on success.
    \return NULL if sk is NULL or i is out of range.

    \param sk stack to inspect.
    \param i zero-based element index.

    _Example_
    \code
    // see wolfSSL_sk_X509_NAME_value usage
    \endcode

    \sa wolfSSL_sk_X509_NAME_num
*/
WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_value(const WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk, int i);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509_NAME elements held in the stack. Mirrors OpenSSL's sk_X509_NAME_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_NAME_num usage
    \endcode

    \sa wolfSSL_sk_X509_NAME_value
*/
int wolfSSL_sk_X509_NAME_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk);

/*!
    \ingroup CertsKeys
    \brief Removes and returns the top WOLFSSL_X509_NAME of the stack. Mirrors OpenSSL's sk_X509_NAME_pop().

    \return popped WOLFSSL_X509_NAME on success.
    \return NULL if the stack is empty or NULL.

    \param sk stack to pop from.

    _Example_
    \code
    // see wolfSSL_sk_X509_NAME_pop usage
    \endcode

    \sa wolfSSL_sk_X509_NAME_push
*/
WOLFSSL_X509_NAME* wolfSSL_sk_X509_NAME_pop(WOLF_STACK_OF(WOLFSSL_X509_NAME)* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_X509_NAME element it contains. Mirrors OpenSSL's sk_X509_NAME_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_X509_NAME_free usage
    \endcode

    \sa wolfSSL_sk_X509_NAME_pop_free
*/
void wolfSSL_sk_X509_NAME_free(WOLF_STACK_OF(WOLFSSL_X509_NAME) * sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509_NAME_ENTRY elements held in the stack. Mirrors OpenSSL's sk_X509_NAME_ENTRY_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_NAME_ENTRY_num usage
    \endcode

    \sa wolfSSL_sk_X509_NAME_ENTRY_value
*/
int  wolfSSL_sk_X509_NAME_ENTRY_num(const WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_X509_NAME_ENTRY element it contains. Mirrors OpenSSL's sk_X509_NAME_ENTRY_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_X509_NAME_ENTRY_free usage
    \endcode

    \sa wolfSSL_sk_X509_NAME_ENTRY_new
*/
void wolfSSL_sk_X509_NAME_ENTRY_free(WOLF_STACK_OF(WOLFSSL_X509_NAME_ENTRY)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_X509_OBJECT elements held in the stack. Mirrors OpenSSL's sk_X509_OBJECT_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if s is NULL.

    \param s stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_X509_OBJECT_num usage
    \endcode

    \sa wolfSSL_sk_X509_OBJECT_value
*/
int wolfSSL_sk_X509_OBJECT_num(const WOLF_STACK_OF(WOLFSSL_X509_OBJECT) *s);

/*!
    \ingroup CertsKeys
    \brief Allocates an empty WOLFSSL_STACK suitable for holding WOLFSSL_CONF_VALUE elements. Mirrors OpenSSL's sk_CONF_VALUE_new().

    \return newly allocated stack on success.
    \return NULL on allocation failure.

    \param compFunc optional comparison callback used for ordered insertion; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_CONF_VALUE_new usage
    \endcode

    \sa wolfSSL_sk_CONF_VALUE_push
    \sa wolfSSL_sk_CONF_VALUE_free
*/
WOLFSSL_STACK *wolfSSL_sk_CONF_VALUE_new(WOLF_SK_COMPARE_CB(WOLFSSL_CONF_VALUE, compFunc));

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_CONF_VALUE element it contains. Mirrors OpenSSL's sk_CONF_VALUE_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_CONF_VALUE_free usage
    \endcode

    \sa wolfSSL_sk_CONF_VALUE_new
*/
void wolfSSL_sk_CONF_VALUE_free(struct WOLFSSL_STACK *sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_CONF_VALUE elements held in the stack. Mirrors OpenSSL's sk_CONF_VALUE_num().

    \return number of elements (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_CONF_VALUE_num usage
    \endcode

    \sa wolfSSL_sk_CONF_VALUE_value
*/
int wolfSSL_sk_CONF_VALUE_num(const WOLFSSL_STACK *sk);

/*!
    \ingroup CertsKeys
    \brief Returns the WOLFSSL_X509 element at index i without removing it. Mirrors OpenSSL's sk_X509_value().

    \return pointer to the element on success.
    \return NULL if the stack is NULL or i is out of range.

    \param sk stack to inspect.
    \param i zero-based element index.

    _Example_
    \code
    // see wolfSSL_sk_X509_value usage
    \endcode

    \sa wolfSSL_sk_X509_num
*/
WOLFSSL_X509* wolfSSL_sk_X509_value(WOLF_STACK_OF(WOLFSSL_X509)* sk, int i);

/*!
    \ingroup CertsKeys
    \brief Removes and returns the bottom WOLFSSL_X509 of the stack. Mirrors OpenSSL's sk_X509_shift().

    \return shifted WOLFSSL_X509 on success.
    \return NULL if the stack is empty or NULL.

    \param sk stack to shift from.

    _Example_
    \code
    // see wolfSSL_sk_X509_shift usage
    \endcode

    \sa wolfSSL_sk_X509_pop
*/
WOLFSSL_X509* wolfSSL_sk_X509_shift(WOLF_STACK_OF(WOLFSSL_X509)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the WOLFSSL_X509_OBJECT element at index i without removing it. Mirrors OpenSSL's sk_X509_OBJECT_value().

    \return pointer to the element on success.
    \return NULL if the stack is NULL or i is out of range.

    \param sk stack to inspect.
    \param i zero-based element index.

    _Example_
    \code
    // see wolfSSL_sk_X509_OBJECT_value usage
    \endcode

    \sa wolfSSL_sk_X509_OBJECT_num
*/
void* wolfSSL_sk_X509_OBJECT_value(WOLF_STACK_OF(WOLFSSL_X509_OBJECT)* sk, int i);

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_X509 element using the supplied freeing callback. Mirrors OpenSSL's sk_X509_pop_free().

    \return none.

    \param sk stack to free; may be NULL.
    \param f callback invoked for each element prior to releasing the node.

    _Example_
    \code
    // see wolfSSL_sk_X509_pop_free usage
    \endcode

    \sa wolfSSL_sk_X509_free
*/
void wolfSSL_sk_X509_pop_free(WOLF_STACK_OF(WOLFSSL_X509)* sk, void (*f) (WOLFSSL_X509*));

/*!
    \ingroup CertsKeys
    \brief Frees the stack and each WOLFSSL_STRING entry it holds. Mirrors OpenSSL's sk_OPENSSL_STRING_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_WOLFSSL_STRING_free usage
    \endcode

    \sa wolfSSL_sk_WOLFSSL_STRING_value
*/
void wolfSSL_sk_WOLFSSL_STRING_free(WOLF_STACK_OF(WOLFSSL_STRING)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the number of WOLFSSL_CIPHER entries in the SSL cipher stack. Mirrors OpenSSL's sk_SSL_CIPHER_num().

    \return number of entries (>= 0).
    \return WOLFSSL_FATAL_ERROR if p is NULL.

    \param p stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_SSL_CIPHER_num usage
    \endcode

    \sa wolfSSL_sk_SSL_CIPHER_value
*/
int wolfSSL_sk_SSL_CIPHER_num(const WOLF_STACK_OF(WOLFSSL_CIPHER)* p);

/*!
    \ingroup CertsKeys
    \brief Frees an SSL cipher stack created by wolfSSL_get_ciphers_compat() or similar APIs. Mirrors OpenSSL's sk_SSL_CIPHER_free().

    \return none.

    \param sk stack to free; may be NULL.

    _Example_
    \code
    // see wolfSSL_sk_SSL_CIPHER_free usage
    \endcode

    \sa wolfSSL_sk_SSL_CIPHER_num
*/
void wolfSSL_sk_SSL_CIPHER_free(WOLF_STACK_OF(WOLFSSL_CIPHER)* sk);

/*!
    \ingroup CertsKeys
    \brief Empties the SSL compression-methods stack. Mirrors OpenSSL's sk_SSL_COMP_zero(); wolfSSL does not implement TLS compression so this resets the stack to length zero.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE if st is NULL.

    \param st stack to clear.

    _Example_
    \code
    // see wolfSSL_sk_SSL_COMP_zero usage
    \endcode

    \sa wolfSSL_sk_SSL_COMP_num
*/
int wolfSSL_sk_SSL_COMP_zero(WOLFSSL_STACK* st);

/*!
    \ingroup CertsKeys
    \brief Returns the number of compression methods registered in the stack. wolfSSL does not implement TLS compression, so this typically returns 0. Mirrors OpenSSL's sk_SSL_COMP_num().

    \return number of entries (>= 0).
    \return WOLFSSL_FATAL_ERROR if sk is NULL.

    \param sk stack to inspect.

    _Example_
    \code
    // see wolfSSL_sk_SSL_COMP_num usage
    \endcode

    \sa wolfSSL_sk_SSL_COMP_zero
*/
int wolfSSL_sk_SSL_COMP_num(WOLF_STACK_OF(WOLFSSL_COMP)* sk);

/*!
    \ingroup CertsKeys
    \brief Returns the WOLFSSL_CIPHER stored at index i in the SSL cipher stack. Mirrors OpenSSL's sk_SSL_CIPHER_value().

    \return pointer to the cipher on success.
    \return NULL if sk is NULL or i is out of range.

    \param sk stack to inspect.
    \param i zero-based index.

    _Example_
    \code
    // see wolfSSL_sk_SSL_CIPHER_value usage
    \endcode

    \sa wolfSSL_sk_SSL_CIPHER_num
*/
WOLFSSL_CIPHER* wolfSSL_sk_SSL_CIPHER_value(WOLFSSL_STACK* sk, int i);


/*!
    \ingroup openSSL
    \brief Writes a human-readable description of the cipher into buffer in (up to len bytes). Mirrors OpenSSL's SSL_CIPHER_description().

    \return pointer to in on success.
    \return NULL on failure or invalid arguments.

    \param cipher WOLFSSL_CIPHER to describe.
    \param in destination buffer.
    \param len size of in.

    _Example_
    \code
    // see wolfSSL_CIPHER_description usage
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
char* wolfSSL_CIPHER_description(const WOLFSSL_CIPHER* cipher, char* in, int len);

/*!
    \ingroup openSSL
    \brief Returns the NID of the authentication algorithm used by the cipher. Mirrors OpenSSL's SSL_CIPHER_get_auth_nid().

    \return NID identifying the authentication algorithm.
    \return NID_undef on error or unknown cipher.

    \param cipher WOLFSSL_CIPHER to query.

    _Example_
    \code
    // see wolfSSL_CIPHER_get_auth_nid usage
    \endcode

    \sa wolfSSL_CIPHER_get_cipher_nid
    \sa wolfSSL_CIPHER_get_digest_nid
*/
int wolfSSL_CIPHER_get_auth_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Returns the number of secret bits used by the cipher. If alg_bits is non-NULL, the underlying algorithm bit size is also stored there. Mirrors OpenSSL's SSL_CIPHER_get_bits().

    \return number of secret bits on success.
    \return 0 on error.

    \param c WOLFSSL_CIPHER to query.
    \param alg_bits optional output for algorithm bits.

    _Example_
    \code
    // see wolfSSL_CIPHER_get_bits usage
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
int wolfSSL_CIPHER_get_bits(const WOLFSSL_CIPHER *c, int *alg_bits);

/*!
    \ingroup openSSL
    \brief Returns the NID of the symmetric cipher used by the WOLFSSL_CIPHER. Mirrors OpenSSL's SSL_CIPHER_get_cipher_nid().

    \return NID for the cipher algorithm.
    \return NID_undef on error or unknown cipher.

    \param cipher WOLFSSL_CIPHER to query.

    _Example_
    \code
    // see wolfSSL_CIPHER_get_cipher_nid usage
    \endcode

    \sa wolfSSL_CIPHER_get_auth_nid
    \sa wolfSSL_CIPHER_get_digest_nid
*/
int wolfSSL_CIPHER_get_cipher_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Returns the NID of the digest (MAC) algorithm used by the cipher. Mirrors OpenSSL's SSL_CIPHER_get_digest_nid().

    \return NID for the digest algorithm.
    \return NID_undef on error or unknown cipher.

    \param cipher WOLFSSL_CIPHER to query.

    _Example_
    \code
    // see wolfSSL_CIPHER_get_digest_nid usage
    \endcode

    \sa wolfSSL_CIPHER_get_auth_nid
    \sa wolfSSL_CIPHER_get_cipher_nid
*/
int wolfSSL_CIPHER_get_digest_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Returns the numerical identifier of the cipher suite. Mirrors OpenSSL's SSL_CIPHER_get_id().

    \return cipher identifier.

    \param cipher WOLFSSL_CIPHER to query.

    _Example_
    \code
    // see wolfSSL_CIPHER_get_id usage
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
word32 wolfSSL_CIPHER_get_id(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Returns the NID of the key-exchange algorithm used by the cipher. Mirrors OpenSSL's SSL_CIPHER_get_kx_nid().

    \return NID identifying the key-exchange algorithm.
    \return NID_undef on error or unknown cipher.

    \param cipher WOLFSSL_CIPHER to query.

    _Example_
    \code
    // see wolfSSL_CIPHER_get_kx_nid usage
    \endcode

    \sa wolfSSL_CIPHER_get_auth_nid
*/
int wolfSSL_CIPHER_get_kx_nid(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Returns the protocol version string (e.g. "TLSv1.2") the cipher was negotiated for. Mirrors OpenSSL's SSL_CIPHER_get_version().

    \return null-terminated version string on success.
    \return NULL on failure.

    \param cipher WOLFSSL_CIPHER to query.

    _Example_
    \code
    // see wolfSSL_CIPHER_get_version usage
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
const char* wolfSSL_CIPHER_get_version(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Reports whether the cipher uses an AEAD (Authenticated Encryption with Associated Data) algorithm. Mirrors OpenSSL's SSL_CIPHER_is_aead().

    \return 1 if the cipher is AEAD.
    \return 0 otherwise.

    \param cipher WOLFSSL_CIPHER to query.

    _Example_
    \code
    // see wolfSSL_CIPHER_is_aead usage
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
int wolfSSL_CIPHER_is_aead(const WOLFSSL_CIPHER* cipher);

/*!
    \ingroup openSSL
    \brief Stub for adding a compression method. wolfSSL does not implement TLS-level compression; this is provided for OpenSSL compatibility only.

    \return 0 always.

    \param method unused.
    \param data unused.

    _Example_
    \code
    // see wolfSSL_COMP_add_compression_method usage
    \endcode

    \sa wolfSSL_COMP_get_name
*/
int wolfSSL_COMP_add_compression_method(int method, void* data);

/*!
    \ingroup openSSL
    \brief Returns the name of the compression method. Always returns a placeholder string since wolfSSL does not perform TLS compression. Mirrors OpenSSL's SSL_COMP_get_name().

    \return compression name string.
    \return NULL if comp is NULL.

    \param comp compression method pointer.

    _Example_
    \code
    // see wolfSSL_COMP_get_name usage
    \endcode

    \sa wolfSSL_COMP_add_compression_method
*/
const char *wolfSSL_COMP_get_name(const WOLFSSL_COMP_METHOD *comp);

/*!
    \ingroup openSSL
    \brief Returns a pointer used to reference RLE compression. wolfSSL does not implement TLS compression; provided for OpenSSL API compatibility.

    \return NULL.

    _Example_
    \code
    // see wolfSSL_COMP_rle usage
    \endcode

    \sa wolfSSL_COMP_zlib
*/
WOLFSSL_COMP_METHOD* wolfSSL_COMP_rle(void);

/*!
    \ingroup openSSL
    \brief Returns a pointer used to reference zlib compression. wolfSSL does not implement TLS compression; provided for OpenSSL API compatibility.

    \return NULL.

    _Example_
    \code
    // see wolfSSL_COMP_zlib usage
    \endcode

    \sa wolfSSL_COMP_rle
*/
WOLFSSL_COMP_METHOD* wolfSSL_COMP_zlib(void);

/*!
    \ingroup openSSL
    \brief Finalizes processing of any pending configuration commands held in the WOLFSSL_CONF_CTX. Mirrors OpenSSL's SSL_CONF_CTX_finish().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param cctx configuration context.

    _Example_
    \code
    // see wolfSSL_CONF_CTX_finish usage
    \endcode

    \sa wolfSSL_CONF_CTX_new
    \sa wolfSSL_CONF_CTX_free
*/
int wolfSSL_CONF_CTX_finish(WOLFSSL_CONF_CTX* cctx);

/*!
    \ingroup openSSL
    \brief Releases a WOLFSSL_CONF_CTX allocated with wolfSSL_CONF_CTX_new(). Mirrors OpenSSL's SSL_CONF_CTX_free().

    \return none No returns.

    \param cctx configuration context to free.

    _Example_
    \code
    // see wolfSSL_CONF_CTX_free usage
    \endcode

    \sa wolfSSL_CONF_CTX_new
*/
void wolfSSL_CONF_CTX_free(WOLFSSL_CONF_CTX* cctx);

/*!
    \ingroup openSSL
    \brief Allocates and returns a new WOLFSSL_CONF_CTX used to process configuration commands. Mirrors OpenSSL's SSL_CONF_CTX_new().

    \return pointer to a new WOLFSSL_CONF_CTX on success.
    \return NULL on allocation failure.

    _Example_
    \code
    // see wolfSSL_CONF_CTX_new usage
    \endcode

    \sa wolfSSL_CONF_CTX_free
    \sa wolfSSL_CONF_CTX_set_flags
*/
WOLFSSL_CONF_CTX* wolfSSL_CONF_CTX_new(void);

/*!
    \ingroup openSSL
    \brief Sets command-processing flags (e.g. file vs. command-line, server/client) on the configuration context. Mirrors OpenSSL's SSL_CONF_CTX_set_flags().

    \return the resulting set of flags after applying the bitmask.

    \param cctx configuration context.
    \param flags bitmask of WOLFSSL_CONF_FLAG_* values.

    _Example_
    \code
    // see wolfSSL_CONF_CTX_set_flags usage
    \endcode

    \sa wolfSSL_CONF_CTX_new
*/
unsigned int wolfSSL_CONF_CTX_set_flags(WOLFSSL_CONF_CTX* cctx, unsigned int flags);

/*!
    \ingroup openSSL
    \brief Associates a WOLFSSL_CTX with the configuration context so that subsequent wolfSSL_CONF_cmd() calls modify it. Mirrors OpenSSL's SSL_CONF_CTX_set_ssl_ctx().

    \return WOLFSSL_SUCCESS on success.

    \param cctx configuration context.
    \param ctx WOLFSSL_CTX to associate.

    _Example_
    \code
    // see wolfSSL_CONF_CTX_set_ssl_ctx usage
    \endcode

    \sa wolfSSL_CONF_cmd
*/
void wolfSSL_CONF_CTX_set_ssl_ctx(WOLFSSL_CONF_CTX* cctx, WOLFSSL_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Processes a single configuration command/value pair against the associated WOLFSSL_CTX. Mirrors OpenSSL's SSL_CONF_cmd().

    \return recognized command type code on success.
    \return WOLFSSL_FAILURE if the command is unknown.
    \return -2 if the command requires a value that was not provided.

    \param cctx configuration context.
    \param cmd command string.
    \param value command argument or NULL.

    _Example_
    \code
    // see wolfSSL_CONF_cmd usage
    \endcode

    \sa wolfSSL_CONF_cmd_value_type
*/
int wolfSSL_CONF_cmd(WOLFSSL_CONF_CTX* cctx, const char* cmd, const char* value);

/*!
    \ingroup openSSL
    \brief Returns the type of value expected by a configuration command. Mirrors OpenSSL's SSL_CONF_cmd_value_type().

    \return one of the SSL_CONF_TYPE_* constants.

    \param cctx configuration context.
    \param cmd command name.

    _Example_
    \code
    // see wolfSSL_CONF_cmd_value_type usage
    \endcode

    \sa wolfSSL_CONF_cmd
*/
int wolfSSL_CONF_cmd_value_type(WOLFSSL_CONF_CTX *cctx, const char *cmd);

/*!
    \ingroup openSSL
    \brief Returns a newly allocated string containing the path to the default OpenSSL configuration file. Mirrors OpenSSL's CONF_get1_default_config_file().

    \return heap-allocated string the caller must free.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_CONF_get1_default_config_file usage
    \endcode

    \sa wolfSSL_OPENSSL_config
*/
char* wolfSSL_CONF_get1_default_config_file(void);

/*!
    \ingroup openSSL
    \brief Unloads dynamically-loaded configuration modules. Provided for OpenSSL compatibility; in wolfSSL it is a no-op.

    \return 1 always.

    \param all unused.

    _Example_
    \code
    // see wolfSSL_CONF_modules_unload usage
    \endcode

    \sa wolfSSL_OPENSSL_config
*/
void wolfSSL_CONF_modules_unload(int all);

/*!
    \ingroup openSSL
    \brief Cleans up all per-object extra-data slots registered via CRYPTO_get_ex_new_index(). Mirrors OpenSSL's CRYPTO_cleanup_all_ex_data(); a no-op in wolfSSL.

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_CRYPTO_cleanup_all_ex_data usage
    \endcode

    \sa wolfSSL_CRYPTO_get_ex_new_index
*/
void wolfSSL_CRYPTO_cleanup_all_ex_data(void);

/*!
    \ingroup openSSL
    \brief Wrapper around free() that matches the OpenSSL CRYPTO_free() signature. The file and line arguments are ignored.

    \return none No returns.

    \param str pointer previously returned by wolfSSL_CRYPTO_malloc.
    \param file unused.
    \param line unused.

    _Example_
    \code
    // see wolfSSL_CRYPTO_free usage
    \endcode

    \sa wolfSSL_CRYPTO_malloc
*/
void wolfSSL_CRYPTO_free(void *str, const char *file, int line);

/*!
    \ingroup openSSL
    \brief Wrapper around malloc() that matches the OpenSSL CRYPTO_malloc() signature. The file and line arguments are ignored.

    \return pointer to the allocated buffer on success.
    \return NULL on failure.

    \param num number of bytes to allocate.
    \param file unused.
    \param line unused.

    _Example_
    \code
    // see wolfSSL_CRYPTO_malloc usage
    \endcode

    \sa wolfSSL_CRYPTO_free
*/
void *wolfSSL_CRYPTO_malloc(size_t num, const char *file, int line);

/*!
    \ingroup openSSL
    \brief Performs a constant-time comparison of two buffers, returning zero only if they are equal. Mirrors OpenSSL's CRYPTO_memcmp().

    \return 0 if the buffers are equal.
    \return non-zero if they differ.

    \param a first buffer.
    \param b second buffer.
    \param size number of bytes to compare.

    _Example_
    \code
    // see wolfSSL_CRYPTO_memcmp usage
    \endcode

    \sa wolfSSL_CRYPTO_malloc
*/
int wolfSSL_CRYPTO_memcmp(const void *a, const void *b, size_t size);

/*!
    \ingroup CertsKeys
    \brief Loads RFC 5114 1024-bit MODP Diffie-Hellman prime into the supplied WOLFSSL_BIGNUM. Mirrors OpenSSL's BN_get_rfc2409_prime_1024().

    \return bn on success.
    \return NULL on failure.

    \param bn destination BIGNUM; allocated if NULL.

    _Example_
    \code
    // see wolfSSL_DH_1024_prime usage
    \endcode

    \sa wolfSSL_DH_2048_prime
    \sa wolfSSL_DH_3072_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_1024_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup CertsKeys
    \brief Returns a newly allocated WOLFSSL_BIGNUM containing the 1536-bit MODP Diffie-Hellman prime from RFC 3526.

    \return allocated BIGNUM on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_DH_1536_prime usage
    \endcode

    \sa wolfSSL_DH_2048_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_1536_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup CertsKeys
    \brief Returns a newly allocated WOLFSSL_BIGNUM containing the 2048-bit MODP Diffie-Hellman prime from RFC 3526.

    \return allocated BIGNUM on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_DH_2048_prime usage
    \endcode

    \sa wolfSSL_DH_3072_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_2048_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup CertsKeys
    \brief Returns a newly allocated WOLFSSL_BIGNUM containing the 3072-bit MODP Diffie-Hellman prime from RFC 3526.

    \return allocated BIGNUM on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_DH_3072_prime usage
    \endcode

    \sa wolfSSL_DH_4096_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_3072_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup CertsKeys
    \brief Returns a newly allocated WOLFSSL_BIGNUM containing the 4096-bit MODP Diffie-Hellman prime from RFC 3526.

    \return allocated BIGNUM on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_DH_4096_prime usage
    \endcode

    \sa wolfSSL_DH_6144_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_4096_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup CertsKeys
    \brief Returns a newly allocated WOLFSSL_BIGNUM containing the 6144-bit MODP Diffie-Hellman prime from RFC 3526.

    \return allocated BIGNUM on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_DH_6144_prime usage
    \endcode

    \sa wolfSSL_DH_8192_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_6144_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup CertsKeys
    \brief Returns a newly allocated WOLFSSL_BIGNUM containing the 768-bit MODP Diffie-Hellman prime. Provided for legacy/test use; the 768-bit group is no longer considered secure.

    \return allocated BIGNUM on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_DH_768_prime usage
    \endcode

    \sa wolfSSL_DH_2048_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_768_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup CertsKeys
    \brief Returns a newly allocated WOLFSSL_BIGNUM containing the 8192-bit MODP Diffie-Hellman prime from RFC 3526.

    \return allocated BIGNUM on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_DH_8192_prime usage
    \endcode

    \sa wolfSSL_DH_4096_prime
*/
WOLFSSL_BIGNUM* wolfSSL_DH_8192_prime(WOLFSSL_BIGNUM* bn);

/*!
    \ingroup Debug
    \brief Extracts the library component from a packed wolfSSL/OpenSSL error code. Mirrors OpenSSL's ERR_GET_LIB().

    \return library identifier portion of the error code.

    \param err packed error code.

    _Example_
    \code
    // see wolfSSL_ERR_GET_LIB usage
    \endcode

    \sa wolfSSL_ERR_GET_REASON
*/
int wolfSSL_ERR_GET_LIB(unsigned long err);

/*!
    \ingroup Debug
    \brief Extracts the reason code from a packed wolfSSL/OpenSSL error code. Mirrors OpenSSL's ERR_GET_REASON().

    \return reason portion of the error code.

    \param err packed error code.

    _Example_
    \code
    // see wolfSSL_ERR_GET_REASON usage
    \endcode

    \sa wolfSSL_ERR_GET_LIB
*/
int wolfSSL_ERR_GET_REASON(unsigned long err);

/*!
    \ingroup Debug
    \brief Clears all errors currently queued for the calling thread. Mirrors OpenSSL's ERR_clear_error().

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_ERR_clear_error usage
    \endcode

    \sa wolfSSL_ERR_get_error
*/
void wolfSSL_ERR_clear_error(void);

/*!
    \ingroup Debug
    \brief Writes a human-readable dump of every error currently on the thread error queue to fp. Mirrors OpenSSL's ERR_print_errors_fp().

    \return none No returns.

    \param fp destination file.

    _Example_
    \code
    // see wolfSSL_ERR_dump_errors_fp usage
    \endcode

    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_ERR_print_errors
*/
void wolfSSL_ERR_dump_errors_fp(XFILE fp);

/*!
    \ingroup Debug
    \brief Frees any error string tables loaded by wolfSSL_ERR_load_*_strings(). Mirrors OpenSSL's ERR_free_strings(); a no-op in wolfSSL.

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_ERR_free_strings usage
    \endcode

    \sa wolfSSL_ERR_load_ERR_strings
*/
void wolfSSL_ERR_free_strings(void);

/*!
    \ingroup Debug
    \brief Returns the function name component of an error code as a string. Mirrors OpenSSL's ERR_func_error_string(); always returns an empty string in wolfSSL.

    \return empty string.

    \param err packed error code.

    _Example_
    \code
    // see wolfSSL_ERR_func_error_string usage
    \endcode

    \sa wolfSSL_ERR_lib_error_string
    \sa wolfSSL_ERR_reason_error_string
*/
const char* wolfSSL_ERR_func_error_string(unsigned long e);

/*!
    \ingroup Debug
    \brief Removes and returns the next error from the thread error queue, or 0 if the queue is empty. Mirrors OpenSSL's ERR_get_error().

    \return error code value, or 0 when the queue is empty.

    _Example_
    \code
    // see wolfSSL_ERR_get_error usage
    \endcode

    \sa wolfSSL_ERR_peek_error
    \sa wolfSSL_ERR_clear_error
*/
unsigned long wolfSSL_ERR_get_error(void);

/*!
    \ingroup Debug
    \brief Removes the next error from the thread error queue and additionally returns the file and line where it was recorded. Mirrors OpenSSL's ERR_get_error_line().

    \return error code value, or 0 when the queue is empty.

    \param file optional output for source file name.
    \param line optional output for line number.

    _Example_
    \code
    // see wolfSSL_ERR_get_error_line usage
    \endcode

    \sa wolfSSL_ERR_get_error
    \sa wolfSSL_ERR_peek_last_error_line
*/
unsigned long wolfSSL_ERR_get_error_line(const char** file, int* line);

/*!
    \ingroup Debug
    \brief Returns the library name component of an error code as a string. Mirrors OpenSSL's ERR_lib_error_string().

    \return library name string, or empty string.

    \param err packed error code.

    _Example_
    \code
    // see wolfSSL_ERR_lib_error_string usage
    \endcode

    \sa wolfSSL_ERR_func_error_string
    \sa wolfSSL_ERR_reason_error_string
*/
const char* wolfSSL_ERR_lib_error_string(unsigned long e);

/*!
    \ingroup Debug
    \brief Loads the BIO subsystem error strings. Mirrors OpenSSL's ERR_load_BIO_strings(); a no-op in wolfSSL.

    \return 0 always.

    _Example_
    \code
    // see wolfSSL_ERR_load_BIO_strings usage
    \endcode

    \sa wolfSSL_ERR_load_ERR_strings
*/
void wolfSSL_ERR_load_BIO_strings(void);

/*!
    \ingroup Debug
    \brief Loads the ERR subsystem error strings. Mirrors OpenSSL's ERR_load_ERR_strings(); a no-op in wolfSSL.

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_ERR_load_ERR_strings usage
    \endcode

    \sa wolfSSL_ERR_load_crypto_strings
*/
int wolfSSL_ERR_load_ERR_strings(void);

/*!
    \ingroup Debug
    \brief Loads the SSL subsystem error strings. Mirrors OpenSSL's ERR_load_SSL_strings(); a no-op in wolfSSL.

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_ERR_load_SSL_strings usage
    \endcode

    \sa wolfSSL_ERR_load_ERR_strings
*/
void wolfSSL_ERR_load_SSL_strings(void);

/*!
    \ingroup Debug
    \brief Loads the libcrypto error strings. Mirrors OpenSSL's ERR_load_crypto_strings(); a no-op in wolfSSL.

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_ERR_load_crypto_strings usage
    \endcode

    \sa wolfSSL_ERR_load_ERR_strings
*/
void wolfSSL_ERR_load_crypto_strings(void);

/*!
    \ingroup Debug
    \brief Returns the next error on the thread error queue without removing it. Mirrors OpenSSL's ERR_peek_error().

    \return error code value, or 0 when the queue is empty.

    _Example_
    \code
    // see wolfSSL_ERR_peek_error usage
    \endcode

    \sa wolfSSL_ERR_get_error
*/
unsigned long wolfSSL_ERR_peek_error(void);

/*!
    \ingroup Debug
    \brief Returns the most recent error on the queue (without removing it) and reports the file and line where it was recorded. Mirrors OpenSSL's ERR_peek_last_error_line().

    \return error code value, or 0 when the queue is empty.

    \param file optional output for source file name.
    \param line optional output for line number.

    _Example_
    \code
    // see wolfSSL_ERR_peek_last_error_line usage
    \endcode

    \sa wolfSSL_ERR_peek_last_error
    \sa wolfSSL_ERR_get_error_line
*/
unsigned long wolfSSL_ERR_peek_last_error_line(const char **file, int *line);

/*!
    \ingroup Debug
    \brief Writes a human-readable dump of every error currently on the thread error queue to the supplied BIO. Mirrors OpenSSL's ERR_print_errors().

    \return none No returns.

    \param bio destination BIO.

    _Example_
    \code
    // see wolfSSL_ERR_print_errors usage
    \endcode

    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_ERR_print_errors_cb
*/
void wolfSSL_ERR_print_errors(WOLFSSL_BIO *bio);

/*!
    \ingroup Debug
    \brief Returns a human-readable string describing the reason portion of err. Mirrors OpenSSL's ERR_reason_error_string().

    \return static string describing the error.
    \return NULL or empty string if unknown.

    \param err packed error code.

    _Example_
    \code
    // see wolfSSL_ERR_reason_error_string usage
    \endcode

    \sa wolfSSL_ERR_error_string
    \sa wolfSSL_ERR_lib_error_string
*/
const char* wolfSSL_ERR_reason_error_string(unsigned long e);

/*!
    \ingroup Debug
    \brief Removes per-thread error state for the given thread id. Mirrors OpenSSL's ERR_remove_state(); wolfSSL clears the current thread's error queue regardless of the id.

    \return none No returns.

    \param id thread identifier (unused).

    _Example_
    \code
    // see wolfSSL_ERR_remove_state usage
    \endcode

    \sa wolfSSL_ERR_remove_thread_state
*/
void wolfSSL_ERR_remove_state(unsigned long id);

/*!
    \ingroup Debug
    \brief Removes per-thread error state for the supplied thread. Mirrors OpenSSL's ERR_remove_thread_state(); wolfSSL clears the current thread's error queue.

    \return none No returns.

    \param id thread state pointer (unused).

    _Example_
    \code
    // see wolfSSL_ERR_remove_thread_state usage
    \endcode

    \sa wolfSSL_ERR_remove_state
*/
void wolfSSL_ERR_remove_thread_state(void* pid);

/*!
    \ingroup openSSL
    \brief Releases any resources allocated by wolfSSL_OBJ_create(). Mirrors OpenSSL's OBJ_cleanup().

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_OBJ_cleanup usage
    \endcode

    \sa wolfSSL_OBJ_create
*/
void wolfSSL_OBJ_cleanup(void);

/*!
    \ingroup openSSL
    \brief Registers a new object identifier (OID) at runtime under the given short and long names and returns its NID. Mirrors OpenSSL's OBJ_create().

    \return the new NID on success.
    \return NID_undef on failure.

    \param oid OID string in dotted decimal form.
    \param sn short name.
    \param ln long name.

    _Example_
    \code
    // see wolfSSL_OBJ_create usage
    \endcode

    \sa wolfSSL_OBJ_cleanup
    \sa wolfSSL_OBJ_txt2nid
*/
int wolfSSL_OBJ_create(const char *oid, const char *sn, const char *ln);

/*!
    \ingroup openSSL
    \brief Returns the type of a WOLFSSL_GENERAL_NAME field. Mirrors OpenSSL's GENERAL_NAME type accessor.

    \return the GEN_* type value.

    \param o WOLFSSL_ASN1_OBJECT or general-name pointer.

    _Example_
    \code
    // see wolfSSL_OBJ_get_type usage
    \endcode

    \sa wolfSSL_OBJ_obj2nid
*/
int wolfSSL_OBJ_get_type(const WOLFSSL_ASN1_OBJECT *o);

/*!
    \ingroup openSSL
    \brief Returns the length of the DER-encoded OID held in obj. Mirrors OpenSSL's OBJ_length().

    \return size in bytes of the encoded OID.
    \return 0 if obj is NULL.

    \param o WOLFSSL_ASN1_OBJECT to query.

    _Example_
    \code
    // see wolfSSL_OBJ_length usage
    \endcode

    \sa wolfSSL_OBJ_get0_data
*/
size_t wolfSSL_OBJ_length(const WOLFSSL_ASN1_OBJECT* o);

/*!
    \ingroup openSSL
    \brief Maps a long name string to its NID. Mirrors OpenSSL's OBJ_ln2nid().

    \return matching NID on success.
    \return NID_undef if not found.

    \param ln long name to look up.

    _Example_
    \code
    // see wolfSSL_OBJ_ln2nid usage
    \endcode

    \sa wolfSSL_OBJ_sn2nid
    \sa wolfSSL_OBJ_nid2ln
*/
int wolfSSL_OBJ_ln2nid(const char *ln);

/*!
    \ingroup openSSL
    \brief Returns the long name string associated with a NID. Mirrors OpenSSL's OBJ_nid2ln().

    \return long name on success.
    \return NULL if no match.

    \param n NID to look up.

    _Example_
    \code
    // see wolfSSL_OBJ_nid2ln usage
    \endcode

    \sa wolfSSL_OBJ_nid2sn
    \sa wolfSSL_OBJ_ln2nid
*/
const char* wolfSSL_OBJ_nid2ln(int n);

/*!
    \ingroup openSSL
    \brief Returns a WOLFSSL_ASN1_OBJECT representing the given NID. Mirrors OpenSSL's OBJ_nid2obj().

    \return pointer to a WOLFSSL_ASN1_OBJECT on success.
    \return NULL on failure.

    \param n NID identifier.

    _Example_
    \code
    // see wolfSSL_OBJ_nid2obj usage
    \endcode

    \sa wolfSSL_OBJ_obj2nid
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_nid2obj(int n);

/*!
    \ingroup openSSL
    \brief Returns the short name string associated with a NID. Mirrors OpenSSL's OBJ_nid2sn().

    \return short name on success.
    \return NULL if no match.

    \param n NID to look up.

    _Example_
    \code
    // see wolfSSL_OBJ_nid2sn usage
    \endcode

    \sa wolfSSL_OBJ_nid2ln
    \sa wolfSSL_OBJ_sn2nid
*/
const char* wolfSSL_OBJ_nid2sn(int n);

/*!
    \ingroup openSSL
    \brief Returns the NID corresponding to a WOLFSSL_ASN1_OBJECT. Mirrors OpenSSL's OBJ_obj2nid().

    \return NID on success.
    \return NID_undef if unknown.

    \param o object to look up.

    _Example_
    \code
    // see wolfSSL_OBJ_obj2nid usage
    \endcode

    \sa wolfSSL_OBJ_nid2obj
*/
int wolfSSL_OBJ_obj2nid(const WOLFSSL_ASN1_OBJECT *o);

/*!
    \ingroup openSSL
    \brief Maps a short name string to its NID. Mirrors OpenSSL's OBJ_sn2nid().

    \return matching NID on success.
    \return NID_undef if not found.

    \param sn short name to look up.

    _Example_
    \code
    // see wolfSSL_OBJ_sn2nid usage
    \endcode

    \sa wolfSSL_OBJ_ln2nid
*/
int wolfSSL_OBJ_sn2nid(const char *sn);

/*!
    \ingroup openSSL
    \brief Maps a textual representation (short name, long name, or dotted OID) to a NID. Mirrors OpenSSL's OBJ_txt2nid().

    \return matching NID on success.
    \return NID_undef if not found.

    \param s textual identifier.

    _Example_
    \code
    // see wolfSSL_OBJ_txt2nid usage
    \endcode

    \sa wolfSSL_OBJ_txt2obj
*/
int wolfSSL_OBJ_txt2nid(const char *sn);

/*!
    \ingroup openSSL
    \brief Maps a textual representation to a WOLFSSL_ASN1_OBJECT. When no_name is non-zero only dotted OID form is accepted. Mirrors OpenSSL's OBJ_txt2obj().

    \return pointer to a WOLFSSL_ASN1_OBJECT on success.
    \return NULL on failure.

    \param s textual identifier.
    \param no_name if non-zero, only accept dotted OID.

    _Example_
    \code
    // see wolfSSL_OBJ_txt2obj usage
    \endcode

    \sa wolfSSL_OBJ_txt2nid
*/
WOLFSSL_ASN1_OBJECT* wolfSSL_OBJ_txt2obj(const char* s, int no_name);

/*!
    \ingroup openSSL
    \brief Releases a WOLFSSL_INIT_SETTINGS object allocated by wolfSSL_OPENSSL_INIT_new().

    \return none No returns.

    \param init settings object to free.

    _Example_
    \code
    // see wolfSSL_OPENSSL_INIT_free usage
    \endcode

    \sa wolfSSL_OPENSSL_INIT_new
*/
void wolfSSL_OPENSSL_INIT_free(WOLFSSL_INIT_SETTINGS* init);

/*!
    \ingroup openSSL
    \brief Allocates a new WOLFSSL_INIT_SETTINGS object used to control library initialization. Mirrors OpenSSL's OPENSSL_INIT_new().

    \return pointer to a new settings object on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_OPENSSL_INIT_new usage
    \endcode

    \sa wolfSSL_OPENSSL_INIT_free
*/
WOLFSSL_INIT_SETTINGS* wolfSSL_OPENSSL_INIT_new(void);

/*!
    \ingroup openSSL
    \brief Securely zeroes len bytes of memory at ptr in a way that should not be optimized away. Mirrors OpenSSL's OPENSSL_cleanse().

    \return none No returns.

    \param ptr buffer to clear.
    \param len size of buffer in bytes.

    _Example_
    \code
    // see wolfSSL_OPENSSL_cleanse usage
    \endcode

    \sa wolfSSL_CRYPTO_free
*/
void wolfSSL_OPENSSL_cleanse(void *ptr, size_t len);

/*!
    \ingroup openSSL
    \brief Loads the OpenSSL-style application configuration. Mirrors OpenSSL's OPENSSL_config(); a no-op in wolfSSL.

    \return none No returns.

    \param config_name configuration section name (unused).

    _Example_
    \code
    // see wolfSSL_OPENSSL_config usage
    \endcode

    \sa wolfSSL_CONF_modules_unload
*/
void wolfSSL_OPENSSL_config(char *config_name);

/*!
    \ingroup CertsKeys
    \brief Default PEM password callback that copies the user-supplied passphrase (passed via the void* userdata) into name. Mirrors OpenSSL's PEM_def_callback().

    \return number of bytes written to name on success.
    \return 0 on failure.

    \param name output buffer for the password.
    \param num size of name.
    \param w unused.
    \param key user data pointer holding the passphrase string.

    _Example_
    \code
    // see wolfSSL_PEM_def_callback usage
    \endcode

    \sa wolfSSL_CTX_set_default_passwd_cb
*/
int wolfSSL_PEM_def_callback(char* name, int num, int w, void* key);

/*!
    \ingroup CertsKeys
    \brief Writes the PEM encoding of x to the BIO bp. Mirrors OpenSSL's PEM_write_bio_X509().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bp destination BIO.
    \param x certificate to write.

    _Example_
    \code
    // see wolfSSL_PEM_write_bio_X509 usage
    \endcode

    \sa wolfSSL_PEM_write_bio_X509_AUX
    \sa wolfSSL_PEM_read_bio_X509
*/
int wolfSSL_PEM_write_bio_X509(WOLFSSL_BIO *bp, WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys
    \brief Writes the PEM encoding of x to the BIO bp, including auxiliary trust information when present. Mirrors OpenSSL's PEM_write_bio_X509_AUX().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bp destination BIO.
    \param x certificate to write.

    _Example_
    \code
    // see wolfSSL_PEM_write_bio_X509_AUX usage
    \endcode

    \sa wolfSSL_PEM_write_bio_X509
    \sa wolfSSL_PEM_read_bio_X509_AUX
*/
int wolfSSL_PEM_write_bio_X509_AUX(WOLFSSL_BIO *bp,WOLFSSL_X509 *x);

/*!
    \ingroup CertsKeys
    \brief Writes the PEM encoding of a certificate signing request to the BIO bp. Mirrors OpenSSL's PEM_write_bio_X509_REQ().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bp destination BIO.
    \param x CSR to write.

    _Example_
    \code
    // see wolfSSL_PEM_write_bio_X509_REQ usage
    \endcode

    \sa wolfSSL_PEM_write_bio_X509
*/
int wolfSSL_PEM_write_bio_X509_REQ(WOLFSSL_BIO *bp,WOLFSSL_X509 *x);

/*!
    \ingroup openSSL
    \brief Releases any state held by the OpenSSL-compatibility PRNG. Mirrors OpenSSL's RAND_cleanup().

    \return WOLFSSL_SUCCESS on success.

    _Example_
    \code
    // see wolfSSL_RAND_Cleanup usage
    \endcode

    \sa wolfSSL_RAND_seed
*/
void wolfSSL_RAND_Cleanup(void);

/*!
    \ingroup openSSL
    \brief Adds entropy from buf into the OpenSSL-compatibility PRNG. Mirrors OpenSSL's RAND_add().

    \return none No returns.

    \param buf entropy buffer.
    \param num length of buf.
    \param entropy estimated entropy in bytes.

    _Example_
    \code
    // see wolfSSL_RAND_add usage
    \endcode

    \sa wolfSSL_RAND_seed
    \sa wolfSSL_RAND_poll
*/
void wolfSSL_RAND_add(const void* add, int len, double entropy);

/*!
    \ingroup openSSL
    \brief Fills buf with num cryptographically strong random bytes. Mirrors OpenSSL's RAND_bytes().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param buf destination buffer.
    \param num number of random bytes to generate.

    _Example_
    \code
    // see wolfSSL_RAND_bytes usage
    \endcode

    \sa wolfSSL_RAND_pseudo_bytes
*/
int wolfSSL_RAND_bytes(unsigned char* buf, int num);

/*!
    \ingroup openSSL
    \brief Reads entropy from an Entropy Gathering Daemon (EGD) socket. Mirrors OpenSSL's RAND_egd().

    \return number of bytes read on success.
    \return -1 on error.

    \param nm path of EGD socket.

    _Example_
    \code
    // see wolfSSL_RAND_egd usage
    \endcode

    \sa wolfSSL_RAND_poll
*/
int wolfSSL_RAND_egd(const char* nm);

/*!
    \ingroup openSSL
    \brief Returns the default RAND seed file path, copying it into buf. Mirrors OpenSSL's RAND_file_name().

    \return buf on success.
    \return NULL on error.

    \param fname output buffer.
    \param len size of buf.

    _Example_
    \code
    // see wolfSSL_RAND_file_name usage
    \endcode

    \sa wolfSSL_RAND_load_file
    \sa wolfSSL_RAND_write_file
*/
const char* wolfSSL_RAND_file_name(char* fname, unsigned long len);

/*!
    \ingroup openSSL
    \brief Reads entropy from the named file and seeds the PRNG with it. Mirrors OpenSSL's RAND_load_file().

    \return number of bytes read on success.
    \return -1 on error.

    \param fname file path.
    \param len maximum bytes to read; -1 for all.

    _Example_
    \code
    // see wolfSSL_RAND_load_file usage
    \endcode

    \sa wolfSSL_RAND_write_file
*/
int wolfSSL_RAND_load_file(const char* fname, long len);

/*!
    \ingroup openSSL
    \brief Triggers a poll of the system entropy source to reseed the PRNG. Mirrors OpenSSL's RAND_poll().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    _Example_
    \code
    // see wolfSSL_RAND_poll usage
    \endcode

    \sa wolfSSL_RAND_add
*/
int wolfSSL_RAND_poll(void);

/*!
    \ingroup openSSL
    \brief Fills buf with num pseudo-random bytes; provided for OpenSSL compatibility. wolfSSL routes this through the same cryptographically strong PRNG as wolfSSL_RAND_bytes().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param buf destination buffer.
    \param num number of bytes to generate.

    _Example_
    \code
    // see wolfSSL_RAND_pseudo_bytes usage
    \endcode

    \sa wolfSSL_RAND_bytes
*/
int wolfSSL_RAND_pseudo_bytes(unsigned char* buf, int num);

/*!
    \ingroup openSSL
    \brief Seeds the PRNG using screen contents (Windows-specific in OpenSSL). Mirrors OpenSSL's RAND_screen(); a no-op in wolfSSL.

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_RAND_screen usage
    \endcode

    \sa wolfSSL_RAND_poll
*/
void wolfSSL_RAND_screen(void);

/*!
    \ingroup openSSL
    \brief Seeds the PRNG with the contents of buf. Mirrors OpenSSL's RAND_seed().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param buf entropy buffer.
    \param num length of buf.

    _Example_
    \code
    // see wolfSSL_RAND_seed usage
    \endcode

    \sa wolfSSL_RAND_add
*/
int wolfSSL_RAND_seed(const void* seed, int len);

/*!
    \ingroup openSSL
    \brief Installs a user-supplied set of PRNG operations (WOLFSSL_RAND_METHOD). Mirrors OpenSSL's RAND_set_rand_method().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param methods pointer to method structure.

    _Example_
    \code
    // see wolfSSL_RAND_set_rand_method usage
    \endcode

    \sa wolfSSL_RAND_bytes
*/
int wolfSSL_RAND_set_rand_method(const WOLFSSL_RAND_METHOD *methods);

/*!
    \ingroup openSSL
    \brief Reports whether the PRNG has been seeded with sufficient entropy. Mirrors OpenSSL's RAND_status().

    \return 1 if the PRNG is ready.
    \return 0 otherwise.

    _Example_
    \code
    // see wolfSSL_RAND_status usage
    \endcode

    \sa wolfSSL_RAND_poll
*/
int wolfSSL_RAND_status(void);

/*!
    \ingroup openSSL
    \brief Writes the current PRNG state out to a seed file. Mirrors OpenSSL's RAND_write_file().

    \return number of bytes written on success.
    \return -1 on error.

    \param fname destination file path.

    _Example_
    \code
    // see wolfSSL_RAND_write_file usage
    \endcode

    \sa wolfSSL_RAND_load_file
*/
int wolfSSL_RAND_write_file(const char* fname);

/*!
    \ingroup openSSL
    \brief Returns the name of the cipher associated with the given session. Mirrors OpenSSL's SSL_SESSION_CIPHER_get_name().

    \return cipher name string on success.
    \return NULL on failure.

    \param session session to inspect.

    _Example_
    \code
    // see wolfSSL_SESSION_CIPHER_get_name usage
    \endcode

    \sa wolfSSL_CIPHER_get_name
    \sa wolfSSL_SESSION_get_cipher
*/
const char* wolfSSL_SESSION_CIPHER_get_name(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Returns a deep copy of session that the caller must free with wolfSSL_SESSION_free(). Mirrors OpenSSL's SSL_SESSION_dup().

    \return new session on success.
    \return NULL on failure.

    \param session source session.

    _Example_
    \code
    // see wolfSSL_SESSION_dup usage
    \endcode

    \sa wolfSSL_SESSION_free
    \sa wolfSSL_SESSION_up_ref
*/
WOLFSSL_SESSION* wolfSSL_SESSION_dup(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Decrements the reference count on session and frees it once the count reaches zero. Mirrors OpenSSL's SSL_SESSION_free().

    \return none No returns.

    \param session session to free.

    _Example_
    \code
    // see wolfSSL_SESSION_free usage
    \endcode

    \sa wolfSSL_SESSION_new
    \sa wolfSSL_SESSION_up_ref
*/
void wolfSSL_SESSION_free(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Returns the peer certificate stored on the session without taking a reference. Mirrors OpenSSL's SSL_SESSION_get0_peer().

    \return peer certificate on success.
    \return NULL if none.

    \param session session to inspect.

    _Example_
    \code
    // see wolfSSL_SESSION_get0_peer usage
    \endcode

    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_X509* wolfSSL_SESSION_get0_peer(WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Returns the application data stored on the session at index idx. Mirrors OpenSSL's SSL_SESSION_get_ex_data().

    \return stored pointer on success.
    \return NULL if not set.

    \param session session to inspect.
    \param idx ex-data slot index.

    _Example_
    \code
    // see wolfSSL_SESSION_get_ex_data usage
    \endcode

    \sa wolfSSL_SESSION_set_ex_data
*/
void* wolfSSL_SESSION_get_ex_data(const WOLFSSL_SESSION* session, int idx);

/*!
    \ingroup openSSL
    \brief Returns the time at which the session was established, in seconds since the epoch. Mirrors OpenSSL's SSL_SESSION_get_time().

    \return session start time.
    \return 0 if session is NULL.

    \param session session to inspect.

    _Example_
    \code
    // see wolfSSL_SESSION_get_time usage
    \endcode

    \sa wolfSSL_SESSION_set_time
    \sa wolfSSL_SESSION_get_timeout
*/
long wolfSSL_SESSION_get_time(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Returns the configured lifetime of the session in seconds. Mirrors OpenSSL's SSL_SESSION_get_timeout().

    \return timeout in seconds.
    \return 0 if session is NULL.

    \param session session to inspect.

    _Example_
    \code
    // see wolfSSL_SESSION_get_timeout usage
    \endcode

    \sa wolfSSL_SESSION_get_time
*/
long wolfSSL_SESSION_get_timeout(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Reports whether the session contains a session ticket. Mirrors OpenSSL's SSL_SESSION_has_ticket().

    \return 1 if a ticket is present.
    \return 0 otherwise.

    \param session session to inspect.

    _Example_
    \code
    // see wolfSSL_SESSION_has_ticket usage
    \endcode

    \sa wolfSSL_SESSION_is_resumable
*/
int wolfSSL_SESSION_has_ticket(const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Reports whether session is in a state usable for resumption. Mirrors OpenSSL's SSL_SESSION_is_resumable().

    \return 1 if resumable.
    \return 0 otherwise.

    \param session session to inspect.

    _Example_
    \code
    // see wolfSSL_SESSION_is_resumable usage
    \endcode

    \sa wolfSSL_SESSION_has_ticket
*/
int wolfSSL_SESSION_is_resumable(const WOLFSSL_SESSION *s);

/*!
    \ingroup openSSL
    \brief Allocates a new, empty WOLFSSL_SESSION using the library default heap. Mirrors OpenSSL's SSL_SESSION_new().

    \return pointer to a new session on success.
    \return NULL on failure.

    _Example_
    \code
    // see wolfSSL_SESSION_new usage
    \endcode

    \sa wolfSSL_SESSION_new_ex
    \sa wolfSSL_SESSION_free
*/
WOLFSSL_SESSION* wolfSSL_SESSION_new(void);

/*!
    \ingroup openSSL
    \brief Allocates a new, empty WOLFSSL_SESSION using the supplied heap hint.

    \return pointer to a new session on success.
    \return NULL on failure.

    \param heap heap hint passed to the allocator.

    _Example_
    \code
    // see wolfSSL_SESSION_new_ex usage
    \endcode

    \sa wolfSSL_SESSION_new
    \sa wolfSSL_SESSION_free
*/
WOLFSSL_SESSION* wolfSSL_SESSION_new_ex(void* heap);

/*!
    \ingroup openSSL
    \brief Writes a human-readable description of session to the given BIO. Mirrors OpenSSL's SSL_SESSION_print().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bp destination BIO.
    \param session session to print.

    _Example_
    \code
    // see wolfSSL_SESSION_print usage
    \endcode

    \sa wolfSSL_SESSION_get_time
*/
int wolfSSL_SESSION_print(WOLFSSL_BIO* bp, const WOLFSSL_SESSION* session);

/*!
    \ingroup openSSL
    \brief Stores application data on the session at index idx. Mirrors OpenSSL's SSL_SESSION_set_ex_data().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param session session to modify.
    \param idx ex-data slot index.
    \param data pointer to store.

    _Example_
    \code
    // see wolfSSL_SESSION_set_ex_data usage
    \endcode

    \sa wolfSSL_SESSION_get_ex_data
*/
int wolfSSL_SESSION_set_ex_data(WOLFSSL_SESSION* session, int idx, void* data);

/*!
    \ingroup openSSL
    \brief Sets the session creation time. Mirrors OpenSSL's SSL_SESSION_set_time().

    \return the value set on success.
    \return 0 if session is NULL.

    \param session session to modify.
    \param t creation time in seconds since the epoch.

    _Example_
    \code
    // see wolfSSL_SESSION_set_time usage
    \endcode

    \sa wolfSSL_SESSION_get_time
*/
long wolfSSL_SESSION_set_time(WOLFSSL_SESSION *ses, long t);

/*!
    \ingroup openSSL
    \brief Increments the reference count on session so that ownership can be shared. Mirrors OpenSSL's SSL_SESSION_up_ref().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param session session to reference.

    _Example_
    \code
    // see wolfSSL_SESSION_up_ref usage
    \endcode

    \sa wolfSSL_SESSION_free
    \sa wolfSSL_SESSION_dup
*/
int wolfSSL_SESSION_up_ref(WOLFSSL_SESSION* session);

/*!
    \ingroup Setup
    \brief Disables any system or user crypto policy currently in effect for this process.

    \return none No returns.

    _Example_
    \code
    // see wolfSSL_crypto_policy_disable usage
    \endcode

    \sa wolfSSL_crypto_policy_enable
    \sa wolfSSL_crypto_policy_is_enabled
*/
void wolfSSL_crypto_policy_disable(void);

/*!
    \ingroup Setup
    \brief Loads and activates the crypto policy described by the named policy file.

    \return WOLFSSL_SUCCESS on success.
    \return a negative wolfSSL error code on failure.

    \param policy path to a crypto policy file.

    _Example_
    \code
    // see wolfSSL_crypto_policy_enable usage
    \endcode

    \sa wolfSSL_crypto_policy_enable_buffer
    \sa wolfSSL_crypto_policy_disable
*/
int wolfSSL_crypto_policy_enable(const char * policy);

/*!
    \ingroup Setup
    \brief Loads and activates a crypto policy whose contents are supplied directly in memory.

    \return WOLFSSL_SUCCESS on success.
    \return a negative wolfSSL error code on failure.

    \param buf policy contents.
    \param len length of buf.

    _Example_
    \code
    // see wolfSSL_crypto_policy_enable_buffer usage
    \endcode

    \sa wolfSSL_crypto_policy_enable
*/
int wolfSSL_crypto_policy_enable_buffer(const char * buf);

/*!
    \ingroup Setup
    \brief Returns the colon-separated cipher list dictated by the active crypto policy.

    \return static string of cipher names.
    \return NULL if no policy is active.

    _Example_
    \code
    // see wolfSSL_crypto_policy_get_ciphers usage
    \endcode

    \sa wolfSSL_crypto_policy_enable
*/
const char * wolfSSL_crypto_policy_get_ciphers(void);

/*!
    \ingroup Setup
    \brief Returns the security level associated with the active crypto policy.

    \return security level (>= 0) on success.
    \return a negative value if no policy is active.

    _Example_
    \code
    // see wolfSSL_crypto_policy_get_level usage
    \endcode

    \sa wolfSSL_crypto_policy_enable
*/
int wolfSSL_crypto_policy_get_level(void);

/*!
    \ingroup Setup
    \brief Reports whether a crypto policy is currently active.

    \return 1 if a policy is active.
    \return 0 otherwise.

    _Example_
    \code
    // see wolfSSL_crypto_policy_is_enabled usage
    \endcode

    \sa wolfSSL_crypto_policy_enable
    \sa wolfSSL_crypto_policy_disable
*/
int wolfSSL_crypto_policy_is_enabled(void);

/*!
    \ingroup CertsKeys
    \brief Decodes a DER-encoded ASN.1 DisplayText string from *in into a WOLFSSL_ASN1_STRING. Mirrors OpenSSL's d2i_DISPLAYTEXT().

    \return pointer to the resulting WOLFSSL_ASN1_STRING on success.
    \return NULL on failure.

    \param asn optional pre-allocated destination.
    \param in pointer to DER buffer pointer; advanced on success.
    \param len length of the DER buffer.

    _Example_
    \code
    // see wolfSSL_d2i_DISPLAYTEXT usage
    \endcode

    \sa wolfSSL_ASN1_STRING_new
*/
WOLFSSL_ASN1_STRING* wolfSSL_d2i_DISPLAYTEXT(WOLFSSL_ASN1_STRING **asn, const unsigned char **in, long len);

/*!
    \ingroup CertsKeys
    \brief Reads a DER-encoded private key from bio and returns a WOLFSSL_EVP_PKEY for it. Mirrors OpenSSL's d2i_PrivateKey_bio().

    \return allocated WOLFSSL_EVP_PKEY on success.
    \return NULL on failure.

    \param bio source BIO.
    \param out optional output pointer that will receive the key.

    _Example_
    \code
    // see wolfSSL_d2i_PrivateKey_bio usage
    \endcode

    \sa wolfSSL_PEM_read_bio_PrivateKey
*/
WOLFSSL_EVP_PKEY* wolfSSL_d2i_PrivateKey_bio(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY** pkey);

/*!
    \ingroup CertsKeys
    \brief Reads a DER-encoded RSA private key from bio and returns a WOLFSSL_RSA. Mirrors OpenSSL's d2i_RSAPrivateKey_bio().

    \return allocated WOLFSSL_RSA on success.
    \return NULL on failure.

    \param bio source BIO.
    \param out optional output pointer.

    _Example_
    \code
    // see wolfSSL_d2i_RSAPrivateKey_bio usage
    \endcode

    \sa wolfSSL_d2i_PrivateKey_bio
*/
WOLFSSL_RSA* wolfSSL_d2i_RSAPrivateKey_bio(WOLFSSL_BIO* bio, WOLFSSL_RSA** out);

/*!
    \ingroup CertsKeys
    \brief Reads a DER-encoded X.509 CRL from file fp. Mirrors OpenSSL's d2i_X509_CRL_fp().

    \return allocated WOLFSSL_X509_CRL on success.
    \return NULL on failure.

    \param fp input file.
    \param crl optional output pointer.

    _Example_
    \code
    // see wolfSSL_d2i_X509_CRL_fp usage
    \endcode

    \sa wolfSSL_PEM_read_X509_CRL
*/
WOLFSSL_X509_CRL *wolfSSL_d2i_X509_CRL_fp(XFILE file, WOLFSSL_X509_CRL **crl);

/*!
    \ingroup CertsKeys
    \brief Reads a DER-encoded certificate signing request from file fp. Mirrors OpenSSL's d2i_X509_REQ_fp().

    \return allocated WOLFSSL_X509 representing the CSR on success.
    \return NULL on failure.

    \param fp input file.
    \param req optional output pointer.

    _Example_
    \code
    // see wolfSSL_d2i_X509_REQ_fp usage
    \endcode

    \sa wolfSSL_PEM_read_bio_X509_REQ
*/
WOLFSSL_X509* wolfSSL_d2i_X509_REQ_fp(XFILE fp, WOLFSSL_X509 **req);

/*!
    \ingroup CertsKeys
    \brief Serializes a WOLFSSL_ASN1_OBJECT to DER. If *pp is non-NULL the encoding is written there and *pp is advanced; otherwise a buffer is allocated. Mirrors OpenSSL's i2d_ASN1_OBJECT().

    \return number of bytes written on success.
    \return WOLFSSL_FAILURE on error.

    \param a object to encode.
    \param pp optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2d_ASN1_OBJECT usage
    \endcode

    \sa wolfSSL_OBJ_obj2nid
*/
int wolfSSL_i2d_ASN1_OBJECT(WOLFSSL_ASN1_OBJECT *a, unsigned char **pp);

/*!
    \ingroup CertsKeys
    \brief Serializes the public portion of an EVP_PKEY into a SubjectPublicKeyInfo DER blob. Mirrors OpenSSL's i2d_PUBKEY().

    \return number of bytes written on success.
    \return WOLFSSL_FAILURE on error.

    \param key key to encode.
    \param der optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2d_PUBKEY usage
    \endcode

    \sa wolfSSL_PEM_write_bio_PUBKEY
*/
int wolfSSL_i2d_PUBKEY(const WOLFSSL_EVP_PKEY *key, unsigned char **der);

/*!
    \ingroup CertsKeys
    \brief Serializes an RSA private key into a DER buffer. Mirrors OpenSSL's i2d_RSAPrivateKey().

    \return length of the DER encoding on success.
    \return WOLFSSL_FAILURE on error.

    \param rsa key to encode.
    \param pp optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2d_RSAPrivateKey usage
    \endcode

    \sa wolfSSL_i2d_RSAPublicKey
*/
int wolfSSL_i2d_RSAPrivateKey(WOLFSSL_RSA *r, unsigned char **pp);

/*!
    \ingroup CertsKeys
    \brief Serializes the public portion of an RSA key into a DER buffer. Mirrors OpenSSL's i2d_RSAPublicKey().

    \return length of the DER encoding on success.
    \return WOLFSSL_FAILURE on error.

    \param rsa key to encode.
    \param pp optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2d_RSAPublicKey usage
    \endcode

    \sa wolfSSL_i2d_RSAPrivateKey
*/
int wolfSSL_i2d_RSAPublicKey(WOLFSSL_RSA *r, unsigned char **pp);

/*!
    \ingroup openSSL
    \brief Serializes a WOLFSSL_SESSION to DER for storage or transport. If pp is non-NULL the encoding is written there and *pp advanced. Mirrors OpenSSL's i2d_SSL_SESSION().

    \return length of the DER encoding on success.
    \return 0 on error.

    \param sess session to encode.
    \param pp optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2d_SSL_SESSION usage
    \endcode

    \sa wolfSSL_d2i_SSL_SESSION
*/
int wolfSSL_i2d_SSL_SESSION(WOLFSSL_SESSION* sess,unsigned char** p);

/*!
    \ingroup CertsKeys
    \brief Serializes an X.509 certificate to DER. If out is non-NULL the encoding is written there and *out advanced; otherwise a heap buffer is allocated. Mirrors OpenSSL's i2d_X509().

    \return length of the DER encoding on success.
    \return WOLFSSL_FAILURE on error.

    \param x509 certificate to encode.
    \param out optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2d_X509 usage
    \endcode

    \sa wolfSSL_d2i_X509
    \sa wolfSSL_PEM_write_bio_X509
*/
int wolfSSL_i2d_X509(WOLFSSL_X509* x509, unsigned char** out);

/*!
    \ingroup CertsKeys
    \brief Serializes a certificate signing request to DER. Mirrors OpenSSL's i2d_X509_REQ().

    \return length of the DER encoding on success.
    \return WOLFSSL_FAILURE on error.

    \param req CSR to encode.
    \param out optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2d_X509_REQ usage
    \endcode

    \sa wolfSSL_i2d_X509
    \sa wolfSSL_PEM_write_bio_X509_REQ
*/
int wolfSSL_i2d_X509_REQ(WOLFSSL_X509* req, unsigned char** out);

/*!
    \ingroup CertsKeys
    \brief Writes the DER encoding of a certificate signing request to the supplied BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio destination BIO.
    \param req CSR to encode.

    _Example_
    \code
    // see wolfSSL_i2d_X509_REQ_bio usage
    \endcode

    \sa wolfSSL_i2d_X509_REQ
*/
int wolfSSL_i2d_X509_REQ_bio(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Writes the DER encoding of an X.509 certificate to the supplied BIO.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio destination BIO.
    \param x509 certificate to encode.

    _Example_
    \code
    // see wolfSSL_i2d_X509_bio usage
    \endcode

    \sa wolfSSL_i2d_X509
    \sa wolfSSL_d2i_X509_bio
*/
int wolfSSL_i2d_X509_bio(WOLFSSL_BIO* bio, WOLFSSL_X509* x509);
/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available DTLS protocol as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfDTLS_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLS_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available DTLS protocol as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLS_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLS_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available DTLS protocol as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLS_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLS_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available DTLS protocol as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLS_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLS_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.0 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfDTLSv1_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.0 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.0 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.0 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.2 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfDTLSv1_2_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.2 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_2_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.2 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfDTLSv1_2_client_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_client_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.2 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_2_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_2_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.3 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfDTLSv1_3_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_3_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.3 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_3_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_3_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.3 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_3_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_3_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the DTLS 1.3 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfDTLSv1_3_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfDTLSv1_3_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available SSL/TLS protocol as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfSSLv23_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv23_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available SSL/TLS protocol as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfSSLv23_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv23_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available SSL/TLS protocol as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfSSLv23_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv23_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the SSL 2.0 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSLv2_client_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD* wolfSSLv2_client_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the SSL 2.0 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSLv2_server_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD* wolfSSLv2_server_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the SSL 3.0 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSLv3_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the SSL 3.0 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfSSLv3_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the SSL 3.0 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfSSLv3_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the SSL 3.0 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfSSLv3_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfSSLv3_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available TLS protocol as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfTLS_client_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLS_client_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available TLS protocol as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLS_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLS_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available TLS protocol as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfTLS_server_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLS_server_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the highest available TLS protocol as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLS_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLS_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.0 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfTLSv1_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.0 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.0 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.0 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.1 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfTLSv1_1_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.1 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_1_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.1 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_1_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.1 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_1_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_1_server_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.2 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param none No parameters.

    _Example_
    \code
    // see wolfTLSv1_2_method usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_method(void);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.2 as a both client and server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_2_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.2 as a client. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_2_client_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_client_method_ex(void* heap);

/*!
    \ingroup Setup
    \brief Returns a new WOLFSSL_METHOD configured for the TLS 1.2 as a server. The returned method is passed to wolfSSL_CTX_new() to create an SSL/TLS context.

    \return WOLFSSL_METHOD* pointer to a newly allocated method on success.
    \return NULL on memory allocation failure or if the protocol is disabled in the build.

    \param heap pointer to a heap hint used for memory allocation, may be NULL to use the default heap.

    _Example_
    \code
    // see wolfTLSv1_2_server_method_ex usage
    \endcode

    \sa wolfSSL_CTX_new
*/
WOLFSSL_METHOD *wolfTLSv1_2_server_method_ex(void* heap);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_ACCESS_DESCRIPTION object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_ACCESS_DESCRIPTION_free usage
    \endcode

*/
void wolfSSL_ACCESS_DESCRIPTION_free(WOLFSSL_ACCESS_DESCRIPTION* a);

/*!
    \ingroup CertsKeys
    \brief Frees a stack of WOLFSSL_DIST_POINT object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_DIST_POINTS_free usage
    \endcode

*/
void wolfSSL_DIST_POINTS_free(WOLFSSL_DIST_POINTS* dp);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_DIST_POINT object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_DIST_POINT_free usage
    \endcode

*/
void wolfSSL_DIST_POINT_free(WOLFSSL_DIST_POINT* dp);

/*!
    \ingroup CertsKeys
    \brief Allocates and zero-initializes a new WOLFSSL_DIST_POINT object for use with the OpenSSL compatibility X.509 extension API.

    \return WOLFSSL_DIST_POINT* on success.
    \return NULL on memory allocation failure.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_DIST_POINT_new usage
    \endcode

*/
WOLFSSL_DIST_POINT* wolfSSL_DIST_POINT_new(void);

/*!
    \ingroup CertsKeys
    \brief Frees a stack representing an X.509 Extended Key Usage extension object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_EXTENDED_KEY_USAGE_free usage
    \endcode

*/
void wolfSSL_EXTENDED_KEY_USAGE_free(WOLFSSL_STACK * sk);

/*!
    \ingroup CertsKeys
    \brief Frees a stack of WOLFSSL_GENERAL_NAME object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_GENERAL_NAMES_free usage
    \endcode

*/
void wolfSSL_GENERAL_NAMES_free(WOLFSSL_GENERAL_NAMES* name);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_GENERAL_NAME object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_GENERAL_NAME_free usage
    \endcode

*/
void wolfSSL_GENERAL_NAME_free(WOLFSSL_GENERAL_NAME* gn);

/*!
    \ingroup CertsKeys
    \brief Allocates and zero-initializes a new WOLFSSL_GENERAL_NAME object for use with the OpenSSL compatibility X.509 extension API.

    \return WOLFSSL_GENERAL_NAME* on success.
    \return NULL on memory allocation failure.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_GENERAL_NAME_new usage
    \endcode

*/
WOLFSSL_GENERAL_NAME* wolfSSL_GENERAL_NAME_new(void);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_GENERAL_SUBTREE object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_GENERAL_SUBTREE_free usage
    \endcode

*/
void wolfSSL_GENERAL_SUBTREE_free(WOLFSSL_GENERAL_SUBTREE* subtree);

/*!
    \ingroup CertsKeys
    \brief Allocates and zero-initializes a new WOLFSSL_GENERAL_SUBTREE object for use with the OpenSSL compatibility X.509 extension API.

    \return WOLFSSL_GENERAL_SUBTREE* on success.
    \return NULL on memory allocation failure.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_GENERAL_SUBTREE_new usage
    \endcode

*/
WOLFSSL_GENERAL_SUBTREE* wolfSSL_GENERAL_SUBTREE_new(void);

/*!
    \ingroup CertsKeys
    \brief Frees a WOLFSSL_NAME_CONSTRAINTS object previously created by the corresponding _new() function or returned by the parser.

    \return No return value.

    \param object pointer to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_NAME_CONSTRAINTS_free usage
    \endcode

*/
void wolfSSL_NAME_CONSTRAINTS_free(WOLFSSL_NAME_CONSTRAINTS* nc);

/*!
    \ingroup CertsKeys
    \brief Allocates and zero-initializes a new WOLFSSL_NAME_CONSTRAINTS object for use with the OpenSSL compatibility X.509 extension API.

    \return WOLFSSL_NAME_CONSTRAINTS* on success.
    \return NULL on memory allocation failure.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_NAME_CONSTRAINTS_new usage
    \endcode

*/
WOLFSSL_NAME_CONSTRAINTS* wolfSSL_NAME_CONSTRAINTS_new(void);

/*!
    \ingroup openSSL
    \brief Prints the contents of an EC_POINT (hex coordinates) to stderr with the supplied prefix message. Intended as a debugging helper.

    \return No return value.

    \param msg short prefix string printed before the dump.
    \param p   EC_POINT to dump; if NULL the message "(null)" is printed.

    _Example_
    \code
    // see wolfSSL_EC_POINT_dump usage
    \endcode

*/
void wolfSSL_EC_POINT_dump(const char *msg, const WOLFSSL_EC_POINT *p);

/*!
    \ingroup openSSL
    \brief Verifies that the algorithm parameters of the key associated with the supplied EVP_PKEY_CTX are valid.

    \return WOLFSSL_SUCCESS when the parameters validate.
    \return WOLFSSL_FAILURE on any failure.

    \param ctx EVP_PKEY_CTX whose key parameters are to be checked.

    _Example_
    \code
    // see wolfSSL_EVP_PKEY_param_check usage
    \endcode

    \sa wolfSSL_EVP_PKEY_CTX_new
*/
int wolfSSL_EVP_PKEY_param_check(WOLFSSL_EVP_PKEY_CTX* ctx);

/*!
    \ingroup openSSL
    \brief Increments the reference count of a WOLFSSL_EVP_PKEY so it can be safely shared between multiple owners.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param pkey EVP_PKEY whose reference count is incremented.

    _Example_
    \code
    // see wolfSSL_EVP_PKEY_up_ref usage
    \endcode

    \sa wolfSSL_EVP_PKEY_new
    \sa wolfSSL_EVP_PKEY_free
*/
int wolfSSL_EVP_PKEY_up_ref(WOLFSSL_EVP_PKEY* pkey);

/*!
    \ingroup openSSL
    \brief Prints a human-readable representation of an RSA key to the supplied BIO. Mirrors OpenSSL's RSA_print().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param bio    destination BIO.
    \param rsa    RSA key to print.
    \param offset indent (in spaces) applied to each printed line.

    _Example_
    \code
    // see wolfSSL_RSA_print usage
    \endcode

    \sa wolfSSL_RSA_print_fp
*/
int wolfSSL_RSA_print(WOLFSSL_BIO* bio, WOLFSSL_RSA* rsa, int offset);

/*!
    \ingroup openSSL
    \brief Prints a human-readable representation of an RSA key to the supplied FILE pointer. Mirrors OpenSSL's RSA_print_fp().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param fp     destination file.
    \param rsa    RSA key to print.
    \param indent indent (in spaces) applied to each printed line.

    _Example_
    \code
    // see wolfSSL_RSA_print_fp usage
    \endcode

    \sa wolfSSL_RSA_print
*/
int wolfSSL_RSA_print_fp(XFILE fp, WOLFSSL_RSA* rsa, int indent);

/*!
    \ingroup openSSL
    \brief Increments the reference count of a WOLFSSL_RSA so the object can be safely shared between multiple owners.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param rsa RSA whose reference count is incremented.

    _Example_
    \code
    // see wolfSSL_RSA_up_ref usage
    \endcode

    \sa wolfSSL_RSA_new
    \sa wolfSSL_RSA_free
*/
int wolfSSL_RSA_up_ref(WOLFSSL_RSA* rsa);

/*!
    \ingroup openSSL
    \brief One-shot SHA-1 hash of the input buffer. If md is non-NULL the digest is written there; otherwise the digest is written to an internal static buffer. Mirrors OpenSSL's SHA1().

    \return Pointer to the buffer holding the digest on success.
    \return NULL on error.

    \param d  input data.
    \param n  length of d in bytes.
    \param md optional 20-byte destination buffer.

    _Example_
    \code
    // see wolfSSL_SHA1 usage
    \endcode

    \sa wolfSSL_SHA256
    \sa wc_Sha
*/
unsigned char *wolfSSL_SHA1(const unsigned char *d, size_t n, unsigned char *md);

/*!
    \ingroup openSSL
    \brief One-shot SHA-224 hash of the input buffer. If md is non-NULL the digest is written there; otherwise the digest is written to an internal static buffer.

    \return Pointer to the buffer holding the digest on success.
    \return NULL on error.

    \param d  input data.
    \param n  length of d in bytes.
    \param md optional 28-byte destination buffer.

    _Example_
    \code
    // see wolfSSL_SHA224 usage
    \endcode

    \sa wolfSSL_SHA256
*/
unsigned char *wolfSSL_SHA224(const unsigned char *d, size_t n, unsigned char *md);

/*!
    \ingroup openSSL
    \brief One-shot SHA-256 hash of the input buffer. If md is non-NULL the digest is written there; otherwise the digest is written to an internal static buffer. Mirrors OpenSSL's SHA256().

    \return Pointer to the buffer holding the digest on success.
    \return NULL on error.

    \param d  input data.
    \param n  length of d in bytes.
    \param md optional 32-byte destination buffer.

    _Example_
    \code
    // see wolfSSL_SHA256 usage
    \endcode

    \sa wolfSSL_SHA1
    \sa wolfSSL_SHA512
*/
unsigned char *wolfSSL_SHA256(const unsigned char *d, size_t n, unsigned char *md);

/*!
    \ingroup openSSL
    \brief One-shot SHA-384 hash of the input buffer. If md is non-NULL the digest is written there; otherwise the digest is written to an internal static buffer.

    \return Pointer to the buffer holding the digest on success.
    \return NULL on error.

    \param d  input data.
    \param n  length of d in bytes.
    \param md optional 48-byte destination buffer.

    _Example_
    \code
    // see wolfSSL_SHA384 usage
    \endcode

    \sa wolfSSL_SHA512
*/
unsigned char *wolfSSL_SHA384(const unsigned char *d, size_t n, unsigned char *md);

/*!
    \ingroup openSSL
    \brief One-shot SHA-512 hash of the input buffer. If md is non-NULL the digest is written there; otherwise the digest is written to an internal static buffer. Mirrors OpenSSL's SHA512().

    \return Pointer to the buffer holding the digest on success.
    \return NULL on error.

    \param d  input data.
    \param n  length of d in bytes.
    \param md optional 64-byte destination buffer.

    _Example_
    \code
    // see wolfSSL_SHA512 usage
    \endcode

    \sa wolfSSL_SHA256
*/
unsigned char *wolfSSL_SHA512(const unsigned char *d, size_t n, unsigned char *md);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the Diffie-Hellman shared secret agreement public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetDhAgreeCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetDhAgreeCtx usage
    \endcode

    \sa wolfSSL_GetDhAgreeCtx
*/
void wolfSSL_SetDhAgreeCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetDhAgreeCtx() for the Diffie-Hellman shared secret agreement public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetDhAgreeCtx usage
    \endcode

    \sa wolfSSL_SetDhAgreeCtx
*/
void* wolfSSL_GetDhAgreeCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the ECC key generation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEccKeyGenCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEccKeyGenCtx usage
    \endcode

    \sa wolfSSL_GetEccKeyGenCtx
*/
void  wolfSSL_SetEccKeyGenCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEccKeyGenCtx() for the ECC key generation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEccKeyGenCtx usage
    \endcode

    \sa wolfSSL_SetEccKeyGenCtx
*/
void* wolfSSL_GetEccKeyGenCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the ECC shared secret derivation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEccSharedSecretCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEccSharedSecretCtx usage
    \endcode

    \sa wolfSSL_GetEccSharedSecretCtx
*/
void  wolfSSL_SetEccSharedSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEccSharedSecretCtx() for the ECC shared secret derivation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEccSharedSecretCtx usage
    \endcode

    \sa wolfSSL_SetEccSharedSecretCtx
*/
void* wolfSSL_GetEccSharedSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the Ed25519 signing public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEd25519SignCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEd25519SignCtx usage
    \endcode

    \sa wolfSSL_GetEd25519SignCtx
*/
void  wolfSSL_SetEd25519SignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEd25519SignCtx() for the Ed25519 signing public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEd25519SignCtx usage
    \endcode

    \sa wolfSSL_SetEd25519SignCtx
*/
void* wolfSSL_GetEd25519SignCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the Ed25519 verification public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEd25519VerifyCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEd25519VerifyCtx usage
    \endcode

    \sa wolfSSL_GetEd25519VerifyCtx
*/
void  wolfSSL_SetEd25519VerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEd25519VerifyCtx() for the Ed25519 verification public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEd25519VerifyCtx usage
    \endcode

    \sa wolfSSL_SetEd25519VerifyCtx
*/
void* wolfSSL_GetEd25519VerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the Ed448 signing public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEd448SignCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEd448SignCtx usage
    \endcode

    \sa wolfSSL_GetEd448SignCtx
*/
void  wolfSSL_SetEd448SignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEd448SignCtx() for the Ed448 signing public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEd448SignCtx usage
    \endcode

    \sa wolfSSL_SetEd448SignCtx
*/
void* wolfSSL_GetEd448SignCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the Ed448 verification public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEd448VerifyCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEd448VerifyCtx usage
    \endcode

    \sa wolfSSL_GetEd448VerifyCtx
*/
void  wolfSSL_SetEd448VerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEd448VerifyCtx() for the Ed448 verification public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEd448VerifyCtx usage
    \endcode

    \sa wolfSSL_SetEd448VerifyCtx
*/
void* wolfSSL_GetEd448VerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the symmetric encrypt-keys derivation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEncryptKeysCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEncryptKeysCtx usage
    \endcode

    \sa wolfSSL_GetEncryptKeysCtx
*/
void  wolfSSL_SetEncryptKeysCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEncryptKeysCtx() for the symmetric encrypt-keys derivation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEncryptKeysCtx usage
    \endcode

    \sa wolfSSL_SetEncryptKeysCtx
*/
void* wolfSSL_GetEncryptKeysCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the authenticated encryption / MAC public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetEncryptMacCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetEncryptMacCtx usage
    \endcode

    \sa wolfSSL_GetEncryptMacCtx
*/
void  wolfSSL_SetEncryptMacCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetEncryptMacCtx() for the authenticated encryption / MAC public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetEncryptMacCtx usage
    \endcode

    \sa wolfSSL_SetEncryptMacCtx
*/
void* wolfSSL_GetEncryptMacCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the extended master-secret generation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetGenExtMasterSecretCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetGenExtMasterSecretCtx usage
    \endcode

    \sa wolfSSL_GetGenExtMasterSecretCtx
*/
void  wolfSSL_SetGenExtMasterSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetGenExtMasterSecretCtx() for the extended master-secret generation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetGenExtMasterSecretCtx usage
    \endcode

    \sa wolfSSL_SetGenExtMasterSecretCtx
*/
void* wolfSSL_GetGenExtMasterSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the master-secret generation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetGenMasterSecretCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetGenMasterSecretCtx usage
    \endcode

    \sa wolfSSL_GetGenMasterSecretCtx
*/
void  wolfSSL_SetGenMasterSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetGenMasterSecretCtx() for the master-secret generation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetGenMasterSecretCtx usage
    \endcode

    \sa wolfSSL_SetGenMasterSecretCtx
*/
void* wolfSSL_GetGenMasterSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the pre-master secret generation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetGenPreMasterCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetGenPreMasterCtx usage
    \endcode

    \sa wolfSSL_GetGenPreMasterCtx
*/
void  wolfSSL_SetGenPreMasterCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetGenPreMasterCtx() for the pre-master secret generation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetGenPreMasterCtx usage
    \endcode

    \sa wolfSSL_SetGenPreMasterCtx
*/
void* wolfSSL_GetGenPreMasterCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the session-key generation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetGenSessionKeyCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetGenSessionKeyCtx usage
    \endcode

    \sa wolfSSL_GetGenSessionKeyCtx
*/
void  wolfSSL_SetGenSessionKeyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetGenSessionKeyCtx() for the session-key generation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetGenSessionKeyCtx usage
    \endcode

    \sa wolfSSL_SetGenSessionKeyCtx
*/
void* wolfSSL_GetGenSessionKeyCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the HKDF-Extract public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetHKDFExtractCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetHKDFExtractCtx usage
    \endcode

    \sa wolfSSL_GetHKDFExtractCtx
*/
void  wolfSSL_SetHKDFExtractCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetHKDFExtractCtx() for the HKDF-Extract public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetHKDFExtractCtx usage
    \endcode

    \sa wolfSSL_SetHKDFExtractCtx
*/
void* wolfSSL_GetHKDFExtractCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the RSA-PSS signing public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetRsaPssSignCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetRsaPssSignCtx usage
    \endcode

    \sa wolfSSL_GetRsaPssSignCtx
*/
void  wolfSSL_SetRsaPssSignCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetRsaPssSignCtx() for the RSA-PSS signing public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetRsaPssSignCtx usage
    \endcode

    \sa wolfSSL_SetRsaPssSignCtx
*/
void* wolfSSL_GetRsaPssSignCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the RSA-PSS verification public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetRsaPssVerifyCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetRsaPssVerifyCtx usage
    \endcode

    \sa wolfSSL_GetRsaPssVerifyCtx
*/
void  wolfSSL_SetRsaPssVerifyCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetRsaPssVerifyCtx() for the RSA-PSS verification public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetRsaPssVerifyCtx usage
    \endcode

    \sa wolfSSL_SetRsaPssVerifyCtx
*/
void* wolfSSL_GetRsaPssVerifyCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the TLS Finished message PRF public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetTlsFinishedCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetTlsFinishedCtx usage
    \endcode

    \sa wolfSSL_GetTlsFinishedCtx
*/
void  wolfSSL_SetTlsFinishedCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetTlsFinishedCtx() for the TLS Finished message PRF public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetTlsFinishedCtx usage
    \endcode

    \sa wolfSSL_SetTlsFinishedCtx
*/
void* wolfSSL_GetTlsFinishedCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the AEAD verify-decrypt public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetVerifyDecryptCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetVerifyDecryptCtx usage
    \endcode

    \sa wolfSSL_GetVerifyDecryptCtx
*/
void  wolfSSL_SetVerifyDecryptCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetVerifyDecryptCtx() for the AEAD verify-decrypt public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetVerifyDecryptCtx usage
    \endcode

    \sa wolfSSL_SetVerifyDecryptCtx
*/
void* wolfSSL_GetVerifyDecryptCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the MAC verification public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetVerifyMacCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetVerifyMacCtx usage
    \endcode

    \sa wolfSSL_GetVerifyMacCtx
*/
void  wolfSSL_SetVerifyMacCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetVerifyMacCtx() for the MAC verification public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetVerifyMacCtx usage
    \endcode

    \sa wolfSSL_SetVerifyMacCtx
*/
void* wolfSSL_GetVerifyMacCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the X25519 key generation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetX25519KeyGenCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetX25519KeyGenCtx usage
    \endcode

    \sa wolfSSL_GetX25519KeyGenCtx
*/
void  wolfSSL_SetX25519KeyGenCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetX25519KeyGenCtx() for the X25519 key generation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetX25519KeyGenCtx usage
    \endcode

    \sa wolfSSL_SetX25519KeyGenCtx
*/
void* wolfSSL_GetX25519KeyGenCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the X25519 shared secret derivation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetX25519SharedSecretCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetX25519SharedSecretCtx usage
    \endcode

    \sa wolfSSL_GetX25519SharedSecretCtx
*/
void  wolfSSL_SetX25519SharedSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetX25519SharedSecretCtx() for the X25519 shared secret derivation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetX25519SharedSecretCtx usage
    \endcode

    \sa wolfSSL_SetX25519SharedSecretCtx
*/
void* wolfSSL_GetX25519SharedSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the X448 key generation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetX448KeyGenCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetX448KeyGenCtx usage
    \endcode

    \sa wolfSSL_GetX448KeyGenCtx
*/
void  wolfSSL_SetX448KeyGenCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetX448KeyGenCtx() for the X448 key generation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetX448KeyGenCtx usage
    \endcode

    \sa wolfSSL_SetX448KeyGenCtx
*/
void* wolfSSL_GetX448KeyGenCtx(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Stores an opaque user context pointer that is later passed to the X448 shared secret derivation public-key callback registered on the WOLFSSL or WOLFSSL_CTX. Use the matching wolfSSL_GetX448SharedSecretCtx() to retrieve it from inside the callback.

    \return No return value.

    \param ssl WOLFSSL object the callback context is associated with.
    \param ctx opaque user pointer that will be passed back to the callback.

    _Example_
    \code
    // see wolfSSL_SetX448SharedSecretCtx usage
    \endcode

    \sa wolfSSL_GetX448SharedSecretCtx
*/
void  wolfSSL_SetX448SharedSecretCtx(WOLFSSL* ssl, void *ctx);

/*!
    \ingroup CertsKeys
    \brief Retrieves the opaque user context pointer previously set with wolfSSL_SetX448SharedSecretCtx() for the X448 shared secret derivation public-key callback. Typically called from inside the callback to recover application state.

    \return Pointer previously stored with the corresponding Set function, or NULL if none was set.

    \param ssl WOLFSSL object whose callback context is queried.

    _Example_
    \code
    // see wolfSSL_GetX448SharedSecretCtx usage
    \endcode

    \sa wolfSSL_SetX448SharedSecretCtx
*/
void* wolfSSL_GetX448SharedSecretCtx(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Frees the protocol-list buffer that was allocated and returned by wolfSSL_ALPN_GetPeerProtocol(). The pointer at *list is freed and set to NULL.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl or list is NULL.

    \param ssl  active WOLFSSL object the protocol list belongs to.
    \param list address of the protocol list pointer returned by wolfSSL_ALPN_GetPeerProtocol().

    _Example_
    \code
    // see wolfSSL_ALPN_FreePeerProtocol usage
    \endcode

    \sa wolfSSL_ALPN_GetPeerProtocol
*/
int wolfSSL_ALPN_FreePeerProtocol(WOLFSSL* ssl, char **list);

/*!
    \ingroup Setup
    \brief Enables or disables negotiation of the encrypt-then-MAC extension (RFC 7366) on the given WOLFSSL session. Encrypt-then-MAC is allowed by default; this call may be used to turn it off for a specific connection.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.
    \return SIDE_ERROR if called after the handshake has already started.

    \param s   WOLFSSL session.
    \param set non-zero to allow EtM negotiation, zero to disable it.

    _Example_
    \code
    // see wolfSSL_AllowEncryptThenMac usage
    \endcode

    \sa wolfSSL_CTX_AllowEncryptThenMac
*/
int wolfSSL_AllowEncryptThenMac(WOLFSSL *s, int set);

/*!
    \ingroup IO
    \brief Drives one step of an asynchronous record encryption operation that was previously reported ready by wolfSSL_AsyncEncryptReady(). Used by the asynchronous-crypto build to interleave application progress with hardware offload.

    \return WOLFSSL_SUCCESS when the asynchronous operation completed for this record.
    \return WC_PENDING_E when the operation still needs more time.
    \return A negative error code on failure.

    \param ssl active WOLFSSL session.
    \param idx index of the pending record entry to advance.

    _Example_
    \code
    // see wolfSSL_AsyncEncrypt usage
    \endcode

    \sa wolfSSL_AsyncEncryptReady
    \sa wolfSSL_AsyncEncryptStop
    \sa wolfSSL_AsyncPoll
*/
int wolfSSL_AsyncEncrypt(WOLFSSL* ssl, int idx);

/*!
    \ingroup IO
    \brief Returns whether the asynchronous record-encryption operation at the given index is ready to be advanced by wolfSSL_AsyncEncrypt().

    \return 1 when the entry is ready to be processed.
    \return 0 when no work is pending for the entry.
    \return A negative error code on failure.

    \param ssl active WOLFSSL session.
    \param idx index of the pending record entry.

    _Example_
    \code
    // see wolfSSL_AsyncEncryptReady usage
    \endcode

    \sa wolfSSL_AsyncEncrypt
    \sa wolfSSL_AsyncEncryptStop
*/
int wolfSSL_AsyncEncryptReady(WOLFSSL* ssl, int idx);

/*!
    \ingroup IO
    \brief Cancels an asynchronous record-encryption operation that was queued for the supplied WOLFSSL session and entry index, releasing any resources held by the device backend.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl active WOLFSSL session.
    \param idx index of the pending record entry to stop.

    _Example_
    \code
    // see wolfSSL_AsyncEncryptStop usage
    \endcode

    \sa wolfSSL_AsyncEncrypt
*/
int wolfSSL_AsyncEncryptStop(WOLFSSL* ssl, int idx);

/*!
    \ingroup IO
    \brief Polls the asynchronous crypto event queue associated with the WOLFSSL session, advancing any operations that are ready and returning when at least one event completed or the queue is empty.

    \return Number of events processed on success.
    \return WC_PENDING_E if no events are ready yet.
    \return A negative error code on failure.

    \param ssl   active WOLFSSL session.
    \param flags WOLF_EVENT_FLAG bitmask controlling polling behaviour (e.g. WOLF_POLL_FLAG_CHECK_HW).

    _Example_
    \code
    // see wolfSSL_AsyncPoll usage
    \endcode

    \sa wolfSSL_CTX_AsyncPoll
*/
int wolfSSL_AsyncPoll(WOLFSSL* ssl, WOLF_EVENT_FLAG flags);

/*!
    \ingroup CertsKeys
    \brief Increments the reference count of a WOLFSSL_CERT_MANAGER so it can be safely shared between multiple WOLFSSL_CTX objects or other owners.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param cm certificate manager whose reference count is incremented.

    _Example_
    \code
    // see wolfSSL_CertManager_up_ref usage
    \endcode

    \sa wolfSSL_CertManagerNew
    \sa wolfSSL_CertManagerFree
*/
int wolfSSL_CertManager_up_ref(WOLFSSL_CERT_MANAGER* cm);

/*!
    \ingroup IO
    \brief Handles a DTLS 1.x retransmission timeout by stepping the internal timer state and, when appropriate, retransmitting the last flight. This is the OpenSSL-compatibility wrapper around wolfSSL_dtls_got_timeout().

    \return 1 when a retransmission occurred.
    \return 0 when no retransmission was needed.
    \return WOLFSSL_FAILURE on error.

    \param ssl active DTLS WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_DTLSv1_handle_timeout usage
    \endcode

    \sa wolfSSL_dtls_got_timeout
    \sa wolfSSL_dtls_get_current_timeout
*/
int  wolfSSL_DTLSv1_handle_timeout(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Disables negotiation of the extended-master-secret extension (RFC 7627) on the given WOLFSSL session. Extended master secret is on by default; call this prior to the handshake to disable it.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_DisableExtendedMasterSecret usage
    \endcode

    \sa wolfSSL_CTX_DisableExtendedMasterSecret
*/
int wolfSSL_DisableExtendedMasterSecret(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Disables OCSP stapling (status_request extension) negotiation on the given WOLFSSL session. Must be called before the handshake starts.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_DisableOCSPStapling usage
    \endcode

    \sa wolfSSL_EnableOCSPStapling
    \sa wolfSSL_CTX_DisableOCSPStapling
*/
int wolfSSL_DisableOCSPStapling(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Enables OCSP stapling (status_request extension) negotiation on the given WOLFSSL session. Must be called before the handshake starts.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_EnableOCSPStapling usage
    \endcode

    \sa wolfSSL_DisableOCSPStapling
    \sa wolfSSL_CTX_EnableOCSPStapling
*/
int wolfSSL_EnableOCSPStapling(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub that reports whether FIPS mode is active. In standard wolfSSL builds this always returns 0; in FIPS-validated builds it reports the current mode.

    \return 0 in non-FIPS builds.
    \return Non-zero when FIPS mode is active in a FIPS build.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_FIPS_mode usage
    \endcode

    \sa wolfSSL_FIPS_mode_set
*/
int wolfSSL_FIPS_mode(void);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub that attempts to set the FIPS mode. In standard wolfSSL builds this is a no-op that returns failure when asked to enable FIPS; in FIPS-validated builds it activates the requested mode.

    \return WOLFSSL_SUCCESS when the requested mode could be set.
    \return WOLFSSL_FAILURE otherwise.

    \param r requested FIPS mode (0 to disable, non-zero to enable).

    _Example_
    \code
    // see wolfSSL_FIPS_mode_set usage
    \endcode

    \sa wolfSSL_FIPS_mode
*/
int wolfSSL_FIPS_mode_set(int r);

/*!
    \ingroup Setup
    \brief Releases handshake-only buffers and state from a completed WOLFSSL session. After this call the session can still send and receive application data but cannot renegotiate.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session whose handshake resources are freed.

    _Example_
    \code
    // see wolfSSL_FreeHandshakeResources usage
    \endcode

    \sa wolfSSL_KeepHandshakeResources
*/
int wolfSSL_FreeHandshakeResources(WOLFSSL* ssl);

/*!
    \ingroup Debug
    \brief Returns the reason code embedded in an OpenSSL-style packed error value. Companion to wolfSSL_ERR_GET_REASON().

    \return Reason code extracted from the packed error value.

    \param x packed error value as returned by wolfSSL_ERR_get_error() and friends.

    _Example_
    \code
    // see wolfSSL_GET_REASON usage
    \endcode

    \sa wolfSSL_ERR_GET_REASON
*/
int           wolfSSL_GET_REASON(int);

/*!
    \ingroup CertsKeys
    \brief Returns a pointer to the DTLS MAC key for the requested direction and epoch. Used by user encryption/MAC callbacks to compute or verify record MACs.

    \return Pointer to the MAC key buffer on success.
    \return NULL on error.

    \param ssl         active DTLS WOLFSSL session.
    \param verify      non-zero to request the peer (verify) key, zero for the local (encrypt) key.
    \param epochOrder  which epoch entry to consult (current, previous, etc.).

    _Example_
    \code
    // see wolfSSL_GetDtlsMacSecret usage
    \endcode

    \sa wolfSSL_SetMacEncryptCb
*/
const unsigned char* wolfSSL_GetDtlsMacSecret(WOLFSSL* ssl, int verify, int epochOrder);

/*!
    \ingroup IO
    \brief Retrieves the most recent record sequence number received from the peer on this WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl or seq is NULL.

    \param ssl active WOLFSSL session.
    \param seq output: peer record sequence number.

    _Example_
    \code
    // see wolfSSL_GetPeerSequenceNumber usage
    \endcode

    \sa wolfSSL_GetSequenceNumber
*/
int                  wolfSSL_GetPeerSequenceNumber(WOLFSSL* ssl, word64* seq);

/*!
    \ingroup IO
    \brief Retrieves the next record sequence number that will be sent on this WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl or seq is NULL.

    \param ssl active WOLFSSL session.
    \param seq output: local record sequence number.

    _Example_
    \code
    // see wolfSSL_GetSequenceNumber usage
    \endcode

    \sa wolfSSL_GetPeerSequenceNumber
*/
int                  wolfSSL_GetSequenceNumber(WOLFSSL* ssl, word64* seq);

/*!
    \ingroup IO
    \brief Returns the negotiated protocol version of the WOLFSSL session as a wolfSSL internal version constant (WOLFSSL_TLSV1_2, WOLFSSL_TLSV1_3, etc.).

    \return Version constant on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_GetVersion usage
    \endcode

    \sa wolfSSL_version
    \sa wolfSSL_get_version
*/
int wolfSSL_GetVersion(const WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Reports whether at least one private-key public-key callback (RSA sign, ECC sign, Ed25519 sign, …) has been installed on the given WOLFSSL session. Useful for determining whether external key handling is active.

    \return 1 when a private PK callback is set.
    \return 0 when none is set.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_IsPrivatePkSet usage
    \endcode

    \sa wolfSSL_CTX_IsPrivatePkSet
*/
int wolfSSL_IsPrivatePkSet(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Marks the WOLFSSL session so that handshake buffers and state are retained after the handshake completes, allowing secure renegotiation and access to handshake data such as peer certificates.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_KeepHandshakeResources usage
    \endcode

    \sa wolfSSL_FreeHandshakeResources
*/
int wolfSSL_KeepHandshakeResources(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Loads a single CRL file into the certificate manager attached to the given WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl  WOLFSSL session.
    \param file path to the CRL file.
    \param type WOLFSSL_FILETYPE_PEM or WOLFSSL_FILETYPE_ASN1.

    _Example_
    \code
    // see wolfSSL_LoadCRLFile usage
    \endcode

    \sa wolfSSL_CTX_LoadCRLFile
    \sa wolfSSL_EnableCRL
*/
int wolfSSL_LoadCRLFile(WOLFSSL* ssl, const char* file, int type);

/*!
    \ingroup Setup
    \brief Returns sizeof(WOLFSSL_METHOD) so that statically allocated method buffers can be sized correctly without exposing the internal struct.

    \return Size in bytes of the WOLFSSL_METHOD structure.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_METHOD_GetObjectSize usage
    \endcode

    \sa wolfSSL_CTX_new
*/
int wolfSSL_METHOD_GetObjectSize(void);

/*!
    \ingroup Setup
    \brief Disables session-ticket use for the given WOLFSSL session when negotiating TLS 1.2 or earlier. Has no effect on TLS 1.3 tickets.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_NoTicketTLSv12 usage
    \endcode

    \sa wolfSSL_CTX_NoTicketTLSv12
    \sa wolfSSL_UseSessionTicket
*/
int wolfSSL_NoTicketTLSv12(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns a const string describing the running wolfSSL build, formatted to resemble OpenSSL_version().

    \return Constant version string.

    \param a OpenSSL_version() selector (OPENSSL_VERSION, OPENSSL_BUILT_ON, …). Currently ignored.

    _Example_
    \code
    // see wolfSSL_OpenSSL_version usage
    \endcode

    \sa wolfSSL_lib_version
*/
const char* wolfSSL_OpenSSL_version(int a);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub. Historically this registered PKCS#12 PBE algorithms; wolfSSL's PBE algorithms are always available so the function is a no-op.

    \return No return value.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_PKCS12_PBE_add usage
    \endcode

    \sa wolfSSL_PKCS12_parse
*/
void wolfSSL_PKCS12_PBE_add(void);

/*!
    \ingroup Setup
    \brief Returns the configured session timeout (in seconds) of a WOLFSSL_CTX. Mirrors OpenSSL's SSL_CTX_get_timeout().

    \return Session timeout in seconds on success.
    \return 0 when ctx is NULL.

    \param ctx WOLFSSL_CTX whose session timeout is queried.

    _Example_
    \code
    // see wolfSSL_SSL_CTX_get_timeout usage
    \endcode

    \sa wolfSSL_CTX_set_timeout
*/
long wolfSSL_SSL_CTX_get_timeout(const WOLFSSL_CTX *ctx);

/*!
    \ingroup openSSL
    \brief Sets the timeout (in seconds) on a WOLFSSL_SESSION object. Mirrors OpenSSL's SSL_SESSION_set_timeout().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ses session whose timeout is set.
    \param t   timeout in seconds.

    _Example_
    \code
    // see wolfSSL_SSL_SESSION_set_timeout usage
    \endcode

    \sa wolfSSL_SESSION_get_timeout
*/
long wolfSSL_SSL_SESSION_set_timeout(WOLFSSL_SESSION* ses, long t);

/*!
    \ingroup IO
    \brief OpenSSL-compatibility wrapper that drives the next step of the TLS handshake on the given WOLFSSL session, calling wolfSSL_connect() or wolfSSL_accept() depending on the session role.

    \return WOLFSSL_SUCCESS when the handshake completes.
    \return A negative error code (e.g. WOLFSSL_ERROR_WANT_READ) when more I/O is required.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_do_handshake usage
    \endcode

    \sa wolfSSL_connect
    \sa wolfSSL_accept
*/
int wolfSSL_SSL_do_handshake(WOLFSSL *s);

/*!
    \ingroup openSSL
    \brief Returns a non-owning pointer to the WOLFSSL_SESSION associated with the WOLFSSL object. Mirrors OpenSSL's SSL_get0_session(); the caller must not free the returned object.

    \return Pointer to the internal session, or NULL when none exists.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_get0_session usage
    \endcode

    \sa wolfSSL_get_session
    \sa wolfSSL_get1_session
*/
WOLFSSL_SESSION *wolfSSL_SSL_get0_session(const WOLFSSL *s);

/*!
    \ingroup openSSL
    \brief Returns the bitmask of SSL_MODE_* flags currently set on the WOLFSSL session. Mirrors OpenSSL's SSL_get_mode().

    \return Current SSL mode bitmask.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_get_mode usage
    \endcode

    \sa wolfSSL_CTX_get_mode
*/
long wolfSSL_SSL_get_mode(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns the read BIO currently attached to the WOLFSSL session, or NULL if none. Mirrors OpenSSL's SSL_get_rbio().

    \return Pointer to the read BIO, or NULL.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_get_rbio usage
    \endcode

    \sa wolfSSL_SSL_get_wbio
    \sa wolfSSL_set_bio
*/
WOLFSSL_BIO *wolfSSL_SSL_get_rbio(const WOLFSSL *s);

/*!
    \ingroup openSSL
    \brief Reports whether the WOLFSSL session successfully negotiated the secure renegotiation extension (RFC 5746).

    \return 1 when secure renegotiation is supported by the peer.
    \return 0 otherwise.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_get_secure_renegotiation_support usage
    \endcode

    \sa wolfSSL_UseSecureRenegotiation
*/
long wolfSSL_SSL_get_secure_renegotiation_support(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns the write BIO currently attached to the WOLFSSL session, or NULL if none. Mirrors OpenSSL's SSL_get_wbio().

    \return Pointer to the write BIO, or NULL.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_get_wbio usage
    \endcode

    \sa wolfSSL_SSL_get_rbio
    \sa wolfSSL_set_bio
*/
WOLFSSL_BIO *wolfSSL_SSL_get_wbio(const WOLFSSL *s);

/*!
    \ingroup openSSL
    \brief Reports whether the WOLFSSL session has not yet started the handshake (SSL_in_before() compatibility).

    \return 1 when no handshake activity has occurred yet.
    \return 0 otherwise.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_in_before usage
    \endcode

    \sa wolfSSL_SSL_in_init
    \sa wolfSSL_is_init_finished
*/
int wolfSSL_SSL_in_before(const WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Reports whether the WOLFSSL session is currently in the middle of a client-side (connect) handshake. Mirrors OpenSSL's SSL_in_connect_init().

    \return 1 when the client handshake is in progress.
    \return 0 otherwise.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_in_connect_init usage
    \endcode

    \sa wolfSSL_SSL_in_init
    \sa wolfSSL_connect
*/
int wolfSSL_SSL_in_connect_init(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Reports whether the WOLFSSL session is currently in the middle of a handshake (either initial or renegotiation). Mirrors OpenSSL's SSL_in_init().

    \return 1 when a handshake is in progress.
    \return 0 otherwise.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_in_init usage
    \endcode

    \sa wolfSSL_is_init_finished
*/
int wolfSSL_SSL_in_init(const WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Reports whether the WOLFSSL session has a pending renegotiation. Mirrors OpenSSL's SSL_renegotiate_pending().

    \return 1 when a renegotiation is pending.
    \return 0 otherwise.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SSL_renegotiate_pending usage
    \endcode

    \sa wolfSSL_Rehandshake
*/
int  wolfSSL_SSL_renegotiate_pending(WOLFSSL *s);

/*!
    \ingroup Setup
    \brief Marks the WOLFSSL session to perform a secure (cryptographically bound) session resumption on the next handshake attempt. Used in combination with wolfSSL_set_session().

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SecureResume usage
    \endcode

    \sa wolfSSL_UseSecureRenegotiation
    \sa wolfSSL_set_session
*/
int wolfSSL_SecureResume(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Schedules a user_canceled TLS warning alert to be sent to the peer before the next close_notify. Useful for signalling abandonment of a handshake.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_SendUserCanceled usage
    \endcode

    \sa wolfSSL_shutdown
*/
int wolfSSL_SendUserCanceled(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Reports whether the given WOLFSSL_SESSION has been fully populated and is ready to be used for resumption.

    \return 1 when the session is set up.
    \return 0 otherwise.

    \param session session to query.

    _Example_
    \code
    // see wolfSSL_SessionIsSetup usage
    \endcode

    \sa wolfSSL_get_session
    \sa wolfSSL_set_session
*/
int wolfSSL_SessionIsSetup(WOLFSSL_SESSION* session);

/*!
    \ingroup CertsKeys
    \brief Registers a user callback that is invoked to fetch a CRL on demand when one is missing from the certificate manager associated with the WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.
    \param cb  callback invoked to retrieve a CRL.

    _Example_
    \code
    // see wolfSSL_SetCRL_IOCb usage
    \endcode

    \sa wolfSSL_CTX_SetCRL_IOCb
    \sa wolfSSL_EnableCRL
*/
int wolfSSL_SetCRL_IOCb(WOLFSSL* ssl, CbCrlIO cb);

/*!
    \ingroup Setup
    \brief Enables or disables Encrypted Client Hello (ECH) processing on the WOLFSSL session.

    \return No return value.

    \param ssl    WOLFSSL session.
    \param enable non-zero to enable ECH, zero to disable.

    _Example_
    \code
    // see wolfSSL_SetEchEnable usage
    \endcode

    \sa wolfSSL_SetEchConfigs
*/
void wolfSSL_SetEchEnable(WOLFSSL* ssl, byte enable);

/*!
    \ingroup CertsKeys
    \brief Enables or disables the FIPS Diffie-Hellman key validation test for the WOLFSSL session. Used in FIPS builds to bypass the test when keys have been validated externally.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl    WOLFSSL session.
    \param enable non-zero to enable, zero to skip the DH key test.

    _Example_
    \code
    // see wolfSSL_SetEnableDhKeyTest usage
    \endcode

*/
int wolfSSL_SetEnableDhKeyTest(WOLFSSL* ssl, int enable);

/*!
    \ingroup CertsKeys
    \brief Sets the ECDHE key size (in bytes) that the WOLFSSL server session will use when generating temporary ECDHE keys. Overrides the default selected for the negotiated curve.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL or sz is invalid.

    \param ssl WOLFSSL session.
    \param sz  desired key size in bytes.

    _Example_
    \code
    // see wolfSSL_SetTmpEC_DHE_Sz usage
    \endcode

    \sa wolfSSL_CTX_SetTmpEC_DHE_Sz
*/
int  wolfSSL_SetTmpEC_DHE_Sz(WOLFSSL* ssl, word16 sz);

/*!
    \ingroup openSSL
    \brief Fills in a WOLFSSL_CRYPTO_THREADID object with the current thread's identifier. Mirrors OpenSSL's CRYPTO_THREADID_current().

    \return No return value.

    \param id destination thread-id object.

    _Example_
    \code
    // see wolfSSL_THREADID_current usage
    \endcode

    \sa wolfSSL_THREADID_set_numeric
*/
void wolfSSL_THREADID_current(WOLFSSL_CRYPTO_THREADID* id);

/*!
    \ingroup openSSL
    \brief Stores a numeric thread identifier in a WOLFSSL_CRYPTO_THREADID object. Mirrors OpenSSL's CRYPTO_THREADID_set_numeric().

    \return No return value.

    \param id  destination thread-id object (opaque).
    \param val numeric thread identifier to store.

    _Example_
    \code
    // see wolfSSL_THREADID_set_numeric usage
    \endcode

    \sa wolfSSL_THREADID_current
*/
void wolfSSL_THREADID_set_numeric(void* id, unsigned long val);

/*!
    \ingroup CertsKeys
    \brief Removes all trust-peer (TOFU) certificates that were loaded onto the WOLFSSL session, returning it to the pristine state regarding peer trust.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_Unload_trust_peers usage
    \endcode

    \sa wolfSSL_trust_peer_cert
    \sa wolfSSL_CTX_Unload_trust_peers
*/
int wolfSSL_Unload_trust_peers(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Configures the Composite-Key-Schemes signature specification used by hybrid post-quantum certificates on this WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG on invalid arguments.

    \param ssl        WOLFSSL session.
    \param sigSpec    buffer holding the signature specification.
    \param sigSpecSz  length of sigSpec in bytes.

    _Example_
    \code
    // see wolfSSL_UseCKS usage
    \endcode

    \sa wolfSSL_CTX_UseCKS
*/
int wolfSSL_UseCKS(WOLFSSL* ssl, byte *sigSpec, word16 sigSpecSz);

/*!
    \ingroup Setup
    \brief Restricts the WOLFSSL session to use the client-side cipher suite list only, ignoring server-side preferences.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_UseClientSuites usage
    \endcode

    \sa wolfSSL_CTX_UseClientSuites
*/
int wolfSSL_UseClientSuites(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Frees a WOLFSSL_STRING (an OpenSSL-compatibility alias for char*) that was allocated by the wolfSSL OpenSSL-compatibility layer.

    \return No return value.

    \param s string to free; safe to pass NULL.

    _Example_
    \code
    // see wolfSSL_WOLFSSL_STRING_free usage
    \endcode

*/
void wolfSSL_WOLFSSL_STRING_free(WOLFSSL_STRING s);

/*!
    \ingroup CertsKeys
    \brief Adds an X.509 certificate to the chain associated with the WOLFSSL session, transferring ownership of x509 to wolfSSL. Mirrors OpenSSL's SSL_add0_chain_cert().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl  WOLFSSL session.
    \param x509 certificate to add to the chain (ownership transferred).

    _Example_
    \code
    // see wolfSSL_add0_chain_cert usage
    \endcode

    \sa wolfSSL_add1_chain_cert
*/
int wolfSSL_add0_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Adds an X.509 certificate to the chain associated with the WOLFSSL session by reference, incrementing its reference count. Mirrors OpenSSL's SSL_add1_chain_cert().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl  WOLFSSL session.
    \param x509 certificate to add to the chain (refcount bumped).

    _Example_
    \code
    // see wolfSSL_add1_chain_cert usage
    \endcode

    \sa wolfSSL_add0_chain_cert
*/
int wolfSSL_add1_chain_cert(WOLFSSL* ssl, WOLFSSL_X509* x509);

/*!
    \ingroup CertsKeys
    \brief Appends the certificate to the list of certificate-authority names advertised by the WOLFSSL server during the CertificateRequest message. Mirrors OpenSSL's SSL_add1_to_CA_list().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl  WOLFSSL session.
    \param x509 CA certificate to advertise.

    _Example_
    \code
    // see wolfSSL_add1_to_CA_list usage
    \endcode

    \sa wolfSSL_add_client_CA
*/
int  wolfSSL_add1_to_CA_list(WOLFSSL *ssl, WOLFSSL_X509 *x509);

/*!
    \ingroup CertsKeys
    \brief Adds a CA certificate to the client-CA list advertised by the WOLFSSL server during the CertificateRequest message. Mirrors OpenSSL's SSL_add_client_CA().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl  WOLFSSL session.
    \param x509 CA certificate.

    _Example_
    \code
    // see wolfSSL_add_client_CA usage
    \endcode

    \sa wolfSSL_CTX_add_client_CA
*/
int  wolfSSL_add_client_CA(WOLFSSL *ssl, WOLFSSL_X509 *x509);

/*!
    \ingroup Debug
    \brief Returns a human-readable long description of the TLS alert description value (e.g. "handshake failure"). Mirrors OpenSSL's SSL_alert_desc_string_long().

    \return Constant descriptive string.

    \param alertID alert description code.

    _Example_
    \code
    // see wolfSSL_alert_desc_string_long usage
    \endcode

    \sa wolfSSL_alert_type_string_long
*/
const char* wolfSSL_alert_desc_string_long(int alertID);

/*!
    \ingroup Debug
    \brief Returns a human-readable long description of the TLS alert level value (warning / fatal). Mirrors OpenSSL's SSL_alert_type_string_long().

    \return Constant descriptive string.

    \param alertID alert level code.

    _Example_
    \code
    // see wolfSSL_alert_type_string_long usage
    \endcode

    \sa wolfSSL_alert_desc_string_long
*/
const char* wolfSSL_alert_type_string_long(int alertID);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub. The function exists for ABI compatibility and performs no action.

    \return No return value.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_cert_service usage
    \endcode

*/
void wolfSSL_cert_service(void);

/*!
    \ingroup CertsKeys
    \brief Clears any certificate or private key data attached to the WOLFSSL session so a different identity can be configured before the handshake.

    \return No return value.

    \param ssl WOLFSSL session whose certs are cleared.

    _Example_
    \code
    // see wolfSSL_certs_clear usage
    \endcode

    \sa wolfSSL_use_certificate
    \sa wolfSSL_use_PrivateKey
*/
void wolfSSL_certs_clear(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub that releases any global ex_data slot allocations. In wolfSSL this is a no-op kept for API parity.

    \return No return value.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_cleanup_all_ex_data usage
    \endcode

    \sa wolfSSL_set_ex_data
*/
void wolfSSL_cleanup_all_ex_data(void);

/*!
    \ingroup Setup
    \brief Resets a WOLFSSL session so it can be reused for another handshake without freeing and reallocating it. Mirrors OpenSSL's SSL_clear().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_clear usage
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
int  wolfSSL_clear(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns the number of renegotiations that have completed on the session and resets the counter to zero. Mirrors OpenSSL's SSL_clear_num_renegotiations().

    \return Previous renegotiation count.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_clear_num_renegotiations usage
    \endcode

    \sa wolfSSL_num_renegotiations
    \sa wolfSSL_total_renegotiations
*/
long wolfSSL_clear_num_renegotiations(WOLFSSL *s);

/*!
    \ingroup openSSL
    \brief Clears the requested option bits on the WOLFSSL session and returns the resulting option bitmask. Mirrors OpenSSL's SSL_clear_options().

    \return New options bitmask after the clear.

    \param s  WOLFSSL session.
    \param op bitmask of option bits to clear.

    _Example_
    \code
    // see wolfSSL_clear_options usage
    \endcode

    \sa wolfSSL_set_options
    \sa wolfSSL_get_options
*/
long wolfSSL_clear_options(WOLFSSL *s,  long op);

/*!
    \ingroup CertsKeys
    \brief Compares the peer certificate received during the handshake against the certificate stored in the given file (DER or PEM). Useful for certificate pinning.

    \return WOLFSSL_SUCCESS when the certificates match.
    \return A negative error code on mismatch or error.

    \param ssl   WOLFSSL session.
    \param fname path to a certificate file.

    _Example_
    \code
    // see wolfSSL_cmp_peer_cert_to_file usage
    \endcode

    \sa wolfSSL_get_peer_certificate
*/
int wolfSSL_cmp_peer_cert_to_file(WOLFSSL* ssl, const char* fname);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility dispatch routine that performs miscellaneous control operations on a WOLFSSL session. Most callers should use the dedicated wrapper for the desired operation rather than calling ctrl directly.

    \return Operation-specific value; typically 1 on success and 0 on error.

    \param ssl WOLFSSL session.
    \param cmd ctrl command identifier.
    \param opt numeric option for the command.
    \param pt  pointer option for the command.

    _Example_
    \code
    // see wolfSSL_ctrl usage
    \endcode

    \sa wolfSSL_CTX_ctrl
*/
long wolfSSL_ctrl(WOLFSSL* ssl, int cmd, long opt, void* pt);

/*!
    \ingroup Setup
    \brief Enables or disables acceptance of fragmented ClientHello messages in DTLS 1.3 on the given session. Useful when the peer's ClientHello (with extensions) exceeds the network MTU.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl     WOLFSSL session.
    \param enabled non-zero to allow fragmentation, zero to require an unfragmented ClientHello.

    _Example_
    \code
    // see wolfSSL_dtls13_allow_ch_frag usage
    \endcode

*/
int wolfSSL_dtls13_allow_ch_frag(WOLFSSL *ssl, int enabled);

/*!
    \ingroup Setup
    \brief Configures whether the DTLS 1.3 server will skip the HelloRetryRequest cookie exchange when a session is being resumed.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl     WOLFSSL session.
    \param enabled non-zero to skip HRR on resumption, zero to keep the default behaviour.

    _Example_
    \code
    // see wolfSSL_dtls13_no_hrr_on_resume usage
    \endcode

*/
int wolfSSL_dtls13_no_hrr_on_resume(WOLFSSL *ssl, int enabled);

/*!
    \ingroup Setup
    \brief Returns the maximum length, in bytes, that wolfSSL will accept for a DTLS Connection ID.

    \return Maximum supported CID length in bytes.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_dtls_cid_max_size usage
    \endcode

    \sa wolfSSL_dtls_cid_use
    \sa wolfSSL_dtls_cid_set
*/
int wolfSSL_dtls_cid_max_size(void);

/*!
    \ingroup IO
    \brief Allocates a peer address structure suitable for wolfSSL_dtls_set_peer() from the supplied IPv4 dotted-quad address and port. Convenience helper for callers that do not want to build a sockaddr themselves.

    \return Pointer to the newly allocated peer structure on success.
    \return NULL on error.

    \param port UDP port number.
    \param ip   NUL-terminated IPv4 address string.

    _Example_
    \code
    // see wolfSSL_dtls_create_peer usage
    \endcode

    \sa wolfSSL_dtls_free_peer
    \sa wolfSSL_dtls_set_peer
*/
void* wolfSSL_dtls_create_peer(int port, char* ip);

/*!
    \ingroup IO
    \brief Frees a peer address structure previously returned by wolfSSL_dtls_create_peer().

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when addr is NULL.

    \param addr peer pointer to free.

    _Example_
    \code
    // see wolfSSL_dtls_free_peer usage
    \endcode

    \sa wolfSSL_dtls_create_peer
*/
int   wolfSSL_dtls_free_peer(void* addr);

/*!
    \ingroup IO
    \brief Sets the maximum transmission unit (in bytes) used when fragmenting DTLS records for the given session.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG on invalid arguments.

    \param ssl WOLFSSL session.
    \param mtu maximum transmission unit in bytes.

    _Example_
    \code
    // see wolfSSL_dtls_set_mtu usage
    \endcode

    \sa wolfSSL_CTX_dtls_set_mtu
*/
int  wolfSSL_dtls_set_mtu(WOLFSSL* ssl, unsigned short mtu);

/*!
    \ingroup IO
    \brief Configures the WOLFSSL session to run DTLS over SCTP (RFC 6083) rather than UDP. Must be called before the handshake starts.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_dtls_set_sctp usage
    \endcode

    \sa wolfSSL_CTX_dtls_set_sctp
*/
int  wolfSSL_dtls_set_sctp(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns a non-owning pointer to the X509_VERIFY_PARAM structure associated with the WOLFSSL session. Mirrors OpenSSL's SSL_get0_param().

    \return Pointer to the embedded verification parameters.
    \return NULL when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get0_param usage
    \endcode

    \sa wolfSSL_set1_host
    \sa wolfSSL_X509_VERIFY_PARAM_set1_host
*/
WOLFSSL_X509_VERIFY_PARAM* wolfSSL_get0_param(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns the most recent peer hostname configured on the WOLFSSL session via wolfSSL_set1_host() or wolfSSL_check_private_key(). Mirrors OpenSSL's SSL_get0_peername().

    \return Pointer to the hostname string on success.
    \return NULL when none has been set.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get0_peername usage
    \endcode

    \sa wolfSSL_set1_host
*/
const char *wolfSSL_get0_peername(WOLFSSL *ssl);

/*!
    \ingroup Setup
    \brief Returns the WOLFSSL_CTX that the WOLFSSL session was created from. Mirrors OpenSSL's SSL_get_SSL_CTX().

    \return Pointer to the WOLFSSL_CTX on success.
    \return NULL when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_SSL_CTX usage
    \endcode

    \sa wolfSSL_set_SSL_CTX
*/
WOLFSSL_CTX* wolfSSL_get_SSL_CTX(const WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Returns the application-specific data pointer that was previously stored on the WOLFSSL session via wolfSSL_set_app_data().

    \return Application data pointer or NULL if none was set.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_app_data usage
    \endcode

    \sa wolfSSL_set_app_data
*/
void* wolfSSL_get_app_data( const WOLFSSL *ssl);

/*!
    \ingroup CertsKeys
    \brief Returns the X.509 certificate the WOLFSSL session is configured to present to the peer, or NULL if no certificate has been loaded.

    \return Pointer to the local certificate on success.
    \return NULL when none is set.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_certificate usage
    \endcode

    \sa wolfSSL_use_certificate
    \sa wolfSSL_get_peer_certificate
*/
WOLFSSL_X509* wolfSSL_get_certificate(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Returns the WOLFSSL_CIPHER object whose two-byte TLS suite identifier matches the supplied value. Mirrors OpenSSL's SSL_CIPHER_find()/get_cipher_by_value().

    \return Pointer to a static WOLFSSL_CIPHER on success.
    \return NULL when no cipher matches.

    \param value two-byte TLS cipher suite identifier.

    _Example_
    \code
    // see wolfSSL_get_cipher_by_value usage
    \endcode

    \sa wolfSSL_CIPHER_get_name
*/
const WOLFSSL_CIPHER* wolfSSL_get_cipher_by_value(word16 value);

/*!
    \ingroup IO
    \brief Returns a pointer to the name of the cipher at the requested priority position in the cipher list configured on the WOLFSSL session.

    \return Cipher name on success.
    \return NULL when the index is out of range.

    \param ssl      WOLFSSL session.
    \param priority zero-based priority index into the cipher list.

    _Example_
    \code
    // see wolfSSL_get_cipher_list_ex usage
    \endcode

    \sa wolfSSL_get_cipher_list
*/
char* wolfSSL_get_cipher_list_ex(WOLFSSL* ssl, int priority);

/*!
    \ingroup IO
    \brief Writes the colon-separated IANA names of all cipher suites supported by the current build into the supplied buffer.

    \return WOLFSSL_SUCCESS on success.
    \return BUFFER_E when the buffer is too small.

    \param buf destination buffer.
    \param len size of buf in bytes.

    _Example_
    \code
    // see wolfSSL_get_ciphers_iana usage
    \endcode

    \sa wolfSSL_get_ciphers
*/
int wolfSSL_get_ciphers_iana(char* buf, int len);

/*!
    \ingroup openSSL
    \brief Returns the active record-layer compression method on the WOLFSSL session. wolfSSL does not implement record compression, so this always returns NULL.

    \return NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_current_compression usage
    \endcode

    \sa wolfSSL_get_current_expansion
*/
const WOLFSSL_COMP_METHOD* wolfSSL_get_current_compression(const WOLFSSL *ssl);

/*!
    \ingroup openSSL
    \brief Returns the active record-layer expansion method on the WOLFSSL session. wolfSSL does not implement record compression, so this always returns NULL.

    \return NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_current_expansion usage
    \endcode

    \sa wolfSSL_get_current_compression
*/
const WOLFSSL_COMP_METHOD* wolfSSL_get_current_expansion(const WOLFSSL *ssl);

/*!
    \ingroup IO
    \brief Returns the name of the elliptic curve negotiated by the WOLFSSL session's (EC)DHE key exchange, or NULL if none is in use.

    \return Curve name on success.
    \return NULL when not applicable.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_curve_name usage
    \endcode

    \sa wolfSSL_get_curve_id
*/
const char* wolfSSL_get_curve_name(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Reports the result of TLS 1.3 early-data processing on the WOLFSSL session (rejected, accepted, or not attempted).

    \return WOLFSSL_EARLY_DATA_ACCEPTED, WOLFSSL_EARLY_DATA_REJECTED, or WOLFSSL_EARLY_DATA_NOT_SENT.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_early_data_status usage
    \endcode

    \sa wolfSSL_write_early_data
    \sa wolfSSL_read_early_data
*/
int  wolfSSL_get_early_data_status(const WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Retrieves the application-specific pointer previously stored at the given ex_data index on the WOLFSSL session. Mirrors OpenSSL's SSL_get_ex_data().

    \return Stored pointer or NULL.

    \param ssl WOLFSSL session.
    \param idx ex_data slot index.

    _Example_
    \code
    // see wolfSSL_get_ex_data usage
    \endcode

    \sa wolfSSL_set_ex_data
*/
void* wolfSSL_get_ex_data(const WOLFSSL* ssl, int idx);

/*!
    \ingroup openSSL
    \brief Returns the well-known ex_data index used to recover the WOLFSSL session from a WOLFSSL_X509_STORE_CTX during verification callbacks. Mirrors OpenSSL's SSL_get_ex_data_X509_STORE_CTX_idx().

    \return ex_data index value.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_get_ex_data_X509_STORE_CTX_idx usage
    \endcode

    \sa wolfSSL_X509_STORE_CTX_get_ex_data
*/
int  wolfSSL_get_ex_data_X509_STORE_CTX_idx(void);

/*!
    \ingroup IO
    \brief Copies the last Finished message sent by the local side into the supplied buffer.

    \return Number of bytes copied.
    \return 0 on error.

    \param ssl   WOLFSSL session.
    \param buf   destination buffer.
    \param count buffer size in bytes.

    _Example_
    \code
    // see wolfSSL_get_finished usage
    \endcode

    \sa wolfSSL_get_peer_finished
*/
size_t wolfSSL_get_finished(const WOLFSSL *ssl, void *buf, size_t count);

/*!
    \ingroup IO
    \brief Returns the size, in bytes, of the TLS key-block (MAC + key + IV material for both directions) negotiated for the session.

    \return Key block size on success.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_keyblock_size usage
    \endcode

    \sa wolfSSL_get_keys
*/
int wolfSSL_get_keyblock_size(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns the global locking callback installed via wolfSSL_set_locking_callback(). Mirrors OpenSSL's CRYPTO_get_locking_callback().

    \return Pointer to the callback or NULL when none is set.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_get_locking_callback usage
    \endcode

    \sa wolfSSL_set_locking_callback
*/
mutex_cb* wolfSSL_get_locking_callback(void);

/*!
    \ingroup IO
    \brief Returns the maximum amount of TLS 1.3 early data, in bytes, that the WOLFSSL session is willing to accept.

    \return Maximum early-data size in bytes.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_max_early_data usage
    \endcode

    \sa wolfSSL_set_max_early_data
    \sa wolfSSL_write_early_data
*/
int  wolfSSL_get_max_early_data(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Returns the alternate verification chain that was built by the WOLFSSL session when the original peer chain could not be verified. Used to inspect why a fallback path was needed.

    \return Pointer to the alternate chain or NULL when none exists.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_peer_alt_chain usage
    \endcode

    \sa wolfSSL_is_peer_alt_cert_chain
    \sa wolfSSL_get_peer_chain
*/
WOLFSSL_X509_CHAIN* wolfSSL_get_peer_alt_chain(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Copies the last Finished message sent by the peer into the supplied buffer.

    \return Number of bytes copied.
    \return 0 on error.

    \param ssl   WOLFSSL session.
    \param buf   destination buffer.
    \param count buffer size in bytes.

    _Example_
    \code
    // see wolfSSL_get_peer_finished usage
    \endcode

    \sa wolfSSL_get_finished
*/
size_t wolfSSL_get_peer_finished(const WOLFSSL *ssl, void *buf, size_t count);

/*!
    \ingroup CertsKeys
    \brief Returns the NID of the signature algorithm used by the peer for its handshake signature (CertificateVerify in TLS 1.3 or ServerKeyExchange/Certificate in earlier versions).

    \return WOLFSSL_SUCCESS on success with *nid populated.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param nid output: signature NID.

    _Example_
    \code
    // see wolfSSL_get_peer_signature_nid usage
    \endcode

    \sa wolfSSL_get_signature_nid
*/
int wolfSSL_get_peer_signature_nid(WOLFSSL* ssl, int* nid);

/*!
    \ingroup CertsKeys
    \brief Returns a freshly allocated WOLFSSL_EVP_PKEY wrapping the ephemeral key the peer used during (EC)DHE key exchange. Caller frees with wolfSSL_EVP_PKEY_free().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl  WOLFSSL session.
    \param pkey output: newly allocated EVP_PKEY containing the peer ephemeral public key.

    _Example_
    \code
    // see wolfSSL_get_peer_tmp_key usage
    \endcode

    \sa wolfSSL_get_peer_certificate
*/
int wolfSSL_get_peer_tmp_key(const WOLFSSL* ssl, WOLFSSL_EVP_PKEY** pkey);

/*!
    \ingroup CertsKeys
    \brief Returns a non-owning pointer to the private key the WOLFSSL session is configured to use, or NULL if none is loaded.

    \return Pointer to the private key on success.
    \return NULL otherwise.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_privatekey usage
    \endcode

    \sa wolfSSL_use_PrivateKey
*/
WOLFSSL_EVP_PKEY *wolfSSL_get_privatekey(const WOLFSSL *ssl);

/*!
    \ingroup IO
    \brief Reports whether read-ahead is enabled on the WOLFSSL session. With read-ahead enabled wolfSSL will read more than one record at a time when possible.

    \return 1 when enabled.
    \return 0 when disabled.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_read_ahead usage
    \endcode

    \sa wolfSSL_set_read_ahead
*/
int  wolfSSL_get_read_ahead(const WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Returns the current OpenSSL-compatibility security level configured on the WOLFSSL session.

    \return Security level value (0-5).

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_security_level usage
    \endcode

    \sa wolfSSL_set_security_level
*/
int    wolfSSL_get_security_level(const WOLFSSL * ssl);

/*!
    \ingroup IO
    \brief Returns the SNI hostname sent by the client or received by the server during the handshake, depending on which side this WOLFSSL session represents.

    \return Pointer to the SNI string on success.
    \return NULL when no SNI was negotiated.

    \param ssl  WOLFSSL session.
    \param type SNI type, currently always WOLFSSL_SNI_HOST_NAME.

    _Example_
    \code
    // see wolfSSL_get_servername usage
    \endcode

    \sa wolfSSL_UseSNI
*/
const char* wolfSSL_get_servername(WOLFSSL* ssl, unsigned char type);

/*!
    \ingroup CertsKeys
    \brief Returns the NID of the signature algorithm the local side used for its handshake signature.

    \return WOLFSSL_SUCCESS on success with *nid populated.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param nid output: signature NID.

    _Example_
    \code
    // see wolfSSL_get_signature_nid usage
    \endcode

    \sa wolfSSL_get_peer_signature_nid
*/
int wolfSSL_get_signature_nid(WOLFSSL* ssl, int* nid);

/*!
    \ingroup CertsKeys
    \brief Returns the NID of the hash algorithm portion of the local side's handshake signature.

    \return WOLFSSL_SUCCESS on success with *nid populated.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param nid output: hash NID.

    _Example_
    \code
    // see wolfSSL_get_signature_type_nid usage
    \endcode

    \sa wolfSSL_get_signature_nid
*/
int wolfSSL_get_signature_type_nid(const WOLFSSL* ssl, int* nid);

/*!
    \ingroup CertsKeys
    \brief Returns the SRP username being used by the WOLFSSL session, or NULL if SRP is not in use.

    \return Username string on success.
    \return NULL otherwise.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_srp_username usage
    \endcode

    \sa wolfSSL_CTX_set_srp_username
*/
char* wolfSSL_get_srp_username(WOLFSSL *ssl);

/*!
    \ingroup IO
    \brief Returns the current TLS handshake state of the WOLFSSL session. Mirrors OpenSSL's SSL_get_state().

    \return Integer encoding of the current handshake state.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_state usage
    \endcode

    \sa wolfSSL_state_string_long
*/
int wolfSSL_get_state(const WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Returns the session timeout (in seconds) configured on the WOLFSSL session. Mirrors OpenSSL's SSL_get_default_timeout().

    \return Timeout value in seconds.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_timeout usage
    \endcode

    \sa wolfSSL_SSL_CTX_get_timeout
*/
long wolfSSL_get_timeout(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief OpenSSL-compatibility stub for SSL_get_tlsext_status_exts. wolfSSL's OCSP stapling configuration is done through dedicated calls; this function performs no action.

    \return WOLFSSL_FAILURE.

    \param s WOLFSSL session.
    \param arg ignored.

    _Example_
    \code
    // see wolfSSL_get_tlsext_status_exts usage
    \endcode

    \sa wolfSSL_set_tlsext_status_exts
*/
long wolfSSL_get_tlsext_status_exts(WOLFSSL *s, void *arg);

/*!
    \ingroup IO
    \brief OpenSSL-compatibility stub for SSL_get_tlsext_status_ids. wolfSSL handles OCSP responder IDs internally; this function performs no action.

    \return WOLFSSL_FAILURE.

    \param s WOLFSSL session.
    \param arg ignored.

    _Example_
    \code
    // see wolfSSL_get_tlsext_status_ids usage
    \endcode

    \sa wolfSSL_set_tlsext_status_ids
*/
long wolfSSL_get_tlsext_status_ids(WOLFSSL *s, void *arg);

/*!
    \ingroup IO
    \brief Returns the TLS status_request type negotiated for the session (typically TLSEXT_STATUSTYPE_ocsp) or -1 if OCSP stapling was not negotiated.

    \return Status-request type code, or -1 when not negotiated.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_tlsext_status_type usage
    \endcode

    \sa wolfSSL_set_tlsext_status_type
    \sa wolfSSL_EnableOCSPStapling
*/
long wolfSSL_get_tlsext_status_type(WOLFSSL *s);

/*!
    \ingroup CertsKeys
    \brief Returns the verify callback currently installed on the WOLFSSL session.

    \return Function pointer to the verify callback or NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_verify_callback usage
    \endcode

    \sa wolfSSL_set_verify
*/
VerifyCallback wolfSSL_get_verify_callback(WOLFSSL* ssl);

/*!
    \ingroup CertsKeys
    \brief Returns the bitmask of WOLFSSL_VERIFY_* flags currently configured on the WOLFSSL session.

    \return Verify mode bitmask.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_get_verify_mode usage
    \endcode

    \sa wolfSSL_set_verify
*/
int wolfSSL_get_verify_mode(const WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Reports whether the WOLFSSL session has buffered application data that has not yet been read.

    \return 1 when data is pending.
    \return 0 when no data is pending.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_has_pending usage
    \endcode

    \sa wolfSSL_pending
*/
int wolfSSL_has_pending(const WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief Writes a human-readable textual representation of an ASN.1 OBJECT IDENTIFIER to the supplied BIO. Mirrors OpenSSL's i2a_ASN1_OBJECT().

    \return Number of characters written on success.
    \return A negative value on error.

    \param bp destination BIO.
    \param a  ASN.1 OBJECT to print.

    _Example_
    \code
    // see wolfSSL_i2a_ASN1_OBJECT usage
    \endcode

    \sa wolfSSL_i2t_ASN1_OBJECT
*/
int wolfSSL_i2a_ASN1_OBJECT(WOLFSSL_BIO *bp, WOLFSSL_ASN1_OBJECT *a);

/*!
    \ingroup openSSL
    \brief Encodes an ASN.1 INTEGER as a two's-complement big-endian byte string. If pp is non-NULL the encoding is written there and *pp advanced. Mirrors OpenSSL's i2c_ASN1_INTEGER().

    \return Length of the encoding in bytes.
    \return 0 on error.

    \param a  ASN.1 INTEGER to encode.
    \param pp optional destination pointer.

    _Example_
    \code
    // see wolfSSL_i2c_ASN1_INTEGER usage
    \endcode

    \sa wolfSSL_i2d_ASN1_INTEGER
*/
int wolfSSL_i2c_ASN1_INTEGER(WOLFSSL_ASN1_INTEGER *a, unsigned char **pp);

/*!
    \ingroup openSSL
    \brief Writes a textual (dotted) representation of an ASN.1 OBJECT IDENTIFIER into the supplied buffer. Mirrors OpenSSL's i2t_ASN1_OBJECT().

    \return Number of bytes written on success.
    \return 0 on error.

    \param buf     destination buffer.
    \param buf_len size of buf in bytes.
    \param a       ASN.1 OBJECT to print.

    _Example_
    \code
    // see wolfSSL_i2t_ASN1_OBJECT usage
    \endcode

    \sa wolfSSL_i2a_ASN1_OBJECT
*/
int wolfSSL_i2t_ASN1_OBJECT(char *buf, int buf_len, WOLFSSL_ASN1_OBJECT *a);

/*!
    \ingroup CertsKeys
    \brief Reports whether the WOLFSSL session ended up using the alternate verification chain rather than the chain the peer originally sent.

    \return 1 when the alternate chain was used.
    \return 0 otherwise.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_is_peer_alt_cert_chain usage
    \endcode

    \sa wolfSSL_get_peer_alt_chain
*/
int wolfSSL_is_peer_alt_cert_chain(const WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Reports whether the WOLFSSL session is acting as a server.

    \return 1 when ssl is a server-side session.
    \return 0 when it is client-side.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_is_server usage
    \endcode

    \sa wolfSSL_set_accept_state
    \sa wolfSSL_set_connect_state
*/
int  wolfSSL_is_server(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Reports whether the WOLFSSL session keeps full handshake state (stateful) or has been put into the stateless DTLS cookie-check mode.

    \return Non-zero when the session is stateful.
    \return 0 when it is stateless.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_is_stateful usage
    \endcode

    \sa wolfSSL_send_hrr_cookie
*/
byte wolfSSL_is_stateful(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Returns the maximum number of multicast peers that this wolfSSL build supports per group.

    \return Maximum number of multicast peers.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_mcast_get_max_peers usage
    \endcode

    \sa wolfSSL_mcast_peer_add
*/
int  wolfSSL_mcast_get_max_peers(void);

/*!
    \ingroup Setup
    \brief Adds (or removes) a peer to the multicast group associated with the WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl    WOLFSSL multicast session.
    \param peerId identifier of the peer to add.
    \param sub    non-zero to subscribe (add), zero to unsubscribe (remove).

    _Example_
    \code
    // see wolfSSL_mcast_peer_add usage
    \endcode

    \sa wolfSSL_mcast_peer_known
    \sa wolfSSL_mcast_get_max_peers
*/
int  wolfSSL_mcast_peer_add(WOLFSSL* ssl, unsigned short peerId, int sub);

/*!
    \ingroup Setup
    \brief Reports whether the given peer identifier is already known to the WOLFSSL multicast session.

    \return 1 when the peer is known.
    \return 0 when unknown.
    \return A negative error code on failure.

    \param ssl    WOLFSSL multicast session.
    \param peerId identifier of the peer to query.

    _Example_
    \code
    // see wolfSSL_mcast_peer_known usage
    \endcode

    \sa wolfSSL_mcast_peer_add
*/
int  wolfSSL_mcast_peer_known(WOLFSSL* ssl, unsigned short peerId);

/*!
    \ingroup IO
    \brief Reads an application-data record from the WOLFSSL multicast session and reports the peer identifier of the sender.

    \return Number of bytes read on success.
    \return A negative error code on failure.

    \param ssl  WOLFSSL multicast session.
    \param id   output: peer identifier of the sender.
    \param data destination buffer.
    \param sz   size of data in bytes.

    _Example_
    \code
    // see wolfSSL_mcast_read usage
    \endcode

    \sa wolfSSL_mcast_peer_add
*/
int  wolfSSL_mcast_read(WOLFSSL* ssl, unsigned short* id, void* data, int sz);

/*!
    \ingroup IO
    \brief Stores an opaque user-context pointer that is later passed to the multicast high-water sequence-number callback when it fires.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL multicast session.
    \param ctx opaque user pointer.

    _Example_
    \code
    // see wolfSSL_mcast_set_highwater_ctx usage
    \endcode

    \sa wolfSSL_CTX_mcast_set_highwater_cb
*/
int  wolfSSL_mcast_set_highwater_ctx(WOLFSSL* ssl, void* ctx);

/*!
    \ingroup Setup
    \brief Enables or disables mutual (peer) authentication for the WOLFSSL session. When enabled, the local side will refuse to complete the handshake unless the peer presents a certificate.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.
    \param req non-zero to require peer authentication, zero to disable.

    _Example_
    \code
    // see wolfSSL_mutual_auth usage
    \endcode

    \sa wolfSSL_CTX_mutual_auth
*/
int  wolfSSL_mutual_auth(WOLFSSL* ssl, int req);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub. wolfSSL's locking is per-object; this always returns 0.

    \return 0.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_num_locks usage
    \endcode

    \sa wolfSSL_set_locking_callback
*/
int  wolfSSL_num_locks(void);

/*!
    \ingroup openSSL
    \brief Returns the number of renegotiations completed on the WOLFSSL session since the last call to wolfSSL_clear_num_renegotiations(). Mirrors OpenSSL's SSL_num_renegotiations().

    \return Renegotiation count.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_num_renegotiations usage
    \endcode

    \sa wolfSSL_clear_num_renegotiations
    \sa wolfSSL_total_renegotiations
*/
long wolfSSL_num_renegotiations(WOLFSSL* s);

/*!
    \ingroup Setup
    \brief Restricts the WOLFSSL session to PSK cipher suites that perform a Diffie-Hellman or ECDHE key exchange, rejecting plain PSK suites.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_only_dhe_psk usage
    \endcode

    \sa wolfSSL_set_psk_callback_ctx
*/
int  wolfSSL_only_dhe_psk(WOLFSSL* ssl);

/*!
    \ingroup Debug
    \brief Drains the wolfSSL error queue and prints every entry to the supplied FILE pointer in a human-readable format. Mirrors OpenSSL's ERR_print_errors_fp().

    \return No return value.

    \param fp destination file.

    _Example_
    \code
    // see wolfSSL_print_all_errors_fp usage
    \endcode

    \sa wolfSSL_ERR_print_errors_fp
    \sa wolfSSL_ERR_get_error
*/
void wolfSSL_print_all_errors_fp(XFILE fp);

/*!
    \ingroup IO
    \brief Reads up to sz bytes of application data from the WOLFSSL session into data and stores the actual number read in *rd. Mirrors OpenSSL's SSL_read_ex().

    \return WOLFSSL_SUCCESS on success.
    \return 0 on error or EOF.

    \param ssl  WOLFSSL session.
    \param data destination buffer.
    \param sz   size of data in bytes.
    \param rd   output: number of bytes actually read.

    _Example_
    \code
    // see wolfSSL_read_ex usage
    \endcode

    \sa wolfSSL_read
    \sa wolfSSL_write_ex
*/
int wolfSSL_read_ex(WOLFSSL* ssl, void* data, size_t sz, size_t* rd);

/*!
    \ingroup Setup
    \brief Replaces the list of acceptable elliptic curves for the WOLFSSL session with the colon-separated set provided. Mirrors OpenSSL's SSL_set1_curves_list().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl   WOLFSSL session.
    \param names colon-separated curve names (e.g. "P-256:P-384").

    _Example_
    \code
    // see wolfSSL_set1_curves_list usage
    \endcode

    \sa wolfSSL_CTX_set1_curves_list
*/
int wolfSSL_set1_curves_list(WOLFSSL* ssl, const char* names);

/*!
    \ingroup Setup
    \brief Replaces the list of acceptable (EC)DH groups for the WOLFSSL session with the array provided. Each element is a wolfSSL named-group constant.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl    WOLFSSL session.
    \param groups array of named-group identifiers.
    \param count  number of elements in groups.

    _Example_
    \code
    // see wolfSSL_set1_groups usage
    \endcode

    \sa wolfSSL_set1_curves_list
*/
int  wolfSSL_set1_groups(WOLFSSL* ssl, int* groups, int count);

/*!
    \ingroup Setup
    \brief Sets the expected peer hostname used during X.509 verification on the WOLFSSL session, replacing any previously configured value. Mirrors OpenSSL's SSL_set1_host().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl  WOLFSSL session.
    \param name NUL-terminated hostname.

    _Example_
    \code
    // see wolfSSL_set1_host usage
    \endcode

    \sa wolfSSL_X509_VERIFY_PARAM_set1_host
    \sa wolfSSL_get0_peername
*/
int wolfSSL_set1_host(WOLFSSL* ssl, const char * name);

/*!
    \ingroup Setup
    \brief Re-associates the WOLFSSL session with a different WOLFSSL_CTX, inheriting that context's configuration. Mirrors OpenSSL's SSL_set_SSL_CTX().

    \return Pointer to the new WOLFSSL_CTX on success.
    \return NULL on error.

    \param ssl WOLFSSL session.
    \param ctx new WOLFSSL_CTX to associate with the session.

    _Example_
    \code
    // see wolfSSL_set_SSL_CTX usage
    \endcode

    \sa wolfSSL_get_SSL_CTX
*/
WOLFSSL_CTX* wolfSSL_set_SSL_CTX(WOLFSSL* ssl,WOLFSSL_CTX* ctx);

/*!
    \ingroup Setup
    \brief Configures the WOLFSSL session to act as a server (accept side) for the upcoming handshake. Mirrors OpenSSL's SSL_set_accept_state().

    \return No return value.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_set_accept_state usage
    \endcode

    \sa wolfSSL_set_connect_state
    \sa wolfSSL_accept
*/
void wolfSSL_set_accept_state(WOLFSSL* ssl);

/*!
    \ingroup Setup
    \brief Stores an application-specific pointer on the WOLFSSL session, retrievable later via wolfSSL_get_app_data().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param arg application-defined pointer.

    _Example_
    \code
    // see wolfSSL_set_app_data usage
    \endcode

    \sa wolfSSL_get_app_data
*/
int wolfSSL_set_app_data(WOLFSSL *ssl, void *arg);

/*!
    \ingroup IO
    \brief Replaces the read and write BIOs attached to the WOLFSSL session. The session takes ownership of both BIOs; if rd and wr are the same object, ownership is transferred only once. Mirrors OpenSSL's SSL_set_bio().

    \return No return value.

    \param ssl WOLFSSL session.
    \param rd  read BIO (may be NULL).
    \param wr  write BIO (may be NULL).

    _Example_
    \code
    // see wolfSSL_set_bio usage
    \endcode

    \sa wolfSSL_set_rbio
    \sa wolfSSL_set_wbio
*/
void wolfSSL_set_bio(WOLFSSL* ssl, WOLFSSL_BIO* rd, WOLFSSL_BIO* wr);

/*!
    \ingroup Setup
    \brief Sets the cipher list for the WOLFSSL session using a raw two-byte-per-suite TLS encoding (rather than the colon-separated string form).

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl    WOLFSSL session.
    \param list   buffer holding the encoded cipher suites.
    \param listSz length of list in bytes.

    _Example_
    \code
    // see wolfSSL_set_cipher_list_bytes usage
    \endcode

    \sa wolfSSL_set_cipher_list
*/
int  wolfSSL_set_cipher_list_bytes(WOLFSSL* ssl, const byte* list, const int listSz);

/*!
    \ingroup Setup
    \brief Configures the WOLFSSL session to act as a client (connect side) for the upcoming handshake. Mirrors OpenSSL's SSL_set_connect_state().

    \return No return value.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_set_connect_state usage
    \endcode

    \sa wolfSSL_set_accept_state
    \sa wolfSSL_connect
*/
void wolfSSL_set_connect_state(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub for SSL_set_ecdh_auto(). wolfSSL always selects ECDH parameters automatically, so the function is effectively a no-op.

    \return WOLFSSL_SUCCESS.

    \param ssl   WOLFSSL session.
    \param onoff non-zero to enable automatic ECDH parameters.

    _Example_
    \code
    // see wolfSSL_set_ecdh_auto usage
    \endcode

*/
int wolfSSL_set_ecdh_auto(WOLFSSL* ssl, int onoff);

/*!
    \ingroup openSSL
    \brief Stores an application pointer at the given ex_data slot on the WOLFSSL session. Mirrors OpenSSL's SSL_set_ex_data().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl  WOLFSSL session.
    \param idx  ex_data slot index.
    \param data application pointer.

    _Example_
    \code
    // see wolfSSL_set_ex_data usage
    \endcode

    \sa wolfSSL_get_ex_data
*/
int  wolfSSL_set_ex_data(WOLFSSL* ssl, int idx, void* data);

/*!
    \ingroup openSSL
    \brief Registers a thread-id callback used by the OpenSSL-compatibility layer for locking. Mirrors OpenSSL's CRYPTO_set_id_callback().

    \return No return value.

    \param f callback returning the current thread's identifier.

    _Example_
    \code
    // see wolfSSL_set_id_callback usage
    \endcode

    \sa wolfSSL_thread_id
*/
void wolfSSL_set_id_callback(unsigned long (*f)(void));

/*!
    \ingroup openSSL
    \brief Registers a global locking callback used by the OpenSSL-compatibility layer. Mirrors OpenSSL's CRYPTO_set_locking_callback().

    \return No return value.

    \param f locking callback.

    _Example_
    \code
    // see wolfSSL_set_locking_callback usage
    \endcode

    \sa wolfSSL_get_locking_callback
*/
void wolfSSL_set_locking_callback(mutex_cb* f);

/*!
    \ingroup Setup
    \brief Sets the maximum protocol version that the WOLFSSL session will negotiate. Mirrors OpenSSL's SSL_set_max_proto_version().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl     WOLFSSL session.
    \param version protocol version constant (TLS1_2_VERSION, TLS1_3_VERSION, …) or 0 for no upper bound.

    _Example_
    \code
    // see wolfSSL_set_max_proto_version usage
    \endcode

    \sa wolfSSL_set_min_proto_version
*/
int wolfSSL_set_max_proto_version(WOLFSSL* ssl, int version);

/*!
    \ingroup Setup
    \brief Sets the minimum protocol version that the WOLFSSL session will negotiate. Mirrors OpenSSL's SSL_set_min_proto_version().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl     WOLFSSL session.
    \param version protocol version constant or 0 for no lower bound.

    _Example_
    \code
    // see wolfSSL_set_min_proto_version usage
    \endcode

    \sa wolfSSL_set_max_proto_version
*/
int wolfSSL_set_min_proto_version(WOLFSSL* ssl, int version);

/*!
    \ingroup IO
    \brief OpenSSL-compatible wrapper around wolfSSL_dtls_set_mtu().

    \return 1 on success.
    \return 0 on error.

    \param ssl WOLFSSL session.
    \param mtu maximum transmission unit in bytes.

    _Example_
    \code
    // see wolfSSL_set_mtu_compat usage
    \endcode

    \sa wolfSSL_dtls_set_mtu
*/
int  wolfSSL_set_mtu_compat(WOLFSSL* ssl, unsigned short mtu);

/*!
    \ingroup CertsKeys
    \brief Sets the OCSP responder URL used when the WOLFSSL session needs to fetch an OCSP response on its own (i.e. no stapled response is available).

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.
    \param url NUL-terminated OCSP responder URL.

    _Example_
    \code
    // see wolfSSL_set_ocsp_url usage
    \endcode

    \sa wolfSSL_CTX_SetOCSP_OverrideURL
*/
int wolfSSL_set_ocsp_url(WOLFSSL* ssl, char* url);

/*!
    \ingroup Setup
    \brief Enables or disables TLS 1.3 post-handshake client authentication on the WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl WOLFSSL session.
    \param val non-zero to enable PHA, zero to disable.

    _Example_
    \code
    // see wolfSSL_set_post_handshake_auth usage
    \endcode

    \sa wolfSSL_verify_client_post_handshake
*/
int wolfSSL_set_post_handshake_auth(WOLFSSL* ssl, int val);

/*!
    \ingroup Setup
    \brief Enables or disables quiet shutdown mode on the WOLFSSL session. With quiet shutdown enabled, wolfSSL_shutdown() returns success immediately without sending or expecting a close_notify alert. Mirrors OpenSSL's SSL_set_quiet_shutdown().

    \return No return value.

    \param ssl  WOLFSSL session.
    \param mode non-zero to enable quiet shutdown.

    _Example_
    \code
    // see wolfSSL_set_quiet_shutdown usage
    \endcode

    \sa wolfSSL_CTX_set_quiet_shutdown
    \sa wolfSSL_shutdown
*/
void wolfSSL_set_quiet_shutdown(WOLFSSL* ssl, int mode);

/*!
    \ingroup IO
    \brief Replaces the read BIO attached to the WOLFSSL session, taking ownership of rd. Mirrors OpenSSL's SSL_set0_rbio().

    \return No return value.

    \param ssl WOLFSSL session.
    \param rd  read BIO (may be NULL).

    _Example_
    \code
    // see wolfSSL_set_rbio usage
    \endcode

    \sa wolfSSL_set_wbio
    \sa wolfSSL_set_bio
*/
void wolfSSL_set_rbio(WOLFSSL* ssl, WOLFSSL_BIO* rd);

/*!
    \ingroup IO
    \brief Enables or disables read-ahead on the WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.
    \param v   non-zero to enable, zero to disable read-ahead.

    _Example_
    \code
    // see wolfSSL_set_read_ahead usage
    \endcode

    \sa wolfSSL_get_read_ahead
*/
int  wolfSSL_set_read_ahead(WOLFSSL* ssl, int v);

/*!
    \ingroup IO
    \brief Sets the file descriptor that the WOLFSSL session reads from. Mirrors OpenSSL's SSL_set_rfd().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param fd  read file descriptor.

    _Example_
    \code
    // see wolfSSL_set_read_fd usage
    \endcode

    \sa wolfSSL_set_write_fd
    \sa wolfSSL_set_rfd
*/
int  wolfSSL_set_read_fd (WOLFSSL* ssl, int fd);

/*!
    \ingroup IO
    \brief OpenSSL-compatible wrapper that sets the file descriptor used for reading by the WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param rfd read file descriptor.

    _Example_
    \code
    // see wolfSSL_set_rfd usage
    \endcode

    \sa wolfSSL_set_wfd
    \sa wolfSSL_set_fd
*/
int  wolfSSL_set_rfd(WOLFSSL* ssl, int rfd);

/*!
    \ingroup CertsKeys
    \brief Registers a callback that is invoked when each TLS 1.2-or-earlier traffic secret has been derived. Useful for exporting keys for debugging or logging.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.
    \param cb  secret-derived callback.
    \param ctx opaque user pointer passed to cb.

    _Example_
    \code
    // see wolfSSL_set_secret_cb usage
    \endcode

    \sa wolfSSL_set_tls13_secret_cb
*/
int wolfSSL_set_secret_cb(WOLFSSL* ssl, TlsSecretCb cb, void* ctx);

/*!
    \ingroup openSSL
    \brief Sets the OpenSSL-compatibility security level (0-5) on the WOLFSSL session.

    \return No return value.

    \param ssl   WOLFSSL session.
    \param level security level value.

    _Example_
    \code
    // see wolfSSL_set_security_level usage
    \endcode

    \sa wolfSSL_get_security_level
*/
void   wolfSSL_set_security_level(WOLFSSL * ssl, int level);

/*!
    \ingroup Setup
    \brief Sets the shutdown state of the WOLFSSL session to opt (a bitwise combination of WOLFSSL_SENT_SHUTDOWN and WOLFSSL_RECEIVED_SHUTDOWN). Mirrors OpenSSL's SSL_set_shutdown().

    \return No return value.

    \param ssl WOLFSSL session.
    \param opt shutdown bitmask.

    _Example_
    \code
    // see wolfSSL_set_shutdown usage
    \endcode

    \sa wolfSSL_get_shutdown
    \sa wolfSSL_shutdown
*/
void wolfSSL_set_shutdown(WOLFSSL* ssl, int opt);

/*!
    \ingroup CertsKeys
    \brief Registers a callback invoked when each TLS 1.3 traffic secret has been derived. Useful for exporting keys for tools such as Wireshark.

    \return WOLFSSL_SUCCESS on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.
    \param arg secret-derived callback (Tls13SecretCb).
    \param ctx opaque user pointer.

    _Example_
    \code
    // see wolfSSL_set_tls13_secret_cb usage
    \endcode

    \sa wolfSSL_set_secret_cb
*/
int  wolfSSL_set_tls13_secret_cb(WOLFSSL* ssl, Tls13SecretCb, void*);

/*!
    \ingroup IO
    \brief Sets the SNI hostname the WOLFSSL client session will send to the server during the handshake. Mirrors OpenSSL's SSL_set_tlsext_host_name().

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl       WOLFSSL session.
    \param host_name NUL-terminated SNI hostname.

    _Example_
    \code
    // see wolfSSL_set_tlsext_host_name usage
    \endcode

    \sa wolfSSL_UseSNI
    \sa wolfSSL_get_servername
*/
int wolfSSL_set_tlsext_host_name(WOLFSSL* ssl, const char* host_name);

/*!
    \ingroup IO
    \brief OpenSSL-compatibility stub for SSL_set_tlsext_status_exts. Returns failure as wolfSSL configures stapling through dedicated calls.

    \return WOLFSSL_FAILURE.

    \param s WOLFSSL session.
    \param arg ignored.

    _Example_
    \code
    // see wolfSSL_set_tlsext_status_exts usage
    \endcode

    \sa wolfSSL_get_tlsext_status_exts
*/
long wolfSSL_set_tlsext_status_exts(WOLFSSL *s, void *arg);

/*!
    \ingroup IO
    \brief OpenSSL-compatibility stub for SSL_set_tlsext_status_ids. Returns failure as wolfSSL configures stapling through dedicated calls.

    \return WOLFSSL_FAILURE.

    \param s WOLFSSL session.
    \param arg ignored.

    _Example_
    \code
    // see wolfSSL_set_tlsext_status_ids usage
    \endcode

    \sa wolfSSL_get_tlsext_status_ids
*/
long wolfSSL_set_tlsext_status_ids(WOLFSSL *s, void *arg);

/*!
    \ingroup Setup
    \brief Sets the temporary Diffie-Hellman parameters for the WOLFSSL session (server side). Mirrors OpenSSL's SSL_set_tmp_dh().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param s  WOLFSSL session.
    \param dh DH parameters.

    _Example_
    \code
    // see wolfSSL_set_tmp_dh usage
    \endcode

    \sa wolfSSL_SetTmpDH
*/
long wolfSSL_set_tmp_dh(WOLFSSL *s, WOLFSSL_DH *dh);

/*!
    \ingroup CertsKeys
    \brief Sets the maximum depth of the certificate chain that the WOLFSSL session will accept during verification. Mirrors OpenSSL's SSL_set_verify_depth().

    \return No return value.

    \param ssl   WOLFSSL session.
    \param depth maximum chain depth.

    _Example_
    \code
    // see wolfSSL_set_verify_depth usage
    \endcode

    \sa wolfSSL_CTX_set_verify_depth
*/
void wolfSSL_set_verify_depth(WOLFSSL *ssl,int depth);

/*!
    \ingroup openSSL
    \brief Overrides the result of certificate verification on the WOLFSSL session. Mirrors OpenSSL's SSL_set_verify_result().

    \return No return value.

    \param ssl WOLFSSL session.
    \param v   verification result value (X509_V_OK or an error code).

    _Example_
    \code
    // see wolfSSL_set_verify_result usage
    \endcode

    \sa wolfSSL_get_verify_result
*/
void wolfSSL_set_verify_result(WOLFSSL* ssl, long v);

/*!
    \ingroup IO
    \brief Replaces the write BIO attached to the WOLFSSL session, taking ownership of wr. Mirrors OpenSSL's SSL_set0_wbio().

    \return No return value.

    \param ssl WOLFSSL session.
    \param wr  write BIO (may be NULL).

    _Example_
    \code
    // see wolfSSL_set_wbio usage
    \endcode

    \sa wolfSSL_set_rbio
    \sa wolfSSL_set_bio
*/
void wolfSSL_set_wbio(WOLFSSL* ssl, WOLFSSL_BIO* wr);

/*!
    \ingroup IO
    \brief OpenSSL-compatible wrapper that sets the file descriptor used for writing by the WOLFSSL session.

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param wfd write file descriptor.

    _Example_
    \code
    // see wolfSSL_set_wfd usage
    \endcode

    \sa wolfSSL_set_rfd
*/
int  wolfSSL_set_wfd(WOLFSSL* ssl, int wfd);

/*!
    \ingroup IO
    \brief Sets the file descriptor that the WOLFSSL session writes to. Mirrors OpenSSL's SSL_set_wfd().

    \return WOLFSSL_SUCCESS on success.
    \return WOLFSSL_FAILURE on error.

    \param ssl WOLFSSL session.
    \param fd  write file descriptor.

    _Example_
    \code
    // see wolfSSL_set_write_fd usage
    \endcode

    \sa wolfSSL_set_read_fd
    \sa wolfSSL_set_wfd
*/
int  wolfSSL_set_write_fd (WOLFSSL* ssl, int fd);

/*!
    \ingroup Debug
    \brief Returns a long human-readable description of the current handshake state of the WOLFSSL session. Mirrors OpenSSL's SSL_state_string_long().

    \return Constant descriptive string.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_state_string_long usage
    \endcode

    \sa wolfSSL_get_state
*/
const char* wolfSSL_state_string_long(const WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub for SSL_thread_id(). wolfSSL relies on platform-native thread identifiers; this implementation returns 0.

    \return 0.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_thread_id usage
    \endcode

    \sa wolfSSL_set_id_callback
*/
unsigned long wolfSSL_thread_id(void);

/*!
    \ingroup openSSL
    \brief Returns the total number of renegotiations completed on the WOLFSSL session, including those already cleared by wolfSSL_clear_num_renegotiations().

    \return Total renegotiation count.

    \param s WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_total_renegotiations usage
    \endcode

    \sa wolfSSL_num_renegotiations
*/
long wolfSSL_total_renegotiations(WOLFSSL *s);

/*!
    \ingroup CertsKeys
    \brief Selects a private key by label from a configured crypto-device (devId). Used with PKCS#11 or other hardware modules.

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl   WOLFSSL session.
    \param label NUL-terminated key label as known to the device.
    \param devId crypto-callback device identifier.

    _Example_
    \code
    // see wolfSSL_use_PrivateKey_Label usage
    \endcode

    \sa wolfSSL_CTX_use_PrivateKey_Label
*/
int wolfSSL_use_PrivateKey_Label(WOLFSSL* ssl, const char* label, int devId);

/*!
    \ingroup Setup
    \brief Triggers a TLS 1.3 post-handshake client authentication request on a server-side WOLFSSL session. The peer must have advertised support via wolfSSL_set_post_handshake_auth().

    \return WOLFSSL_SUCCESS on success.
    \return A negative error code on failure.

    \param ssl server-side WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_verify_client_post_handshake usage
    \endcode

    \sa wolfSSL_set_post_handshake_auth
*/
int wolfSSL_verify_client_post_handshake(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Returns the negotiated protocol version of the WOLFSSL session as an OpenSSL-style version constant (TLS1_2_VERSION, TLS1_3_VERSION, …).

    \return Protocol version constant on success.
    \return BAD_FUNC_ARG when ssl is NULL.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_version usage
    \endcode

    \sa wolfSSL_GetVersion
*/
int  wolfSSL_version(WOLFSSL* ssl);

/*!
    \ingroup IO
    \brief Returns what the WOLFSSL session is currently waiting on (read, write, x509-lookup, async-job, nothing). Mirrors OpenSSL's SSL_want().

    \return One of SSL_NOTHING, SSL_WRITING, SSL_READING, SSL_X509_LOOKUP, or SSL_ASYNC_JOB.

    \param ssl WOLFSSL session.

    _Example_
    \code
    // see wolfSSL_want usage
    \endcode

    \sa wolfSSL_get_error
*/
int wolfSSL_want(WOLFSSL* ssl);

/*!
    \ingroup openSSL
    \brief OpenSSL-compatibility stub. The function exists for ABI compatibility with builds that integrate SCEP support and performs no action.

    \return No return value.

    \param none No parameters.

    _Example_
    \code
    // see wolfSSL_wolfSCEP usage
    \endcode

*/
void wolfSSL_wolfSCEP(void);

/*!
    \ingroup IO
    \brief Creates a write-only duplicate of the WOLFSSL session so one thread can read while another writes on the same underlying connection. Mirrors OpenSSL's SSL_write_dup().

    \return Pointer to the duplicated WOLFSSL on success.
    \return NULL on error.

    \param ssl WOLFSSL session to duplicate.

    _Example_
    \code
    // see wolfSSL_write_dup usage
    \endcode

    \sa wolfSSL_new
    \sa wolfSSL_free
*/
WOLFSSL* wolfSSL_write_dup(WOLFSSL* ssl);

