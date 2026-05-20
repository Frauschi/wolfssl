/*!
    \ingroup Logging

    \brief This function registers a logging callback that will be used to
    handle the wolfSSL log message. By default, if the system supports it
    fprintf() to stderr is used but by using this function anything
    can be done by the user.

    \return Success If successful this function will return 0.
    \return BAD_FUNC_ARG is the error that will be returned if a function
    pointer is not provided.

    \param log_function function to register as a logging callback.
    Function signature must follow the above prototype.

    _Example_
    \code
    int ret = 0;
    // Logging callback prototype
    void MyLoggingCallback(const int logLevel, const char* const logMessage);
    // Register the custom logging callback with wolfSSL
    ret = wolfSSL_SetLoggingCb(MyLoggingCallback);
    if (ret != 0) {
	    // failed to set logging callback
    }
    void MyLoggingCallback(const int logLevel, const char* const logMessage)
    {
	// custom logging function
    }
    \endcode

    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_Debugging_OFF
*/
int wolfSSL_SetLoggingCb(wolfSSL_Logging_cb log_function);

/*!
    \ingroup Debug

    \brief If logging has been enabled at build time this function turns on
    logging at runtime.  To enable logging at build time use --enable-debug
    or define DEBUG_WOLFSSL.

    \return 0 upon success.
    \return NOT_COMPILED_IN is the error that will be returned if logging
    isn’t enabled for this build.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_Debugging_ON();
    \endcode

    \sa wolfSSL_Debugging_OFF
    \sa wolfSSL_SetLoggingCb
*/
int  wolfSSL_Debugging_ON(void);

/*!
    \ingroup Debug

    \brief This function turns off runtime logging messages.  If they’re
    already off, no action is taken.

    \return none No returns.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_Debugging_OFF();
    \endcode

    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_SetLoggingCb
*/
void wolfSSL_Debugging_OFF(void);

/*!
    \ingroup Logging

    \brief Returns the currently registered logging callback, or NULL if none
    has been set. The callback is the function previously registered with
    wolfSSL_SetLoggingCb().

    \return A pointer to the currently registered wolfSSL_Logging_cb, or NULL
    if no callback is set.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_Logging_cb cb = wolfSSL_GetLoggingCb();
    if (cb == NULL) {
        // no callback registered
    }
    \endcode

    \sa wolfSSL_SetLoggingCb
    \sa wolfSSL_Debugging_ON
*/
wolfSSL_Logging_cb wolfSSL_GetLoggingCb(void);

/*!
    \ingroup Logging

    \brief Sets a prefix string that will be prepended to each log message
    written by wolfSSL. Pass NULL to clear the prefix. The pointer must remain
    valid for the lifetime of its use by wolfSSL (the string is not copied).
    The prefix is honored only when debug logging or cert debug logging is
    compiled in.

    \return none No returns.

    \param prefix Null-terminated string to prepend to each log message, or
    NULL to disable any previously set prefix.

    _Example_
    \code
    wolfSSL_SetLoggingPrefix("myApp");
    \endcode

    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_SetLoggingCb
*/
void wolfSSL_SetLoggingPrefix(const char* prefix);

/*!
    \ingroup Logging

    \brief Turns on runtime certificate debugging messages. Requires that
    certificate debugging support has been compiled in (DEBUG_WOLFSSL or
    WOLFSSL_DEBUG_CERTS).

    \return 0 upon success.
    \return NOT_COMPILED_IN if certificate debugging is not compiled in.

    \param none No parameters.

    _Example_
    \code
    if (wolfSSL_CertDebugging_ON() != 0) {
        // certificate debug not compiled in
    }
    \endcode

    \sa wolfSSL_CertDebugging_OFF
    \sa wolfSSL_Debugging_ON
*/
int wolfSSL_CertDebugging_ON(void);

/*!
    \ingroup Logging

    \brief Turns off runtime certificate debugging messages. Requires that
    certificate debugging support has been compiled in.

    \return 0 upon success.
    \return NOT_COMPILED_IN if certificate debugging is not compiled in.

    \param none No parameters.

    _Example_
    \code
    wolfSSL_CertDebugging_OFF();
    \endcode

    \sa wolfSSL_CertDebugging_ON
    \sa wolfSSL_Debugging_OFF
*/
int wolfSSL_CertDebugging_OFF(void);

/*!
    \ingroup Logging

    \brief Returns a string describing the configure-time arguments used to
    build the wolfSSL library. Requires that HAVE_WC_INTROSPECTION was defined
    when the library was built.

    \return A constant, null-terminated string with the configure arguments.

    \param none No parameters.

    _Example_
    \code
    const char* args = wolfSSL_configure_args();
    printf("configure: %s\n", args);
    \endcode

    \sa wolfSSL_global_cflags
*/
const char *wolfSSL_configure_args(void);

/*!
    \ingroup Logging

    \brief Returns a string describing the C compiler flags used to build the
    wolfSSL library. Requires that HAVE_WC_INTROSPECTION was defined when the
    library was built.

    \return A constant, null-terminated string with the C compiler flags.

    \param none No parameters.

    _Example_
    \code
    const char* cflags = wolfSSL_global_cflags();
    printf("CFLAGS: %s\n", cflags);
    \endcode

    \sa wolfSSL_configure_args
*/
const char *wolfSSL_global_cflags(void);

/*!
    \ingroup Logging

    \brief Sets the dynamic memory heap hint used by the internal wolfSSL
    error queue when allocating error nodes. The heap pointer is opaque and is
    interpreted by user-defined memory callbacks. Available when OPENSSL_EXTRA,
    DEBUG_WOLFSSL_VERBOSE, or HAVE_MEMCACHED is defined.

    \return 0 on success.

    \param h Heap hint pointer to pass to XMALLOC/XFREE calls for error nodes.

    _Example_
    \code
    void* heap = myHeap;
    wc_SetLoggingHeap(heap);
    \endcode

    \sa wc_ERR_remove_state
*/
int wc_SetLoggingHeap(void* h);

/*!
    \ingroup Logging

    \brief Frees the wolfSSL error queue state for the current thread. This
    clears any accumulated error nodes. Available when OPENSSL_EXTRA,
    DEBUG_WOLFSSL_VERBOSE, or HAVE_MEMCACHED is defined.

    \return 0 on success.

    \param none No parameters.

    _Example_
    \code
    wc_ERR_remove_state();
    \endcode

    \sa wc_SetLoggingHeap
    \sa wc_ERR_print_errors_fp
*/
int wc_ERR_remove_state(void);

/*!
    \ingroup Logging

    \brief Prints all accumulated errors from the wolfSSL error queue to the
    given file pointer, one error per line. The queue is consumed as it is
    printed. Available when OPENSSL_EXTRA, DEBUG_WOLFSSL_VERBOSE, or
    HAVE_MEMCACHED is defined and the build supports a filesystem.

    \return none No returns.

    \param fp Open XFILE handle to which formatted error strings are written.

    _Example_
    \code
    wc_ERR_print_errors_fp(stderr);
    \endcode

    \sa wc_ERR_remove_state
*/
void wc_ERR_print_errors_fp(XFILE fp);

/*!
    \ingroup Logging

    \brief Records the start time of a TLS handshake function for performance
    profiling. Only available when WOLFSSL_FUNC_TIME is defined. Not
    thread-safe; intended for debugging performance only and must not be used
    in production builds.

    \return none No returns.

    \param funcNum Function identifier from the wc_FuncNum enum (e.g.
    WC_FUNC_CLIENT_HELLO_SEND).

    _Example_
    \code
    WOLFSSL_START(WC_FUNC_CLIENT_HELLO_SEND);
    // ... function body ...
    WOLFSSL_END(WC_FUNC_CLIENT_HELLO_SEND);
    \endcode

    \sa WOLFSSL_END
    \sa WOLFSSL_TIME
*/
void WOLFSSL_START(int funcNum);

/*!
    \ingroup Logging

    \brief Records the end time of a TLS handshake function for performance
    profiling, accumulating elapsed time since the matching WOLFSSL_START
    call. Only available when WOLFSSL_FUNC_TIME is defined. Not thread-safe;
    debugging use only.

    \return none No returns.

    \param funcNum Function identifier from the wc_FuncNum enum (must match
    the value passed to WOLFSSL_START).

    _Example_
    \code
    WOLFSSL_START(WC_FUNC_CLIENT_HELLO_SEND);
    // ... function body ...
    WOLFSSL_END(WC_FUNC_CLIENT_HELLO_SEND);
    \endcode

    \sa WOLFSSL_START
    \sa WOLFSSL_TIME
*/
void WOLFSSL_END(int funcNum);

/*!
    \ingroup Logging

    \brief Prints a summary of average per-call timings for each profiled
    handshake function. Times reported are accumulated elapsed time divided
    by the supplied count. Only available when WOLFSSL_FUNC_TIME is defined.

    \return none No returns.

    \param count Number of handshake iterations measured; used as the divisor
    for the accumulated per-function times.

    _Example_
    \code
    WOLFSSL_TIME(iterations);
    \endcode

    \sa WOLFSSL_START
    \sa WOLFSSL_END
*/
void WOLFSSL_TIME(int count);

/*!
    \ingroup Logging

    \brief Logs a single certificate-related message at the CERT_LOG level.
    Active only when certificate debugging is compiled in (DEBUG_WOLFSSL or
    WOLFSSL_DEBUG_CERTS with XVSNPRINTF available). When disabled, this is a
    do-nothing macro.

    \return 0 on success.
    \return NOT_COMPILED_IN when certificate debugging is not compiled in.

    \param msg Null-terminated string to log.

    _Example_
    \code
    WOLFSSL_MSG_CERT("parsing peer certificate");
    \endcode

    \sa WOLFSSL_MSG_CERT_EX
    \sa WOLFSSL_MSG
*/
int WOLFSSL_MSG_CERT(const char* msg);

/*!
    \ingroup Logging

    \brief Logs a printf-style certificate-related message at the CERT_LOG
    level. Output is truncated to WOLFSSL_MSG_CERT_BUF_SZ characters. Active
    only when certificate debugging is compiled in. When disabled, this is a
    do-nothing macro.

    \return 0 on success.
    \return NOT_COMPILED_IN when certificate debugging is not compiled in.

    \param fmt printf-style format string followed by matching variadic
    arguments.

    _Example_
    \code
    WOLFSSL_MSG_CERT_EX("cert serial length = %d", serialLen);
    \endcode

    \sa WOLFSSL_MSG_CERT
    \sa WOLFSSL_MSG_EX
*/
int WOLFSSL_MSG_CERT_EX(const char* fmt, ...);

/*!
    \ingroup Logging

    \brief Logs an "entering function" trace message at the ENTER_LOG level.
    Typically called at the beginning of a function. Active only when
    DEBUG_WOLFSSL is defined and WOLFSSL_DEBUG_ERRORS_ONLY is not; otherwise
    a do-nothing macro.

    \return none No returns.

    \param msg Null-terminated function name or label.

    _Example_
    \code
    int myFunc(void)
    {
        WOLFSSL_ENTER("myFunc");
        // ...
        WOLFSSL_LEAVE("myFunc", 0);
        return 0;
    }
    \endcode

    \sa WOLFSSL_LEAVE
    \sa WOLFSSL_MSG
*/
void WOLFSSL_ENTER(const char* msg);

/*!
    \ingroup Logging

    \brief Logs a "leaving function" trace message including a return value at
    the LEAVE_LOG level. Typically called just before a function returns.
    Active only when DEBUG_WOLFSSL is defined and WOLFSSL_DEBUG_ERRORS_ONLY is
    not; otherwise a do-nothing macro.

    \return none No returns.

    \param msg Null-terminated function name or label.
    \param ret The integer return value to report.

    _Example_
    \code
    WOLFSSL_LEAVE("myFunc", ret);
    \endcode

    \sa WOLFSSL_ENTER
    \sa WOLFSSL_MSG
*/
void WOLFSSL_LEAVE(const char* msg, int ret);

/*!
    \ingroup Logging

    \brief Reports whether runtime debug logging is currently enabled. Returns
    nonzero when logging has been turned on with wolfSSL_Debugging_ON() and
    DEBUG_WOLFSSL is compiled in.

    \return 1 if debug logging is enabled.
    \return 0 if debug logging is disabled or not compiled in.

    \param none No parameters.

    _Example_
    \code
    if (WOLFSSL_IS_DEBUG_ON()) {
        // emit extra information
    }
    \endcode

    \sa wolfSSL_Debugging_ON
    \sa wolfSSL_Debugging_OFF
*/
int WOLFSSL_IS_DEBUG_ON(void);

/*!
    \ingroup Logging

    \brief Logs a single informational message at the INFO_LOG level. Active
    only when DEBUG_WOLFSSL is defined and WOLFSSL_DEBUG_ERRORS_ONLY is not;
    otherwise a do-nothing macro.

    \return none No returns.

    \param msg Null-terminated string to log.

    _Example_
    \code
    WOLFSSL_MSG("connection established");
    \endcode

    \sa WOLFSSL_MSG_EX
    \sa WOLFSSL_ERROR_MSG
*/
void WOLFSSL_MSG(const char* msg);

/*!
    \ingroup Logging

    \brief Logs a printf-style informational message at the INFO_LOG level.
    Output is truncated to WOLFSSL_MSG_EX_BUF_SZ characters. Active only when
    DEBUG_WOLFSSL is defined, WOLFSSL_DEBUG_ERRORS_ONLY is not, XVSNPRINTF is
    available, and NO_WOLFSSL_MSG_EX is not defined. Otherwise a do-nothing
    macro.

    \return none No returns.

    \param fmt printf-style format string followed by matching variadic
    arguments.

    _Example_
    \code
    WOLFSSL_MSG_EX("bytes received = %d", n);
    \endcode

    \sa WOLFSSL_MSG
*/
void WOLFSSL_MSG_EX(const char* fmt, ...);

/*!
    \ingroup Logging

    \brief Dumps a binary buffer as a hex/ASCII trace at the OTHER_LOG level.
    Active only when DEBUG_WOLFSSL is defined and WOLFSSL_DEBUG_ERRORS_ONLY is
    not; otherwise a do-nothing macro.

    \return none No returns.

    \param buffer Pointer to the byte buffer to dump.
    \param length Number of bytes in the buffer to dump.

    _Example_
    \code
    WOLFSSL_BUFFER(payload, payloadLen);
    \endcode

    \sa WOLFSSL_MSG
*/
void WOLFSSL_BUFFER(const byte* buffer, word32 length);

/*!
    \ingroup Logging

    \brief Reports an error code through the wolfSSL logging system and, when
    enabled, pushes a corresponding entry onto the OpenSSL-style error queue.
    Active when DEBUG_WOLFSSL, OPENSSL_ALL, WOLFSSL_NGINX, WOLFSSL_HAPROXY, or
    OPENSSL_EXTRA is defined; otherwise a no-op expression.

    \return none No returns.

    \param err Numeric wolfSSL or OpenSSL-compatible error code.

    _Example_
    \code
    if (rc < 0) {
        WOLFSSL_ERROR(rc);
    }
    \endcode

    \sa WOLFSSL_ERROR_MSG
    \sa wc_ERR_print_errors_fp
*/
void WOLFSSL_ERROR(int err);

/*!
    \ingroup Logging

    \brief Logs an error message string at the ERROR_LOG level. Active when
    DEBUG_WOLFSSL, OPENSSL_ALL, WOLFSSL_NGINX, WOLFSSL_HAPROXY, or
    OPENSSL_EXTRA is defined; otherwise a no-op expression.

    \return none No returns.

    \param msg Null-terminated error description.

    _Example_
    \code
    WOLFSSL_ERROR_MSG("failed to verify peer certificate");
    \endcode

    \sa WOLFSSL_ERROR
    \sa WOLFSSL_MSG
*/
void WOLFSSL_ERROR_MSG(const char* msg);

/*!
    \ingroup Logging

    \brief Reports whether stack-trace decoding of error codes is currently
    enabled. Requires WOLFSSL_DEBUG_TRACE_ERROR_CODES at build time.

    \return 1 when error code tracing is enabled.
    \return 0 when error code tracing is disabled.

    \param none No parameters.

    _Example_
    \code
    if (wc_debug_trace_error_codes_enabled()) {
        // tracing is on
    }
    \endcode

    \sa wc_debug_trace_error_codes_set
    \sa wc_backtrace_set_fp
*/
int wc_debug_trace_error_codes_enabled(void);

/*!
    \ingroup Logging

    \brief Enables or disables stack-trace decoding of error codes at runtime.
    Requires WOLFSSL_DEBUG_TRACE_ERROR_CODES at build time.

    \return The previous tracing state (1 if it was enabled, 0 if disabled).

    \param state Nonzero to enable error code tracing, 0 to disable it.

    _Example_
    \code
    int prev = wc_debug_trace_error_codes_set(1);
    \endcode

    \sa wc_debug_trace_error_codes_enabled
    \sa wc_backtrace_set_fp
*/
int wc_debug_trace_error_codes_set(int state);

/*!
    \ingroup Logging

    \brief Sets the file pointer used by wolfSSL to emit backtrace output for
    decoded error codes, returning the previous file pointer. Requires
    WOLFSSL_DEBUG_TRACE_ERROR_CODES and XFILE support at build time.

    \return The previously configured XFILE backtrace destination.

    \param new_fp Open XFILE handle that future backtrace output will be
    written to.

    _Example_
    \code
    XFILE prev = wc_backtrace_set_fp(stderr);
    \endcode

    \sa wc_debug_trace_error_codes_enabled
    \sa wc_debug_trace_error_codes_set
*/
XFILE wc_backtrace_set_fp(XFILE new_fp);

/*!
    \ingroup Logging

    \brief Arduino-only logging helper that writes a string to the Arduino
    serial console. Implemented in the Arduino-specific wolfssl.h shim.
    Available only when ARDUINO is defined.

    \return 0 on success.
    \return Negative value on failure.

    \param s Null-terminated string to print on the serial console.

    _Example_
    \code
    wolfSSL_Arduino_Serial_Print("wolfSSL initialized");
    \endcode

    \sa wolfSSL_SetLoggingCb
*/
int wolfSSL_Arduino_Serial_Print(const char* const s);
