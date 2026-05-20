/*!
    \ingroup Error

    \brief This function stores the error string for a particular error code
    in the given buffer.

    \return none No returns.

    \param error error code for which to get the string
    \param buffer buffer in which to store the error string. Buffer should be
    at least WOLFSSL_MAX_ERROR_SZ (80 bytes) long

    _Example_
    \code
    char errorMsg[WOLFSSL_MAX_ERROR_SZ];
    int err = wc_some_function();

    if( err != 0) { // error occurred
    	wc_ErrorString(err, errorMsg);
    }
    \endcode

    \sa wc_GetErrorString
*/
void wc_ErrorString(int err, char* buff);

/*!
    \ingroup Error

    \brief This function returns the error string for a particular error code.

    \return string Returns the error string for an error code as a
    string literal.

    \param error error code for which to get the string

    _Example_
    \code
    char * errorMsg;
    int err = wc_some_function();

    if( err != 0) { // error occurred
    	errorMsg = wc_GetErrorString(err);
    }
    \endcode

    \sa wc_ErrorString
*/
const char* wc_GetErrorString(int error);

/*!
    \ingroup Error

    \brief Renders a backtrace of the current call stack to the wolfSSL
    debug log output. This helper is used to annotate error returns with
    where they originated, and is wired into the
    WOLFSSL_DEBUG_BACKTRACE_RENDER_CLAUSE macro. Behavior depends on the
    build: in the Linux kernel module port the function calls
    dump_stack(); in user space it uses libbacktrace to print symbolic
    frames to stderr. The function is only available when wolfSSL is
    built with WOLFSSL_DEBUG_BACKTRACE_ERROR_CODES enabled.

    \return 0 Returned on success.
    \return non-zero Returned if the backtrace could not be produced.

    _Example_
    \code
    if (wc_some_function() < 0) {
        wc_backtrace_render();
    }
    \endcode

    \sa wc_ErrorString
    \sa wc_GetErrorString
*/
int wc_backtrace_render(void);
