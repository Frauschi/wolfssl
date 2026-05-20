/*!
    \file wolfssl/wolfcrypt/fips_test.h
*/

/*!
    \ingroup wolfCrypt

    \brief Registers an application callback that is invoked when a
    wolfCrypt FIPS Power-On Self-Test (POST) or Conditional Algorithm
    Self-Test (CAST) completes. The callback receives a success/failure
    indicator, the wolfCrypt error code on failure, and the expected
    integrity hash. This API is only available in FIPS-enabled builds.

    \return 0 on success.
    \return BAD_FUNC_ARG when an invalid callback is supplied.

    \param cbf user-supplied callback of type
    \c wolfCrypt_fips_cb. The callback signature is
    \c void(*)(int ok, int err, const char* hash). Pass NULL to clear a
    previously installed callback.

    _Example_
    \code
    static void fipsCb(int ok, int err, const char* hash)
    {
        printf("FIPS callback ok=%d err=%d hash=%s\n", ok, err,
               hash ? hash : "(none)");
    }

    if (wolfCrypt_SetCb_fips(fipsCb) != 0) {
        fprintf(stderr, "failed to register FIPS callback\n");
    }
    \endcode

    \sa wolfCrypt_GetStatus_fips
    \sa wolfCrypt_GetMode_fips
*/
int wolfCrypt_SetCb_fips(wolfCrypt_fips_cb cbf);

/*!
    \ingroup wolfCrypt

    \brief Returns the current status of the wolfCrypt FIPS module. A
    return value of 0 indicates that the Power-On Self-Test (POST) and
    integrity check have passed and the module is operational. Any
    non-zero return is the wolfCrypt error code that caused the module
    to enter the failure state. This API is only available in
    FIPS-enabled builds.

    \return 0 the FIPS module is in the operational state.
    \return <0 a negative wolfCrypt error code describing the failure.

    _Example_
    \code
    int status = wolfCrypt_GetStatus_fips();
    if (status != 0) {
        fprintf(stderr, "FIPS module not operational: %d\n", status);
    }
    \endcode

    \sa wolfCrypt_SetStatus_fips
    \sa wolfCrypt_GetMode_fips
    \sa wolfCrypt_SetCb_fips
*/
int wolfCrypt_GetStatus_fips(void);

/*!
    \ingroup wolfCrypt

    \brief Returns the current operating mode of the wolfCrypt FIPS
    module. The returned value is one of the values defined by
    \c enum FipsModeId: \c FIPS_MODE_INIT, \c FIPS_MODE_NORMAL,
    \c FIPS_MODE_DEGRADED or \c FIPS_MODE_FAILED. This API is only
    available in FIPS-enabled builds.

    \return The current FIPS mode as a value from \c enum FipsModeId.

    _Example_
    \code
    int mode = wolfCrypt_GetMode_fips();
    if (mode != FIPS_MODE_NORMAL) {
        fprintf(stderr, "wolfCrypt not in normal FIPS mode (%d)\n", mode);
    }
    \endcode

    \sa wolfCrypt_GetStatus_fips
    \sa wolfCrypt_SetCb_fips
*/
int wolfCrypt_GetMode_fips(void);

/*!
    \ingroup wolfCrypt

    \brief Returns the expected (embedded) integrity-check hash that was
    compiled into the wolfCrypt FIPS module. This is the value the
    module compares its computed hash against during the Power-On
    Self-Test. The returned string is a NUL-terminated base-16
    representation of the digest. This API is only available in
    FIPS-enabled builds.

    \return A pointer to a NUL-terminated string holding the expected
    in-core integrity hash. The buffer is statically allocated and must
    not be modified or freed.

    _Example_
    \code
    const char* expected = wolfCrypt_GetCoreHash_fips();
    printf("expected FIPS in-core hash: %s\n", expected);
    \endcode

    \sa wolfCrypt_GetRawComputedHash_fips
    \sa wolfCrypt_GetStatus_fips
*/
const char* wolfCrypt_GetCoreHash_fips(void);

/*!
    \ingroup wolfCrypt

    \brief Returns the raw integrity-check hash computed by the wolfCrypt
    FIPS module during the Power-On Self-Test. The returned string is a
    NUL-terminated base-16 representation of the digest and can be
    compared against the value returned by wolfCrypt_GetCoreHash_fips()
    when diagnosing integrity check failures. This API is only available
    in FIPS-enabled builds.

    \return A pointer to a NUL-terminated string holding the computed
    in-core integrity hash. The buffer is statically allocated and must
    not be modified or freed.

    _Example_
    \code
    const char* expected = wolfCrypt_GetCoreHash_fips();
    const char* computed = wolfCrypt_GetRawComputedHash_fips();
    if (strcmp(expected, computed) != 0) {
        fprintf(stderr, "FIPS integrity check mismatch\n");
    }
    \endcode

    \sa wolfCrypt_GetCoreHash_fips
    \sa wolfCrypt_GetStatus_fips
*/
const char* wolfCrypt_GetRawComputedHash_fips(void);

/*!
    \ingroup wolfCrypt

    \brief Forces the wolfCrypt FIPS module into a particular status,
    primarily so that operational testing can drive the module through
    failure scenarios. This API is only present when wolfSSL is built
    with \c HAVE_FORCE_FIPS_FAILURE in addition to FIPS support and is
    intended exclusively for FIPS lab testing.

    \return 0 on success.
    \return BAD_FUNC_ARG when an invalid status value is supplied.

    \param status the status code to assign. A value of 0 places the
    module back into the operational state; any negative wolfCrypt
    error code forces the module into the failed state.

    _Example_
    \code
    // Force the module into a failed state for operational testing.
    if (wolfCrypt_SetStatus_fips(-1) != 0) {
        fprintf(stderr, "unable to force FIPS failure\n");
    }
    \endcode

    \sa wolfCrypt_GetStatus_fips
    \sa wolfCrypt_SetCb_fips
*/
int wolfCrypt_SetStatus_fips(int status);

/*!
    \ingroup wolfCrypt

    \brief Runs a single wolfCrypt FIPS Conditional Algorithm Self-Test
    (CAST) identified by the given test id. The supplied id must be one
    of the values from \c enum FipsCastId (for example
    \c FIPS_CAST_AES_CBC or \c FIPS_CAST_HMAC_SHA2_256). The function
    blocks until the test completes and returns the result. This API is
    only available in FIPS-enabled builds.

    \return 0 when the requested CAST passes.
    \return <0 a negative wolfCrypt error code if the test fails or the
    id is unknown.

    \param type the CAST identifier from \c enum FipsCastId.

    _Example_
    \code
    if (wc_RunCast_fips(FIPS_CAST_AES_GCM) != 0) {
        fprintf(stderr, "AES-GCM CAST failed\n");
    }
    \endcode

    \sa wc_RunAllCast_fips
    \sa wc_GetCastStatus_fips
*/
int wc_RunCast_fips(int type);

/*!
    \ingroup wolfCrypt

    \brief Returns the cached status of a previously executed wolfCrypt
    FIPS Conditional Algorithm Self-Test (CAST). The result is one of
    the values from \c enum FipsCastStateId
    (\c FIPS_CAST_STATE_INIT, \c FIPS_CAST_STATE_PROCESSING,
    \c FIPS_CAST_STATE_SUCCESS or \c FIPS_CAST_STATE_FAILURE). This API
    is only available in FIPS-enabled builds.

    \return The CAST state as a value from \c enum FipsCastStateId.
    \return BAD_FUNC_ARG when the requested test id is out of range.

    \param type the CAST identifier from \c enum FipsCastId.

    _Example_
    \code
    int state = wc_GetCastStatus_fips(FIPS_CAST_DRBG);
    if (state != FIPS_CAST_STATE_SUCCESS) {
        fprintf(stderr, "DRBG CAST not in success state (%d)\n", state);
    }
    \endcode

    \sa wc_RunCast_fips
    \sa wc_RunAllCast_fips
*/
int wc_GetCastStatus_fips(int type);

/*!
    \ingroup wolfCrypt

    \brief Executes every wolfCrypt FIPS Conditional Algorithm Self-Test
    (CAST) registered in the build. This is a convenience wrapper that
    iterates over the values in \c enum FipsCastId and invokes
    wc_RunCast_fips() for each one. This API is only available in
    FIPS-enabled builds.

    \return 0 when every CAST passes.
    \return <0 the negative wolfCrypt error code of the first failing
    test.

    _Example_
    \code
    if (wc_RunAllCast_fips() != 0) {
        fprintf(stderr, "one or more wolfCrypt CASTs failed\n");
    }
    \endcode

    \sa wc_RunCast_fips
    \sa wc_GetCastStatus_fips
*/
int wc_RunAllCast_fips(void);
