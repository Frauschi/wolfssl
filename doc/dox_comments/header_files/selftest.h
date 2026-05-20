/*!
    \file wolfssl/wolfcrypt/selftest.h
*/

/*!
    \ingroup wolfCrypt

    \brief Returns the CAVP (Cryptographic Algorithm Validation Program)
    self-test version string for the wolfCrypt FIPS module. This API is
    only available when wolfSSL is built with the FIPS self-test feature
    enabled (HAVE_SELFTEST).

    \return A pointer to a NUL-terminated string identifying the CAVP
    self-test version. The returned string is statically allocated and
    must not be modified or freed by the caller.

    _Example_
    \code
    const char* ver = wolfCrypt_GetVersion_CAVP_selftest();
    printf("wolfCrypt CAVP self-test version: %s\n", ver);
    \endcode

    \sa wolfCrypt_SelfTest
*/
const char* wolfCrypt_GetVersion_CAVP_selftest(void);

/*!
    \ingroup wolfCrypt

    \brief Runs the wolfCrypt CAVP Known Answer Tests (KATs). This is the
    public entry point used to exercise the algorithm self-tests required
    for FIPS/CAVP validation. The function executes the full battery of
    known answer tests for the algorithms compiled into the library and
    returns success only when every test passes. This API is only
    available when wolfSSL is built with HAVE_SELFTEST.

    \return 0 on successful completion of all known answer tests.
    \return <0 a negative wolfCrypt error code indicating which test
    failed.

    _Example_
    \code
    int ret = wolfCrypt_SelfTest();
    if (ret != 0) {
        fprintf(stderr, "wolfCrypt self test failed: %d\n", ret);
        return -1;
    }
    \endcode

    \sa wolfCrypt_GetVersion_CAVP_selftest
*/
int wolfCrypt_SelfTest(void);
