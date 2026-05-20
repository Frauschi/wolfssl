/*!
    \file wolfssl/wolfcrypt/wolfentropy.h
*/

/*!
    \ingroup wolfEntropy

    \brief This function reads raw, unconditioned samples from the wolfSSL
    MemUse entropy source (HAVE_ENTROPY_MEMUSE) into the supplied buffer.
    It is intended for entropy source assessment and characterization
    (for example to drive NIST SP 800-90B noise source tests) rather than
    for use as a general-purpose random number generator. The number of
    raw bytes requested is given by cnt and the caller must ensure that
    raw points to a buffer of at least cnt bytes.

    \return 0 on success.
    \return BAD_FUNC_ARG if raw is NULL or cnt is less than or equal to 0.
    \return BAD_MUTEX_E if the internal entropy mutex cannot be locked.
    \return ENTROPY_RT_E or ENTROPY_APT_E on entropy health-test failure.

    \param raw pointer to a buffer that receives the raw entropy bytes.
    \param cnt number of raw entropy bytes to collect.

    _Example_
    \code
    unsigned char raw[1024];

    if (wc_Entropy_GetRawEntropy(raw, sizeof(raw)) != 0) {
        // failed to collect raw entropy
    }
    \endcode

    \sa wc_Entropy_Get
    \sa wc_Entropy_OnDemandTest
*/
int wc_Entropy_GetRawEntropy(unsigned char* raw, int cnt);

/*!
    \ingroup wolfEntropy

    \brief This function generates conditioned, full-entropy output from
    the wolfSSL MemUse entropy source (HAVE_ENTROPY_MEMUSE). The caller
    specifies how many bits of entropy are required (up to
    MAX_ENTROPY_BITS, 256) and how many bytes of output to produce. The
    implementation collects enough raw noise to satisfy the requested
    entropy strength, runs the SP 800-90B health tests on it, and
    conditions it using SHA3 before writing len bytes to entropy.

    \return 0 on success.
    \return BAD_FUNC_ARG if bits is less than or equal to 0, if entropy
    is NULL while len is non-zero, or if bits exceeds MAX_ENTROPY_BITS.
    \return BAD_MUTEX_E if the internal entropy mutex cannot be locked.
    \return ENTROPY_RT_E or ENTROPY_APT_E on entropy health-test failure.

    \param bits requested bits of entropy (must be > 0 and
    <= MAX_ENTROPY_BITS).
    \param entropy pointer to the output buffer.
    \param len number of bytes to write to entropy.

    _Example_
    \code
    unsigned char buf[32];

    if (wc_Entropy_Get(256, buf, sizeof(buf)) != 0) {
        // failed to obtain entropy
    }
    \endcode

    \sa wc_Entropy_GetRawEntropy
    \sa wc_Entropy_OnDemandTest
*/
int wc_Entropy_Get(int bits, unsigned char* entropy, word32 len);

/*!
    \ingroup wolfEntropy

    \brief This function runs the on-demand startup health test for the
    wolfSSL MemUse entropy source (HAVE_ENTROPY_MEMUSE). It executes the
    SP 800-90B Repetition Count Test (RCT) and Adaptive Proportion Test
    (APT) on freshly collected noise samples to verify that the
    underlying noise source is still operating correctly. The function
    takes no arguments.

    \return 0 on success.
    \return BAD_MUTEX_E if the internal entropy mutex cannot be locked.
    \return ENTROPY_RT_E if the Repetition Count Test fails.
    \return ENTROPY_APT_E if the Adaptive Proportion Test fails.

    _Example_
    \code
    if (wc_Entropy_OnDemandTest() != 0) {
        // entropy source health-test failure
    }
    \endcode

    \sa wc_Entropy_Get
    \sa wc_Entropy_GetRawEntropy
*/
int wc_Entropy_OnDemandTest(void);
