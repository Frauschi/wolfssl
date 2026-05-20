/*!
    \file wolfssl/wolfcrypt/async.h
*/

/*!
    \ingroup Async

    \brief This function initializes the underlying asynchronous crypto
    hardware (e.g. Cavium Nitrox, Intel QuickAssist) used by wolfSSL when
    built with WOLFSSL_ASYNC_CRYPT. It opens any required device handles
    and prepares the internal driver state so subsequent
    wolfAsync_DevOpen calls succeed. It should be called once at startup
    before any async crypto operations are issued.

    \return 0 on success.
    \return Negative driver-specific error code on failure.

    _Example_
    \code
    if (wolfAsync_HardwareStart() != 0) {
        // failed to start async hardware
    }
    \endcode

    \sa wolfAsync_HardwareStop
    \sa wolfAsync_DevOpen
*/
int wolfAsync_HardwareStart(void);

/*!
    \ingroup Async

    \brief This function shuts down the asynchronous crypto hardware
    previously brought up by wolfAsync_HardwareStart. It releases any
    driver-level resources and should be called once at program
    teardown after all async devices have been closed.

    \return none No return value.

    _Example_
    \code
    wolfAsync_HardwareStart();
    // ... perform async crypto ...
    wolfAsync_HardwareStop();
    \endcode

    \sa wolfAsync_HardwareStart
*/
void wolfAsync_HardwareStop(void);

/*!
    \ingroup Async

    \brief This function opens an asynchronous crypto device and returns
    a device id through devId. The id can later be passed to crypto
    init routines (for example wc_AesInit, wc_ecc_init_ex) to associate
    a crypto context with the async device. This must be called after
    wolfAsync_HardwareStart.

    \return 0 on success.
    \return Negative driver-specific error code on failure.

    \param devId output pointer that receives the assigned async
    device id.

    _Example_
    \code
    int devId = INVALID_DEVID;
    if (wolfAsync_DevOpen(&devId) != 0) {
        // failed to open async device
    }
    \endcode

    \sa wolfAsync_DevClose
    \sa wolfAsync_DevOpenThread
    \sa wolfAsync_DevCtxInit
*/
int wolfAsync_DevOpen(int *devId);

/*!
    \ingroup Async

    \brief This function opens an asynchronous crypto device and binds
    it to the supplied thread id, returning the assigned device id
    through devId. Use this in multi-threaded async setups where each
    worker thread requires its own dedicated async device handle.

    \return 0 on success.
    \return Negative driver-specific error code on failure.

    \param devId output pointer that receives the assigned async
    device id.
    \param threadId platform-specific thread id (e.g. a pthread_t*) to
    bind to the device.

    _Example_
    \code
    pthread_t tid = pthread_self();
    int devId = INVALID_DEVID;
    if (wolfAsync_DevOpenThread(&devId, &tid) != 0) {
        // failed to open async device for thread
    }
    \endcode

    \sa wolfAsync_DevOpen
    \sa wolfAsync_DevClose
*/
int wolfAsync_DevOpenThread(int *devId, void* threadId);

/*!
    \ingroup Async

    \brief This function releases the resources held by a WC_ASYNC_DEV
    crypto-context structure. It is called from each algorithm-specific
    free routine (for example wc_AesFree, wc_ecc_free) when the
    associated crypto object is destroyed. The marker identifies which
    algorithm owns the context.

    \return none No return value.

    \param asyncDev pointer to the WC_ASYNC_DEV to release.
    \param marker async marker identifying the owning algorithm (e.g.
    WOLFSSL_ASYNC_MARKER_AES).

    _Example_
    \code
    WC_ASYNC_DEV* asyncDev = ...;
    wolfAsync_DevCtxFree(asyncDev, WOLFSSL_ASYNC_MARKER_AES);
    \endcode

    \sa wolfAsync_DevOpen
*/
void wolfAsync_DevCtxFree(WC_ASYNC_DEV* asyncDev, word32 marker);

/*!
    \ingroup Async

    \brief This function closes an async crypto device previously
    opened with wolfAsync_DevOpen or wolfAsync_DevOpenThread. The
    device id is invalidated. Should be called once per matching open
    call before wolfAsync_HardwareStop.

    \return none No return value.

    \param devId pointer to the async device id to close. On return
    *devId is set to INVALID_DEVID.

    _Example_
    \code
    int devId = INVALID_DEVID;
    wolfAsync_DevOpen(&devId);
    // ... use device ...
    wolfAsync_DevClose(&devId);
    \endcode

    \sa wolfAsync_DevOpen
    \sa wolfAsync_HardwareStop
*/
void wolfAsync_DevClose(int *devId);

/*!
    \ingroup Async

    \brief This function makes a shallow copy of one WC_ASYNC_DEV into
    another. It is used internally by crypto context copy routines
    (e.g. when duplicating an Aes or ecc_key structure) so that the
    copy inherits the source's async marker, device id, and driver
    state.

    \return 0 on success.
    \return BAD_FUNC_ARG if src or dst is NULL.

    \param src pointer to the source async device context.
    \param dst pointer to the destination async device context.

    _Example_
    \code
    WC_ASYNC_DEV src, dst;
    // ... initialize src ...
    if (wolfAsync_DevCopy(&src, &dst) != 0) {
        // copy failed
    }
    \endcode

    \sa wolfAsync_DevCtxFree
*/
int wolfAsync_DevCopy(WC_ASYNC_DEV* src, WC_ASYNC_DEV* dst);

/*!
    \ingroup Async

    \brief This function waits synchronously for a single asynchronous
    WOLF_EVENT to complete. It blocks the caller until the underlying
    hardware/software driver signals that the request finished and
    returns the request's final result code through the event.

    \return 0 on success (event completed).
    \return Negative driver-specific or BAD_FUNC_ARG error code on
    failure.

    \param event pointer to the WOLF_EVENT to wait on.

    _Example_
    \code
    WOLF_EVENT event;
    // ... submit async request that populates event ...
    if (wolfAsync_EventWait(&event) != 0) {
        // wait failed or operation returned an error
    }
    \endcode

    \sa wolfEvent_Poll
    \sa wc_AsyncWait
*/
int wolfAsync_EventWait(WOLF_EVENT* event);

/*!
    \ingroup Async

    \brief This function suspends the calling thread for the supplied
    number of milliseconds. It is a thin portability wrapper used by
    the async polling loops to yield CPU while waiting for hardware
    completion.

    \return 0 on success.
    \return Negative value on platform sleep failure.

    \param ms number of milliseconds to sleep.

    _Example_
    \code
    if (wc_AsyncSleep(10) != 0) {
        // sleep failed
    }
    \endcode

    \sa wc_AsyncWait
*/
int wc_AsyncSleep(word32 ms);

/*!
    \ingroup Async

    \brief This function initializes a WC_ASYNC_DEV for use by the
    software-async simulator (WOLFSSL_ASYNC_CRYPT_SW). The supplied
    type is one of the WC_ASYNC_SW_TYPE enum values and identifies
    which kind of crypto operation will be deferred. This is used
    internally by the async crypto code paths.

    \return 0 on success.
    \return BAD_FUNC_ARG if dev is NULL.

    \param dev pointer to the WC_ASYNC_DEV to initialize.
    \param type one of the WC_ASYNC_SW_TYPE values (e.g.
    ASYNC_SW_ECC_SIGN).

    _Example_
    \code
    WC_ASYNC_DEV dev;
    if (wc_AsyncSwInit(&dev, ASYNC_SW_ECC_SIGN) != 0) {
        // failed to init async sw context
    }
    \endcode

    \sa wolfAsync_DevCtxFree
*/
int wc_AsyncSwInit(WC_ASYNC_DEV* dev, int type);

/*!
    \ingroup Async

    \brief This function returns the number of logical CPUs available
    to the process. It is used by async worker-thread setup code when
    deciding how many threads to spawn and which cores to bind them
    to.

    \return Non-negative count of logical CPUs on success.
    \return Negative value on platform error.

    _Example_
    \code
    int n = wc_AsyncGetNumberOfCpus();
    if (n > 0) {
        // spawn n worker threads
    }
    \endcode

    \sa wc_AsyncThreadBind
*/
int wc_AsyncGetNumberOfCpus(void);

/*!
    \ingroup Async

    \brief This function binds an existing pthread to a specific
    logical CPU core via the pthread_setaffinity_np mechanism. It is
    typically used in async worker pools to pin a worker thread to a
    dedicated core for performance and cache locality.

    \return 0 on success.
    \return Negative value on failure (BAD_FUNC_ARG or platform error).

    \param thread pointer to the pthread to bind.
    \param logicalCore zero-based logical core index to bind to.

    _Example_
    \code
    pthread_t worker;
    wc_AsyncThreadCreate(&worker, asyncWorkerFn, NULL);
    if (wc_AsyncThreadBind(&worker, 0) != 0) {
        // bind failed
    }
    \endcode

    \sa wc_AsyncGetNumberOfCpus
    \sa wc_AsyncThreadStart
*/
int wc_AsyncThreadBind(pthread_t *thread, word32 logicalCore);

/*!
    \ingroup Async

    \brief This function starts (resumes) a pthread that was created
    with a suspended-start policy. It is a thin wrapper that calls
    pthread_kill with SIGCONT (or equivalent) so that worker threads
    that were created paused can begin executing on demand.

    \return 0 on success.
    \return Negative value on failure.

    \param thread pointer to the pthread to start.

    _Example_
    \code
    pthread_t worker;
    wc_AsyncThreadCreate(&worker, asyncWorkerFn, NULL);
    wc_AsyncThreadStart(&worker);
    \endcode

    \sa wc_AsyncThreadKill
    \sa wc_AsyncThreadJoin
*/
int wc_AsyncThreadStart(pthread_t *thread);

/*!
    \ingroup Async

    \brief This function terminates the calling pthread, optionally
    passing a return value back to a future pthread_join. It is a thin
    wrapper around pthread_exit used by async worker-thread routines.

    \return none No return value (does not return).

    \param retval value returned to pthread_join (may be NULL).

    _Example_
    \code
    void* asyncWorkerFn(void* arg)
    {
        // ... do async work ...
        wc_AsyncThreadExit(NULL);
        return NULL;
    }
    \endcode

    \sa wc_AsyncThreadJoin
*/
void wc_AsyncThreadExit(void *retval);

/*!
    \ingroup Async

    \brief This function cancels (kills) the specified pthread by
    sending it a cancellation request. It is a thin wrapper around
    pthread_cancel used to force-terminate async worker threads
    during shutdown.

    \return 0 on success.
    \return Negative value on failure.

    \param thread pointer to the pthread to kill.

    _Example_
    \code
    pthread_t worker;
    wc_AsyncThreadCreate(&worker, asyncWorkerFn, NULL);
    // ... at shutdown ...
    wc_AsyncThreadKill(&worker);
    \endcode

    \sa wc_AsyncThreadExit
    \sa wc_AsyncThreadJoin
*/
int wc_AsyncThreadKill(pthread_t *thread);

/*!
    \ingroup Async

    \brief This function sets the scheduling priority of the supplied
    pthread (keeping its current scheduling policy). It is used by
    async worker pools to tune worker priority relative to the rest
    of the application.

    \return 0 on success.
    \return Negative value on failure.

    \param thread pointer to the pthread whose priority is updated.
    \param priority new scheduling priority (interpretation depends on
    the thread's current SCHED_* policy).

    _Example_
    \code
    pthread_t worker;
    wc_AsyncThreadCreate(&worker, asyncWorkerFn, NULL);
    wc_AsyncThreadPrioritySet(&worker, 10);
    \endcode

    \sa wc_AsyncThreadStart
    \sa wc_AsyncThreadBind
*/
int wc_AsyncThreadPrioritySet(pthread_t *thread, word32 priority);

/*!
    \ingroup Async

    \brief This function waits for the supplied pthread to terminate
    and reaps it. It is a thin wrapper around pthread_join used by
    async worker-pool teardown to ensure all workers have exited
    cleanly before resources are released.

    \return 0 on success.
    \return Negative value on failure.

    \param thread pointer to the pthread to join.

    _Example_
    \code
    pthread_t worker;
    wc_AsyncThreadCreate(&worker, asyncWorkerFn, NULL);
    // ... signal worker to exit ...
    wc_AsyncThreadJoin(&worker);
    \endcode

    \sa wc_AsyncThreadExit
    \sa wc_AsyncThreadKill
*/
int wc_AsyncThreadJoin(pthread_t *thread);

/*!
    \ingroup Async

    \brief This function yields execution of the calling thread so
    that other ready threads may run. It is a thin wrapper around
    sched_yield used inside async polling loops.

    \return none No return value.

    _Example_
    \code
    while (!work_available) {
        wc_AsyncThreadYield();
    }
    \endcode

    \sa wc_AsyncSleep
*/
void wc_AsyncThreadYield(void);

/*!
    \ingroup Async

    \brief This function returns the pthread id of the calling thread.
    It is a thin wrapper around pthread_self used by async event
    bookkeeping to record which thread submitted a request.

    \return pthread_t id of the calling thread.

    _Example_
    \code
    pthread_t me = wc_AsyncThreadId();
    \endcode

    \sa wc_AsyncThreadCreate
*/
pthread_t wc_AsyncThreadId(void);
