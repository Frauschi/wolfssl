/*!
    \file wolfssl/wolfcrypt/wolfevent.h
*/

/*!
    \ingroup wolfEvent

    \brief This function initializes a WOLF_EVENT structure. The event
    is zeroed and its type and context fields are populated. The event
    must not already be in the WOLF_EVENT_STATE_PENDING state. WOLF_EVENT
    is the lower-level event abstraction used by the wolfSSL async
    subsystem to track in-flight asynchronous crypto requests.

    \return 0 on success.
    \return BAD_FUNC_ARG if event is NULL.
    \return BAD_COND_E if the event is currently in the
    WOLF_EVENT_STATE_PENDING state.

    \param event pointer to the WOLF_EVENT structure to initialize.
    \param type event type (e.g. WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT).
    \param context caller-defined context pointer associated with the
    event (e.g. a WC_ASYNC_DEV* or WOLFSSL*).

    _Example_
    \code
    WOLF_EVENT event;

    if (wolfEvent_Init(&event, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT,
            asyncDev) != 0) {
        // failed to initialize event
    }
    \endcode

    \sa wolfEvent_Poll
    \sa wolfEventQueue_Push
*/
int wolfEvent_Init(WOLF_EVENT* event, WOLF_EVENT_TYPE type, void* context);

/*!
    \ingroup wolfEvent

    \brief This function polls a single WOLF_EVENT to check whether the
    associated asynchronous operation has completed. For async crypto
    events, this dispatches into the underlying hardware/software async
    driver to advance the request's state.

    \return 0 on success.
    \return BAD_COND_E if no handler is registered for the event type.
    \return Other negative values forwarded from the async driver on
    failure.

    \param event pointer to the WOLF_EVENT to poll.
    \param flags poll flags (e.g. WOLF_POLL_FLAG_CHECK_HW).

    _Example_
    \code
    WOLF_EVENT event;

    wolfEvent_Init(&event, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT, asyncDev);
    // ... submit async work ...
    if (wolfEvent_Poll(&event, WOLF_POLL_FLAG_CHECK_HW) < 0) {
        // poll failed
    }
    \endcode

    \sa wolfEvent_Init
    \sa wolfEventQueue_Poll
*/
int wolfEvent_Poll(WOLF_EVENT* event, WOLF_EVENT_FLAG flags);

/*!
    \ingroup wolfEvent

    \brief This function initializes a WOLF_EVENT_QUEUE structure. The
    head, tail, and count fields are cleared and, when not built
    SINGLE_THREADED, the queue's mutex is initialized. The queue must
    later be released with wolfEventQueue_Free.

    \return 0 on success.
    \return BAD_FUNC_ARG if queue is NULL.
    \return BAD_MUTEX_E or other negative values on mutex init failure.

    \param queue pointer to the WOLF_EVENT_QUEUE structure to initialize.

    _Example_
    \code
    WOLF_EVENT_QUEUE queue;

    if (wolfEventQueue_Init(&queue) != 0) {
        // failed to initialize queue
    }
    \endcode

    \sa wolfEventQueue_Free
    \sa wolfEventQueue_Push
    \sa wolfEventQueue_Poll
*/
int wolfEventQueue_Init(WOLF_EVENT_QUEUE* queue);

/*!
    \ingroup wolfEvent

    \brief This function pushes a WOLF_EVENT onto the tail of a
    WOLF_EVENT_QUEUE. The queue's lock is acquired (when not built
    SINGLE_THREADED) for the duration of the operation so this routine
    is safe to call from multiple threads.

    \return 0 on success.
    \return BAD_FUNC_ARG if queue or event is NULL.
    \return Other negative values forwarded from the mutex lock.

    \param queue pointer to the queue to push onto.
    \param event pointer to the event to push.

    _Example_
    \code
    WOLF_EVENT_QUEUE queue;
    WOLF_EVENT event;

    wolfEventQueue_Init(&queue);
    wolfEvent_Init(&event, WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT, asyncDev);
    if (wolfEventQueue_Push(&queue, &event) != 0) {
        // failed to push event
    }
    \endcode

    \sa wolfEventQueue_Pop
    \sa wolfEventQueue_Add
    \sa wolfEventQueue_Poll
*/
int wolfEventQueue_Push(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);

/*!
    \ingroup wolfEvent

    \brief This function pops the first WOLF_EVENT off the head of a
    WOLF_EVENT_QUEUE and returns it through the event output pointer.
    The queue's lock is acquired (when not built SINGLE_THREADED) for
    the duration of the operation. If the queue is empty, *event is set
    to NULL and 0 is returned.

    \return 0 on success (including the empty-queue case).
    \return BAD_FUNC_ARG if queue or event is NULL.
    \return Other negative values forwarded from the mutex lock.

    \param queue pointer to the queue to pop from.
    \param event output pointer that receives the popped event (or NULL
    if the queue is empty).

    _Example_
    \code
    WOLF_EVENT_QUEUE queue;
    WOLF_EVENT* popped = NULL;

    if (wolfEventQueue_Pop(&queue, &popped) == 0 && popped != NULL) {
        // process popped event
    }
    \endcode

    \sa wolfEventQueue_Push
    \sa wolfEventQueue_Remove
*/
int wolfEventQueue_Pop(WOLF_EVENT_QUEUE* queue, WOLF_EVENT** event);

/*!
    \ingroup wolfEvent

    \brief This function returns the current number of events in the
    WOLF_EVENT_QUEUE. The queue's lock is acquired (when not built
    SINGLE_THREADED) for the duration of the operation.

    \return Non-negative event count on success.
    \return BAD_FUNC_ARG if queue is NULL.
    \return Other negative values forwarded from the mutex lock.

    \param queue pointer to the queue whose events are counted.

    _Example_
    \code
    WOLF_EVENT_QUEUE queue;
    int count = wolfEventQueue_Count(&queue);
    if (count < 0) {
        // error
    }
    \endcode

    \sa wolfEventQueue_Push
    \sa wolfEventQueue_Pop
*/
int wolfEventQueue_Count(WOLF_EVENT_QUEUE* queue);

/*!
    \ingroup wolfEvent

    \brief This function releases the resources associated with a
    WOLF_EVENT_QUEUE. When not built SINGLE_THREADED, the queue's mutex
    is destroyed. The queue's events are not freed by this function;
    the caller is responsible for managing event memory.

    \return none No return value.

    \param queue pointer to the queue to free (may be NULL).

    _Example_
    \code
    WOLF_EVENT_QUEUE queue;
    wolfEventQueue_Init(&queue);
    // ... use queue ...
    wolfEventQueue_Free(&queue);
    \endcode

    \sa wolfEventQueue_Init
*/
void wolfEventQueue_Free(WOLF_EVENT_QUEUE* queue);

/*!
    \ingroup wolfEvent

    \brief This function appends a WOLF_EVENT to the tail of a
    WOLF_EVENT_QUEUE without acquiring the queue's lock. The caller is
    responsible for ensuring the queue is already locked (or that the
    build is SINGLE_THREADED). For thread-safe insertion use
    wolfEventQueue_Push instead.

    \return 0 on success.
    \return BAD_FUNC_ARG if queue or event is NULL.

    \param queue pointer to the (already-locked) queue.
    \param event pointer to the event to add.

    _Example_
    \code
    // queue->lock must already be held by caller
    if (wolfEventQueue_Add(queue, &event) != 0) {
        // failed to add event
    }
    \endcode

    \sa wolfEventQueue_Push
    \sa wolfEventQueue_Remove
*/
int wolfEventQueue_Add(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);

/*!
    \ingroup wolfEvent

    \brief This function removes a WOLF_EVENT from a WOLF_EVENT_QUEUE
    without acquiring the queue's lock. The caller is responsible for
    ensuring the queue is already locked (or that the build is
    SINGLE_THREADED). The event's next/prev links are unlinked and the
    queue's count is decremented.

    \return 0 on success.
    \return BAD_FUNC_ARG if queue or event is NULL.

    \param queue pointer to the (already-locked) queue.
    \param event pointer to the event to remove.

    _Example_
    \code
    // queue->lock must already be held by caller
    if (wolfEventQueue_Remove(queue, &event) != 0) {
        // failed to remove event
    }
    \endcode

    \sa wolfEventQueue_Add
    \sa wolfEventQueue_Pop
*/
int wolfEventQueue_Remove(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);
