#include "so_scheduler.h"
#include <stdbool.h>

static bool initialized = false;

/*
 * creates and initializes scheduler
 * + time quantum for each thread
 * + number of IO devices supported
 * returns: 0 on success or negative on error
 */
DECL_PREFIX int so_init(unsigned int time_quantum, unsigned int io)
{
    if (time_quantum == 0 || io > SO_MAX_NUM_EVENTS || initialized) {
        return -1;
    }

    initialized = true;

    return 0;
}

/*
 * creates a new so_task_t and runs it according to the scheduler
 * + handler function
 * + priority
 * returns: tid of the new task if successful or INVALID_TID
 */
DECL_PREFIX tid_t so_fork(so_handler *func, unsigned int priority)
{
    return 0;
}

/*
 * waits for an IO device
 * + device index
 * returns: -1 if the device does not exist or 0 on success
 */
DECL_PREFIX int so_wait(unsigned int io)
{
    return 0;
}

/*
 * signals an IO device
 * + device index
 * return the number of tasks woke or -1 on error
 */
DECL_PREFIX int so_signal(unsigned int io)
{
    return 0;
}

/*
 * does whatever operation
 */
DECL_PREFIX void so_exec(void)
{
    return;
}

/*
 * destroys a scheduler
 */
DECL_PREFIX void so_end(void)
{
    initialized = false;
}
