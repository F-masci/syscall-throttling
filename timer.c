/**
 * @file timer.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the monitor timer for the system call
 *        throttling module. The timer periodically resets the syscall
 *        invocation count, computes statistics, and wakes up the wait queue.
 * 
 * @version 1.0
 * @date 2026-01-21
 * 
 */

#include <linux/timer.h>
#include <linux/jiffies.h>

#include "timer.h"
#include "monitor.h"
#include "stats.h"

static struct timer_list timer;

/**
 * @brief Monitor timer callback function. Resets invocation count, computes statistics, and wakes up wait queue.
 * The timer is then restarted for the next interval.
 * 
 * The timer is actived by module initialization, so only 1 instance exists.
 * 
 * @param t Pointer to the timer_list structure
 */
void monitor_timer_callback(struct timer_list *t) {

    PR_DEBUG("Monitor timer callback triggered\n");

    // Reset invocation count
    reset_monitor_invoks();
    PR_DEBUG("Reset syscall invocation count to 0\n");

    // Reset statistics for the new interval
    compute_stats_blocked();
    PR_DEBUG("Computed and reset statistics for the new window\n");

    // Wake up the wait queue to notify waiting threads
    wake_monitor_queue();
    PR_DEBUG("Woke up monitor wait queue\n");

    // Reset the timer for the next window
    PR_DEBUG("Resetting monitor timer for next window\n");
    if(start_monitor_timer() != 0) {
        PR_ERROR("Failed to reset monitor timer\n");
    }
}

/**
 * @brief Initializes the monitor timer
 * 
 * @return int 0 on success, negative error code on failure
 */
void setup_monitor_timer(void) {
    PR_DEBUG("Monitor timer initializing\n");
    timer_setup(&timer, monitor_timer_callback, 0);
}

/**
 * @brief Starts the monitor timer
 * 
 * @return int 0 on success, negative error code on failure
 */
int start_monitor_timer(void) {
    PR_DEBUG("Starting monitor timer with interval %d ms\n", INTERVAL_MS);
    mod_timer(&timer, jiffies + msecs_to_jiffies(INTERVAL_MS));
    return 0;
}

/**
 * @brief Stops the monitor timer
 * 
 * @return int 0 on success, negative error code on failure
 */
int stop_monitor_timer(void) {
    PR_DEBUG("Stopping monitor timer\n");
    del_timer_sync(&timer);
    return 0;
}