#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/jiffies.h>

#include "module.h"
#include "timer.h"
#include "monitor.h"
#include "types.h"
#include "stats.h"

#define INTERVAL_MS 10000  // 10 seconds interval

extern sct_monitor_t sct_monitor;

static struct timer_list sct_timer;

static int reset_monitor_timer(void);

/**
 * @brief Monitor timer callback function
 * 
 * @param t Pointer to the timer_list structure
 */
void monitor_timer_callback(struct timer_list *t) {

    printk(KERN_INFO "%s: Monitor timer callback triggered\n", MODULE_NAME);

    // Reset invocation count
    printk(KERN_INFO "%s: Reset syscall invocation count to 0\n", MODULE_NAME);
    __sync_lock_test_and_set(&sct_monitor.invoks, 0);

    // Reset statistics for the new interval
    printk(KERN_INFO "%s: Computing and resetting statistics for the new interval\n", MODULE_NAME);
    compute_stats_blocked();
    printk(KERN_INFO "%s: Peak blocked threads in last interval: %llu\n", MODULE_NAME, get_peakw_blocked());
    printk(KERN_INFO "%s: Average blocked threads per interval: %llu\n", MODULE_NAME, get_avgw_blocked());

    // Wake up the wait queue to allow more syscalls
    printk(KERN_INFO "%s: Waking up wait queue\n", MODULE_NAME);
    wake_up_interruptible(&sct_monitor.wqueue);

    // Reset the timer for the next interval
    printk(KERN_INFO "%s: Resetting monitor timer for next interval\n", MODULE_NAME);
    if(reset_monitor_timer() != 0) {
        printk(KERN_ERR "%s: Failed to reset monitor timer\n", MODULE_NAME);
    }
}

/**
 * @brief Starts the monitor timer
 * 
 * @return int 0 on success, negative error code on failure
 */
int start_monitor_timer(void) {
    printk(KERN_INFO "%s: Starting monitor timer\n", MODULE_NAME);
    // Setup timer
    timer_setup(&sct_timer, monitor_timer_callback, 0);
    // First start after 1 second
    return reset_monitor_timer();
}

/**
 * @brief Stops the monitor timer
 * 
 * @return int 0 on success, negative error code on failure
 */
int stop_monitor_timer(void) {
    printk(KERN_INFO "%s: Stopping monitor timer\n", MODULE_NAME);
    return del_timer_sync(&sct_timer);
}

/**
 * @brief Sets the monitor timer to expire in 1 second
 * 
 * @return int 0 on success, negative error code on failure
 */
static int reset_monitor_timer(void) {
    printk(KERN_INFO "%s: Resetting monitor timer\n", MODULE_NAME);
    return mod_timer(&sct_timer, jiffies + msecs_to_jiffies(INTERVAL_MS));
}