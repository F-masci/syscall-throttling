#include "sct.h"
#include "monitor.h"
#include "filter.h"
#include "timer.h"
#include "hook.h"
#include "dev.h"

// Module information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Masci: francescomasci@outlook.com");
MODULE_DESCRIPTION("System Call Throttling");
MODULE_VERSION("1.0");

/**
 * @brief Initialize the system call throttling module
 * 
 * @return int 
 */
static int __init sct_init(void) {

    int ret;

    PR_INFO("Initializing module...\n");

    /**
     * The correct initialization order is:
     * - monitor
     * - filter
     * - timer
     * - hooks
     * - device
     */

    /* ---- MONITOR ---- */

    // Initialize monitor structure
    setup_monitor();
    PR_INFO("Monitor structures initialized successfully\n");

    /* ---- FILTER ---- */

    // Initialize filter structure
    setup_monitor_filter();
    PR_INFO("Filter structures initialized successfully\n");

    /* ---- TIMER ---- */

    // Setup monitor timer
    setup_monitor_timer();
    PR_INFO("Monitor timer setup completed successfully\n");

    // Start monitor timer
    if(start_monitor_timer()) {
        printk(KERN_ERR "%s: Failed to start monitor timer\n", MODULE_NAME);
        goto err_timer;
    }
    PR_INFO("Monitor timer started successfully\n");

    /* ---- HOOKS ---- */

    ret = setup_syscall_hooks(SYSCALL_TABLE_SIZE);
    if(ret < 0) {
        PR_ERROR("Syscall hooks setup failed with %d\n", ret);
        goto err_hooks;
    }
    PR_INFO("Syscall hooks setup completed successfully\n");

    /* ---- DEVICE ---- */

    ret = setup_monitor_device();
    if(ret < 0) {
        PR_ERROR("Device setup failed with %d\n", ret);
        goto err_device;
    }
    PR_INFO("Device setup completed successfully\n");

    /* --------------- */

    PR_INFO("Module loaded successfully\n");
    return 0;

    /* ---- ERROR PATHS ---- */

err_device:
    cleanup_monitor_device();
err_hooks:
    cleanup_syscall_hooks();
err_timer:
    return ret;

}

/**
 * @brief Cleanup the system call throttling module
 * 
 */
static void __exit sct_exit(void) {

    PR_INFO("Removing module...\n");

    /**
     * The correct cleanup order is:
     * - device
     * - hooks
     * - timer
     * - filter
     * - monitor
     */

    /* ---- DEVICE ---- */

    // Remove device
    cleanup_monitor_device();
    PR_INFO("Device removed successfully\n");

    /* ---- HOOKS ---- */

    cleanup_syscall_hooks();
    PR_INFO("Syscall hooks cleaned up successfully\n");

    /* ---- TIMER ---- */

    // Stop monitor timer
    stop_monitor_timer();
    PR_INFO("Monitor timer stopped successfully\n");

    /* ---- FILTER ---- */

    cleanup_monitor_filter();
    PR_INFO("Filter structures cleaned up successfully\n");

    /* ---- MONITOR ---- */

    cleanup_monitor();
    PR_INFO("Monitor cleaned up successfully\n");

    printk(KERN_INFO "%s: Module unloaded\n", MODULE_NAME);

}

module_init(sct_init);
module_exit(sct_exit);