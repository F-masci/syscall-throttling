#define EXPORT_SYMTAB

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/slab.h>

#include "sct.h"
#include "dev.h"
#include "ops.h"
#include "types.h"
#include "monitor.h"
#include "timer.h"
#include "filter.h"
#include "_syst.h"
#include "hook.h"

// Module information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Masci: francescomasci@outlook.com");
MODULE_DESCRIPTION("System Call Throttling");
MODULE_VERSION("0.1");

bool sct_status = true;
unsigned long sct_max_invoks = 5;

// Throttling control parameter
module_param(sct_status, bool, 0644);
MODULE_PARM_DESC(sct_status, "Enable (1) or disable (0) throttling");

module_param(sct_max_invoks, ulong, 0644);
MODULE_PARM_DESC(sct_max_invoks, "Maximum allowed system call invocations per second");

/**
 * @brief Initialize the system call throttling module
 * 
 * @return int 
 */
static int __init sct_init(void) {

    int ret;

    PR_INFO("Initializing module...\n");

    /* ---- DEVICE ---- */

    ret = setup_monitor_device();
    if(ret < 0) {
        PR_ERROR("Device setup failed with %d\n", ret);
        goto err_device;
    }
    PR_INFO("Device setup completed successfully\n");

    /* ---- FILTER ---- */

    // Initialize filter structure
    setup_monitor_filter();
    PR_INFO("Filter structures initialized successfully\n");

    /* ---- MONITOR ---- */

    // Initialize monitor structure
    setup_monitor();
    PR_INFO("Monitor structures initialized successfully\n");

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

    /* --------------- */

    PR_INFO("Module loaded successfully\n");
    return 0;

    /* ---- ERROR PATHS ---- */

err_hooks:
    cleanup_monitor_device();
err_timer:
    stop_monitor_timer();
err_device:
    return ret;

}

/**
 * @brief Cleanup the system call throttling module
 * 
 */
static void __exit sct_exit(void) {

    PR_INFO("Removing module...\n");

    /* ---- HOOKS ---- */

    cleanup_syscall_hooks();
    PR_INFO("Syscall hooks cleaned up successfully\n");

    /* ---- DEVICE ---- */

    // Remove device
    cleanup_monitor_device();
    PR_INFO("Device removed successfully\n");

    /* ---- TIMER ---- */

    // Stop monitor timer
    stop_monitor_timer();
    PR_INFO("Monitor timer stopped successfully\n");

    /* ---- MONITOR ---- */

    cleanup_monitor();
    PR_INFO("Monitor cleaned up successfully\n");

    /* ---- FILTER ---- */

    cleanup_monitor_filter();
    PR_INFO("Filter structures cleaned up successfully\n");

    printk(KERN_INFO "%s: Module unloaded\n", MODULE_NAME);

}

module_init(sct_init);
module_exit(sct_exit);