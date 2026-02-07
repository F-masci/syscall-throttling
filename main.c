/**
 * @file main.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * @brief This file contains the module initialization and cleanup
 *		functions for the system call throttling module.
 *
 * @version 1.0
 * @date 2026-01-21
 *
 */

#include "sct.h"
#include "monitor.h"
#include "stats.h"
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
static int __init sct_init(void)
{
	int ret;

	PR_INFO("Initializing module...\n");

	/**
	 * The correct initialization order is:
	 * - stats
	 * - filter
	 * - monitor
	 * - timer
	 * - hooks
	 * - device
	 */

	/* ---- STATS ---- */

	// Initialize statistics structures
	ret = setup_monitor_stats();
	if (ret < 0) {
		PR_ERROR("Statistics setup failed with %d\n", ret);
		goto err_stats;
	}
	PR_INFO("Statistics structures initialized successfully\n");

	/* ---- FILTER ---- */

	// Initialize filter structure
	ret = setup_monitor_filter();
	if (ret < 0) {
		PR_ERROR("Filter setup failed with %d\n", ret);
		goto err_filter;
	}
	PR_INFO("Filter structures initialized successfully\n");

	/* ---- MONITOR ---- */

	// Initialize monitor structure
	ret = setup_monitor();
	if (ret < 0) {
		PR_ERROR("Monitor setup failed with %d\n", ret);
		goto err_monitor;
	}
	PR_INFO("Monitor structures initialized successfully\n");

	/* ---- TIMER ---- */

	// Setup monitor timer
	ret = setup_monitor_timer();
	if (ret < 0) {
		PR_ERROR("Timer setup failed with %d\n", ret);
		goto err_timer;
	}
	PR_INFO("Timer setup completed successfully\n");

	// Start monitor timer
	ret = start_monitor_timer();
	if (ret < 0) {
		PR_ERROR("Failed to start monitor timer with %d\n", ret);
		goto err_timer;
	}
	PR_INFO("Timer started successfully\n");

	/* ---- HOOKS ---- */

	ret = setup_syscall_hooks(SYSCALL_TABLE_SIZE);
	if (ret < 0) {
		PR_ERROR("Syscall hooks setup failed with %d\n", ret);
		goto err_hooks;
	}
	PR_INFO("Syscall hooks setup completed successfully\n");

	/* ---- DEVICE ---- */

	ret = setup_monitor_device();
	if (ret < 0) {
		PR_ERROR("Device setup failed with %d\n", ret);
		goto err_device;
	}
	PR_INFO("Device setup completed successfully\n");

	/* --------------- */

	PR_INFO("Module loaded successfully\n");
	return 0;

	/* ---- ERROR PATHS ---- */

err_device:
	cleanup_syscall_hooks();
err_hooks:
	stop_monitor_timer();
err_timer:
	cleanup_monitor();
err_monitor:
	cleanup_monitor_filter();
err_filter:
	cleanup_monitor_stats();
err_stats:

	PR_ERROR("Module initialization failed\n");

	return ret;
}

/**
 * @brief Cleanup the system call throttling module
 */
static void __exit sct_exit(void)
{
	PR_INFO("Removing module...\n");

	/**
	 * The correct cleanup order is:
	 * - device
	 * - hooks
	 * - timer
	 * - monitor
	 * - filter
	 * - stats
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
	PR_INFO("Timer stopped successfully\n");

	/* ---- MONITOR ---- */

	cleanup_monitor();
	PR_INFO("Monitor structures cleaned up successfully\n");

	/* ---- FILTER ---- */

	cleanup_monitor_filter();
	PR_INFO("Filter structures cleaned up successfully\n");

	/* ---- STATS ---- */

	cleanup_monitor_stats();
	PR_INFO("Statistics structures cleaned up successfully\n");

	PR_INFO("Module unloaded\n");
}

module_init(sct_init);
module_exit(sct_exit);
