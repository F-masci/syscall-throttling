#pragma once

#define EXPORT_SYMTAB

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

/**
 * @brief Selection strategy for concurrency mechanism.
 * - RCU is the default for best read performance (Wait-Free readers).
 * - Spinlock is used if explicitly requested OR if LOW_MEMORY mode
 *   is active (to avoid dynamic allocation overhead).
 */
#if !defined(SPINLOCK_PROTECTED) && !defined(LOW_MEMORY)
	#define _RCU_PROTECTED
#else
	#define _SPINLOCK_PROTECTED
#endif

/**
 * @brief Selection strategy for syscall hooking mechanism.
 * - DISCOVER_HOOKING is the default hooking method for better performance.
 * - FTRACE_HOOKING is used if explicitly requested, providing better compatibility.
 */
#ifndef FTRACE_HOOKING
	#define _DISCOVER_HOOKING
#else
	#define _FTRACE_HOOKING
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/limits.h>

#include "types.h"

#define MODULE_NAME "SCT"

#define TIMER_INTERVAL_S	10
#define TIMER_INTERVAL_MS   (TIMER_INTERVAL_S * 1000)
#define DEFAULT_STATUS	  true
#define DEFAULT_FAST_UNLOAD false
#define DEFAULT_MAX_INVOKS  100

#define PR_DEBUG(fmt, ...) pr_debug("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_DEBUG_PID(fmt, ...) PR_DEBUG("[%d] " fmt, task_pid_nr(current), ##__VA_ARGS__)

#define PR_INFO(fmt, ...) pr_info("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_INFO_PID(fmt, ...) PR_INFO("[%d] " fmt, task_pid_nr(current), ##__VA_ARGS__)

#define PR_WARN(fmt, ...) pr_warn("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_WARN_PID(fmt, ...) PR_WARN("[%d] " fmt, task_pid_nr(current), ##__VA_ARGS__)

#define PR_ERROR(fmt, ...) pr_err("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_ERROR_PID(fmt, ...) PR_ERROR("[%d] " fmt, task_pid_nr(current), ##__VA_ARGS__)

#define PROG_HASH_SALT 0