#pragma once

#define EXPORT_SYMTAB

#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
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

#include "types.h"

#define MODULE_NAME "SCT"

#define PR_DEBUG(fmt, ...) pr_debug("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_DEBUG_PID(fmt, ...) PR_DEBUG("[%d] " fmt, current->pid, ##__VA_ARGS__)

#define PR_INFO(fmt, ...) pr_info("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_INFO_PID(fmt, ...) PR_INFO("[%d] " fmt, current->pid, ##__VA_ARGS__)

#define PR_WARN(fmt, ...) pr_warn("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_WARN_PID(fmt, ...) PR_WARN("[%d] " fmt, current->pid, ##__VA_ARGS__)

#define PR_ERROR(fmt, ...) pr_err("%s: " fmt, MODULE_NAME, ##__VA_ARGS__)
#define PR_ERROR_PID(fmt, ...) PR_ERROR("[%d] " fmt, current->pid, ##__VA_ARGS__)

#define MAX_ITEMS 1024