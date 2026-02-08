/**
 * @file ops.c
 * @author Francesco Masci (francescomasci@outlook.com)
 *
 * @brief This file implements the file operations for the monitor device.
 *		It provides the read operation to generate a report of the
 *		current monitoring status and statistics. It gathers data from
 *		various internal structures and formats it into a human-readable
 *		report that can be read from user space. It also provides interfaces
 *		to manage the monitor state.
 *
 * @version 1.0
 * @date 2026-01-21
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "ops.h"
#include "monitor.h"
#include "dev.h"
#include "types.h"
#include "stats.h"
#include "filter.h"
#include "hook.h"
#include "timer.h"

/**
 * @brief Check root permissions.
 * @note We can also use capable(CAP_SYS_ADMIN) if needed
 */
#define REQUIRE_ROOT()                                                     \
	do {                                                               \
		if (unlikely(current_euid().val != 0)) {                   \
			PR_ERROR("Permission denied for non-root user\n"); \
			return -EPERM;                                     \
		}                                                          \
	} while (0)

/**
 * @brief Helper macro for report generation.
 * Print formatted data into kernel buffer and update length
 *
 * @param fmt Format string
 * @param ... Additional arguments for formatting
 *
 * @return int Updated length of data in buffer
 *
 * @note This macro uses scnprintf to safely format and append data to the kernel buffer.
 * It updates the length and limit variables to reflect the new size of the data.
 * @note Ensure that 'len' and 'limit' variables are defined in the scope where this macro is used.
 *
 */
#define __SCNPRINTF(fmt, ...) (len += scnprintf(kbuf + len, limit - len, fmt, ##__VA_ARGS__))

#define AVG_SCALE 100

#define BYTES_HEADER_STATS 1024 // default is 1024 bytes for Header and Stats
#define BYTES_PER_SYSCALL_LINE 32 // default is 32 bytes per syscall line
#define BYTES_PER_UID_LINE 32 // default is 32 bytes per UID line
#define BYTES_PROG_OVERHEAD 64 // default is 64 bytes per Program overhead
#define BYTES_PER_PROG_LINE (PATH_MAX + BYTES_PROG_OVERHEAD) // default is 4096 bytes per Program line

/**
 * @brief Read operation for the monitor device.
 * Generates a report of the current monitoring status and statistics.
 *
 * @param file
 * @param buf
 * @param count
 * @param ppos
 * @return long
 */
static long monitor_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	long ret;
	size_t j;
	int len = 0;

	bool status, fast_unload;
	u64 max_invoks, cur_invoks;
	u64 peak_blocked, avg_blocked, windows_num;
	struct sysc_delayed_t peak_delay;

	int *syscall_list;
	size_t syscall_count;

	uid_t *uid_list;
	size_t uid_count;

	char **prog_list;
	size_t prog_count;
	size_t prog_size = 0;

	char *kbuf;
	size_t limit = PAGE_SIZE;

	/* ---- BUFFER ALLOCATION ---- */

	// Set the error code to return in case of allocation failure
	ret = -ENOMEM;

	// Get monitor status and limits
	status = get_monitor_status();
	fast_unload = get_monitor_fast_unload();
	max_invoks = get_monitor_max_invoks();
	cur_invoks = get_curw_invoks();

	// Get throttling stats
	get_stats_blocked(&peak_blocked, &avg_blocked, &windows_num, AVG_SCALE);

	// Get peak delayed syscall info
	get_peak_delayed_syscall(&peak_delay);

	// Allocate temporary syscall list
	syscall_count = get_syscall_monitor_num();
	syscall_list = kmalloc_array(syscall_count, sizeof(int), GFP_KERNEL);
	if (!syscall_list) {
		PR_ERROR("Failed to allocate memory for syscall list\n");
		goto alloc_syscall_list_err;
	}
	syscall_count = get_syscall_monitor_vals(syscall_list, SYSCALL_TABLE_SIZE);
	PR_DEBUG("Retrieved %lu monitored syscalls\n", syscall_count);

	// Allocate temporary UID list
	uid_count = get_uid_monitor_num();
	uid_list = kmalloc_array(uid_count, sizeof(uid_t), GFP_KERNEL);
	if (!uid_list) {
		PR_ERROR("Failed to allocate memory for UID list\n");
		goto alloc_uid_list_err;
	}
	uid_count = get_uid_monitor_vals(uid_list, uid_count);
	PR_DEBUG("Retrieved %lu monitored UIDs\n", uid_count);

	// Allocate temporary Prog Name list
	prog_count = get_prog_monitor_num();
	prog_list = kmalloc_array(prog_count, sizeof(char *), GFP_KERNEL);
	if (!prog_list) {
		PR_ERROR("Failed to allocate memory for Program Name list\n");
		goto alloc_prog_list_err;
	}
	prog_count = get_prog_monitor_vals(prog_list, prog_count);
	PR_DEBUG("Retrieved %lu monitored Programs\n", prog_count);

	// Compute total size of program names
	// to avoid exceeding memory limits
	for (j = 0; j < prog_count; j++)
		prog_size += strlen(prog_list[j]) + 1 + BYTES_PROG_OVERHEAD;

	prog_size += PAGE_SIZE; // Add margin

	// Compute required buffer size
	// Estimate the size needed for the report
	// based on the number of monitored items
	// and the formatting overhead
	limit = BYTES_HEADER_STATS;
	limit += syscall_count * BYTES_PER_SYSCALL_LINE;
	limit += uid_count * BYTES_PER_UID_LINE;
	// limit += prog_count * BYTES_PER_PROG_LINE; -> replaced with actual size to avoid overestimation
	limit += prog_size;

	// Allocate kernel buffer for report
	kbuf = kvzalloc(limit, GFP_KERNEL);
	if (!kbuf) {
		PR_ERROR("Failed to allocate memory for report buffer\n");
		goto alloc_kbuff_err;
	}
	PR_DEBUG("Allocated %zu bytes for report buffer\n", limit);

	/* ---- REPORT GENERATION ---- */

	// Set the number of bytes to read
	ret = 0;

	// --- General Status ---
	__SCNPRINTF("========= DEVICE STATUS =========\n");
	__SCNPRINTF("Status:	%s\n", status ? "ENABLED" : "DISABLED");
	__SCNPRINTF("Fast Unload:	%s\n", fast_unload ? "ENABLED" : "DISABLED");
	__SCNPRINTF("Max:		%llu invocations/s\n", max_invoks);
	__SCNPRINTF("Win:		%d secs (%d ms)\n", TIMER_INTERVAL_S, TIMER_INTERVAL_MS);

	// --- Throttling Stats ---
	__SCNPRINTF("======== THROTTLING INFO ========\n");
	__SCNPRINTF("Current invocations:	%llu\n", cur_invoks);
	__SCNPRINTF("Peak Blocked Threads:	%llu\n", peak_blocked);
	__SCNPRINTF("Avg Blocked Threads:	%llu.%02llu\n", avg_blocked / AVG_SCALE, avg_blocked % AVG_SCALE);
	__SCNPRINTF("Observed Window:	%llu (%llu s)\n", windows_num, windows_num * TIMER_INTERVAL_S);

	__SCNPRINTF("======== PEAK DELAY INFO ========\n");
	if (peak_delay.syscall > -1) {
		__SCNPRINTF("Delay:	%lld ms\n", peak_delay.delay_ms);
		__SCNPRINTF("Syscall:	%d\n", peak_delay.syscall);
		__SCNPRINTF("Program:	%s\n", peak_delay.prog_name ? peak_delay.prog_name : "N/A");
		__SCNPRINTF("UID:		%d\n", peak_delay.uid);
	} else {
		__SCNPRINTF("No delayed syscalls recorded yet.\n");
	}
	__SCNPRINTF("=================================\n");

	// --- Syscalls ---
	__SCNPRINTF("Registered Syscalls:\n");
	for (j = 0; j < syscall_count; j++)
		__SCNPRINTF("  - [%lu] %u\n", j, syscall_list[j]);

	// --- UIDs ---
	__SCNPRINTF("Registered UIDs:\n");
	for (j = 0; j < uid_count; j++)
		__SCNPRINTF("  - [%lu] %u\n", j, uid_list[j]);

	// --- Programs ---
	__SCNPRINTF("Registered Programs:\n");
	for (j = 0; j < prog_count; j++)
		__SCNPRINTF("  - [%lu] %s\n", j, prog_list[j]);

	__SCNPRINTF("=================================\n");

	/* ---- SEND TO USER ---- */

	// Copy data to user space
	// If user read all data, return 0 to signal EOF
	if (*ppos >= len) {
		PR_DEBUG("All data read by user, returning EOF\n");
		ret = 0;
		goto no_data_to_copy;
	}

	// Compute how many bytes to copy
	// Adjust count if it exceeds available data
	if (count > len - *ppos)
		count = len - *ppos;

	// Copy data to user buffer
	if (copy_to_user(buf, kbuf + *ppos, count)) {
		PR_ERROR("Failed to copy report data to user\n");
		ret = -EFAULT;
		goto no_data_to_copy;
	}

	// Update read position for next call
	*ppos += count;

	// Set return value to number of bytes read
	ret = count;

	/* ---- CLEANUP ---- */

no_data_to_copy:
	kvfree(kbuf);
	PR_DEBUG("Freed report buffer\n");

alloc_kbuff_err:
	// Free temporary program names not only the array
	for (j = 0; j < prog_count; j++)
		kfree(prog_list[j]);

	kfree(prog_list);
	PR_DEBUG("Freed program names list and nodes\n");

alloc_prog_list_err:
	kfree(uid_list);
	PR_DEBUG("Freed UID list\n");

alloc_uid_list_err:
	kfree(syscall_list);
	PR_DEBUG("Freed syscall list\n");

alloc_syscall_list_err:

	// Return the number of bytes read or error code
	return ret;
}
#undef __SCNPRINTF

/**
 * @brief IOCTL operation for the monitor device.
 * Handles various commands to add/remove monitoring filters and configure settings.
 *
 * @param file
 * @param cmd
 * @param arg
 * @return long
 */
static long monitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = 0;

	// Temporary variables for various IOCTL write operations
	int k_syscall_idx;
	uid_t k_uid;
	char *k_progname;
	unsigned long k_ino;
	unsigned int k_dev;
	char k_check_tail;

	// Temporary variables for various IOCTL read operations
	struct monitor_status_t k_status_info;
	struct throttling_stats_t k_stats_info;
	struct sysc_delayed_t k_delay_info;
	struct list_query_t k_query;

	// Temporary variables for various IOCTL configuration operations
	u64 k_max_invoks;
	bool k_status;

	// Temporary lists for fetching monitored items
	int *tmp_syscall_list = NULL;
	uid_t *tmp_uid_list = NULL;
	char **tmp_prog_list = NULL;
	size_t fetched_count, real_items, i, flat_prog_buf_size, flat_prog_buf_offset;
	char *flat_prog_buf = NULL;

	switch (cmd) {
		/* --- ADD COMMANDS --- */

	case SCT_IOCTL_ADD_SYSCALL:
		REQUIRE_ROOT();
		if (copy_from_user(&k_syscall_idx, (int __user *)arg, sizeof(k_syscall_idx))) {
			PR_ERROR("Failed to copy syscall index from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to add syscall %d\n", k_syscall_idx);
		add_syscall_monitoring(k_syscall_idx);
		ret = install_syscall_hook(k_syscall_idx);
		if (ret < 0) {
			PR_ERROR("Failed to install hook on newly added monitored syscall %d\n", k_syscall_idx);
			remove_syscall_monitoring(k_syscall_idx);
			return ret;
		}
		PR_INFO("Added syscall %d\n", k_syscall_idx);
		break;

	case SCT_IOCTL_ADD_UID:
		REQUIRE_ROOT();
		if (copy_from_user(&k_uid, (uid_t __user *)arg, sizeof(k_uid))) {
			PR_ERROR("Failed to copy UID from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to add UID %d\n", k_uid);
		ret = add_uid_monitoring(k_uid);
		if (ret < 0) {
			PR_ERROR("Failed to add UID %d for monitoring\n", k_uid);
			return ret;
		}
		PR_INFO("Added UID %d\n", k_uid);
		break;

	case SCT_IOCTL_ADD_PROG:
		REQUIRE_ROOT();
		k_progname = strndup_user((const char __user *)arg, PATH_MAX);
		if (IS_ERR(k_progname)) {
			PR_ERROR("Failed to copy prog name from user\n");
			return PTR_ERR(k_progname);
		}
		PR_DEBUG("Received command to add prog name %s\n", k_progname);

		// Parsing the program name
		//
		// If the format is <inode>:<device>, we add by inode
		// else we add by path
		if (sscanf(k_progname, "%lu:%u%c", &k_ino, &k_dev, &k_check_tail) == 2) {
			// Inode case
			PR_DEBUG("Adding by direct Inode: %lu, Device: %u\n", k_ino, k_dev);
			ret = add_prog_monitoring_inode(k_ino, (dev_t)k_dev, NULL);
		} else {
			// Path case
			PR_DEBUG("Adding by Path resolution: %s\n", k_progname);
			ret = add_prog_monitoring_path(k_progname);
		}

		if (ret < 0) {
			PR_ERROR("Failed to add prog name %s for monitoring\n", k_progname);
			kfree(k_progname);
			return ret;
		}
		PR_INFO("Added prog name %s\n", k_progname);
		kfree(k_progname);
		break;

		/* --- READ COMMANDS --- */

	case SCT_IOCTL_GET_STATUS:
		PR_DEBUG("Received command to get monitor status\n");
		k_status_info.enabled = get_monitor_status() ? 1 : 0;
		k_status_info.fast_unload = get_monitor_fast_unload() ? 1 : 0;
		k_status_info.max_invoks = get_monitor_max_invoks();
		k_status_info.cur_invoks = get_curw_invoks();
		k_status_info.window_sec = TIMER_INTERVAL_MS / 1000;
		if (copy_to_user((void __user *)arg, &k_status_info, sizeof(k_status_info))) {
			PR_ERROR("Failed to copy monitor status to user\n");
			return -EFAULT;
		}
		break;

	case SCT_IOCTL_GET_STATS:
		PR_DEBUG("Received command to get throttling stats\n");

		// Get stats of throttling
		get_stats_blocked(&k_stats_info.peak_blocked, &k_stats_info.avg_blocked_int, &k_stats_info.windows_num, AVG_SCALE);

		// Update avg blocked to have integer and decimal parts
		k_stats_info.avg_blocked_dec = k_stats_info.avg_blocked_int % AVG_SCALE;
		k_stats_info.avg_blocked_int = k_stats_info.avg_blocked_int / AVG_SCALE;

		if (copy_to_user((void __user *)arg, &k_stats_info, sizeof(k_stats_info))) {
			PR_ERROR("Failed to copy throttling stats to user\n");
			return -EFAULT;
		}
		break;

	case SCT_IOCTL_GET_PEAK_DELAY:
		PR_DEBUG("Received command to get peak delay info\n");
		get_peak_delayed_syscall(&k_delay_info);
		if (copy_to_user((void __user *)arg, &k_delay_info, sizeof(k_delay_info))) {
			PR_ERROR("Failed to copy peak delay info to user\n");
			return -EFAULT;
		}
		break;

	case SCT_IOCTL_GET_SYSCALL_LIST:
		// The user provides a struct list_query_t struct with:
		// - ptr: pointer to user buffer to fill
		// - max_items: maximum number of items that can be stored in the buffer
		// The kernel fills the buffer and updates real_items with the actual number of items copied
		if (copy_from_user(&k_query, (void __user *)arg, sizeof(k_query))) {
			PR_ERROR("Failed to copy syscall list query from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to get syscall list\n");

		// Allocate temporary array to fetch syscalls
		real_items = get_syscall_monitor_num();
		tmp_syscall_list = kmalloc_array(real_items, sizeof(int), GFP_KERNEL);
		if (!tmp_syscall_list) {
			PR_ERROR("Failed to allocate memory for syscall list\n");
			return -ENOMEM;
		}
		real_items = get_syscall_monitor_vals(tmp_syscall_list, real_items);

		// Compute how many items to copy based on user buffer size
		fetched_count = real_items;
		if (k_query.max_items < fetched_count)
			fetched_count = k_query.max_items;

		// Copy syscall list to user buffer
		if (copy_to_user(k_query.ptr, tmp_syscall_list, fetched_count * sizeof(int))) {
			PR_ERROR("Failed to copy syscall list to user buffer\n");
			ret = -EFAULT;
			goto send_syscall_err;
		}

		// Update real_items and fetched_items in user struct
		k_query.real_items = real_items;
		k_query.fetched_items = fetched_count;
		if (copy_to_user((void __user *)arg, &k_query, sizeof(k_query))) {
			PR_ERROR("Failed to copy syscall list query result to user\n");
			ret = -EFAULT;
			goto send_syscall_err;
		}

send_syscall_err:
		kfree(tmp_syscall_list);
		break;

	case SCT_IOCTL_GET_UID_LIST:
		// The user provides a struct list_query_t struct with:
		// - ptr: pointer to user buffer to fill
		// - max_items: maximum number of items that can be stored in the buffer
		// The kernel fills the buffer and updates real_items with the actual number of items copied
		if (copy_from_user(&k_query, (void __user *)arg, sizeof(k_query))) {
			PR_ERROR("Failed to copy UID list query from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to get UID list\n");

		// Allocate temporary array to fetch UIDs
		real_items = get_uid_monitor_num();
		tmp_uid_list = kmalloc_array(real_items, sizeof(uid_t), GFP_KERNEL);
		if (!tmp_uid_list) {
			PR_ERROR("Failed to allocate memory for UID list\n");
			return -ENOMEM;
		}
		real_items = get_uid_monitor_vals(tmp_uid_list, real_items);

		// Compute how many items to copy based on user buffer size
		fetched_count = real_items;
		if (k_query.max_items < fetched_count)
			fetched_count = k_query.max_items;

		// Copy UID list to user buffer
		if (copy_to_user(k_query.ptr, tmp_uid_list, fetched_count * sizeof(uid_t))) {
			PR_ERROR("Failed to copy UID list to user buffer\n");
			ret = -EFAULT;
			goto send_uid_err;
		}

		// Update real_items and fetched_items in user struct
		k_query.real_items = real_items;
		k_query.fetched_items = fetched_count;
		if (copy_to_user((void __user *)arg, &k_query, sizeof(k_query))) {
			PR_ERROR("Failed to copy UID list query result to user\n");
			ret = -EFAULT;
			goto send_uid_err;
		}

send_uid_err:
		kfree(tmp_uid_list);
		break;

	case SCT_IOCTL_GET_PROG_LIST:
		// The user provides a struct list_query_t struct with:
		// - ptr: pointer to user buffer to fill
		// - max_items: maximum number of items that can be stored in the buffer
		// The kernel fills the buffer and updates real_items with the actual number of items copied
		//
		// We assume the user allocated a flat buffer of size max_items * PATH_MAX bytes
		// so we will copy packed-length strings into it, one after another.
		if (copy_from_user(&k_query, (void __user *)arg, sizeof(k_query))) {
			PR_ERROR("Failed to copy prog name list query from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to get prog name list\n");

		// Allocate temporary array to fetch prog names
		real_items = get_prog_monitor_num();
		tmp_prog_list = kmalloc_array(real_items, sizeof(char *), GFP_KERNEL);
		if (!tmp_prog_list) {
			PR_ERROR("Failed to allocate memory for prog name list\n");
			return -ENOMEM;
		}
		real_items = get_prog_monitor_vals(tmp_prog_list, real_items);

		// Compute how many items to copy based on user buffer size
		fetched_count = real_items;
		if (k_query.max_items < fetched_count)
			fetched_count = k_query.max_items;

		// Compute size needed for flat buffer
		flat_prog_buf_size = 0;
		for (i = 0; i < fetched_count; i++)
			flat_prog_buf_size += (tmp_prog_list[i]) ? strlen(tmp_prog_list[i]) + 1 : 1;

		// Allocate flat buffer to hold prog names
		flat_prog_buf = kvzalloc(flat_prog_buf_size, GFP_KERNEL);
		if (!flat_prog_buf) {
			PR_ERROR("Failed to allocate memory for flat prog name buffer\n");
			ret = -ENOMEM;
			goto alloc_flat_buf_err;
		}

		// Create flat buffer with fixed-length entries
		// from tmp prog list
		flat_prog_buf_offset = 0;
		for (i = 0; i < fetched_count; i++) {
			char *src = tmp_prog_list[i] ? tmp_prog_list[i] : "";
			size_t len = strlen(src) + 1;

			memcpy(flat_prog_buf + flat_prog_buf_offset, src, len);
			flat_prog_buf_offset += len;
		}

		// Copy flat buffer to user space
		if (copy_to_user(k_query.ptr, flat_prog_buf, flat_prog_buf_size)) {
			PR_ERROR("Failed to copy prog name list to user buffer\n");
			ret = -EFAULT;
			goto send_prog_err;
		}

		// Update real_items and fetched_items in user struct
		k_query.real_items = real_items;
		k_query.fetched_items = fetched_count;
		if (copy_to_user((void __user *)arg, &k_query, sizeof(k_query))) {
			PR_ERROR("Failed to copy prog name list query result to user\n");
			ret = -EFAULT;
			goto send_prog_err;
		}

send_prog_err:
		kvfree(flat_prog_buf);
		PR_DEBUG("Freed flat prog name buffer\n");

alloc_flat_buf_err:
		// Free list and names buffer
		for (i = 0; i < fetched_count; i++)
			kfree(tmp_prog_list[i]);
		PR_DEBUG("Freed prog name list nodes\n");
		kfree(tmp_prog_list);
		PR_DEBUG("Freed prog name list array\n");
		break;

		/* --- REMOVE COMMANDS --- */

	case SCT_IOCTL_DEL_SYSCALL:
		REQUIRE_ROOT();
		if (copy_from_user(&k_syscall_idx, (int __user *)arg, sizeof(k_syscall_idx))) {
			PR_ERROR("Failed to copy syscall index from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to remove syscall %d\n", k_syscall_idx);
		ret = uninstall_syscall_hook(k_syscall_idx);
		if (ret < 0) {
			PR_ERROR("Failed to uninstall hook on monitored syscall %d\n", k_syscall_idx);
			return ret;
		}
		remove_syscall_monitoring(k_syscall_idx);
		PR_INFO("Removed syscall %d\n", k_syscall_idx);
		break;

	case SCT_IOCTL_DEL_UID:
		REQUIRE_ROOT();
		if (copy_from_user(&k_uid, (uid_t __user *)arg, sizeof(k_uid))) {
			PR_ERROR("Failed to copy UID from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to remove UID %d\n", k_uid);
		ret = remove_uid_monitoring(k_uid);
		if (ret < 0) {
			PR_ERROR("Failed to remove UID %d\n", k_uid);
			return ret;
		}
		PR_INFO("Removed UID %d\n", k_uid);
		break;

	case SCT_IOCTL_DEL_PROG:
		REQUIRE_ROOT();
		k_progname = strndup_user((const char __user *)arg, PATH_MAX);
		if (IS_ERR(k_progname)) {
			PR_ERROR("Failed to copy prog name from user\n");
			return PTR_ERR(k_progname);
		}
		PR_DEBUG("Received command to remove prog name %s\n", k_progname);

		// Parsing the program name
		//
		// If the format is <inode>:<device>, we remove by inode
		// else we remove by path
		if (sscanf(k_progname, "%lu:%u%c", &k_ino, &k_dev, &k_check_tail) == 2) {
			// Inode case
			PR_DEBUG("Removing by direct Inode: %lu, Device: %u\n", k_ino, k_dev);
			ret = remove_prog_monitoring_inode(k_ino, (dev_t)k_dev);
		} else {
			// Path case
			PR_DEBUG("Removing by Path resolution: %s\n", k_progname);
			ret = remove_prog_monitoring_path(k_progname);
		}

		if (ret < 0) {
			PR_ERROR("Failed to remove prog name %s\n", k_progname);
			kfree(k_progname);
			return ret;
		}
		PR_INFO("Removed prog name %s\n", k_progname);
		kfree(k_progname);
		break;

		/* --- CONFIGURATION COMMANDS --- */

	case SCT_IOCTL_SET_LIMIT:
		REQUIRE_ROOT();
		if (copy_from_user(&k_max_invoks, (u64 __user *)arg, sizeof(k_max_invoks))) {
			PR_ERROR("Failed to copy max invocations limit from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to set new max invocations limit: %llu\n", k_max_invoks);
		ret = set_monitor_max_invoks(k_max_invoks);
		if (ret < 0) {
			PR_ERROR("Failed to set new max invocations limit: %llu\n", k_max_invoks);
			return ret;
		}
		PR_INFO("Set new max invocations limit: %llu\n", k_max_invoks);
		break;

	case SCT_IOCTL_SET_STATUS:
		REQUIRE_ROOT();
		if (copy_from_user(&k_status, (int __user *)arg, sizeof(k_status))) {
			PR_ERROR("Failed to copy monitor status from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to set monitor status: %s\n", k_status ? "ENABLED" : "DISABLED");
		ret = set_monitor_status(k_status != 0);
		if (ret < 0) {
			PR_ERROR("Failed to set monitor status: %s\n", k_status ? "ENABLED" : "DISABLED");
			return ret;
		}
		PR_INFO("Set monitor status: %s\n", k_status ? "ENABLED" : "DISABLED");
		break;

	case SCT_IOCTL_SET_FAST_UNLOAD:
		REQUIRE_ROOT();
		if (copy_from_user(&k_status, (int __user *)arg, sizeof(k_status))) {
			PR_ERROR("Failed to copy monitor fast unload status from user\n");
			return -EFAULT;
		}
		PR_DEBUG("Received command to set monitor fast unload: %s\n", k_status ? "ENABLED" : "DISABLED");
		ret = set_monitor_fast_unload(k_status != 0);
		if (ret < 0) {
			PR_ERROR("Failed to set monitor fast unload: %s\n", k_status ? "ENABLED" : "DISABLED");
			return ret;
		}
		PR_INFO("Set monitor fast unload: %s\n", k_status ? "ENABLED" : "DISABLED");
		break;

	default:
		PR_ERROR("Invalid IOCTL command: %u\n", cmd);
		return -EINVAL;
	}

	return ret;
}

const struct file_operations monitor_operations = {
	.owner = THIS_MODULE,
	.read = monitor_read,
	.unlocked_ioctl = monitor_ioctl,
};
