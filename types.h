#pragma once

#ifndef _SCT_TYPES_H
#define _SCT_TYPES_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/ftrace.h>
#include <linux/sched.h>

struct hook_syscall_t {
	int syscall_idx;
	bool active;
	bool nil_syscall;
	unsigned long original_addr;
	unsigned long hook_addr;
#ifdef _FTRACE_HOOKING
	// ftrace mode
	struct ftrace_ops fops;
#elif defined(_DISCOVER_HOOKING)
	// discover mode
	// (no additional fields needed)
#endif
};

// For historical statistics
// To compute average blocked threads per window:
//	avg_blocked_threads = sum_blocked_threads / total_windows_count
struct wstats_t {
	u64 max_blocked_threads; // Peak number of blocked threads observed in a single time window
	u64 sum_blocked_threads; // Total sum of blocked threads in all windows (for the average)
	u64 total_windows_count; // Number of windows considered
};

#else
#include <stdint.h>

#define __user

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef int64_t s64;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#endif

struct sysc_delayed_t {
	int syscall;
	uid_t uid;
	s64 delay_ms;
	char *prog_name;
};

/* ---- IOCTL STRUCTURES ---- */

// Monitor status structure
struct monitor_status_t {
	int enabled;
	int fast_unload;
	u64 max_invoks;
	u64 cur_invoks;
	u64 window_sec;
};

// Throttling statistics structure
struct throttling_stats_t {
	u64 peak_blocked;
	u64 avg_blocked_int;
	u64 avg_blocked_dec;
	u64 windows_num;
};

// Generic structure for requesting lists (Syscall, UID, Prog)
// The user fills 'ptr' (allocated buffer) and 'max_items'.
// The kernel fills the buffer and updates 'real_items'.
struct list_query_t {
	void __user *ptr;
	size_t max_items;
	size_t real_items;
	size_t fetched_items;
};
#endif
