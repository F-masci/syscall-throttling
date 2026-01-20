#pragma once

#include <linux/types.h>
#include <linux/wait.h>
#include <linux/ftrace.h>

#ifdef __KERNEL__
    #include <linux/types.h>
#else
    #include <stdint.h>
    
    typedef uint64_t u64;
    typedef uint32_t u32;
    typedef uint16_t u16;
    typedef uint8_t  u8;
#endif

// System call index type
typedef int scidx_t;

// Monitor configuration structure
typedef struct {
    char ** prog_names;
    uid_t * uids;
    scidx_t * syscalls;

    wait_queue_head_t wqueue;
    bool unloading;

    u64 invoks;
} sct_monitor_t;

typedef struct {
    bool active;
    unsigned long original_addr;
    // ftrace mode
    struct kprobe *kp;
    struct ftrace_ops sct_ftrace_ops;
    // discover mode - no additional fields needed
} hook_syscall_t;

typedef struct {
    u64 invocked_current_window;       // Number of invocations in the current time window
    u64 blocked_current_window;        // Number of blocked threads in the current time window

    // For historical statistics
    u64 max_invocked_threads;          // Peak number of invocations observed in a single time window
    u64 max_blocked_threads;           // Peak number of blocked threads observed in a single time window
    u64 sum_invocked_threads;          // Total sum of invocations in all windows (for the average)
    u64 sum_blocked_threads;           // Total sum of blocked threads in all windows (for the average)
    u64 total_windows_count;           // Number of windows considered
    
    // To compute average <invocked|blocked> threads per window:
    //   avg = sum_<invocked|blocked>_threads / total_windows_count
} sct_stats_t;

typedef struct {
    pid_t pid;
    char prog_name[TASK_COMM_LEN];
    scidx_t syscall;
    uid_t uid;
    s64 timestamp_ns;
} sct_sys_delayed_t;