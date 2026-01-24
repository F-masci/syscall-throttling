#pragma once

// System call index type
typedef int scidx_t;

#ifdef __KERNEL__
    #include <linux/types.h>
    #include <linux/wait.h>
    #include <linux/ftrace.h>

    typedef struct {
        bool active;
        unsigned long original_addr;
        // ftrace mode
        struct kprobe *kp;
        struct ftrace_ops fops;
        // discover mode - no additional fields needed
    } hook_syscall_t;
    
    typedef struct {
        pid_t pid;
        char prog_name[TASK_COMM_LEN];
        scidx_t syscall;
        uid_t uid;
        s64 delay_ms;
    } sysc_delayed_t;

    // For historical statistics
    // To compute average blocked threads per window:
    //   avg_blocked_threads = sum_blocked_threads / total_windows_count
    typedef struct {
        u64 max_blocked_threads;           // Peak number of blocked threads observed in a single time window
        u64 sum_blocked_threads;           // Total sum of blocked threads in all windows (for the average)
        u64 total_windows_count;           // Number of windows considered
    } wstats_t;

#else
    #include <stdint.h>
    
    typedef uint64_t u64;
    typedef uint32_t u32;
    typedef uint16_t u16;
    typedef uint8_t  u8;
#endif