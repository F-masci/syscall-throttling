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