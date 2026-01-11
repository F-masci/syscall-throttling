#pragma once

#include <linux/types.h>
#include <linux/wait.h>

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
