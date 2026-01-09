#pragma once

#include <linux/types.h>

// System call index type
typedef int scidx_t;

// Monitor configuration structure
typedef struct {
    char ** prog_names;
    pid_t * pids;
    scidx_t * syscalls;

    u64 invoks;
} sct_monitor_t;
