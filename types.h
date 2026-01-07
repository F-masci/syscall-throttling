#pragma once

#include <linux/types.h>

// System call index type
typedef int scidx_t;

// Device configuration structure
typedef struct {
    char ** prog_names;
    pid_t * pids;
    scidx_t * syscalls;
} sctdev_confs_t;
