#pragma once

#include <linux/fs.h>
#include <linux/types.h>
#include "types.h"

extern const struct file_operations sct_ops;

// IOCTL definitions
#define SCT_IOC_MAGIC 'S'

#define SCT_IOCTL_ADD_PID      _IOW(SCT_IOC_MAGIC, 1, pid_t)
#define SCT_IOCTL_ADD_SYSCALL  _IOW(SCT_IOC_MAGIC, 2, uint64_t)
#define SCT_IOCTL_ADD_PROG     _IOW(SCT_IOC_MAGIC, 3, char *)