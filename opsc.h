/**
 * @file opsc.h
 * @brief Header file IOCTL definitions for System Call Throttling module
 * 
 */

#pragma once

#include <linux/ioctl.h>

#define SCT_IOC_MAGIC 'S'

#define SCT_IOCTL_ADD_UID      _IOW(SCT_IOC_MAGIC, 1, uid_t)
#define SCT_IOCTL_ADD_SYSCALL  _IOW(SCT_IOC_MAGIC, 2, uint64_t)
#define SCT_IOCTL_ADD_PROG     _IOW(SCT_IOC_MAGIC, 3, char *)