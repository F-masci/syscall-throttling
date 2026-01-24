/**
 * @file opsc.h
 * @brief Header file IOCTL definitions for System Call Throttling module
 * 
 */

#pragma once

#include <linux/ioctl.h>

#include "types.h"

#define SCT_IOC_MAGIC 'S'

#define SCT_IOCTL_ADD_UID           _IOW(SCT_IOC_MAGIC, 1, uid_t)
#define SCT_IOCTL_ADD_SYSCALL       _IOW(SCT_IOC_MAGIC, 2, u64)
#define SCT_IOCTL_ADD_PROG          _IOW(SCT_IOC_MAGIC, 3, char *)

#define SCT_IOCTL_GET_STATUS        _IOR(SCT_IOC_MAGIC, 4, monitor_status_t)
#define SCT_IOCTL_GET_STATS         _IOR(SCT_IOC_MAGIC, 5, throttling_stats_t)
#define SCT_IOCTL_GET_PEAK_DELAY    _IOR(SCT_IOC_MAGIC, 6, sysc_delayed_t)
#define SCT_IOCTL_GET_SYSCALL_LIST  _IOWR(SCT_IOC_MAGIC, 7, list_query_t)
#define SCT_IOCTL_GET_UID_LIST      _IOWR(SCT_IOC_MAGIC, 8, list_query_t)
#define SCT_IOCTL_GET_PROG_LIST     _IOWR(SCT_IOC_MAGIC, 9, list_query_t)

#define SCT_IOCTL_DEL_UID           _IOW(SCT_IOC_MAGIC, 10, uid_t)
#define SCT_IOCTL_DEL_SYSCALL       _IOW(SCT_IOC_MAGIC, 11, u64)
#define SCT_IOCTL_DEL_PROG          _IOW(SCT_IOC_MAGIC, 12, char *)

#define SCT_IOCTL_SET_LIMIT         _IOW(SCT_IOC_MAGIC, 13, u64)
#define SCT_IOCTL_SET_STATUS        _IOW(SCT_IOC_MAGIC, 14, bool)