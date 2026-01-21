#pragma once

#include "sct.h"

#define DEVICE_MINOR 0
#define MAX_DEV_MINORS 1

#define DEVICE_NAME "sctm"
#define CLASS_NAME DEVICE_NAME
#define DNODE_NAME "sct-monitor"

int setup_monitor_device(void);
void cleanup_monitor_device(void);