#pragma once

#include "sct.h"

#define INTERVAL_MS 10000  // => 10 seconds

void setup_monitor_timer(void);
int start_monitor_timer(void);
int stop_monitor_timer(void);