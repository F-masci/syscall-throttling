#pragma once

#include "sct.h"

#define TIMER_INTERVAL_MS 10000  // => 10 seconds to test

void setup_monitor_timer(void);
int start_monitor_timer(void);
int stop_monitor_timer(void);