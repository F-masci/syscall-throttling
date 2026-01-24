#pragma once

#include "sct.h"

int setup_monitor_stats(void);

void get_peak_delayed_syscall(sysc_delayed_t *);
bool update_peak_delay(s64, uid_t, pid_t, const char *, scidx_t);
int reset_peak_delay(void);

u64 increment_curw_blocked(void);
u64 get_peakw_blocked(void);
u64 get_avgw_blocked(u64);

u64 compres_wstats_blocked(void);
int reset_stats_blocked(void);