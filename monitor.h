#pragma once

#include "sct.h"

int setup_monitor(void);
void cleanup_monitor(void);

u64 get_curw_invoks(void);
u64 reset_curw_invoks(void);

u64 get_monitor_max_invoks(void);
int set_monitor_max_invoks(u64 max);

bool get_monitor_status(void);
int set_monitor_status(bool s);

bool get_monitor_fast_unload(void);
int set_monitor_fast_unload(bool fu);

void wake_monitor_queue(void);

asmlinkage long syscall_wrapper(struct pt_regs *regs);
