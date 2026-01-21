#pragma once

#include "sct.h"

void setup_monitor(void);
void cleanup_monitor(void);

inline u64 get_monitor_cur_invoks(void);
inline u64 get_monitor_max_invoks(void);
inline u64 set_monitor_max_invoks(u64);
inline bool get_monitor_status(void);
inline bool set_monitor_status(bool);

inline u64 reset_monitor_invoks(void);
inline void wake_monitor_queue(void);

long syscall_wrapper(struct pt_regs *);