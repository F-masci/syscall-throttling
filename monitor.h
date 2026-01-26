#pragma once

#include "sct.h"

int setup_monitor(void);
void cleanup_monitor(void);

inline u64 get_curw_invoks(void);
inline u64 reset_curw_invoks(void);

inline u64 get_monitor_max_invoks(void);
int set_monitor_max_invoks(u64);

inline bool get_monitor_status(void);
inline int set_monitor_status(bool);

inline bool get_monitor_fast_unload(void);
int set_monitor_fast_unload(bool);

inline void wake_monitor_queue(void);

asmlinkage long syscall_wrapper(struct pt_regs *);