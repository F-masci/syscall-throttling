#include <linux/types.h>

#include "types.h"

sct_sys_delayed_t * get_peak_delayed_syscall(void);
void update_peak_delay(s64, uid_t, pid_t, const char *, scidx_t);
void reset_peak_delay(void);

u64 increment_curw_invoked(void);
u64 increment_curw_blocked(void);
u64 get_peakw_invoked(void);
u64 get_peakw_blocked(void);
u64 get_avgw_invoked(void);
u64 get_avgw_blocked(void);

void compute_stats_blocked(void);
void reset_stats_blocked(void);