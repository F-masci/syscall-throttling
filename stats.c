#include <linux/types.h>
#include <linux/sched.h>

#include "module.h"
#include "stats.h"
#include "types.h"

static sct_stats_t sct_stats = {0, 0};
static sct_sys_delayed_t peak_delayed_syscall = {0, "\0", -1, 0, 0};

sct_sys_delayed_t * get_peak_delayed_syscall(void) {
    return &peak_delayed_syscall;
}

void update_peak_delay(s64 delay_ms, uid_t uid, pid_t pid, const char *prog_name, scidx_t syscall) {
    if (delay_ms > peak_delayed_syscall.timestamp_ns) {
        peak_delayed_syscall.timestamp_ns = delay_ms;
        peak_delayed_syscall.uid = uid;
        peak_delayed_syscall.pid = pid;
        strncpy(peak_delayed_syscall.prog_name, prog_name, TASK_COMM_LEN);
        peak_delayed_syscall.syscall = syscall;

        printk(KERN_INFO "%s: Updated peak delayed syscall: pid=%d, prog_name=%s, uid=%d, syscall=%d, delay_ms=%lld\n", MODULE_NAME, pid, prog_name, uid, syscall, delay_ms);

    }
}

void reset_peak_delay(void) {
    peak_delayed_syscall.timestamp_ns = 0;
    peak_delayed_syscall.uid = 0;
    peak_delayed_syscall.pid = 0;
    memset(peak_delayed_syscall.prog_name, 0, TASK_COMM_LEN);
    peak_delayed_syscall.syscall = -1;
}





u64 increment_curw_invoked(void) {
    return __sync_add_and_fetch(&sct_stats.invocked_current_window, 1);
}

u64 increment_curw_blocked(void) {
    return __sync_add_and_fetch(&sct_stats.blocked_current_window, 1);
}

void compute_stats_blocked(void) {
    // Update historical statistics
    if (sct_stats.blocked_current_window > sct_stats.max_blocked_threads) {
        sct_stats.max_blocked_threads = sct_stats.blocked_current_window;
    }
    if (sct_stats.invocked_current_window > sct_stats.max_invocked_threads) {
        sct_stats.max_invocked_threads = sct_stats.invocked_current_window;
    }

    // Update sum and count
    sct_stats.sum_invocked_threads += sct_stats.invocked_current_window;
    sct_stats.sum_blocked_threads += sct_stats.blocked_current_window;

    sct_stats.invocked_current_window = 0;
    sct_stats.blocked_current_window = 0;

    sct_stats.total_windows_count += 1;
}

u64 get_peakw_invoked(void) {
    return sct_stats.max_invocked_threads;
}

u64 get_peakw_blocked(void) {
    return sct_stats.max_blocked_threads;
}

u64 get_avgw_invoked(void) {
    if (sct_stats.total_windows_count == 0) return 0;
    return sct_stats.sum_invocked_threads / sct_stats.total_windows_count;
}

u64 get_avgw_blocked(void) {
    if (sct_stats.total_windows_count == 0) return 0;
    return sct_stats.sum_blocked_threads / sct_stats.total_windows_count;
}

void reset_stats_blocked(void) {
    sct_stats.invocked_current_window = 0;
    sct_stats.blocked_current_window = 0;
    sct_stats.max_invocked_threads = 0;
    sct_stats.max_blocked_threads = 0;
    sct_stats.sum_invocked_threads = 0;
    sct_stats.sum_blocked_threads = 0;
    sct_stats.total_windows_count = 0;
}