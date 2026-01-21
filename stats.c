/**
 * @file stats.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the statistics gathering mechanisms for the
 *        system call throttling module. It tracks peak delayed syscalls,
 *        and counts of invoked and blocked threads per time window.
 * 
 * @version 1.0
 * @date 2026-01-21
 * 
 */

#include "stats.h"

static DEFINE_SPINLOCK(stats_lock);

static sysc_delayed_t peak_delayed_syscall = {0, "\0", -1, 0, 0};

static atomic64_t invoked_current_window = ATOMIC64_INIT(0);        // Number of invocations in the current time window
static atomic64_t blocked_current_window = ATOMIC64_INIT(0);        // Number of blocked threads in the current time window

// For historical statistics
// To compute average <invocked|blocked> threads per window:
//   avg = sum_<invocked|blocked>_threads / total_windows_count
u64 max_invocked_threads;          // Peak number of invocations observed in a single time window
u64 max_blocked_threads;           // Peak number of blocked threads observed in a single time window
u64 sum_invocked_threads;          // Total sum of invocations in all windows (for the average)
u64 sum_blocked_threads;           // Total sum of blocked threads in all windows (for the average)
u64 total_windows_count;           // Number of windows considered

/* ---- PEAK DELAYED SYSCALL ---- */

/**
 * @brief Get the peak delayed syscall info
 * 
 * @param _out Output structure to fill with peak delayed syscall info
 */
void get_peak_delayed_syscall(sysc_delayed_t *_out) {
    unsigned long flags;
    spin_lock_irqsave(&stats_lock, flags);
    memcpy(_out, &peak_delayed_syscall, sizeof(sysc_delayed_t));
    spin_unlock_irqrestore(&stats_lock, flags);
}

#define MIN_DELAY_MS 0
/**
 * @brief Update the peak delayed syscall info if the new delay is greater than the current peak
 * 
 * @param delay_ms Delay in milliseconds
 * @param uid UID of the process
 * @param pid PID of the process
 * @param prog_name Program name
 * @param syscall Syscall number
 * 
 * @return bool True if updated, false otherwise
 */
bool update_peak_delay(s64 delay_ms, uid_t uid, pid_t pid, const char *prog_name, scidx_t syscall) {

    unsigned long flags;
    bool updated = false;

    // Fast check without lock
    if(delay_ms <= MIN_DELAY_MS) return updated;
    if(delay_ms <= peak_delayed_syscall.delay_ms) return updated;

    spin_lock_irqsave(&stats_lock, flags);

    // Re-check with lock
    PR_DEBUG("Checking for peak delayed syscall update: current peak %lld ms, new delay %lld ms\n", peak_delayed_syscall.delay_ms, delay_ms);
    if (delay_ms > peak_delayed_syscall.delay_ms) {
        peak_delayed_syscall.delay_ms = delay_ms;
        peak_delayed_syscall.uid = uid;
        peak_delayed_syscall.pid = pid;
        strscpy(peak_delayed_syscall.prog_name, prog_name, TASK_COMM_LEN);
        peak_delayed_syscall.syscall = syscall;

        PR_DEBUG("Updated peak delayed syscall: pid=%d, prog_name=%s, uid=%d, syscall=%d, delay_ms=%lld\n", pid, prog_name, uid, syscall, delay_ms);

        updated = true;
    }

    spin_unlock_irqrestore(&stats_lock, flags);

    return updated;
}
#undef MIN_DELAY_MS

/**
 * @brief Reset the peak delayed syscall info
 * 
 */
void reset_peak_delay(void) {
    unsigned long flags;

    spin_lock_irqsave(&stats_lock, flags);
    peak_delayed_syscall.delay_ms = 0;
    peak_delayed_syscall.uid = 0;
    peak_delayed_syscall.pid = 0;
    memset(peak_delayed_syscall.prog_name, 0, TASK_COMM_LEN);
    peak_delayed_syscall.syscall = -1;
    spin_unlock_irqrestore(&stats_lock, flags);
}

/* ---- CURRENT WINDOW COUNTERS ---- */

/**
 * @brief Increment the current window invoked counter
 * 
 * @return u64 The new value of the invoked counter
 */
u64 increment_curw_invoked(void) {
    return (u64) atomic64_inc_return(&invoked_current_window);
}

/**
 * @brief Increment the current window blocked counter
 * 
 * @return u64 The new value of the blocked counter
 */
u64 increment_curw_blocked(void) {
    return (u64) atomic64_inc_return(&blocked_current_window);
}

/**
 * @brief Compute and update the statistics for blocked and invoked threads,
 * and reset current window counters
 * 
 */
void compute_stats_blocked(void) {

    unsigned long flags;
    u64 curr_invoked, curr_blocked;

    curr_invoked = atomic64_xchg(&invoked_current_window, 0);
    curr_blocked = atomic64_xchg(&blocked_current_window, 0);

    spin_lock_irqsave(&stats_lock, flags);

    if (curr_blocked > max_blocked_threads)
        max_blocked_threads = curr_blocked;

    if (curr_invoked > max_invocked_threads)
        max_invocked_threads = curr_invoked;

    sum_invocked_threads += curr_invoked;
    sum_blocked_threads += curr_blocked;
    total_windows_count++;

    spin_unlock_irqrestore(&stats_lock, flags);
}

/**
 * @brief Get the peakw invoked count
 * 
 * @return u64
 */
u64 get_peakw_invoked(void) {
    unsigned long flags;
    u64 ret;
    spin_lock_irqsave(&stats_lock, flags);
    ret = max_invocked_threads;
    spin_unlock_irqrestore(&stats_lock, flags);
    return ret;
}

/**
 * @brief Get the peakw blocked count
 * 
 * @return u64 
 */
u64 get_peakw_blocked(void) {
    unsigned long flags;
    u64 ret;
    spin_lock_irqsave(&stats_lock, flags);
    ret = max_blocked_threads;
    spin_unlock_irqrestore(&stats_lock, flags);
    return ret;
}

/**
 * @brief Get the avgw invoked count
 * 
 * @return u64 
 */
u64 get_avgw_invoked(void) {
    unsigned long flags;
    u64 sum, count;
    
    spin_lock_irqsave(&stats_lock, flags);
    sum = sum_invocked_threads;
    count = total_windows_count;
    spin_unlock_irqrestore(&stats_lock, flags);

    if (count == 0) return 0;
    return sum / count;
}

/**
 * @brief Get the avgw blocked count
 * 
 * @return u64 
 */
u64 get_avgw_blocked(void) {
    unsigned long flags;
    u64 sum, count;
    
    spin_lock_irqsave(&stats_lock, flags);
    sum = sum_blocked_threads;
    count = total_windows_count;
    spin_unlock_irqrestore(&stats_lock, flags);

    if (count == 0) return 0;
    return sum / count;
}

/**
 * @brief Reset all blocked/invoked statistics
 * 
 */
void reset_stats_blocked(void) {
    unsigned long flags;
    
    // Reset the atomic counters (current window)
    atomic64_set(&invoked_current_window, 0);
    atomic64_set(&blocked_current_window, 0);

    // Reset the history under lock
    spin_lock_irqsave(&stats_lock, flags);
    max_invocked_threads = 0;
    max_blocked_threads = 0;
    sum_invocked_threads = 0;
    sum_blocked_threads = 0;
    total_windows_count = 0;
    spin_unlock_irqrestore(&stats_lock, flags);
}