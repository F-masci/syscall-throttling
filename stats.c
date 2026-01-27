/**
 * @file stats.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the statistics gathering mechanisms for the
 *        system call throttling module. It tracks peak delayed syscalls,
 *        and counts of invoked and blocked threads per time window.
 * 
 * @version 1.0
 * @date 2026-01-26
 * 
 */

#include "stats.h"
#include "filter.h"

#ifdef _RCU_PROTECTED

struct peak_wrapper {
    struct rcu_head rcu;
    sysc_delayed_t data;
};

struct stats_wrapper {
    struct rcu_head rcu;
    wstats_t data;
};

static struct peak_wrapper __rcu *peakd_ptr  = NULL;
static struct stats_wrapper __rcu *stats_ptr = NULL;

#elif defined _SPINLOCK_PROTECTED

static sysc_delayed_t peak_ds   = {0};
static wstats_t wstats          = {0, 0, 0};

#endif

static DEFINE_RWLOCK(peakd_lock);
static DEFINE_RWLOCK(stats_lock);

static atomic64_t blocked_current_window = ATOMIC64_INIT(0);        // Number of blocked threads in the current time window

/* ---- PEAK DELAYED SYSCALL ---- */

/**
 * @brief Setup the monitor statistics structures
 * 
 * @return int 0 on success, negative error code on failure
 */
int setup_monitor_stats(void) {
#ifdef _RCU_PROTECTED
    struct peak_wrapper *init_peakd_ptr;
    struct stats_wrapper *init_stats_ptr;

    init_peakd_ptr = kzalloc(sizeof(struct peak_wrapper), GFP_KERNEL);
    if (!init_peakd_ptr) return -ENOMEM;
    init_peakd_ptr->data.syscall = -1; 
    
    init_stats_ptr = kzalloc(sizeof(struct stats_wrapper), GFP_KERNEL);
    if (!init_stats_ptr) {
        kfree(init_peakd_ptr);
        return -ENOMEM;
    }

    // Publish initial pointer
    RCU_INIT_POINTER(peakd_ptr, init_peakd_ptr);
    RCU_INIT_POINTER(stats_ptr, init_stats_ptr);
#else
#endif

    return 0;
}

/**
 * @brief Cleanup the monitor statistics structures
 * 
 */
void cleanup_monitor_stats(void) {
#ifdef _RCU_PROTECTED
    struct peak_wrapper *_peakd_ptr;
    struct stats_wrapper *_stats_ptr;

    // Cleanup peak delayed syscall structure
    _peakd_ptr = rcu_dereference_protected(peakd_ptr, true);
    if (_peakd_ptr) kfree_rcu(_peakd_ptr, rcu);
    RCU_INIT_POINTER(peakd_ptr, NULL);

    // Cleanup stats structure
    _stats_ptr = rcu_dereference_protected(stats_ptr, true);
    if (_stats_ptr) kfree_rcu(_stats_ptr, rcu);
    RCU_INIT_POINTER(stats_ptr, NULL);
#else
#endif
}

/**
 * @brief Get the peak delayed syscall info
 * 
 * @param _out Output structure to fill with peak delayed syscall info
 */
void get_peak_delayed_syscall(sysc_delayed_t *_out) {
#ifdef _RCU_PROTECTED
    struct peak_wrapper *peak_ptr;
#elif defined _SPINLOCK_PROTECTED
    unsigned long flags;
#endif

    // Safety check
    if(!_out) return;

    // Copy data to output buffer
#ifdef _RCU_PROTECTED
    rcu_read_lock();
    peak_ptr = rcu_dereference(peakd_ptr);
    if(peak_ptr) memcpy(_out, &peak_ptr->data, sizeof(sysc_delayed_t));
    rcu_read_unlock();
#elif defined _SPINLOCK_PROTECTED
    read_lock_irqsave(&peakd_lock, flags);
    memcpy(_out, &peak_ds, sizeof(sysc_delayed_t));
    read_unlock_irqrestore(&peakd_lock, flags);
#endif
}

// Fast path minimum delay threshold
// This avoids taking the lock for negligible delays
#define MIN_DELAY_MS 0
/**
 * @brief Update the peak delayed syscall info if the new delay is greater than the current peak
 * 
 * @param delay_ms Delay in milliseconds
 * @param syscall Syscall number
 * 
 * @return bool True if updated, false otherwise
 */
bool update_peak_delay(s64 delay_ms, scidx_t syscall) {

    unsigned long flags;
    char * prog_name = NULL;
    bool updated = false;
#ifdef _RCU_PROTECTED
    struct peak_wrapper *old_peak_ptr, *new_peak_ptr;
#else
#endif

    // Fast check without lock
    if(likely(delay_ms <= MIN_DELAY_MS)) return updated;
#ifdef _RCU_PROTECTED
    old_peak_ptr = rcu_access_pointer(peakd_ptr);
    if (likely(old_peak_ptr && delay_ms <= old_peak_ptr->data.delay_ms)) return false;
#elif defined _SPINLOCK_PROTECTED
    if(likely(delay_ms <= peak_ds.delay_ms)) return updated;
#endif

    // Allocate new peak structure
#ifdef _RCU_PROTECTED
    new_peak_ptr = kzalloc(sizeof(struct peak_wrapper), GFP_ATOMIC);
    if (!new_peak_ptr) return false;
#else
#endif

    write_lock_irqsave(&peakd_lock, flags);

#ifdef _RCU_PROTECTED
    // Re-check with lock
    old_peak_ptr = rcu_dereference_protected(peakd_ptr, lockdep_is_held(&peakd_lock));
    PR_DEBUG("Checking for peak delayed syscall update: current peak %lld ms, new delay %lld ms\n", old_peak_ptr->data.delay_ms, delay_ms);
    if (likely(old_peak_ptr && delay_ms > old_peak_ptr->data.delay_ms)) {
        // Free old program name
        if (old_peak_ptr->data.prog_name) {
            kfree(old_peak_ptr->data.prog_name);
            old_peak_ptr->data.prog_name = NULL;
        }
#elif defined _SPINLOCK_PROTECTED
    // Re-check with lock
    PR_DEBUG("Checking for peak delayed syscall update: current peak %lld ms, new delay %lld ms\n", peak_ds.delay_ms, delay_ms);
    if (likely(delay_ms > peak_ds.delay_ms)) {
        // Free old program name
        if (peak_ds.prog_name) {
            kfree(peak_ds.prog_name);
            peak_ds.prog_name = NULL;
        }
#endif

        // Get program name
        task_lock(current);
        prog_name = get_exe_path(current->mm->exe_file);
        if (!prog_name) {
            PR_WARN_PID("Failed to get program name for peak delayed syscall update\n");
            prog_name = kstrdup("N/A", GFP_ATOMIC);
            if (!prog_name) {
#ifdef _RCU_PROTECTED
                kfree(new_peak_ptr);
#elif defined _SPINLOCK_PROTECTED
#endif
                updated = false;
                goto alloc_proc_err;
            }
        }
        task_unlock(current);

#ifdef _RCU_PROTECTED
        new_peak_ptr->data.delay_ms = delay_ms;
        new_peak_ptr->data.uid = current_euid().val;
        new_peak_ptr->data.prog_name = prog_name;
        new_peak_ptr->data.syscall = syscall;

        // Publish new peak pointer
        rcu_assign_pointer(peakd_ptr, new_peak_ptr);

        // Free old peak after a grace period
        if (old_peak_ptr) kfree_rcu(old_peak_ptr, rcu);
#elif defined _SPINLOCK_PROTECTED
        peak_ds.delay_ms = delay_ms;
        peak_ds.uid = current_euid().val;
        peak_ds.prog_name = prog_name;
        peak_ds.syscall = syscall;
#endif

        PR_DEBUG("Updated peak delayed syscall: prog_name=%s, euid=%d, syscall=%d, delay_ms=%lld\n", prog_name, current_euid().val, syscall, delay_ms);

        updated = true;
    }
#ifdef _RCU_PROTECTED
    else {
        kfree(new_peak_ptr);
    }
#elif defined _SPINLOCK_PROTECTED
#endif

alloc_proc_err:
    write_unlock_irqrestore(&peakd_lock, flags);

    return updated;
}
#undef MIN_DELAY_MS

/**
 * @brief Reset the peak delayed syscall info
 * 
 */
int reset_peak_delay(void) {
    unsigned long flags;
#ifdef _RCU_PROTECTED
    struct peak_wrapper *old_peak_ptr, *new_peak_ptr;

    new_peak_ptr = kzalloc(sizeof(struct peak_wrapper), GFP_ATOMIC);
    if (!new_peak_ptr) return -ENOMEM;
    new_peak_ptr->data.syscall = -1;
#else
#endif
    
    write_lock_irqsave(&peakd_lock, flags);

    // Publish new peak pointer
#ifdef _RCU_PROTECTED
    old_peak_ptr = rcu_dereference_protected(peakd_ptr, lockdep_is_held(&peakd_lock));
    rcu_assign_pointer(peakd_ptr, new_peak_ptr);
    if (old_peak_ptr) kfree_rcu(old_peak_ptr, rcu);
#elif defined _SPINLOCK_PROTECTED
    memset(&peak_ds, 0, sizeof(sysc_delayed_t));
    peak_ds.syscall = -1;
#endif
    
    write_unlock_irqrestore(&peakd_lock, flags);

    return 0;
}

/* ---- CURRENT WINDOW COUNTERS ---- */

/**
 * @brief Increment the current window blocked counter
 * 
 * @return u64 The new value of the blocked counter
 */
u64 increment_curw_blocked(void) {
    return (u64) atomic64_inc_return(&blocked_current_window);
}

/**
 * @brief Compute and update the statistics for blocked threads,
 * and reset current window counters
 * 
 * @return u64 The old value of the blocked counter before reset
 */
u64 compres_wstats_blocked(void) {

    unsigned long flags;
    u64 curr_blocked;
#ifdef _RCU_PROTECTED
    struct stats_wrapper *old_stats_ptr, *new_stats_ptr;
#else
#endif

    // Atomically get and reset the current window blocked count
    curr_blocked = atomic64_xchg(&blocked_current_window, 0);

    // Allocate new stats structure
#ifdef _RCU_PROTECTED
    new_stats_ptr = kzalloc(sizeof(struct stats_wrapper), GFP_ATOMIC);
    if (!new_stats_ptr) return curr_blocked;
#else
#endif

    write_lock_irqsave(&stats_lock, flags);

#ifdef _RCU_PROTECTED

    // Get old stats
    old_stats_ptr = rcu_dereference_protected(stats_ptr, lockdep_is_held(&stats_lock));
    if(old_stats_ptr) {
        new_stats_ptr->data.max_blocked_threads = old_stats_ptr->data.max_blocked_threads;
        new_stats_ptr->data.sum_blocked_threads = old_stats_ptr->data.sum_blocked_threads;
        new_stats_ptr->data.total_windows_count = old_stats_ptr->data.total_windows_count;
    }

    // Update peak blocked threads if current is greater
    if (curr_blocked > new_stats_ptr->data.max_blocked_threads)
        new_stats_ptr->data.max_blocked_threads = curr_blocked;

    // Update sum and window count for average calculation
    new_stats_ptr->data.sum_blocked_threads += curr_blocked;
    new_stats_ptr->data.total_windows_count++;

    // Publish new stats pointer
    rcu_assign_pointer(stats_ptr, new_stats_ptr);

    // Free old stats after a grace period
    if (old_stats_ptr) kfree_rcu(old_stats_ptr, rcu);

#elif defined _SPINLOCK_PROTECTED

    // Update peak blocked threads if current is greater
    if (curr_blocked > wstats.max_blocked_threads)
        wstats.max_blocked_threads = curr_blocked;

    // Update sum and window count for average calculation
    wstats.sum_blocked_threads += curr_blocked;
    wstats.total_windows_count++;

#endif

    write_unlock_irqrestore(&stats_lock, flags);

    return curr_blocked;
}

/**
 * @brief Get the peakw blocked count
 * 
 * @return u64 
 */
u64 get_peakw_blocked(void) {
    u64 ret;

#ifdef _RCU_PROTECTED
    struct stats_wrapper *sptr;
    rcu_read_lock();
    sptr = rcu_dereference(stats_ptr);
    if (sptr) ret = sptr->data.max_blocked_threads;
    else ret = 0;
    rcu_read_unlock();
#elif defined _SPINLOCK_PROTECTED
    unsigned long flags;
    read_lock_irqsave(&stats_lock, flags);
    ret = wstats.max_blocked_threads;
    read_unlock_irqrestore(&stats_lock, flags);
#endif

    return ret;
}

/**
 * @brief Get the average blocked count scaled by the given factor
 * Example: with scale = 100 (for percentage), if the average is 2.5 returns 250.
 * 
 * @param scale Scaling factor
 * 
 * @return u64 
 */
u64 get_avgw_blocked(u64 scale) {
    u64 sum, count;
#ifdef _RCU_PROTECTED
    struct stats_wrapper *sptr;
#elif defined _SPINLOCK_PROTECTED
    unsigned long flags;
#endif
    
#ifdef _RCU_PROTECTED
    rcu_read_lock();
    sptr = rcu_dereference(stats_ptr);
    if (sptr) {
        sum = sptr->data.sum_blocked_threads;
        count = sptr->data.total_windows_count;
    }
    rcu_read_unlock();

#elif defined _SPINLOCK_PROTECTED
    read_lock_irqsave(&stats_lock, flags);
    sum = wstats.sum_blocked_threads;
    count = wstats.total_windows_count;
    read_unlock_irqrestore(&stats_lock, flags);
#endif

    if(scale <= 0) scale = 1;

    if (count == 0) return 0;
    return (sum * scale) / count;
}

/**
 * @brief Get statistics for blocked threads on time windows
 * 
 * @param peak_blocked Pointer to store max blocked threads (can be NULL)
 * @param avg_blocked Pointer to store average blocked threads (can be NULL)
 * @param windows_num Time windows counter (can be NULL)
 * @param scale Scaling factor for average
 */
void get_stats_blocked(u64 *peak_blocked, u64 *avg_blocked, u64 * windows_num, u64 scale) {
#ifdef _RCU_PROTECTED
    struct stats_wrapper *sptr;
#elif defined _SPINLOCK_PROTECTED
    unsigned long flags;
#endif

    // Early exit if no data requested
    if(!peak_blocked && !avg_blocked) return;

    // Sanitize scale
    if(scale <= 0) scale = 1;

    // Initialize outputs
    if(peak_blocked) *peak_blocked = 0;
    if(avg_blocked) *avg_blocked = 0;

#ifdef _RCU_PROTECTED
    rcu_read_lock();
    sptr = rcu_dereference(stats_ptr);
    if (sptr) {
        if(windows_num)
            *windows_num = sptr->data.total_windows_count;

        if (peak_blocked)
            *peak_blocked = sptr->data.max_blocked_threads;

        if (avg_blocked) {
            if (sptr->data.total_windows_count == 0)
                *avg_blocked = 0;
            else
                *avg_blocked = (sptr->data.sum_blocked_threads * scale) / sptr->data.total_windows_count;
        }
    }
    rcu_read_unlock();

#elif defined _SPINLOCK_PROTECTED
    read_lock_irqsave(&stats_lock, flags);
    if(windows_num)
        *windows_num = wstats.total_windows_count;

    if (peak_blocked)
        *peak_blocked = wstats.max_blocked_threads;

    if (avg_blocked) {
        if (wstats.total_windows_count == 0)
            *avg_blocked = 0;
        else
            *avg_blocked = (wstats.sum_blocked_threads * scale) / wstats.total_windows_count;
    }
    read_unlock_irqrestore(&stats_lock, flags);
#endif
}

/**
 * @brief Reset all blocked statistics on time windows
 * 
 */
int reset_stats_blocked(void) {
    unsigned long flags;
#ifdef _RCU_PROTECTED
    struct stats_wrapper *new_stats, *old_stats;
#else
#endif
    
    // Reset the atomic counters (current window)
    atomic64_set(&blocked_current_window, 0);

#ifdef _RCU_PROTECTED
    // Allocate new stats structure
    new_stats = kzalloc(sizeof(struct stats_wrapper), GFP_ATOMIC);
    if (!new_stats) return -ENOMEM;
#else
#endif

    write_lock_irqsave(&stats_lock, flags);

#ifdef _RCU_PROTECTED
    // Get old stats
    old_stats = rcu_dereference_protected(stats_ptr, lockdep_is_held(&stats_lock));

    // Publish new stats pointer
    rcu_assign_pointer(stats_ptr, new_stats);

    // Free old stats after a grace period
    if (old_stats) kfree_rcu(old_stats, rcu);

#elif defined _SPINLOCK_PROTECTED
    memset(&wstats, 0, sizeof(wstats_t));
#endif

    write_unlock_irqrestore(&stats_lock, flags);

    return 0;
}