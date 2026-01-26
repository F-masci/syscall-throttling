/**
 * @file monitor.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the monitoring mechanisms for the system call. It
 *        provides functions to enable and disable monitoring, manage invokation
 *        counts, and handle the monitor state. Also, it implements the syscall
 *        wrapper logic to enforce throttling based on the monitoring configuration.
 * 
 * @version 1.0
 * @date 2026-01-26
 * 
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/nospec.h>
#include <asm/barrier.h>

#ifdef _FTRACE_HOOKING
#include <linux/mutex.h>
#elif defined(_DISCOVER_HOOKING)
#endif

#include "monitor.h"
#include "hook.h"
#include "types.h"
#include "stats.h"
#include "filter.h"
#include "timer.h"

static wait_queue_head_t syscall_wqueue;
static atomic64_t invoks = ATOMIC64_INIT(0);

static bool unloading           = false;
static atomic_t active_threads  = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(unload_wqueue);

static bool status      = DEFAULT_STATUS;
static u64 max_invoks   = DEFAULT_MAX_INVOKS;
static bool fast_unload = DEFAULT_FAST_UNLOAD;

#ifdef _FTRACE_HOOKING
static DEFINE_MUTEX(minvoks_mutex);
static DEFINE_MUTEX(status_mutex);
#elif defined(_DISCOVER_HOOKING)
static DEFINE_RWLOCK(minvoks_lock);
static DEFINE_RWLOCK(status_lock);
#endif
static DEFINE_RWLOCK(fast_unload_lock);

static int __enable_monitoring(void);
static int __disable_monitoring(void);

/**
 * @brief Set the up monitor structure. Initialize wait queue and monitor parameters.
 * 
 * @return int 0 on success, negative error code on failure
 */
int setup_monitor(void) {

    init_waitqueue_head(&syscall_wqueue);
    PR_DEBUG("Initialized monitor wait queue\n");
    init_waitqueue_head(&unload_wqueue);
    PR_DEBUG("Initialized unload wait queue\n");

    return 0;
}

/**
 * @brief Cleanup the monitor structure. Set unloading flag and wake up wait queue.
 * 
 */
void cleanup_monitor(void) {
    unloading = true;
    mb();

    // Wake up all waiting threads to allow them to exit
    PR_DEBUG("Awakening monitor wait queue\n");
    wake_up_all(&syscall_wqueue);

    // Wait for incoming thread to enter syscall wrapper
    // This synchronization is necessary to avoid that threads who read
    // the hook address befeore it uninstallation, then try to use it after
    //
    // Whith this synchronization, we ensure that all threads that could
    // have read the hook address have already entered the syscall wrapper
    PR_DEBUG("Waiting for incoming threads to enter syscall wrapper\n");
    synchronize_rcu();

    // Wait for all active threads to exit
    PR_INFO("Waiting for %d active monitor threads started to exit...\n", atomic_read(&active_threads));
    wait_event(unload_wqueue, atomic_read(&active_threads) == 0);
    PR_INFO("All active monitor threads started to exit...\n");

    // Wait for exiting threads to exit syscall wrapper
    // This synchronization is necessary to avoid that threads that
    // are inside the syscall wrapper and are exiting aftere executing
    // the original syscall, could execute the return to the caller
    //
    // With this synchronization, we ensure that all threads that were
    // inside the syscall wrapper have already exited it
    PR_DEBUG("Waiting for outcoming threads to exit syscall wrapper\n");
    synchronize_rcu();

}


/**
 * @brief Get the monitor invoks count in current time window
 * 
 * @return u64 
 */
inline u64 get_curw_invoks(void) {
    return (u64) atomic64_read(&invoks);
}

/**
 * @brief Increment the monitor current invoks count
 * 
 * @return u64 New invoks count
 */
static inline u64 increment_curw_invoks(void) {
    return (u64) atomic64_inc_return(&invoks);
}

/**
 * @brief Reset the monitor invoks count to zero
 * 
 * @return u64 Previous invoks count
 */
inline u64 reset_curw_invoks(void) {
    return atomic64_xchg(&invoks, 0);
}


/**
 * @brief Get the monitor max invoks limit
 * 
 * @return unsigned long 
 */
inline u64 get_monitor_max_invoks(void) {
    return READ_ONCE(max_invoks);
}

/**
 * @brief Set the monitor max invoks limit. Resets stats during the change.
 * 
 * @param max New maximum invoks limit
 * @return int 0 on success, negative error code on failure
 */
int set_monitor_max_invoks(u64 max) {
#ifdef _FTRACE_HOOKING
#elif defined(_DISCOVER_HOOKING)
    unsigned long minvoks_flags;
    unsigned long status_flags;
#endif
    bool status;
    int ret = 0;

    // Check if the value is changing
    if(unlikely(max == get_monitor_max_invoks())) return 0;

#ifdef _FTRACE_HOOKING
    // Write the max_invoks under mutex
    mutex_lock(&minvoks_mutex);

    // Lock status to avoid changes during reset
    mutex_lock(&status_mutex);
#elif defined(_DISCOVER_HOOKING)
    // Write the max_invoks under write lock
    write_lock_irqsave(&minvoks_lock, minvoks_flags);

    // Lock status to avoid changes during reset
    write_lock_irqsave(&status_lock, status_flags);
#endif

    status = get_monitor_status();

    // Temporarily disable monitoring to avoid inconsistencies
    if(status) {
        ret = __disable_monitoring();
        if (ret) {
            PR_ERROR("Failed to disable monitor status before changing max invoks\n");
            goto disable_monitor_err;
        }
    }

    // Reset stats blocked count
    ret = reset_stats_blocked();
    if (ret) {
        PR_ERROR("Failed to reset stats blocked count after changing max invoks\n");
        goto reset_stats_err;
    }

    WRITE_ONCE(max_invoks, max);

reset_stats_err:

    // Restore previous monitor status
    if(status) {
        ret = __enable_monitoring();
        if (ret) {
            PR_ERROR("Failed to restore previous monitor status after changing max invoks\n");
            goto enable_monitor_err;
        }
    }

disable_monitor_err:
enable_monitor_err:
#ifdef _FTRACE_HOOKING
    mutex_unlock(&status_mutex);
    mutex_unlock(&minvoks_mutex);
#elif defined(_DISCOVER_HOOKING)
    write_unlock_irqrestore(&status_lock, status_flags);
    write_unlock_irqrestore(&minvoks_lock, minvoks_flags);
#endif

    return ret;
}


/**
 * @brief Get the monitor status (enabled/disabled)
 * 
 * @return bool 
 */
inline bool get_monitor_status(void) {
    return READ_ONCE(status);
}

/**
 * @brief Enable monitoring. Install all syscall hooks and starts the monitor timer.
 * 
 * @return int 0 on success, negative error code on failure
 */
static int enable_monitoring(void) {
#ifdef _FTRACE_HOOKING
#elif defined(_DISCOVER_HOOKING)
    unsigned long flags;
#endif
    int ret;

    // Write the status under write lock
#ifdef _FTRACE_HOOKING
    mutex_lock(&status_mutex);
#elif defined(_DISCOVER_HOOKING)
    write_lock_irqsave(&status_lock, flags);
#endif

    ret = __enable_monitoring();
    
#ifdef _FTRACE_HOOKING
    mutex_unlock(&status_mutex);
#elif defined(_DISCOVER_HOOKING)
    write_unlock_irqrestore(&status_lock, flags);
#endif

    return ret;
}

/**
 * @brief Internal function to enable monitoring. Assumes status_lock is held.
 * 
 * @return int 
 */
static int __enable_monitoring(void) {
    int ret;

    WRITE_ONCE(status, true);
    mb();

    // Re-add all hooks
    ret = install_monitored_syscalls_hooks();
    if (ret) {
        PR_ERROR("Failed to add all syscall hooks when enabling monitoring\n");
        return ret;
    }

    // Restart the monitor timer
    ret = start_monitor_timer();
    if (ret) {
        PR_ERROR("Failed to start monitor timer when enabling monitoring\n");
        goto start_timer_err;
    }

    return 0;

start_timer_err:

    WRITE_ONCE(status, false);
    mb();

    // Remove all hooks
    ret = uninstall_active_syscalls_hooks();
    if (ret) PR_ERROR("Failed to remove all syscall hooks when disabling monitoring\n");

    return ret;
}

/**
 * @brief Disable monitoring. Removes all syscall hooks and stops the monitor timer.
 * 
 * @return int 0 on success, negative error code on failure
 */
static int disable_monitoring(void) {
#ifdef _FTRACE_HOOKING
#elif defined(_DISCOVER_HOOKING)
    unsigned long flags;
#endif
    int ret;

    // Write the status under write lock
#ifdef _FTRACE_HOOKING
    mutex_lock(&status_mutex);
#elif defined(_DISCOVER_HOOKING)
    write_lock_irqsave(&status_lock, flags);
#endif

    ret = __disable_monitoring();
    
#ifdef _FTRACE_HOOKING
    mutex_unlock(&status_mutex);
#elif defined(_DISCOVER_HOOKING)
    write_unlock_irqrestore(&status_lock, flags);
#endif

    return ret;
}

/**
 * @brief Internal function to disable monitoring. Assumes status_lock is held.
 * 
 * @return int 
 */
static int __disable_monitoring(void) {
    int ret;

    WRITE_ONCE(status, false);
    mb();

    // Wake up all waiting threads to avoid deadlocks
    wake_up_all(&syscall_wqueue);

    // Remove all hooks
    ret = uninstall_active_syscalls_hooks();
    if (ret) {
        PR_ERROR("Failed to remove all syscall hooks when disabling monitoring\n");
        return ret;
    }

    // Stop the monitor timer
    ret = stop_monitor_timer();
    if (ret) {
        PR_ERROR("Failed to stop monitor timer when disabling monitoring\n");
        goto stop_timer_err;
    }

    return 0;

stop_timer_err:

    WRITE_ONCE(status, true);
    mb();

    // Re-add all hooks
    ret = install_monitored_syscalls_hooks();
    if (ret) PR_ERROR("Failed to re-add all syscall hooks when enabling monitoring\n");
    
    return ret;
} 

/**
 * @brief Set the monitor status (enabled/disabled)
 * 
 * @param s New status
 * @return int 0 on success, negative error code on failure
 */
inline int set_monitor_status(bool s) {
    if(unlikely(s == get_monitor_status())) return 0;
    PR_DEBUG("Changing monitor status to %s\n", s ? "ENABLED" : "DISABLED");
    return s ? enable_monitoring() : disable_monitoring();
}

/**
 * @brief Get the monitor fast unload setting
 * 
 * @return true 
 * @return false 
 */
inline bool get_monitor_fast_unload(void) {
    return READ_ONCE(fast_unload);
}

int set_monitor_fast_unload(bool fu) {
    unsigned long flags;

    // Check if the value is changing
    if(unlikely(fu == get_monitor_fast_unload())) return 0;

    // Write the fast_unload under write lock
    write_lock_irqsave(&fast_unload_lock, flags);
    WRITE_ONCE(fast_unload, fu);
    mb();
    write_unlock_irqrestore(&fast_unload_lock, flags);

    return 0;
}


/**
 * @brief Wake up threads in the monitor wait queue
 * 
 */
inline void wake_monitor_queue(void) {
    wake_up_nr(&syscall_wqueue, get_monitor_max_invoks());
}



/* ---- SYS CALL WRAPPER ---- */



#define START_TIMER(__start) do { __start = ktime_get(); } while(0)
#define END_TIMER(__end, __start, __time) \
    do { \
        (__end) = ktime_get(); \
        __time = ktime_to_ms(ktime_sub((__end), (__start))); \
        PR_DEBUG_PID("Resuming after %lld ms (%lld s)\n", __time, __time / 1000); \
    } while (0)
asmlinkage long syscall_wrapper(struct pt_regs *regs) {
    
    unsigned long original_addr;
    asmlinkage long (*syscall)(struct pt_regs *);
    scidx_t syscall_idx;

    ktime_t start, end;
    s64 delay_ms;

    bool inc_blocked = false;
    u64 current_val;
    long ret;

    atomic_inc(&active_threads);

    syscall_idx = (scidx_t) regs->orig_ax;
    if (unlikely(syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE)) {
        PR_ERROR_PID("Invalid syscall index %d\n", syscall_idx);
        ret = -ENOSYS;
        goto invalid_scidx;
    };
    syscall_idx = array_index_nospec(syscall_idx, SYSCALL_TABLE_SIZE);

    // Get original syscall address
    original_addr = get_original_syscall_address(syscall_idx);
    if(original_addr == (unsigned long) NULL) {
        PR_ERROR_PID("Failed to get original address for syscall %d\n", syscall_idx);
        ret = -EINVAL;
        goto invalid_original_addr;
    }
#ifdef _FTRACE_HOOKING
    // Sum to original_addr the offset of MCOUNT_INSN_SIZE to skip ftrace prologue.
    // This is necessary to avoid infinite recursion.
    original_addr += MCOUNT_INSN_SIZE;
#elif defined(_DISCOVER_HOOKING)
#else
#endif
    syscall = (asmlinkage long (*)(struct pt_regs *)) original_addr;

    PR_DEBUG_PID("Syscall %d invoked\n", syscall_idx);
    PR_DEBUG_PID("-> thread pid: %d\n", current->pid);
    PR_DEBUG_PID("-> uid: %d\n", current_uid().val);
    PR_DEBUG_PID("-> comm: %s\n", current->comm);

    PR_DEBUG_PID("-> total invocations: %llu\n", get_curw_invoks());
    
    // Check if throttling is enabled
    if(unlikely(!get_monitor_status())) {
        PR_DEBUG_PID("Throttling disabled, running syscall\n");
        goto run_syscall;
    }

    // Check if had to be monitored
    if(unlikely(!is_syscall_monitored(syscall_idx))) {
        PR_DEBUG_PID("Syscall %d not monitored\n", syscall_idx);
        goto run_syscall;
    }

    // Check if current UID and program is monitored
    if(!is_uid_monitored(current_euid().val) && !is_prog_monitored(current->comm)) {
        PR_DEBUG_PID("UID %d and program %s not monitored\n", current_euid().val, current->comm);
        goto run_syscall;
    }

    PR_DEBUG_PID("Throttling check for syscall %d\n", syscall_idx);
    START_TIMER(start);

    // Throttling logic
    while (1) {
        // Try to acquire a slot
        current_val = increment_curw_invoks();
        PR_DEBUG_PID("Slot acquired: %llu\n", current_val);

        // Check if we are within the limit
        if (likely(current_val <= get_monitor_max_invoks()))
            // SUCCESS: We acquired a slot
            goto allow_syscall;

        // FAILURE: We incremented, but the limit was already reached.
        if (!inc_blocked) {
            increment_curw_blocked();
            inc_blocked = true;
        }

        PR_DEBUG_PID("Limit reached (%llu >= %llu), sleeping...\n", current_val, get_monitor_max_invoks());

        // Wait until the next time window
        ret = wait_event_interruptible(syscall_wqueue, get_curw_invoks() < get_monitor_max_invoks() || !get_monitor_status() || unloading);
        
        PR_DEBUG_PID("Woke up from wait queue\n");

        if(unloading) {
            PR_INFO_PID("Module unloading while waiting\n");
            if(get_monitor_fast_unload()) {
                PR_INFO_PID("Fast unload enabled\n");
                ret = -EINTR;
                goto fast_unload_exit;
            }
            goto run_syscall;
        }
        
        if(!get_monitor_status()) {
            PR_DEBUG_PID("Throttling disabled while waiting\n");
            goto run_syscall;
        }

        if (ret != 0) {
            PR_DEBUG_PID("Interrupted by signal\n");
            goto signal_interrupted;
        }
        
        // If we reach here, we will try to increment again.
        PR_DEBUG_PID("Retrying to acquire slot...\n");

    }

allow_syscall:

    // We have acquired a slot
    PR_DEBUG_PID("Syscall %d allowed (slot %llu)\n", syscall_idx, current_val);
    
    END_TIMER(end, start, delay_ms);
    update_peak_delay(delay_ms, current_uid().val, current->pid, current->comm, syscall_idx);

run_syscall:
    if(unlikely(unloading)) PR_INFO_PID("Running syscall before module unload\n");
    ret = syscall(regs);

fast_unload_exit:
signal_interrupted:
invalid_scidx:
invalid_original_addr:

    // Decrement active threads count and wake up unload wait queue if needed
    if (atomic_dec_and_test(&active_threads)) wake_up(&unload_wqueue);
    if(unlikely(unloading)) PR_INFO_PID("Exiting syscall wrapper, active threads remaining: %d\n", atomic_read(&active_threads));

    return ret;

}