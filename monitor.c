#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/nospec.h>

#include "monitor.h"
#include "hook.h"
#include "types.h"
#include "stats.h"
#include "filter.h"

static wait_queue_head_t wqueue;
static atomic64_t invoks = ATOMIC64_INIT(0);

static bool unloading = false;

static bool status = true;
static u64 max_invoks = 5;


/**
 * @brief Set the up monitor structure. Initialize wait queue and monitor parameters.
 * 
 */
void setup_monitor(void) {
    init_waitqueue_head(&wqueue);
    PR_DEBUG("Initialized monitor wait queue\n");
}

/**
 * @brief Cleanup the monitor structure. Set unloading flag and wake up wait queue.
 * 
 */
void cleanup_monitor(void) {
    unloading = true;
    PR_DEBUG("Awakening monitor wait queue\n");
    wake_up_all(&wqueue);
}

/**
 * @brief Get the monitor invoks count in current time window
 * 
 * @return u64 
 */
inline u64 get_monitor_cur_invoks(void) {
    return atomic64_read(&invoks);
}

/**
 * @brief Get the monitor max invoks limit
 * 
 * @return unsigned long 
 */
inline u64 get_monitor_max_invoks(void) {
    return max_invoks;
}

/**
 * @brief Set the monitor max invoks limit
 * 
 * @param _max_invoks New maximum invoks limit
 * @return u64 Previous max invoks limit
 */
inline u64 set_monitor_max_invoks(u64 _max_invoks) {
    u64 old = max_invoks;
    max_invoks = _max_invoks;
    return old;
}

/**
 * @brief Get the monitor status (enabled/disabled)
 * 
 * @return bool 
 */
inline bool get_monitor_status(void) {
    return status;
}

/**
 * @brief Set the monitor status (enabled/disabled)
 * 
 * @param _status New status
 * @return bool Previous status
 */
inline bool set_monitor_status(bool _status) {
    bool old = status;
    status = _status;
    return old;
}

/**
 * @brief Reset the monitor invoks count to zero
 * 
 * @return u64 Previous invoks count
 */
inline u64 reset_monitor_invoks(void) {
    return atomic64_xchg(&invoks, 0);
}

/**
 * @brief Wake up the monitor wait queue
 * 
 */
inline void wake_monitor_queue(void) {
    wake_up_all(&wqueue);
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
    
    asmlinkage long (*syscall)(struct pt_regs *);

    ktime_t start, end;
    s64 delay_ms;
    bool inc_blocked = false;

    long ret;
    u64 current_val;

    scidx_t syscall_idx = (scidx_t) regs->orig_ax;
    if (syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE) return -ENOSYS;
    syscall_idx = array_index_nospec(syscall_idx, SYSCALL_TABLE_SIZE);

    // Handle special syscalls that should not be throttled
    if (syscall_idx == __NR_rt_sigreturn || 
        syscall_idx == __NR_exit || 
        syscall_idx == __NR_exit_group) {
        goto run_syscall;
    }

#ifdef FTRACE_HOOKING
    // Sum to original_addr the offset of MCOUNT_INSN_SIZE to skip ftrace prologue.
    // This is necessary to avoid infinite recursion.
    syscall = (void *)(get_original_syscall_address(syscall_idx) + MCOUNT_INSN_SIZE);
#else
    syscall = (void *)(get_original_syscall_address(syscall_idx));
#endif

    PR_DEBUG_PID("Syscall %d invoked\n", syscall_idx);
    PR_DEBUG_PID("-> thread pid: %d\n", current->pid);
    PR_DEBUG_PID("-> uid: %d\n", current_uid().val);
    PR_DEBUG_PID("-> comm: %s\n", current->comm);

    PR_DEBUG_PID("-> total invocations: %llu\n", get_monitor_cur_invoks());
    
    // Check if throttling is enabled
    // Could be removed because we hook only when enabled
    if(!status) {
        PR_WARN_PID("Throttling disabled, running syscall\n");
        goto run_syscall;
    }

    // Check if had to be monitored
    // Could be removed because we use separate wrappers per syscall
    if(!is_syscall_monitored(syscall_idx)) {
        PR_WARN_PID("Syscall %d not monitored\n", syscall_idx);
        goto run_syscall;
    }

    // Check if current UID and program is monitored
    if(!is_uid_monitored(current_uid().val) && !is_prog_monitored(current->comm)) {
        PR_DEBUG_PID("UID %d and program %s not monitored\n", current_uid().val, current->comm);
        goto run_syscall;
    }

    PR_DEBUG_PID("Throttling check for syscall %d\n", syscall_idx);
    increment_curw_invoked();
    START_TIMER(start);

    // Throttling logic
    while (1) {
        // Try to acquire a slot
        current_val = atomic64_inc_return(&invoks);
        PR_DEBUG_PID("Slot acquired: %llu\n", current_val);

        // Check if we are within the limit
        if (current_val <= max_invoks)
            // SUCCESS: We acquired a slot
            goto allow_syscall;

        // FAILURE: We incremented, but the limit was already reached.
        if (!inc_blocked) {
            increment_curw_blocked();
            inc_blocked = true;
        }

        PR_DEBUG_PID("Limit reached (%llu >= %llu), sleeping...\n", current_val, max_invoks);

        // Decrement the counter as we failed to acquire a slot and will wait.
        atomic64_dec(&invoks);
        ret = wait_event_interruptible(wqueue, atomic64_read(&invoks) < max_invoks || unloading);
        
        PR_DEBUG_PID("Woke up from wait queue\n");

        if(unloading) {
            PR_INFO_PID("Module unloading, running syscall\n");
            goto run_syscall;
        }

        if (ret != 0) {
            PR_DEBUG_PID("Interrupted by signal\n");
            return ret;
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
    return syscall(regs);
}