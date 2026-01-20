#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "sct.h"
#include "monitor.h"
#include "types.h"
#include "stats.h"
#include "filter.h"

extern hook_syscall_t * syscall_hooks;

sct_monitor_t sct_monitor;
extern unsigned long sct_max_invoks;
extern bool sct_status;

void setup_monitor(void) {
    init_waitqueue_head(&sct_monitor.wqueue);
    PR_DEBUG("Wait queue initialized\n");
    sct_monitor.unloading = false;
    sct_monitor.invoks = 0;
}

void cleanup_monitor(void) {
    sct_monitor.unloading = true;
    PR_DEBUG("Setting unloading flag to true\n");
    wake_up_interruptible(&sct_monitor.wqueue);
    PR_DEBUG("Wait queue awakened\n");
}

#define START_TIMER(__start) do { __start = ktime_get(); } while(0)
#define END_TIMER(__end, __start, __time) \
    do { \
        (__end) = ktime_get(); \
        __time = ktime_to_ms(ktime_sub((__end), (__start))); \
        PR_DEBUG_PID("Resuming after %lld ms (%lld s)\n", __time, __time / 1000); \
    } while (0)
asmlinkage long syscall_wrapper(struct pt_regs *regs) {
    
    ktime_t start, end;
    s64 delay_ms;
    bool inc_blocked = false;

    long ret;
    u64 current_val;

    // Sum to original_addr the offset of MCOUNT_INSN_SIZE to skip ftrace prologue.
    // This is necessary to avoid infinite recursion.
    asmlinkage long (*syscall)(struct pt_regs *) = (void *)(syscall_hooks[regs->orig_ax].original_addr + MCOUNT_INSN_SIZE);

    PR_DEBUG_PID("Syscall %ld invoked\n", regs->orig_ax);
    PR_DEBUG_PID("-> thread pid: %d\n", current->pid);
    PR_DEBUG_PID("-> uid: %d\n", current_uid().val);
    PR_DEBUG_PID("-> comm: %s\n", current->comm);

    PR_DEBUG_PID("-> total invocations: %llu\n", sct_monitor.invoks);
    
    // Check if throttling is enabled
    // Could be removed because we hook only when enabled
    if(!sct_status) {
        PR_WARN_PID("Throttling disabled, running syscall\n");
        goto run_syscall;
    }

    // Check if had to be monitored
    // Could be removed because we use separate wrappers per syscall
    if(!is_syscall_monitored(regs->orig_ax)) {
        PR_WARN_PID("Syscall %ld not monitored\n", regs->orig_ax);
        goto run_syscall;
    }

    // Check if current UID and program is monitored
    if(!is_uid_monitored(current_uid().val) && !is_prog_monitored(current->comm)) {
        PR_DEBUG_PID("UID %d and program %s not monitored\n", current_uid().val, current->comm);
        goto run_syscall;
    }

    PR_DEBUG_PID("Throttling check for syscall %ld\n", regs->orig_ax);

    increment_curw_invoked();
    START_TIMER(start);

    // Throttling logic
    while (1) {
        // Try to acquire a slot
        current_val = __sync_add_and_fetch(&sct_monitor.invoks, 1);
        PR_DEBUG_PID("Slot acquired: %llu\n", current_val);

        // Check if we are within the limit
        if (current_val <= sct_max_invoks)
            // SUCCESS: We acquired a slot
            goto allow_syscall;

        // FAILURE: We incremented, but the limit was already reached.
        if (!inc_blocked) {
            increment_curw_blocked();
            inc_blocked = true;
        }

        PR_DEBUG_PID("Limit reached (%llu >= %lu), sleeping...\n", current_val, sct_max_invoks);

        // Decrement the counter as we failed to acquire a slot and will wait.
        __sync_fetch_and_sub(&sct_monitor.invoks, 1);
        ret = wait_event_interruptible(sct_monitor.wqueue, sct_monitor.invoks < sct_max_invoks || sct_monitor.unloading);
        
        if (ret != 0) {
            PR_DEBUG_PID("Interrupted by signal\n");
            END_TIMER(end, start, delay_ms);
            return -EINTR;
        }
        
        // If we reach here, we will try to increment again.
        PR_DEBUG_PID("Woke up, retrying to acquire slot...\n");

        if(sct_monitor.unloading) {
            PR_INFO_PID("Module unloading, running syscall\n");
            END_TIMER(end, start, delay_ms);
            goto run_syscall;
        }

    }

allow_syscall:

    // We have acquired a slot
    PR_DEBUG_PID("Syscall %ld allowed (slot %llu)\n", regs->orig_ax, current_val);
    
    END_TIMER(end, start, delay_ms);
    update_peak_delay(delay_ms, current_uid().val, current->pid, current->comm, regs->orig_ax);

run_syscall:
    return syscall(regs);
}