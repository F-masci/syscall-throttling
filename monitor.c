#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "monitor.h"
#include "probes.h"
#include "module.h"
#include "types.h"
#include "stats.h"

hook_syscall_t * syscall_hooks;

extern sct_monitor_t sct_monitor;
extern unsigned long sct_max_invoks;

#define START_TIMER(__start) do { __start = ktime_get(); } while(0)
#define END_TIMER(__end, __start, __time) \
    do { \
        (__end) = ktime_get(); \
        __time = ktime_to_ms(ktime_sub((__end), (__start))); \
        printk(KERN_INFO "%s[%d]: Resuming after %lld ms (%lld s)\n", MODULE_NAME, current->pid, __time, __time / 1000); \
    } while (0)

void init_syscall_hooks(int num_syscalls) {
    syscall_hooks = kmalloc_array(num_syscalls, sizeof(hook_syscall_t), GFP_KERNEL);
    memset(syscall_hooks, 0, num_syscalls * sizeof(hook_syscall_t));
}

asmlinkage long syscall_wrapper(struct pt_regs *regs) {
    
    ktime_t start, end;
    s64 delay_ms;
    bool inc_blocked = false;

    long ret;
    u64 current_val;

    // Sum to original_addr the offset of MCOUNT_INSN_SIZE to skip ftrace prologue.
    // This is necessary to avoid infinite recursion.
    asmlinkage long (*syscall)(struct pt_regs *) = (void *)(syscall_hooks[regs->orig_ax].original_addr + MCOUNT_INSN_SIZE);

    printk(KERN_INFO "%s[%d]: Syscall %ld invoked\n", MODULE_NAME, current->pid, regs->orig_ax);
    printk(KERN_INFO "%s[%d]: -> thread pid: %d\n", MODULE_NAME, current->pid, current->pid);
    printk(KERN_INFO "%s[%d]: -> uid: %d\n", MODULE_NAME, current->pid, current_uid().val);
    printk(KERN_INFO "%s[%d]: -> comm: %s\n", MODULE_NAME, current->pid, current->comm);

    printk(KERN_INFO "%s[%d]: -> total invocations: %llu\n", MODULE_NAME, current->pid, sct_monitor.invoks);
    
    if(current_uid().val != 1000) {
        printk(KERN_INFO "%s[%d]: Syscall %ld not called by user, skipping throttling\n", MODULE_NAME, current->pid, regs->orig_ax);
        goto run_orig_syscall;
    }

    increment_curw_invoked();
    START_TIMER(start);

    // Throttling logic
    while (1) {
        // Try to acquire a slot
        current_val = __sync_add_and_fetch(&sct_monitor.invoks, 1);
        printk(KERN_INFO "%s[%d]: Slot acquired: %llu\n", MODULE_NAME, current->pid, current_val);

        // Check if we are within the limit
        if (current_val <= sct_max_invoks)
            // SUCCESS: We acquired a slot
            goto allow_syscall;

        // FAILURE: We incremented, but the limit was already reached.
        if (!inc_blocked) {
            increment_curw_blocked();
            inc_blocked = true;
        }

        printk(KERN_INFO "%s[%d]: Limit reached (%llu >= %lu), sleeping...\n", MODULE_NAME, current->pid, current_val, sct_max_invoks);

        // Decrement the counter as we failed to acquire a slot and will wait.
        __sync_fetch_and_sub(&sct_monitor.invoks, 1);
        ret = wait_event_interruptible(sct_monitor.wqueue, sct_monitor.invoks < sct_max_invoks || sct_monitor.unloading);
        
        if (ret != 0) {
            printk(KERN_INFO "%s[%d]: Interrupted by signal\n", MODULE_NAME, current->pid);
            END_TIMER(end, start, delay_ms);
            return -EINTR;
        }
        
        // If we reach here, we will try to increment again.
        printk(KERN_INFO "%s[%d]: Woke up, retrying to acquire slot...\n", MODULE_NAME, current->pid);

        if(sct_monitor.unloading) {
            printk(KERN_INFO "%s[%d]: Module unloading, exiting wait loop\n", MODULE_NAME, current->pid);
            END_TIMER(end, start, delay_ms);
            goto run_orig_syscall;
        }

    }

allow_syscall:

    // We have acquired a slot
    printk(KERN_INFO "%s[%d]: Syscall %ld allowed (slot %llu)\n", MODULE_NAME, current->pid, regs->orig_ax, current_val);
    
    END_TIMER(end, start, delay_ms);
    update_peak_delay(delay_ms, current_uid().val, current->pid, current->comm, regs->orig_ax);

run_orig_syscall:
    return syscall(regs);
}