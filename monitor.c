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

hook_syscall_t * syscall_hooks;

extern sct_monitor_t sct_monitor;
extern unsigned long sct_max_invoks;

#define START_TIMER(__start) do { __start = ktime_get(); } while(0)
#define END_TIMER(__end, __start) \
    do { \
        s64 __ms_time; \
        (__end) = ktime_get(); \
        __ms_time = ktime_to_ms(ktime_sub((__end), (__start))); \
        printk(KERN_INFO "%s: Interrupted after %lld ms (%lld s)\n", MODULE_NAME, __ms_time, __ms_time / 1000); \
    } while (0)

void init_syscall_hooks(int num_syscalls) {
    syscall_hooks = kmalloc_array(num_syscalls, sizeof(hook_syscall_t), GFP_KERNEL);
    memset(syscall_hooks, 0, num_syscalls * sizeof(hook_syscall_t));
}

asmlinkage long syscall_wrapper(struct pt_regs *regs) {
    
    u64 invoks;
    ktime_t start, end;

    // Sum to original_addr the offset of MCOUNT_INSN_SIZE to skip ftrace prologue.
    // This is necessary to avoid infinite recursion.
    asmlinkage long (*syscall)(struct pt_regs *) = (void *)(syscall_hooks[regs->orig_ax].original_addr + MCOUNT_INSN_SIZE);

    invoks = __sync_fetch_and_add(&sct_monitor.invoks, 1);

    printk(KERN_INFO "%s[%lld]: Syscall %ld invoked\n", MODULE_NAME, invoks, regs->orig_ax);
    printk(KERN_INFO "%s[%lld]: -> thread pid: %d\n", MODULE_NAME, invoks, current->pid);
    printk(KERN_INFO "%s[%lld]: -> uid: %d\n", MODULE_NAME, invoks, current_uid().val);
    printk(KERN_INFO "%s[%lld]: -> comm: %s\n", MODULE_NAME, invoks, current->comm);

    printk(KERN_INFO "%s[%lld]: -> total invocations: %llu\n", MODULE_NAME, invoks, invoks);
    
    if(current_uid().val != 1000) {
        printk(KERN_INFO "%s[%lld]: Syscall %ld not called by user, skipping throttling\n", MODULE_NAME, invoks, regs->orig_ax);
        goto run_orig_syscall;
    }

    START_TIMER(start);
    if(wait_event_interruptible(sct_monitor.wqueue, invoks < sct_max_invoks) != 0) {
        printk(KERN_INFO "%s[%lld]: Syscall %ld interrupted while waiting\n", MODULE_NAME, invoks, regs->orig_ax);
        END_TIMER(end, start);
        return -EINTR;
    }

    printk(KERN_INFO "%s[%lld]: Syscall %ld blocked\n", MODULE_NAME, invoks, regs->orig_ax);
    END_TIMER(end, start);

run_orig_syscall:
    return syscall(regs);
}