#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "ftrace.h"
#include "probes.h"
#include "module.h"

typedef struct {
    bool active;
    unsigned long original_addr;
} hook_syscall_t;

static hook_syscall_t * syscall_hooks;

void init_syscall_hooks(int num_syscalls) {
    syscall_hooks = kmalloc_array(num_syscalls, sizeof(hook_syscall_t), GFP_KERNEL);
    memset(syscall_hooks, 0, num_syscalls * sizeof(hook_syscall_t));
}

static asmlinkage long syscall_wrapper(struct pt_regs *regs) {
    
    // Sum to original_addr the offset of MCOUNT_INSN_SIZE to skip ftrace prologue.
    // This is necessary to avoid infinite recursion.
    asmlinkage long (*syscall)(struct pt_regs *) = 
        (void *)(syscall_hooks[regs->orig_ax].original_addr + MCOUNT_INSN_SIZE);

    printk(KERN_INFO "%s: Syscall %ld invoked\n", MODULE_NAME, regs->orig_ax);

    return syscall(regs);
}

// Change instruction pointer to our syscall_wrapper
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static void notrace sct_ftrace_handler(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    ftrace_regs_set_instruction_pointer(regs, (unsigned long)syscall_wrapper);
}
#else
static void notrace sct_ftrace_handler(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
    regs->ip = (unsigned long)syscall_wrapper;
}
#endif

static struct ftrace_ops sct_ftrace_ops = {
    .func = sct_ftrace_handler,
    .flags = FTRACE_OPS_FL_SAVE_REGS | 
             FTRACE_OPS_FL_RECURSION | 
             FTRACE_OPS_FL_IPMODIFY,
};

int install_syscall_ftrace_hook(int syscall_idx) {
    
    unsigned long syscall_addr;
    int ret;
    hook_syscall_t * hook = &syscall_hooks[syscall_idx];

    // Install kprobe to get syscall address
    struct kprobe *kp;
    if(install_syscall_idx_probe(syscall_idx, &kp) < 0) {
        pr_err("%s: Failed to install kprobe on syscall %d\n", MODULE_NAME, syscall_idx);
        return -EINVAL;
    }
    syscall_addr = (unsigned long)kp->addr;

    // Save original syscall address
    hook->original_addr = syscall_addr;
    hook->active = true;

    // Configure ftrace operation
    sct_ftrace_ops.private = (void *)syscall_addr;

    // Register ftrace operation
    ret = ftrace_set_filter_ip(&sct_ftrace_ops, syscall_addr, 0, 0);
    if (ret) {
        pr_err("%s: ftrace_set_filter_ip failed for syscall %d\n", MODULE_NAME, syscall_idx);
        return ret;
    }

    ret = register_ftrace_function(&sct_ftrace_ops);
    if (ret) {
        pr_err("%s: register_ftrace_function failed for syscall %d\n", MODULE_NAME, syscall_idx);
        ftrace_set_filter_ip(&sct_ftrace_ops, syscall_addr, 1, 0);
        return ret;
    }
    pr_info("%s: ftrace hook installed on syscall %d\n", MODULE_NAME, syscall_idx);

    // FIXME: Unregister kprobe if needed

    return 0;
}