#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "ftrace.h"
#include "probes.h"
#include "module.h"
#include "types.h"
#include "monitor.h"

extern asmlinkage long syscall_wrapper(struct pt_regs *regs);
extern hook_syscall_t * syscall_hooks;

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
    #define FTRACE_REGS_ARG struct ftrace_regs
#else
    #define FTRACE_REGS_ARG struct pt_regs
#endif

static __always_inline void sct_ftrace_set_ip(FTRACE_REGS_ARG *regs, unsigned long ip) {
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
    struct pt_regs *real_regs = (struct pt_regs *)regs;
    real_regs->ip = ip;
#else
    /* Vecchio stile: accesso diretto */
    regs->ip = ip;
#endif
}

// Change instruction pointer to our syscall_wrapper
static void notrace sct_ftrace_handler(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    sct_ftrace_set_ip(regs, (unsigned long)syscall_wrapper);
}

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
    hook->kp = kp;
    syscall_addr = (unsigned long)kp->addr;

    // Save original syscall address
    hook->original_addr = syscall_addr;
    hook->active = true;
    
    // Configure ftrace operation
    hook->sct_ftrace_ops.func   = sct_ftrace_handler;
    hook->sct_ftrace_ops.flags  = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    hook->sct_ftrace_ops.private = (void *)syscall_addr;

    // Register ftrace operation
    ret = ftrace_set_filter_ip(&hook->sct_ftrace_ops, syscall_addr, 0, 0);
    if (ret) {
        pr_err("%s: ftrace_set_filter_ip failed for syscall %d\n", MODULE_NAME, syscall_idx);
        return ret;
    }

    ret = register_ftrace_function(&hook->sct_ftrace_ops);
    if (ret) {
        pr_err("%s: register_ftrace_function failed for syscall %d\n", MODULE_NAME, syscall_idx);
        ftrace_set_filter_ip(&hook->sct_ftrace_ops, syscall_addr, 1, 0);
        return ret;
    }
    pr_info("%s: ftrace hook installed on syscall %d\n", MODULE_NAME, syscall_idx);

    return 0;
}

int uninstall_syscall_ftrace_hook(int syscall_idx) {
    hook_syscall_t * hook = &syscall_hooks[syscall_idx];
    int ret;

    if (!hook->active) {
        pr_warn("%s: No active ftrace hook for syscall %d\n", MODULE_NAME, syscall_idx);
        return -EINVAL;
    }

    // Unregister kprobe
    if (hook->kp) {
        unregister_kprobe(hook->kp);
        kfree(hook->kp);
        hook->kp = NULL;
        pr_info("%s: kprobe uninstalled from syscall %d\n", MODULE_NAME, syscall_idx);
    }

    // Unregister ftrace operation
    ret = unregister_ftrace_function(&hook->sct_ftrace_ops);
    if (ret) {
        pr_err("%s: unregister_ftrace_function failed for syscall %d\n", MODULE_NAME, syscall_idx);
        return ret;
    }

    ret = ftrace_set_filter_ip(&hook->sct_ftrace_ops, hook->original_addr, 1, 0);
    if (ret) {
        pr_err("%s: ftrace_set_filter_ip removal failed for syscall %d\n", MODULE_NAME, syscall_idx);
        return ret;
    }

    hook->active = false;
    pr_info("%s: ftrace hook uninstalled from syscall %d\n", MODULE_NAME, syscall_idx);

    return 0;
}