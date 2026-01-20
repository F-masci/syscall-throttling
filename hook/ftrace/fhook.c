#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kprobes.h>

#include "fhook.h"
#include "../../sct.h"
#include "../../_syst.h"

static unsigned long get_syscall_address(scidx_t);

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
    #define FTRACE_REGS_ARG struct ftrace_regs
#else
    #define FTRACE_REGS_ARG struct pt_regs
#endif

static __always_inline void ftrace_set_ip(FTRACE_REGS_ARG *regs, unsigned long ip) {
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
    struct pt_regs *real_regs = (struct pt_regs *)regs;
    real_regs->ip = ip;
#else
    regs->ip = ip;
#endif
}

static void notrace ftrace_handler(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    unsigned long hook_addr = (unsigned long)ops->private;
    ftrace_set_ip(regs, hook_addr);
}

unsigned long install_syscall_fhook(scidx_t syscall_idx, struct ftrace_ops *ftrace_ops, unsigned long hook_addr) {
    
    unsigned long syscall_addr;
    int ret;

    // Get syscall address
    syscall_addr = get_syscall_address(syscall_idx);
    if (syscall_addr == (unsigned long) NULL) {
        PR_ERROR("Cannot find address for syscall %d\n", syscall_idx);
        return (unsigned long) NULL;
    }
    PR_DEBUG("Syscall %d address found\n", syscall_idx);
    
    // Configure ftrace operation
    ftrace_ops->func    = ftrace_handler;
    ftrace_ops->flags   = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    ftrace_ops->private = (void *) hook_addr;

    // Register ftrace operation
    ret = ftrace_set_filter_ip(ftrace_ops, syscall_addr, 0, 0);
    if (ret) {
        PR_ERROR("ftrace_set_filter_ip failed for syscall %d: %d\n", syscall_idx, ret);
        return ret;
    }
    PR_DEBUG("Ftrace filter set for syscall %d\n", syscall_idx);

    // Register ftrace function
    ret = register_ftrace_function(ftrace_ops);
    if (ret) {
        PR_ERROR("register_ftrace_function failed for syscall %d: %d\n", syscall_idx, ret);
        ftrace_set_filter_ip(ftrace_ops, syscall_addr, 1, 0);
        return ret;
    }

    return 0;
}

unsigned long uninstall_syscall_fhook(scidx_t syscall_idx, struct ftrace_ops *ftrace_ops) {

    unsigned long hook_addr = (unsigned long) ftrace_ops->private;
    int ret;

    // Unregister ftrace operation
    ret = unregister_ftrace_function(ftrace_ops);
    if (ret) {
        PR_ERROR("unregister_ftrace_function failed for syscall %d: %d\n", syscall_idx, ret);
        return ret;
    }

    // Remove ftrace filter
    ret = ftrace_set_filter_ip(ftrace_ops, get_syscall_address(syscall_idx), 1, 0);
    if (ret) {
        PR_ERROR("ftrace_set_filter_ip removal failed for syscall %d: %d\n", syscall_idx, ret);
        return ret;
    }

    return hook_addr;
}


#define FNAME_BUF_SIZE 64
/**
 * @brief Get the syscall address by its index
 * 
 * @param idx Syscall index
 * @return unsigned long Address of the syscall, or NULL on failure
 */
static unsigned long get_syscall_address(scidx_t idx) {

    const char *short_name = __get_syscall_name(idx);
    char full_name[FNAME_BUF_SIZE];

    struct kprobe kp;
    unsigned long addr;

    int ret;

    // Check if syscall name is valid
    if (!short_name) {
        PR_ERROR("Syscall name not found for index %d\n", idx);
        return (unsigned long) NULL;
    }

    // Construct full syscall name
    snprintf(full_name, sizeof(full_name), "__x64_sys_%s", short_name);

    // Setup kprobe
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = full_name;

    // Register kprobe
    ret = register_kprobe(&kp);
    if (ret < 0) {
        PR_ERROR("Failed to register kprobe on %s: %d\n", full_name, ret);
        return (unsigned long) NULL;
    }
    
    // Get syscall address
    addr = (unsigned long) kp.addr;
    
    // Unregister kprobe
    unregister_kprobe(&kp);
    
    return addr;
}
#undef FNAME_BUF_SIZE