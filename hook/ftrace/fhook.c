/**
 * @file fhook.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the ftrace hooking mechanism for syscalls. It
 *        provides functions to initialize, install, and uninstall syscall hooks
 *        using the ftrace hooking method.
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
#include <linux/kprobes.h>
#include <linux/unistd.h>

#include "fhook.h"
#include "probe.h"
#include "../../sct.h"

/**
 * @brief Set up ftrace hooking mode
 * 
 * @return int 0 on success, negative error code on failure
 */
int setup_ftrace_hook(void) {
    int ret;

    // Get sys_ni_syscall address
    ret = load_sys_ni_syscall_address();
    if (ret < 0) {
        PR_ERROR("Failed to get sys_ni_syscall address\n");
        return ret;
    }
    PR_DEBUG("Nil syscall address loaded\n");

    return 0;
}

void cleanup_ftrace_hook(void) {
    // Nothing to do for ftrace hooking cleanup
}




#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
    #define FTRACE_REGS_ARG struct ftrace_regs
#else
    #define FTRACE_REGS_ARG struct pt_regs
#endif

/**
 * @brief Set the instruction pointer in ftrace registers
 * 
 * @param regs Pointer to ftrace registers
 * @param ip Instruction pointer value to set
 * @return
 */
static __always_inline void ftrace_set_ip(FTRACE_REGS_ARG *regs, unsigned long ip) {
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_REGS
    struct pt_regs *real_regs = (struct pt_regs *)regs;
    real_regs->ip = ip;
#else
    regs->ip = ip;
#endif
}

/**
 * @brief Ftrace handler function to redirect syscall execution
 * 
 * @param ip Current instruction pointer
 * @param parent_ip Caller instruction pointer
 * @param ops Ftrace operations structure
 * @param regs Ftrace registers
 */
static void notrace ftrace_handler(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *regs) {
    unsigned long hook_addr = (unsigned long) ops->private;
    ftrace_set_ip(regs, hook_addr);
}

/**
 * @brief Initialize a syscall hook structure for ftrace hooking
 * 
 * @param hook Pointer to the hook_syscall_t structure
 * 
 * @return int 0 on success, negative error code on failure
 */
int init_syscall_fhook(hook_syscall_t * hook) {

    int ret = 0;

    // Check for valid pointer
    if(unlikely(!hook)) {
        PR_ERROR("Invalid hook pointer\n");
        return -EINVAL;
    }

    // Init hook structure
    ret = set_syscall_address(hook);
    if (ret < 0) {
        PR_ERROR("Cannot get syscall address for syscall %d\n", hook->syscall_idx);
        return ret;
    }
    hook->fops.func    = ftrace_handler;
    hook->fops.flags   = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    hook->fops.private = (void *) hook->hook_addr;
    PR_DEBUG("Ftrace hook structure set up for syscall %d\n", hook->syscall_idx);

    return 0;
}

/**
 * @brief Install a syscall hook using ftrace
 * 
 * @param hook Pointer to the hook_syscall_t structure
 * 
 * @return int 0 on success, negative error code on failure
 */
int install_syscall_fhook(hook_syscall_t * hook) {
    
    int ret = 0;

    // Check for valid pointer
    if(unlikely(!hook)) {
        PR_ERROR("Invalid hook pointer\n");
        return -EINVAL;
    }

    // Check if already hooked
    if (unlikely(hook->active)) {
        PR_ERROR("Hook for syscall %d is already active\n", hook->syscall_idx);
        return -EINVAL;
    }

    // Check for nil syscall
    if (unlikely(hook->nil_syscall)) {
        PR_WARN("Skip hook of syscall %d as it is a nil syscall\n", hook->syscall_idx);
        return 0;
    }

    // Register ftrace operation
    ret = ftrace_set_filter_ip(&hook->fops, hook->original_addr, 0, 0);
    if (ret < 0) {
        PR_ERROR("Ftrace set filter failed for syscall %d: %d\n", hook->syscall_idx, ret);
        goto filter_ip_err;
    }
    PR_DEBUG("Ftrace filter set for syscall %d\n", hook->syscall_idx);

    // Register ftrace function
    ret = register_ftrace_function(&hook->fops);
    if (ret < 0) {
        PR_ERROR("Ftrace register failed for syscall %d: %d\n", hook->syscall_idx, ret);
        goto ftrace_register_err;
    }
    PR_DEBUG("Ftrace function registered for syscall %d\n", hook->syscall_idx);
    
    hook->active = true;

    // Ensure memory operations are completed before proceeding
    // so that other CPUs see the updated syscall table
    mb();

    return 0;

ftrace_register_err:
    ftrace_set_filter_ip(&hook->fops, hook->original_addr, 1, 0);

filter_ip_err:
    return ret;
}

/**
 * @brief Uninstall a syscall hook using ftrace
 * 
 * @param hook Pointer to the hook_syscall_t structure
 * 
 * @return int 0 on success, negative error code on failure
 */
int uninstall_syscall_fhook(hook_syscall_t * hook) {

    int ret = 0;

    // Check for valid pointer
    if(unlikely(!hook)) {
        PR_ERROR("Invalid hook pointer\n");
        return -EINVAL;
    }

    // Check if hook is active
    if (unlikely(!hook->active)) {
        PR_ERROR("Hook for syscall %d is not active\n", hook->syscall_idx);
        return -EINVAL;
    }

    // Check for nil syscall
    if (unlikely(hook->nil_syscall)) {
        PR_WARN("Skip unhook of syscall %d as it is a nil syscall\n", hook->syscall_idx);
        return 0;
    }

    // Unregister ftrace operation
    ret = unregister_ftrace_function(&hook->fops);
    if (ret < 0) {
        PR_ERROR("Ftrace unregister failed for syscall %d: %d\n", hook->syscall_idx, ret);
        return ret;
    }
    PR_DEBUG("Ftrace function unregistered for syscall %d\n", hook->syscall_idx);

    // Remove ftrace filter
    ret = ftrace_set_filter_ip(&hook->fops, hook->original_addr, 1, 0);
    if (ret < 0) {
        PR_ERROR("Ftrace set filter removal failed for syscall %d: %d\n", hook->syscall_idx, ret);
        return ret;
    }
    PR_DEBUG("Ftrace filter removed for syscall %d\n", hook->syscall_idx);

    hook->active = false;

    // Ensure memory operations are completed before proceeding
    // so that other CPUs see the updated syscall table
    mb();

    return 0;
}