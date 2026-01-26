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
#include "../../sct.h"
#include "../../_syst.h"

static int get_syscall_address(scidx_t, unsigned long *);

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
    if(!hook) {
        PR_ERROR("Invalid hook pointer\n");
        return -EINVAL;
    }

    // Init hook structure
    ret = get_syscall_address(hook->syscall_idx, &hook->original_addr);
    if (ret < 0) {
        PR_ERROR("Cannot get syscall address for syscall %d\n", hook->syscall_idx);
        return ret;
    }
    hook->fops.func    = ftrace_handler;
    // hook->fops.flags   = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
    hook->fops.flags   = FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;
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

    PR_DEBUG("Installing ftrace hook for syscall %d at address 0x%lx\n", hook->syscall_idx, hook->original_addr);

    // Register ftrace operation
    ret = ftrace_set_filter_ip(&hook->fops, hook->original_addr, 0, 0);
    if (ret < 0) {
        PR_ERROR("Ftrace set filter failed for syscall %d\n", hook->syscall_idx);
        goto filter_ip_err;
    }
    PR_DEBUG("Ftrace filter set for syscall %d\n", hook->syscall_idx);

    // Register ftrace function
    ret = register_ftrace_function(&hook->fops);
    if (ret < 0) {
        PR_ERROR("Ftrace register failed for syscall %d\n", hook->syscall_idx);
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

    // Unregister ftrace operation
    ret = unregister_ftrace_function(&hook->fops);
    if (ret < 0) {
        PR_ERROR("Ftrace unregister failed for syscall %d\n", hook->syscall_idx);
        return ret;
    }
    PR_DEBUG("Ftrace function unregistered for syscall %d\n", hook->syscall_idx);

    // Remove ftrace filter
    ret = ftrace_set_filter_ip(&hook->fops, hook->original_addr, 1, 0);
    if (ret < 0) {
        PR_ERROR("Ftrace set filter removal failed for syscall %d\n", hook->syscall_idx);
        return ret;
    }
    PR_DEBUG("Ftrace filter removed for syscall %d\n", hook->syscall_idx);

    return 0;
}

/**
 * @brief Get the sys_ni_syscall address
 * 
 * @return unsigned long 
 */
static inline unsigned long get_sys_ni_syscall_address(void) {

    // Set up kprobe for sys_ni_syscall
    struct kprobe kp = { .symbol_name = "sys_ni_syscall" };
    unsigned long addr;
    int ret;

    // Register kprobe
    ret = register_kprobe(&kp);
    if (ret < 0) {
        PR_ERROR("Failed to find sys_ni_syscall address\n");
        return ret;
    }
    
    // Get syscall address
    addr = (unsigned long) kp.addr;

    // Unregister kprobe
    unregister_kprobe(&kp);

    return addr;
}

#define SUFFIX_BUF_LEN 16
#define PREFIX_BUF_LEN 16
/**
 * @brief Get the full syscall name by its short name
 * 
 * @param buf Buffer to store the full syscall name
 * @param size Size of the buffer
 * @param syscall_idx Syscall index
 * @return int 0 on success, negative error code on failure
 */
static inline int __get_syscall_fullname(char *buf, size_t size, scidx_t syscall_idx) {
    
    const char *short_name = __get_syscall_name(syscall_idx);
    char prefix[PREFIX_BUF_LEN] = {0};
    char suffix[SUFFIX_BUF_LEN] = {0};
    int ret;

    // Check if syscall name is valid
    if (unlikely(!short_name)) {
        PR_ERROR("Syscall name not found for index %d\n", syscall_idx);
        return -ENOSYS;
    }

    switch(syscall_idx) {
        case __NR_pread64:
        case __NR_pwrite64:
            snprintf(suffix, SUFFIX_BUF_LEN, "64");
            break;
        case __NR_stat:
            short_name = "newstat";
            break;
        case __NR_fstat:
            short_name = "newfstat";
            break;
        case __NR_lstat:
            short_name = "newlstat";
            break;
        case __NR_uname:
            short_name = "newuname";
            break;
        case __NR_umount2:
            short_name = "umount";
            break;
        default:
            break;
    }

    ret = snprintf(buf, size, "__x64_sys_%s%s%s", prefix, short_name, suffix);
    if (ret < 0 || ret >= size) {
        PR_ERROR("Failed to construct full syscall name for %s\n", short_name);
        return ret < 0 ? ret : -ENAMETOOLONG;
    }

    return 0;
}
#undef SUFFIX_BUF_LEN
#undef PREFIX_BUF_LEN


#define FNAME_BUF_SIZE 128
/**
 * @brief Get the syscall address by its index
 * 
 * @param idx Syscall index
 * @param addr Pointer to store the syscall address
 * 
 * @return int 0 on success, negative error code on failure
 */
static int get_syscall_address(scidx_t idx, unsigned long * addr) {

    char full_name[FNAME_BUF_SIZE];
    struct kprobe kp;
    int ret = 0;

    // Check for valid pointer
    if (unlikely(!addr)) {
        PR_ERROR("Invalid pointer for syscall address output\n");
        return -EINVAL;
    }

    // Construct full syscall name
    ret = __get_syscall_fullname(full_name, FNAME_BUF_SIZE, idx);
    if (ret < 0) {
        PR_WARN("Failed to get full syscall name for index %d\n", idx);
        goto nil_syscall_addr;
    }
    PR_DEBUG("Full syscall name for index %d: %s\n", idx, full_name);

    // Setup kprobe
    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = full_name;

    // Register kprobe
    ret = register_kprobe(&kp);
    if (ret < 0) {
        PR_WARN("Failed to register kprobe on %s\n", full_name);
        goto nil_syscall_addr;
    }
    PR_DEBUG("Kprobe registered for %s\n", full_name);
    
    // Get syscall address
    *addr = (unsigned long) kp.addr;
    
    // Unregister kprobe
    unregister_kprobe(&kp);
    PR_DEBUG("Kprobe unregistered for %s\n", full_name);

    return 0;

nil_syscall_addr:
    PR_WARN("Using sys_ni_syscall for index %d\n", idx);
    *addr = get_sys_ni_syscall_address();
    return 0;
}
#undef FNAME_BUF_SIZE