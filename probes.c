#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "probes.h"
#include "module.h"
#include "types.h"
#include "syscall_table.h"

extern sct_monitor_t sct_monitor;

static int syscall_handler_pre(struct kprobe *p, struct pt_regs *regs) {
    sct_monitor.invoks++;
    printk(KERN_INFO "%s: Syscall invoked. Total invocations: %llu\n", MODULE_NAME, sct_monitor.invoks);
    return 0;
}

/**
 * @brief Install a kprobe on a syscall by its name
 * 
 * @param syscall_symbol The name of the syscall to probe
 * @param _kp Pointer to the kprobe structure
 * @return int 0 on success, negative error code on failure
 */
int install_syscall_name_probe(const char *syscall_symbol, struct kprobe **_kp) {

    char *symbol_name_storage;
    int ret;
    
    // Allocate memory for kprobe
    struct kprobe *kp = kmalloc(sizeof(struct kprobe) + strlen(syscall_symbol) + 1, GFP_KERNEL);
    if (!kp) {
        pr_err("%s: Memory allocation failed for kprobe\n", MODULE_NAME);
        return -ENOMEM;
    }

    // Save symbol name after the kprobe struct
    symbol_name_storage = (char *)(kp + 1);
    strcpy(symbol_name_storage, syscall_symbol);
    kp->symbol_name = symbol_name_storage;

    // Set the handlers
    kp->pre_handler = syscall_handler_pre;
    kp->post_handler = NULL;

    // Register the kprobe
    ret = register_kprobe(kp);
    if (ret < 0) {
        pr_err("%s: Failed to register kprobe on %s, error: %d\n", MODULE_NAME, syscall_symbol, ret);
        kfree(kp);
        return ret;
    }

    pr_info("%s: Kprobe installed on %s\n", MODULE_NAME, syscall_symbol);
    if (_kp) *_kp = kp;
    else kfree(kp);

    return 0;
}

/**
 * @brief Install a kprobe on a syscall by its index
 * 
 * @param syscall_idx The index of the syscall to probe
 * @param _kp Pointer to the kprobe structure
 * @return int 0 on success, negative error code on failure
 */
int install_syscall_idx_probe(int syscall_idx, struct kprobe **_kp) {
    const char *syscall_name;

    if (syscall_idx < 0 || syscall_idx >= SYSCALL_TABLE_SIZE) {
        pr_err("%s: Invalid syscall index: %d\n", MODULE_NAME, syscall_idx);
        return -EINVAL;
    }

    syscall_name = syscall_names[syscall_idx];
    if (!syscall_name) {
        pr_err("%s: Syscall name not found for index: %d\n", MODULE_NAME, syscall_idx);
        return -EINVAL;
    }

    return install_syscall_name_probe(syscall_name, _kp);
}