#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#include "discover.h"
#include "monitor.h"
#include "types.h"
#include "module.h"

extern unsigned long install_usctd_syscall_hook(int syscall_nr, unsigned long wrapper_addr);
extern unsigned long uninstall_usctd_syscall_hook(int syscall_nr);

extern hook_syscall_t * syscall_hooks;

int install_syscall_discover_hook(int syscall_idx) {
    
    unsigned long original_addr;
    hook_syscall_t * hook = &syscall_hooks[syscall_idx];

    // Save original syscall address
    original_addr = install_usctd_syscall_hook(syscall_idx, (unsigned long)syscall_wrapper);
    if(original_addr == (unsigned long)NULL) {
        pr_err("%s: Failed to install discover hook on syscall %d\n", MODULE_NAME, syscall_idx);
        return -EINVAL;
    }
    hook->active = true;
    hook->original_addr = original_addr;

    return 0;
}

int uninstall_syscall_discover_hook(int syscall_idx) {

    hook_syscall_t * hook = &syscall_hooks[syscall_idx];
    hook->active = false;
    hook->original_addr = (unsigned long) NULL;

    return uninstall_usctd_syscall_hook(syscall_idx);
}