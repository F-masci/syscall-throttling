#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#include "hook.h"
#include "sct.h"
#include "monitor.h"

#ifdef FTRACE_HOOKING
#include "hook/ftrace/fhook.h"
#else
#include "hook/discover/disc.h"
#include "hook/discover/dhook.h"
#endif

hook_syscall_t * syscall_hooks;
static int syscall_hooks_num = 0;

/**
 * @brief Setup syscall hooks data structure
 * 
 * @param num_syscalls Number of syscalls
 * @return int 0 on success, negative error code on failure
 */
int setup_syscall_hooks(int num_syscalls) {

    int ret;

    syscall_hooks = kmalloc_array(num_syscalls, sizeof(hook_syscall_t), GFP_KERNEL);
    if(!syscall_hooks) {
        PR_ERROR("Cannot allocate memory for syscall hooks\n");
        return -ENOMEM;
    }
    memset(syscall_hooks, 0, num_syscalls * sizeof(hook_syscall_t));
    PR_DEBUG("Syscall hooks data structure allocated\n");

#ifdef FTRACE_HOOKING
    PR_INFO("Setting up ftrace hooking mode...\n");
    // setup_ftrace_hook();
    PR_INFO("Ftrace hooking mode setup completed\n");
#else
    PR_INFO("Setting up discover hooking mode...\n");
    ret = setup_discover_hook();
    if(ret < 0) {
        PR_ERROR("Failed to set up discover hooking mode\n");
        kfree(syscall_hooks);
        return ret;
    }
    PR_INFO("Discover hooking mode setup completed\n");
#endif

    syscall_hooks_num = num_syscalls;

    return 0;
}

/**
 * @brief Install a syscall hook
 * 
 * @param syscall_idx Syscall number to hook
 * @return int 0 on success, negative error code on failure
 */
int install_syscall_hook(int syscall_idx) {
    
    unsigned long original_addr;
    hook_syscall_t * hook = &syscall_hooks[syscall_idx];

    // Install syscall hook and save original syscall address
#ifdef FTRACE_HOOKING
    PR_DEBUG("Installing ftrace hook on syscall %d\n", syscall_idx);
    original_addr = install_syscall_fhook(syscall_idx);
#else
    PR_DEBUG("Installing discover hook on syscall %d\n", syscall_idx);
    original_addr = install_syscall_dhook(syscall_idx, (unsigned long) syscall_wrapper);
#endif

    if(original_addr == (unsigned long)NULL) {
        PR_ERROR("Failed to install discover hook on syscall %d\n", syscall_idx);
        return -EINVAL;
    }
    hook->active = true;
    hook->original_addr = original_addr;

    return 0;
}

/**
 * @brief Uninstall a syscall hook
 * 
 * @param syscall_idx Syscall number to unhook
 * @return int 0 on success, negative error code on failure
 */
int uninstall_syscall_hook(int syscall_idx) {

#ifdef FTRACE_HOOKING
    PR_DEBUG("Uninstalling ftrace hook on syscall %d\n", syscall_idx);
    int ret = uninstall_syscall_fhook(syscall_idx);
    if(ret < 0) {
        PR_ERROR("Failed to uninstall ftrace hook on syscall %d\n", syscall_idx);
        return ret;
    }
#else
    PR_DEBUG("Uninstalling discover hook on syscall %d\n", syscall_idx);
    unsigned long ret = uninstall_syscall_dhook(syscall_idx);
    if(ret == (unsigned long)NULL) {
        PR_ERROR("Failed to uninstall discover hook on syscall %d\n", syscall_idx);
        return -EINVAL;
    }
#endif

    hook_syscall_t * hook = &syscall_hooks[syscall_idx];
    hook->active = false;
    hook->original_addr = (unsigned long) NULL;

    return 0;
}

/**
 * @brief Cleanup syscall hooks
 * 
 */
void cleanup_syscall_hooks(void) {

    for(int i = 0; i < syscall_hooks_num; i++) {
        if(syscall_hooks[i].active) {
            PR_DEBUG("Uninstalling active hook on syscall %d during cleanup\n", i);
            uninstall_syscall_hook(i);
        }
    }

    kfree(syscall_hooks);
    PR_DEBUG("Syscall hooks data structure freed\n");

#ifdef FTRACE_HOOKING
    // cleanup_ftrace_hook();
    PR_DEBUG("Ftrace hooking mode cleaned up\n");
#else
    cleanup_discover_hook();
    PR_DEBUG("Discover hooking mode cleaned up\n");
#endif

}