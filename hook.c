/**
 * @file hook.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the hooking mechanisms for the syscall.
 *        It sets up hooks for syscalls using either ftrace or discover
 *        hooking methods based on configuration on compile time.
 * 
 * @version 1.0
 * @date 2026-01-21
 * 
 */

#include <linux/syscalls.h>
#include <linux/nospec.h>

#include "hook.h"
#include "monitor.h"
#include "filter.h"

#ifdef _FTRACE_HOOKING
#include "hook/ftrace/fhook.h"
#elif defined(_DISCOVER_HOOKING)
#include "hook/discover/disc.h"
#include "hook/discover/dhook.h"
#endif

static hook_syscall_t * syscall_hooks;
static size_t syscall_hooks_num = 0;

static inline scidx_t scidx_sanity_check(scidx_t idx) {
    if(unlikely(idx < 0 || idx >= syscall_hooks_num)) {
        PR_ERROR("Invalid syscall index %d\n", idx);
        return -ENOSYS;
    }
    return array_index_nospec(idx, syscall_hooks_num);
}

/**
 * @brief Setup syscall hooks data structure
 * 
 * @param num_syscalls Number of syscalls
 * @return int 0 on success, negative error code on failure
 */
int setup_syscall_hooks(size_t num_syscalls) {

    int ret;

    // Allocate syscall hooks data structure
    syscall_hooks = kmalloc_array(num_syscalls, sizeof(hook_syscall_t), GFP_KERNEL);
    if(!syscall_hooks) {
        PR_ERROR("Cannot allocate memory for syscall hooks\n");
        return -ENOMEM;
    }
    memset(syscall_hooks, 0, num_syscalls * sizeof(hook_syscall_t));
    PR_DEBUG("Syscall hooks data structure allocated\n");

    // Setup hooking method
#ifdef _FTRACE_HOOKING
    PR_INFO("Setting up ftrace hooking mode...\n");
    ret = 0;
    PR_INFO("Ftrace hooking mode setup completed\n");
#elif defined(_DISCOVER_HOOKING)
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

    return ret;
}

/**
 * @brief Cleanup syscall hooks
 * 
 */
void cleanup_syscall_hooks(void) {

    // Uninstall active hooks
    if(uninstall_active_syscalls_hooks() < 0) {
        PR_ERROR("Failed to uninstall all active syscall hooks during cleanup\n");
    }

    // Free syscall hooks data structure
    kfree(syscall_hooks);
    PR_DEBUG("Syscall hooks data structure freed\n");

    // Cleanup hooking method
#ifdef _FTRACE_HOOKING
    PR_DEBUG("Ftrace hooking mode cleaned up\n");
#elif defined(_DISCOVER_HOOKING)
    cleanup_discover_hook();
    PR_DEBUG("Discover hooking mode cleaned up\n");
#endif

}

/**
 * @brief Install a syscall hook
 * 
 * @param syscall_idx Syscall number to hook
 * @return int 0 on success, negative error code on failure
 */
int install_syscall_hook(scidx_t syscall_idx) {
    
    unsigned long original_addr;
    hook_syscall_t * hook;

    // Sanity check syscall index
    syscall_idx = scidx_sanity_check(syscall_idx);
    if(syscall_idx < 0) return -ENOSYS;

    // Check if already hooked
    hook = &syscall_hooks[syscall_idx];
    if(unlikely(hook->active)) {
        PR_WARN("Syscall %d is already hooked\n", syscall_idx);
        return 0;
    }

    // Install syscall hook and save original syscall address
#ifdef _FTRACE_HOOKING
    PR_DEBUG("Installing ftrace hook on syscall %d\n", syscall_idx);
    original_addr = install_syscall_fhook(syscall_idx, (unsigned long) syscall_wrapper, &hook->fops);
#elif defined(_DISCOVER_HOOKING)
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
 * @brief Install hooks for all monitored syscalls
 * 
 * @return int 0 on success, negative error code on failure
 */
int install_monitored_syscalls_hooks(void) {

    scidx_t *syscall_list;
    size_t syscall_count;
    int ret = 0;

    // Get monitored syscalls
    syscall_list = kmalloc_array(SYSCALL_TABLE_SIZE, sizeof(scidx_t), GFP_KERNEL);
    if (!syscall_list) return -ENOMEM;
    syscall_count = get_syscall_monitor_vals(syscall_list, SYSCALL_TABLE_SIZE);

    // Install hooks
    for (size_t i = 0; i < syscall_count; i++) {
        ret = install_syscall_hook(syscall_list[i]);
        if (ret < 0) break;
    }
    kfree(syscall_list);

    // On error, uninstall all installed hooks
    if(ret < 0 && uninstall_active_syscalls_hooks() < 0) {
        PR_ERROR("Failed to uninstall all syscall hooks after install error\n");
    }
    
    return ret;
}

/**
 * @brief Get the original syscall address (after hooking)
 * 
 * @param syscall_idx Syscall number
 * @return unsigned long Original syscall address, or NULL on failure
 */
unsigned long get_original_syscall_address(scidx_t syscall_idx) {

    hook_syscall_t * hook;

    syscall_idx = scidx_sanity_check(syscall_idx);
    if(syscall_idx < 0) return (unsigned long) NULL;

    hook = &syscall_hooks[syscall_idx];
    if(unlikely(hook->original_addr == (unsigned long) NULL)) {
        PR_ERROR("Cannot get original address for syscall %d\n", syscall_idx);
        return (unsigned long) NULL;
    }

    if(unlikely(!hook->active)) {
        PR_WARN("Returning original address for syscall %d which is not hooked\n", syscall_idx);
    }

    return hook->original_addr;
}

/**
 * @brief Uninstall a syscall hook
 * 
 * @param syscall_idx Syscall number to unhook
 * @return int 0 on success, negative error code on failure
 */
int uninstall_syscall_hook(scidx_t syscall_idx) {
    hook_syscall_t * hook;
    unsigned long ret;

    // Sanity check syscall index
    syscall_idx = scidx_sanity_check(syscall_idx);
    if(syscall_idx < 0) return -ENOSYS;

    // Check if hook is active
    hook = &syscall_hooks[syscall_idx];
    if(unlikely(!hook->active)) {
        PR_WARN("Syscall %d is not hooked, cannot uninstall\n", syscall_idx);
        return 0;
    }

    // Uninstall syscall hook
#ifdef _FTRACE_HOOKING
    PR_DEBUG("Uninstalling ftrace hook on syscall %d\n", syscall_idx);
    ret = uninstall_syscall_fhook(syscall_idx, &hook->fops);
    if(ret == (unsigned long) NULL) {
        PR_ERROR("Failed to uninstall ftrace hook on syscall %d\n", syscall_idx);
        return ret;
    }
#elif defined(_DISCOVER_HOOKING)
    PR_DEBUG("Uninstalling discover hook on syscall %d\n", syscall_idx);
    ret = uninstall_syscall_dhook(syscall_idx);
    if(ret == (unsigned long) NULL) {
        PR_ERROR("Failed to uninstall discover hook on syscall %d\n", syscall_idx);
        return -EINVAL;
    }
#endif

    // Clear hook data
    hook = &syscall_hooks[syscall_idx];
    hook->active = false;

    // Avoid to clear original_addr to allow getting it after uninstall
    // if some threads are still running that syscall and need it
    //
    // hook->original_addr = (unsigned long) NULL;

    return 0;
}

/**
 * @brief Uninstall all active syscall hooks
 * 
 * @return int 0 on success, negative error code on failure
 */
int uninstall_active_syscalls_hooks(void) {

    int ret;

    // Uninstall active hooks
    PR_DEBUG("Uninstalling all active syscall hooks...\n");
    for(size_t i = 0; i < syscall_hooks_num; i++) {
        if(syscall_hooks[i].active) {
            PR_DEBUG("Uninstalling active hook on syscall %zu\n", i);
            ret = uninstall_syscall_hook((scidx_t) i);
            if(ret < 0) {
                PR_ERROR("Failed to uninstall syscall hook on syscall %zu\n", i);
                return ret;
            }
        }
    }

    return 0;
}