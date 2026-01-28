/**
 * @file hook.c
 * @author Francesco Masci (francescomasci@outlook.com)
 *
 * @brief This file implements the hooking mechanisms for the syscall.
 *		It sets up hooks for syscalls using either ftrace or discover
 *		hooking methods based on configuration on compile time.
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
#include <linux/mutex.h>
#elif defined(_DISCOVER_HOOKING)
#endif

static struct hook_syscall_t *syscall_hooks;
static size_t syscall_hooks_num;

#ifdef _FTRACE_HOOKING
static DEFINE_MUTEX(hook_mutex);
#elif defined(_DISCOVER_HOOKING)
static DEFINE_SPINLOCK(hook_lock);
#endif

static inline int scidx_sanity_check(int idx)
{
	if (unlikely(idx < 0 || idx >= syscall_hooks_num)) {
		PR_ERROR("Invalid syscall index %d\n", idx);
		return -EINVAL;
	}
	return array_index_nospec(idx, syscall_hooks_num);
}

/**
 * @brief Setup syscall hooks data structure
 *
 * @param num_syscalls Number of syscalls
 * @return int 0 on success, negative error code on failure
 */
int setup_syscall_hooks(size_t num_syscalls)
{
	int ret;
	struct hook_syscall_t *hook;

	// Allocate syscall hooks data structure
	syscall_hooks = kmalloc_array(num_syscalls, sizeof(struct hook_syscall_t), GFP_KERNEL);
	if (!syscall_hooks) {
		PR_ERROR("Cannot allocate memory for syscall hooks\n");
		ret = -ENOMEM;
		goto hooks_alloc_err;
	}
	memset(syscall_hooks, 0, num_syscalls * sizeof(struct hook_syscall_t));
	PR_DEBUG("Syscall hooks data structure allocated\n");

	// Setup hooking method
#ifdef _FTRACE_HOOKING
	PR_INFO("Setting up ftrace hooking mode...\n");
	// Setup ftrace hooking
#elif defined(_DISCOVER_HOOKING)
	PR_INFO("Setting up discover hooking mode...\n");

	// Setup discover hooking
	ret = setup_discover_hook();
	if (ret < 0) {
		PR_ERROR("Failed to set up discover hooking mode\n");
		goto dhook_setup_err;
	}
#endif

	// Init discover hooking structures
	// Fill hook structures for each syscall
	// with both common and hook-specific data
	for (int idx = 0; idx < num_syscalls; idx++) {
		hook = &syscall_hooks[idx];
		hook->syscall_idx = idx;
		hook->hook_addr = (unsigned long)syscall_wrapper;
#ifdef _FTRACE_HOOKING
		ret = init_syscall_fhook(hook);
#elif defined(_DISCOVER_HOOKING)
		ret = init_syscall_dhook(hook);
#endif

		if (ret < 0) {
#ifdef _FTRACE_HOOKING
			PR_ERROR("Failed to set up ftrace hook structure for syscall %d\n", idx);
#elif defined(_DISCOVER_HOOKING)
			PR_ERROR("Failed to set up discover hook structure for syscall %d\n", idx);
#endif
			goto init_structs_err;
		}
	}

#ifdef _FTRACE_HOOKING
	PR_INFO("Ftrace hooking mode setup completed\n");
#elif defined(_DISCOVER_HOOKING)
	PR_INFO("Discover hooking mode setup completed\n");
#endif

	syscall_hooks_num = num_syscalls;

	// Ensure memory operations are completed before proceeding
	// so that other CPUs see the updated syscall table
	mb();

	return ret;

init_structs_err:
#ifdef _FTRACE_HOOKING
#elif defined(_DISCOVER_HOOKING)
dhook_setup_err:
#endif
	kfree(syscall_hooks);

hooks_alloc_err:
	return ret;
}

/**
 * @brief Cleanup syscall hooks
 *
 */
void cleanup_syscall_hooks(void)
{
	// Uninstall active hooks
	if (uninstall_active_syscalls_hooks() < 0)
		PR_ERROR("Failed to uninstall all active syscall hooks during cleanup\n");
	PR_DEBUG("All active syscall hooks uninstalled\n");

	// Free syscall hooks data structure
	kfree(syscall_hooks);
	PR_DEBUG("Syscall hooks data structure freed\n");

	// Cleanup hooking method
#ifdef _FTRACE_HOOKING
	cleanup_ftrace_hook();
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
int install_syscall_hook(int syscall_idx)
{
#ifdef _FTRACE_HOOKING
#elif defined(_DISCOVER_HOOKING)
	unsigned long flags;
#endif
	struct hook_syscall_t *hook;
	int ret = 0;

	// Sanity check syscall index
	syscall_idx = scidx_sanity_check(syscall_idx);
	if (syscall_idx < 0) {
		PR_ERROR("Invalid syscall index %d\n", syscall_idx);
		return -EINVAL;
	}

	// Check monitor status
	if (unlikely(!get_monitor_status())) {
		PR_WARN("Skip hook installation on syscall %d as monitoring is disabled\n", syscall_idx);
		return 0;
	}

#ifdef _FTRACE_HOOKING
	mutex_lock(&hook_mutex);
#elif defined(_DISCOVER_HOOKING)
	spin_lock_irqsave(&hook_lock, flags);
#endif

	// Check if already hooked
	hook = &syscall_hooks[syscall_idx];
	if (unlikely(hook->active)) {
		PR_WARN("Syscall %d is already hooked\n", syscall_idx);
		goto installed_hook;
	}

	// Install syscall hook
#ifdef _FTRACE_HOOKING
	PR_DEBUG("Installing ftrace hook on syscall %d\n", syscall_idx);
	ret = install_syscall_fhook(hook);
#elif defined(_DISCOVER_HOOKING)
	PR_DEBUG("Installing discover hook on syscall %d\n", syscall_idx);
	ret = install_syscall_dhook(hook);
#endif

	if (ret < 0) {
#ifdef _FTRACE_HOOKING
		PR_ERROR("Failed to install ftrace hook on syscall %d\n", syscall_idx);
#elif defined(_DISCOVER_HOOKING)
		PR_ERROR("Failed to install discover hook on syscall %d\n", syscall_idx);
#endif
		goto installation_hook_err;
	}

	hook->active = true;

installation_hook_err:
installed_hook:

#ifdef _FTRACE_HOOKING
	mutex_unlock(&hook_mutex);
#elif defined(_DISCOVER_HOOKING)
	spin_unlock_irqrestore(&hook_lock, flags);
#endif

	return ret;
}

/**
 * @brief Install hooks for all monitored syscalls
 *
 * @return int 0 on success, negative error code on failure
 */
int install_monitored_syscalls_hooks(void)
{
	int *syscall_list;
	size_t syscall_count;
	int ret = 0;

	// Get monitored syscalls
	syscall_list = kmalloc_array(SYSCALL_TABLE_SIZE, sizeof(int), GFP_KERNEL);
	if (!syscall_list) {
		PR_ERROR("Failed to allocate memory for syscall list\n");
		return -ENOMEM;
	}
	syscall_count = get_syscall_monitor_vals(syscall_list, SYSCALL_TABLE_SIZE);
	PR_DEBUG("Retrieved %lu monitored syscalls to hook\n", syscall_count);

	// Install hooks
	for (size_t i = 0; i < syscall_count; i++) {
		ret = install_syscall_hook(syscall_list[i]);
		if (ret < 0) {
			PR_ERROR("Failed to install hook on monitored syscall %d\n", syscall_list[i]);
			break;
		}
	}
	kfree(syscall_list);

	// On error, uninstall all installed hooks
	if (ret < 0 && uninstall_active_syscalls_hooks() < 0)
		PR_ERROR("Failed to uninstall all syscall hooks after install error\n");

	return ret;
}

/**
 * @brief Get the original syscall address (after hooking)
 *
 * @param syscall_idx Syscall number
 * @return unsigned long Original syscall address, or NULL on failure
 */
unsigned long get_original_syscall_address(int syscall_idx)
{
	struct hook_syscall_t *hook;

	syscall_idx = scidx_sanity_check(syscall_idx);
	if (syscall_idx < 0)
		return (unsigned long)NULL;

	// Get original syscall address
	hook = &syscall_hooks[syscall_idx];
	if (unlikely(hook->original_addr == (unsigned long)NULL)) {
		PR_ERROR("Cannot get original address for syscall %d\n", syscall_idx);
		return (unsigned long)NULL;
	}

	// Warn if syscall is not hooked
	if (unlikely(!hook->active))
		PR_WARN("Returning original address for syscall %d which is not hooked\n", syscall_idx);

	return hook->original_addr;
}

/**
 * @brief Uninstall a syscall hook
 *
 * @param syscall_idx Syscall number to unhook
 * @return int 0 on success, negative error code on failure
 */
int uninstall_syscall_hook(int syscall_idx)
{
#ifdef _FTRACE_HOOKING
#elif defined(_DISCOVER_HOOKING)
	unsigned long flags;
#endif
	struct hook_syscall_t *hook;
	int ret = 0;

	// Sanity check syscall index
	syscall_idx = scidx_sanity_check(syscall_idx);
	if (syscall_idx < 0)
		return -EINVAL;

#ifdef _FTRACE_HOOKING
	mutex_lock(&hook_mutex);
#elif defined(_DISCOVER_HOOKING)
	spin_lock_irqsave(&hook_lock, flags);
#endif

	// Check if hook is active
	hook = &syscall_hooks[syscall_idx];
	if (unlikely(!hook->active)) {
		PR_WARN("Syscall %d is not hooked, cannot uninstall\n", syscall_idx);
		goto uninstalled_hook;
	}

	// Uninstall syscall hook
#ifdef _FTRACE_HOOKING
	PR_DEBUG("Uninstalling ftrace hook on syscall %d\n", syscall_idx);
	ret = uninstall_syscall_fhook(hook);
	if (ret < 0) {
		PR_ERROR("Failed to uninstall ftrace hook on syscall %d\n", syscall_idx);
		goto uninstallation_hook_err;
	}
#elif defined(_DISCOVER_HOOKING)
	PR_DEBUG("Uninstalling discover hook on syscall %d\n", syscall_idx);
	ret = uninstall_syscall_dhook(hook);
	if (ret < 0) {
		PR_ERROR("Failed to uninstall discover hook on syscall %d\n", syscall_idx);
		goto uninstallation_hook_err;
	}
#endif

	hook->active = false;

	// Avoid to clear original_addr to allow getting it after uninstall
	// if some threads are still running that syscall and need it
	//
	// hook->original_addr = (unsigned long) NULL;

uninstallation_hook_err:
uninstalled_hook:

#ifdef _FTRACE_HOOKING
	mutex_unlock(&hook_mutex);
#elif defined(_DISCOVER_HOOKING)
	spin_unlock_irqrestore(&hook_lock, flags);
#endif

	return ret;
}

/**
 * @brief Uninstall all active syscall hooks
 *
 * @return int 0 on success, negative error code on failure
 */
int uninstall_active_syscalls_hooks(void)
{
	int ret;

	// Uninstall active hooks
	PR_DEBUG("Uninstalling all active syscall hooks...\n");
	for (int i = 0; i < syscall_hooks_num; i++) {
		// Check if hook is active
		if (syscall_hooks[i].active) {
			PR_DEBUG("Uninstalling active hook on syscall %d\n", i);
			ret = uninstall_syscall_hook(i);
			if (ret < 0) {
				PR_ERROR("Failed to uninstall syscall hook on syscall %d\n", i);
				return ret;
			}
		}
	}

	return 0;
}
