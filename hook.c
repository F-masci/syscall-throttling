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

#define HOOK_METHOD_NAME "ftrace"

static DEFINE_MUTEX(hook_mutex);
#define HOOK_DEFINE_FLAGS(x)

#define HOOK_LOCK(base_name, flags) mutex_lock(&base_name##_mutex)
#define HOOK_UNLOCK(base_name, flags) mutex_unlock(&base_name##_mutex)

#define SETUP_HOOK() setup_ftrace_hook()
#define INIT_SYSCALL_HOOK(hook) init_syscall_fhook(hook)
#define CLEANUP_HOOK() cleanup_ftrace_hook()

#define INSTALL_SYSCALL_HOOK(hook) install_syscall_fhook(hook)
#define UNINSTALL_SYSCALL_HOOK(hook) uninstall_syscall_fhook(hook)

#elif defined(_DISCOVER_HOOKING)

#define HOOK_METHOD_NAME "discover"

static DEFINE_SPINLOCK(hook_lock);
#define HOOK_DEFINE_FLAGS(x) unsigned long x

#define HOOK_LOCK(base_name, flags) spin_lock_irqsave(&base_name##_lock, flags)
#define HOOK_UNLOCK(base_name, flags) spin_unlock_irqrestore(&base_name##_lock, flags)

#define SETUP_HOOK() setup_discover_hook()
#define INIT_SYSCALL_HOOK(hook) init_syscall_dhook(hook)
#define CLEANUP_HOOK() cleanup_discover_hook()

#define INSTALL_SYSCALL_HOOK(hook) install_syscall_dhook(hook)
#define UNINSTALL_SYSCALL_HOOK(hook) uninstall_syscall_dhook(hook)

#else
#endif

static struct hook_syscall_t *syscall_hooks;
static size_t syscall_hooks_num;

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
	syscall_hooks = kcalloc(num_syscalls, sizeof(struct hook_syscall_t), GFP_KERNEL);
	if (!syscall_hooks) {
		PR_ERROR("Cannot allocate memory for syscall hooks\n");
		ret = -ENOMEM;
		goto hooks_alloc_err;
	}
	PR_DEBUG("Syscall hooks data structure allocated\n");

	// Setup hooking method
	PR_INFO("Setting up %s hooking mode...\n", HOOK_METHOD_NAME);

	// Setup hooking
	ret = SETUP_HOOK();
	if (ret < 0) {
		PR_ERROR("Failed to set up %s hooking mode\n", HOOK_METHOD_NAME);
		goto hook_setup_err;
	}

	// Init discover hooking structures
	// Fill hook structures for each syscall
	// with both common and hook-specific data
	for (int idx = 0; idx < num_syscalls; idx++) {
		hook = &syscall_hooks[idx];
		hook->syscall_idx = idx;
		hook->hook_addr = (unsigned long)syscall_wrapper;
		ret = INIT_SYSCALL_HOOK(hook);

		if (ret < 0) {
			PR_ERROR("Failed to set up %s hook structure for syscall %d\n", HOOK_METHOD_NAME, idx);
			goto init_structs_err;
		}
	}

	PR_INFO("%s hooking mode setup completed\n", HOOK_METHOD_NAME);

	syscall_hooks_num = num_syscalls;

	// Ensure memory operations are completed before proceeding
	// so that other CPUs see the updated syscall table
	mb();

	return ret;

init_structs_err:
	CLEANUP_HOOK();

hook_setup_err:
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
	CLEANUP_HOOK();
	PR_DEBUG("%s hooking mode cleaned up\n", HOOK_METHOD_NAME);
}

/**
 * @brief Install a syscall hook
 *
 * @param syscall_idx Syscall number to hook
 * @return int 0 on success, negative error code on failure
 */
int install_syscall_hook(int syscall_idx)
{
	struct hook_syscall_t *hook;
	int ret = 0;
	HOOK_DEFINE_FLAGS(flags);

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

	HOOK_LOCK(hook, flags);

	// Check if already hooked
	hook = &syscall_hooks[syscall_idx];
	if (unlikely(hook->active)) {
		PR_WARN("Syscall %d is already hooked\n", syscall_idx);
		goto installed_hook;
	}

	// Install syscall hook
	PR_DEBUG("Installing %s hook on syscall %d\n", HOOK_METHOD_NAME, syscall_idx);
	ret = INSTALL_SYSCALL_HOOK(hook);

	if (ret < 0) {
		PR_ERROR("Failed to install %s hook on syscall %d\n", HOOK_METHOD_NAME, syscall_idx);
		goto installation_hook_err;
	}

	hook->active = true;

installation_hook_err:
installed_hook:

	HOOK_UNLOCK(hook, flags);

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
	syscall_list = kcalloc(SYSCALL_TABLE_SIZE, sizeof(int), GFP_KERNEL);
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
	struct hook_syscall_t *hook;
	int ret = 0;
	HOOK_DEFINE_FLAGS(flags);

	// Sanity check syscall index
	syscall_idx = scidx_sanity_check(syscall_idx);
	if (syscall_idx < 0)
		return -EINVAL;

	HOOK_LOCK(hook, flags);

	// Check if hook is active
	hook = &syscall_hooks[syscall_idx];
	if (unlikely(!hook->active)) {
		PR_WARN("Syscall %d is not hooked, cannot uninstall\n", syscall_idx);
		goto uninstalled_hook;
	}

	// Uninstall syscall hook
	PR_DEBUG("Uninstalling %s hook on syscall %d\n", HOOK_METHOD_NAME, syscall_idx);
	ret = UNINSTALL_SYSCALL_HOOK(hook);
	if (ret < 0) {
		PR_ERROR("Failed to uninstall %s hook on syscall %d\n", HOOK_METHOD_NAME, syscall_idx);
		goto uninstallation_hook_err;
	}

	hook->active = false;

	// Avoid to clear original_addr to allow getting it after uninstall
	// if some threads are still running that syscall and need it
	//
	// hook->original_addr = (unsigned long) NULL;

uninstallation_hook_err:
uninstalled_hook:

	HOOK_UNLOCK(hook, flags);

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
