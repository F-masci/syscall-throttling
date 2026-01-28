/**
 * @file dhook.c
 * @author Francesco Masci (francescomasci@outlook.com)
 *
 * @brief This file implements the discover hooking mechanism for syscalls. It
 *		provides functions to initialize, install, and uninstall syscall hooks
 *		using the discover hooking method.
 *
 * @version 1.0
 * @date 2026-01-26
 *
 */

#include <asm/barrier.h>

#include "disc.h"
#include "sthack.h"

#include "dhook.h"
#include "../../sct.h"

/**
 * @brief Initialize a syscall hook structure for discover hooking
 *
 * @param hook Pointer to the struct hook_syscall_t structure
 *
 * @return int 0 on success, negative error code on failure
 */
int init_syscall_dhook(struct hook_syscall_t *hook)
{
	unsigned long **hacked_syscall_tbl = get_syscall_table_addr();

	// Check for valid pointer
	if (unlikely(!hook)) {
		PR_ERROR("Invalid hook pointer\n");
		return -EINVAL;
	}

	// Basic safety check
	if (unlikely(!hacked_syscall_tbl)) {
		PR_ERROR("Syscall table not found\n");
		return -EINVAL;
	}

	// Init hook structure
	hook->original_addr = (unsigned long)hacked_syscall_tbl[hook->syscall_idx];
	if (!hook->original_addr) {
		PR_WARN("Original syscall address is NULL for syscall %d\n", hook->syscall_idx);
		hook->nil_syscall = true;
	}
	PR_DEBUG("Discover hook structure set up for syscall %d\n", hook->syscall_idx);

	return 0;
}

/**
 * @brief Install a syscall hook using discover
 *
 * @param hook Pointer to the struct hook_syscall_t structure
 *
 * @return int 0 on success, negative error code on failure
 */
int install_syscall_dhook(struct hook_syscall_t *hook)
{
	unsigned long **hacked_syscall_tbl = get_syscall_table_addr();
	// unsigned long * original_syscall_addrs = get_original_syscall_addrs();

	// Check for valid pointer
	if (unlikely(!hook)) {
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

	// Basic safety check
	if (unlikely(!hacked_syscall_tbl)) {
		PR_ERROR("Syscall table not found\n");
		return -EINVAL;
	}

	begin_syscall_table_hack();
	PR_DEBUG("Syscall table hacking started for syscall %d\n", hook->syscall_idx);

	// Save the original syscall address (done only once at startup)
	// original_syscall_addrs[syscall_idx] = (unsigned long)hacked_syscall_tbl[syscall_idx];

	// Install the hook
	hacked_syscall_tbl[hook->syscall_idx] = (unsigned long *)hook->hook_addr;

	end_syscall_table_hack();
	PR_DEBUG("Syscall table hacking ended for syscall %d\n", hook->syscall_idx);

	hook->active = true;

	// Ensure memory operations are completed before proceeding
	// so that other CPUs see the updated syscall table
	mb();

	return 0;
}

/**
 * @brief Remove a syscall hook using discover
 *
 * @param hook Pointer to the struct hook_syscall_t structure
 *
 * @return int 0 on success, negative error code on failure
 */
int uninstall_syscall_dhook(struct hook_syscall_t *hook)
{
	unsigned long hook_addr;

	unsigned long **hacked_syscall_tbl = get_syscall_table_addr();

	// Check for valid pointer
	if (unlikely(!hook)) {
		PR_ERROR("Invalid hook pointer\n");
		return -EINVAL;
	}

	// Check for nil syscall
	if (unlikely(hook->nil_syscall)) {
		PR_WARN("Skip unhook of syscall %d as it is a nil syscall\n", hook->syscall_idx);
		return 0;
	}

	// Basic safety check
	if (unlikely(!hacked_syscall_tbl || !hook->original_addr)) {
		PR_ERROR("Invalid state for syscall %d.\n", hook->syscall_idx);
		return -EINVAL;
	}

	// Get the current hook address
	hook_addr = (unsigned long)hacked_syscall_tbl[hook->syscall_idx];

	// Check if the hook is currently installed
	if (unlikely(!hook->active || hook_addr != hook->hook_addr)) {
		PR_ERROR("No hook installed for syscall %d.\n", hook->syscall_idx);
		return -EINVAL;
	}

	begin_syscall_table_hack();
	PR_DEBUG("Syscall table hacking started for syscall %d\n", hook->syscall_idx);

	// Restore the original syscall address
	hacked_syscall_tbl[hook->syscall_idx] = (unsigned long *)hook->original_addr;

	end_syscall_table_hack();
	PR_DEBUG("Syscall table hacking ended for syscall %d\n", hook->syscall_idx);

	hook->active = false;

	// Ensure memory operations are completed before proceeding
	// so that other CPUs see the updated syscall table
	mb();

	return 0;
}
