/**
 * @file probe.c
 * @author Francesco Masci (francescomasci@outlook.com)
 *
 * @brief This file implements helper functions to get syscall addresses. It
 *		provides functions to load the sys_ni_syscall address and to get
 *		syscall addresses by their indices.
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

#include "probe.h"
#include "../../sct.h"
#include "../../_syst.h"

static unsigned long sys_ni_syscall_address;

/**
 * @brief Get the sys_ni_syscall address
 *
 * @return unsigned long
 */
int load_sys_ni_syscall_address(void) {

	// Set up kprobe for sys_ni_syscall
	struct kprobe kp = { .symbol_name = "sys_ni_syscall" };
	int ret;

	// Register kprobe
	ret = register_kprobe(&kp);
	if (ret < 0) {
		PR_ERROR("Failed to find sys_ni_syscall address\n");
		return ret;
	}
	PR_DEBUG("Kprobe registered for sys_ni_syscall\n");

	// Get syscall address
	sys_ni_syscall_address = (unsigned long) kp.addr;

	// Unregister kprobe
	unregister_kprobe(&kp);
	PR_DEBUG("Kprobe unregistered for sys_ni_syscall\n");

	return 0;
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
static inline int __get_syscall_fullname(char *buf, size_t size, int syscall_idx) {

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
		case __NR_perf_event_open:
			PR_WARN("Redirecting perf_event_open tracing to internal function security_perf_event_open\n");
			ret = snprintf(buf, size, "security_perf_event_open");
			goto fullname_found;
		default:
			break;
	}

	ret = snprintf(buf, size, "__x64_sys_%s%s%s", prefix, short_name, suffix);

fullname_found:
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
 * @param hook Pointer to the struct hook_syscall_t structure
 *
 * @return int 0 on success, negative error code on failure
 */
int set_syscall_address(struct hook_syscall_t * hook) {

	char full_name[FNAME_BUF_SIZE];
	struct kprobe kp;
	int ret = 0;

	// Check for valid pointer
	if (unlikely(!hook)) {
		PR_ERROR("Invalid pointer for syscall address output\n");
		return -EINVAL;
	}

	// Construct full syscall name
	ret = __get_syscall_fullname(full_name, FNAME_BUF_SIZE, hook->syscall_idx);
	if (ret < 0) {
		PR_ERROR("Failed to get full syscall name for index %d\n", hook->syscall_idx);
		goto nil_syscall_addr;
	}
	PR_DEBUG("Full syscall name for index %d: %s\n", hook->syscall_idx, full_name);

	// Setup kprobe
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = full_name;

	// Register kprobe
	ret = register_kprobe(&kp);
	if (ret < 0) {
		PR_ERROR("Failed to register kprobe on %s\n", full_name);
		goto nil_syscall_addr;
	}
	PR_DEBUG("Kprobe registered for %s\n", full_name);

	// Get syscall address
	hook->original_addr = (unsigned long) kp.addr;

	// Unregister kprobe
	unregister_kprobe(&kp);
	PR_DEBUG("Kprobe unregistered for %s\n", full_name);

	return 0;

nil_syscall_addr:
	PR_WARN("Using sys_ni_syscall for index %d\n", hook->syscall_idx);
	hook->original_addr = sys_ni_syscall_address;
	hook->nil_syscall = true;
	return 0;
}
#undef FNAME_BUF_SIZE