#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "ops.h"
#include "monitor.h"
#include "dev.h"
#include "types.h"
#include "stats.h"
#include "filter.h"
#include "hook.h"

// Helper macros for report generation
// Print formatted data into kernel buffer and update length
// 
// fmt: format string
// ...: additional arguments for formatting
//
// len: current length of data in buffer
// limit: maximum size of the buffer
#define __SCNPRINTF(fmt, ...) (len += scnprintf(kbuf + len, limit - len, fmt, ##__VA_ARGS__))
static long monitor_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {

    char *kbuf;
    int len = 0;
    int limit = PAGE_SIZE;

    sysc_delayed_t peak_delay;
    unsigned int j;

    scidx_t *syscall_list;
    size_t syscall_count;

    uid_t *uid_list; 
    size_t uid_count;
    
    char **prog_list;
    size_t prog_count;

    get_peak_delayed_syscall(&peak_delay);

    // Allocate kernel buffer
    kbuf = (char *)__get_free_page(GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    // Allocate temporary syscall list
    syscall_list = kmalloc_array(SYSCALL_TABLE_SIZE, sizeof(scidx_t), GFP_KERNEL);
    if (!syscall_list) {
        free_page((unsigned long) kbuf);
        return -ENOMEM;
    }
    syscall_count = get_syscall_monitor_vals(syscall_list, SYSCALL_TABLE_SIZE);

    // Allocate temporary UID list
    uid_list = kmalloc_array(MAX_ITEMS, sizeof(uid_t), GFP_KERNEL);
    if (!uid_list) {
        kfree(syscall_list);
        free_page((unsigned long) kbuf);
        return -ENOMEM;
    }
    uid_count = get_uid_monitor_vals(uid_list, MAX_ITEMS);

    // Allocate temporary Prog Name list
    prog_list = kmalloc_array(MAX_ITEMS, sizeof(char *), GFP_KERNEL);
    if (!prog_list) {
        kfree(uid_list);
        kfree(syscall_list);
        free_page((unsigned long) kbuf);
        return -ENOMEM;
    }
    prog_count = get_prog_monitor_vals(prog_list, MAX_ITEMS);

    // FIXME: Locking the device data structure
    // mutex_lock(&dev->lock);

	// ---------------------------
    // ---- REPORT GENERATION ----
    // ---------------------------

    // --- General Status ---
    __SCNPRINTF("========= DEVICE STATUS =========\n");
    __SCNPRINTF("Status: %s\n", get_monitor_status() ? "ENABLED" : "DISABLED");
    __SCNPRINTF("Max Invocations/s: %llu\n", get_monitor_max_invoks());
    __SCNPRINTF("Total Syscall Invocations: %llu\n", get_monitor_cur_invoks());

    // --- Throttling Stats ---
    __SCNPRINTF("======== THROTTLING INFO ========\n");
    __SCNPRINTF("Peak Invoked Threads: %llu\n", get_peakw_invoked());
    __SCNPRINTF("Peak Blocked Threads: %llu\n", get_peakw_blocked());
    __SCNPRINTF("Avg Invoked Threads: %llu\n", get_avgw_invoked());
    __SCNPRINTF("Avg Blocked Threads: %llu\n", get_avgw_blocked());
    
    __SCNPRINTF("======== PEAK DELAY INFO ========\n");
    if (peak_delay.syscall > -1) {
        __SCNPRINTF("Delay: %lld ms\n", peak_delay.delay_ms);
        __SCNPRINTF("Syscall: %d\n", peak_delay.syscall);
        __SCNPRINTF("Program: %s\n", peak_delay.prog_name);
        __SCNPRINTF("PID: %d, UID: %d\n", peak_delay.pid, peak_delay.uid);
    } else {
        __SCNPRINTF("No delayed syscalls recorded yet.\n");
    }
    __SCNPRINTF("=================================\n");

    // --- Syscalls ---
    __SCNPRINTF("Registered Syscalls:\n");
    for (j = 0; j < syscall_count; j++) {
        __SCNPRINTF("  - [%d] %u\n", j, syscall_list[j]);
    }

    // --- UIDs ---
    __SCNPRINTF("Registered UIDs:\n");
    for (j = 0; j < uid_count; j++) {
        __SCNPRINTF("  - [%d] %u\n", j, uid_list[j]);
    }

    // --- Programs ---
    __SCNPRINTF("Registered Programs:\n");
    for (j = 0; j < prog_count; j++) {
        __SCNPRINTF("  - [%d] %s\n", j, prog_list[j]);
    }

    __SCNPRINTF("=================================\n");

	// ---------------------------
    // ---- END GENERATION ----
    // ---------------------------

    // Copy data to user space
    // If user read all data, return 0 to signal EOF
    if (*ppos >= len) {
        free_page((unsigned long)kbuf);
        return 0;
    }

    // Compute how many bytes to copy
	// Adjust count if it exceeds available data
    if (count > len - *ppos) count = len - *ppos;

	// Copy data to user buffer
    if (copy_to_user(buf, kbuf + *ppos, count)) {
        free_page((unsigned long)kbuf);
        return -EFAULT;
    }

    // Update read position for next call
    *ppos += count;

    // Free kernel buffer
    free_page((unsigned long)kbuf);

    // Free temporary lists
    kfree(syscall_list);
    kfree(uid_list);
    kfree(prog_list);

	// Return the number of bytes read
    return count;
}
#undef __SCNPRINTF

static long monitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

    scidx_t k_syscall_nr;
    uid_t k_uid;
    char *k_progname;

    u64 k_max_invoks;
    bool k_status;

    // Check root permissions
    // We can also use capable(CAP_SYS_ADMIN) if needed
    if (current_euid().val != 0) {
        PR_WARN_PID("Permission denied for non-root user: command %u\n", cmd);
        return -EPERM;
    }

    switch (cmd) {

        /* --- ADD COMMANDS --- */

        case SCT_IOCTL_ADD_SYSCALL:
            if (copy_from_user(&k_syscall_nr, (scidx_t __user *)arg, sizeof(k_syscall_nr))) return -EFAULT;
            PR_DEBUG("Adding syscall %d\n", k_syscall_nr);
            add_syscall_monitoring(k_syscall_nr);
            install_syscall_hook(k_syscall_nr);
            PR_INFO("Added syscall %d\n", k_syscall_nr);
            break;

        case SCT_IOCTL_ADD_UID:
            if (copy_from_user(&k_uid, (uid_t __user *)arg, sizeof(k_uid))) return -EFAULT;
            PR_DEBUG("Adding UID %d\n", k_uid);
            add_uid_monitoring(k_uid);
            PR_INFO("Added UID %d\n", k_uid);
            break;

        case SCT_IOCTL_ADD_PROG:
            k_progname = strndup_user((const char __user *)arg, TASK_COMM_LEN);
            if (IS_ERR(k_progname)) return PTR_ERR(k_progname);
            PR_DEBUG("Adding prog name %s\n", k_progname);
            add_prog_monitoring(k_progname);
			PR_INFO("Added prog name %s\n", k_progname);

            // Free temporary program name
            kfree(k_progname);
            break;

        /* --- REMOVE COMMANDS --- */

        case SCT_IOCTL_DEL_SYSCALL:
            if (copy_from_user(&k_syscall_nr, (scidx_t __user *)arg, sizeof(k_syscall_nr))) return -EFAULT;
            PR_DEBUG("Removing syscall %d\n", k_syscall_nr);
            uninstall_syscall_hook(k_syscall_nr);
            remove_syscall_monitoring(k_syscall_nr);
            PR_INFO("Removed syscall %d\n", k_syscall_nr);
            break;

        case SCT_IOCTL_DEL_UID:
            if (copy_from_user(&k_uid, (uid_t __user *)arg, sizeof(k_uid))) return -EFAULT;
            PR_DEBUG("Removing UID %d\n", k_uid);
            remove_uid_monitoring(k_uid);
            PR_INFO("Removed UID %d\n", k_uid);
            break;

        case SCT_IOCTL_DEL_PROG:
            k_progname = strndup_user((const char __user *)arg, TASK_COMM_LEN);
            if (IS_ERR(k_progname)) return PTR_ERR(k_progname);
            PR_DEBUG("Removing prog name %s\n", k_progname);
            remove_prog_monitoring(k_progname);
            PR_INFO("Removed prog name %s\n", k_progname);

            // Free temporary program name
            kfree(k_progname);
            break;

        /* --- CONFIGURATION COMMANDS --- */

        case SCT_IOCTL_SET_LIMIT:
            if (copy_from_user(&k_max_invoks, (u64 __user *)arg, sizeof(k_max_invoks))) return -EFAULT;
            PR_INFO("Setting new max invocations limit: %llu\n", k_max_invoks);
            set_monitor_max_invoks(k_max_invoks);
            break;

        case SCT_IOCTL_SET_STATUS:
            if (copy_from_user(&k_status, (int __user *)arg, sizeof(k_status))) return -EFAULT;
            PR_INFO("Setting monitor status: %s\n", k_status ? "ENABLED" : "DISABLED");
            set_monitor_status(k_status != 0);
            
            // TODO: Wake up all waiting processes if disabling
            break;

        default:
            return -ENOTTY;
    }

    return 0;
}

const struct file_operations sct_ops = {
    .owner 				= THIS_MODULE,
	.read 				= monitor_read,
	.unlocked_ioctl 	= monitor_ioctl,
};