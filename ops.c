#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include "ops.h"
#include "module.h"
#include "devs.h"
#include "types.h"

extern sctdev_confs_t sct_confs[MAX_DEVICES];
extern bool sct_status;
extern unsigned long sct_max_invoks;

#define THIS_CONF ((sctdev_confs_t *)file->private_data)

static int monitor_open(struct inode *inode, struct file *file) {

	int minor = iminor(inode);
	// TODO: Check if can use %MAX_DEVICES instead of this
    if (minor >= MAX_DEVICES) return -ENODEV;

	// Assign device-specific configuration to file's private data
	// This allows each device instance to maintain its own state
	// based on its minor number
    file->private_data = &sct_confs[minor];

    printk(KERN_INFO "%s: Device opened. Minor: %d\n", MODULE_NAME, minor);
    return 0;
}

// Helper macros for report generation
// Print formatted data into kernel buffer and update length
// 
// fmt: format string
// ...: additional arguments for formatting
//
// len: current length of data in buffer
// limit: maximum size of the buffer
#define __SCNPRINTF(fmt, ...) (len += scnprintf(kbuf + len, limit - len, fmt, ##__VA_ARGS__))

#define __PRINT_LIST_INT(title, array) \
    do { \
        __SCNPRINTF(title); \
        for (int _i = 0; _i < MAX_ITEMS; _i++) { \
            if ((array)[_i] != 0) { \
                __SCNPRINTF("  - [%d] %d\n", _i, (array)[_i]); \
            } \
        } \
    } while(0)

#define __PRINT_LIST_STR(title, array) \
    do { \
        __SCNPRINTF(title); \
        for (int _i = 0; _i < MAX_ITEMS; _i++) { \
            if ((array)[_i] != NULL) { \
                __SCNPRINTF("  - [%d] %s\n", _i, (array)[_i]); \
            } \
        } \
    } while(0)

static long monitor_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {

	sctdev_confs_t *dev = THIS_CONF;
    char *kbuf;
    int len = 0;
    int limit = PAGE_SIZE;

    // Allocate kernel buffer
	// Use __get_free_page to allocate a single page
    kbuf = (char *)__get_free_page(GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    // FIXME: Locking the device data structure
    // mutex_lock(&dev->lock);

	// ---------------------------
    // ---- REPORT GENERATION ----
    // ---------------------------

	// FIXME: Buffer overflow check

    // --- General Status ---
    __SCNPRINTF("=== SCT DEVICE STATUS ===\n");
    __SCNPRINTF("Status: %s\n", sct_status ? "ENABLED" : "DISABLED");
    __SCNPRINTF("Max Invocations/s: %lu\n", sct_max_invoks);
    __SCNPRINTF("-------------------------\n");

    // --- PIDs ---
    __PRINT_LIST_INT("Registered PIDs:\n", dev->pids);

    // --- Syscalls ---
    __PRINT_LIST_INT("Registered Syscalls:\n", dev->syscalls);

    // --- Programs ---
    __PRINT_LIST_STR("Registered Programs:\n", dev->prog_names);

    __SCNPRINTF("=========================\n");

	// ---------------------------
    // ---- END GENERATION ----
    // ---------------------------


    // FIXME: Unlocking the device data structure
    // mutex_unlock(&dev->lock);

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

	// Return the number of bytes read
    return count;
}
#undef __SCNPRINTF
#undef __PRINT_LIST_INT
#undef __PRINT_LIST_STR


#define FIND_FREE_INDEX(array, type) ({ \
    int _ret = -1; \
    for (int _i = 0; _i < (MAX_ITEMS); _i++) { \
        if (((type *)(array))[_i] == 0) { \
            _ret = _i; \
            break; \
        } \
    } \
    _ret; \
})
static long monitor_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {

    sctdev_confs_t *dev = THIS_CONF;

    int idx;
    int ret = 0;
    char *u_str_tmp;

    // TODO: Implementing locking mechanism
    // mutex_lock(&dev->lock);

    // FIXME: Check if there's space in the arrays

    switch (cmd) {
        case SCT_IOCTL_ADD_PID:
            idx = FIND_FREE_INDEX(dev->pids, pid_t);
            if (copy_from_user(&dev->pids[idx], (pid_t __user *)arg, sizeof(*dev->pids)))
				return -EFAULT;
            printk(KERN_INFO "%s: Added PID %d to device\n", MODULE_NAME, dev->pids[idx]);
            break;

        case SCT_IOCTL_ADD_SYSCALL:
			idx = FIND_FREE_INDEX(dev->syscalls, scidx_t);
            if (copy_from_user(&dev->syscalls[idx], (scidx_t __user *)arg, sizeof(scidx_t)))
                return -EFAULT;
            printk(KERN_INFO "%s: Added syscall %d\n", MODULE_NAME, dev->syscalls[idx]);
            break;

        case SCT_IOCTL_ADD_PROG:
            u_str_tmp = strndup_user((const char __user *)arg, 128);
            if (IS_ERR(u_str_tmp)) return PTR_ERR(u_str_tmp);
			
			idx = FIND_FREE_INDEX(dev->prog_names, char *);
			dev->prog_names[idx] = u_str_tmp;
			printk(KERN_INFO "%s: Added prog name %s\n", MODULE_NAME, u_str_tmp);
            break;

        default:
            ret = -ENOTTY; // Comando non valido
    }

	// TODO: Implementing locking mechanism
    // mutex_unlock(&dev->lock);
    return 0;
}
#undef FIND_FREE_INDEX

static int monitor_release(struct inode *inode, struct file *file) {
	printk(KERN_INFO "%s: Device closed. Minor: %d\n", MODULE_NAME, iminor(inode));
	return 0;
}

const struct file_operations sct_ops = {
    .owner 				= THIS_MODULE,
    .open 				= monitor_open,
	.read 				= monitor_read,
	.unlocked_ioctl 	= monitor_ioctl,
    .release 			= monitor_release,
};