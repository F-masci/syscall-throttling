#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>

#include "module.h"
#include "devs.h"
#include "ops.h"
#include "types.h"

// Module information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Masci: francescomasci@outlook.com");
MODULE_DESCRIPTION("System Call Throttling");
MODULE_VERSION("0.1");

// Device variables
static int sct_major;
static int sct_minor = 0;
static struct class* sct_class = NULL;
static struct device* sct_device = NULL;

bool sct_status = true;
unsigned long sct_max_invoks = 1000;

// Throttling control parameter
module_param(sct_status, bool, 0644);
MODULE_PARM_DESC(sct_status, "Enable (1) or disable (0) throttling");

module_param(sct_max_invoks, ulong, 0644);
MODULE_PARM_DESC(sct_max_invoks, "Maximum allowed system call invocations per second");

// Global confs array
sctdev_confs_t sct_confs[MAX_DEVICES];

/**
 * @brief Initialize the system call throttling module
 * 
 * @return int 
 */
static int __init sct_init(void) {

    printk(KERN_INFO "%s: Initializing module...\n", MODULE_NAME);

    // Device registration
    sct_major = register_chrdev(0, DEVICE_NAME, &sct_ops);
    if (sct_major < 0) {
        printk(KERN_ALERT "%s: Device registration failed with %d\n", MODULE_NAME, sct_major);
        return sct_major;
    }
    printk(KERN_INFO "%s: Device registered successfully with major number %d\n", MODULE_NAME, sct_major);

    // Class creation
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
        sct_class = class_create(CLASS_NAME);
    #else
        sct_class = class_create(THIS_MODULE, CLASS_NAME);
    #endif

    if (IS_ERR(sct_class)) {
        printk(KERN_ALERT "%s: Failed to create device class\n", MODULE_NAME);
        unregister_chrdev(sct_major, DEVICE_NAME);
        return PTR_ERR(sct_class);
    }
    printk(KERN_INFO "%s: Device class created successfully\n", MODULE_NAME);

    // Device node creation
    sct_device = device_create(sct_class, NULL, MKDEV(sct_major, sct_minor), NULL, DEFAULT_DEVICE_PATH);
    if (IS_ERR(sct_device)) {
        printk(KERN_ALERT "%s: Failed to create the device node\n", MODULE_NAME);
        class_destroy(sct_class);
        unregister_chrdev(sct_major, DEVICE_NAME);
        return PTR_ERR(sct_device);
    }
    printk(KERN_INFO "%s: Device node created at /dev/%s\n", MODULE_NAME, DEFAULT_DEVICE_PATH);

    // Init confs for each possible minor
    for (int i = 0; i < MAX_DEVICES; i++) {

        // Allocate memory for arrays
        // FIXME: use linked list instead of static arrays to save memory
        sct_confs[i].pids = kcalloc(MAX_ITEMS, sizeof(pid_t), GFP_KERNEL);
        sct_confs[i].syscalls = kcalloc(MAX_ITEMS, sizeof(scidx_t), GFP_KERNEL);
        sct_confs[i].prog_names = kcalloc(MAX_ITEMS, sizeof(char*), GFP_KERNEL);

        if (!sct_confs[i].pids || !sct_confs[i].syscalls || !sct_confs[i].prog_names) {
            // Free previously allocated memory
            kfree(sct_confs[i].pids);
            kfree(sct_confs[i].syscalls);
            kfree(sct_confs[i].prog_names);
            printk(KERN_ERR "%s: Memory allocation error for device %d\n", MODULE_NAME, i);
            return -ENOMEM;
        }
    }

    printk(KERN_INFO "%s: Module loaded successfully\n", MODULE_NAME);

    return 0;
}

/**
 * @brief Cleanup the system call throttling module
 * 
 */
static void __exit sct_exit(void) {

    printk(KERN_INFO "%s: Removing module...\n", MODULE_NAME);

    device_destroy(sct_class, MKDEV(sct_major, sct_minor));
    class_destroy(sct_class);
    unregister_chrdev(sct_major, DEVICE_NAME);

    // Free confs memory
    for (int i = 0; i < MAX_DEVICES; i++) {
        kfree(sct_confs[i].pids);
        kfree(sct_confs[i].syscalls);
        kfree(sct_confs[i].prog_names);
    }

    printk(KERN_INFO "%s: Module unloaded\n", MODULE_NAME);

}

module_init(sct_init);
module_exit(sct_exit);