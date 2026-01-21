/**
 * @file dev.c
 * @author Francesco Masci (francescomasci@outlook.com)
 * 
 * @brief This file implements the character device creation and management
 *        for the syscall throttling module. It sets up the device, class,
 *        and device node in /dev for user-space interaction.
 * 
 * @version 1.0
 * @date 2026-01-21
 * 
 */

#include <linux/cdev.h>
#include <linux/device.h>

#include "dev.h"
#include "ops.h"

static dev_t dev;
static struct cdev cdev;
static struct class* dclass = NULL;
static struct device* dnode = NULL;

/**
 * @brief Set the up monitor device object.
 * Creates and registers the character device for syscall monitoring
 * and the associated device node in /dev.
 * 
 * @return int 0 on success, negative error code on failure
 */
int setup_monitor_device(void) {

    int ret;

    // Device registration
    ret = alloc_chrdev_region(&dev, DEVICE_MINOR, MAX_DEV_MINORS, DEVICE_NAME);
    if (ret < 0) {
        PR_ERROR("Device registration failed with %d\n", ret);
        return ret;
    }
    PR_INFO("Device registered successfully with major number %d\n", MAJOR(dev));

    // Device initialization
    cdev_init(&cdev, &monitor_operations);
    cdev.owner = THIS_MODULE;

    // Device addition
    ret = cdev_add(&cdev, dev, MAX_DEV_MINORS);
    if (ret < 0) {
        PR_ERROR("Device addition failed with %d\n", ret);
        goto err_cdev;
    }
    PR_INFO("Device added successfully\n");

    // Class creation
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
        dclass = class_create(CLASS_NAME);
    #else
        dclass = class_create(THIS_MODULE, CLASS_NAME);
    #endif

    if (IS_ERR(dclass)) {
        PR_ERROR("Failed to create device class\n");
        ret = PTR_ERR(dclass);
        goto err_class;
    }
    PR_INFO("Device class created successfully\n");

    // Device node creation
    dnode = device_create(dclass, NULL, dev, NULL, DNODE_NAME);
    if (IS_ERR(dnode)) {
        PR_ERROR("Failed to create the device node\n");
        ret = PTR_ERR(dnode);
        goto err_device;
    }
    PR_INFO("Device node created at /dev/%s\n", DNODE_NAME);

    return 0;

err_device:
    class_destroy(dclass);
err_class:
    cdev_del(&cdev);
err_cdev:
    unregister_chrdev_region(dev, MAX_DEV_MINORS);
        
    return ret;
}

/**
 * @brief Clean up the monitor device object.
 * Unregisters and deletes the character device and its associated
 * device node in /dev.
 * 
 */
void cleanup_monitor_device(void) {

    // Device node cleanup
    if (dclass && dnode) {
        device_destroy(dclass, dev); 
        dnode = NULL;
        PR_DEBUG("Device node destroyed successfully\n");
    }

    // Class cleanup
    if(dclass) {
        class_destroy(dclass);
        dclass = NULL;
        PR_DEBUG("Class destroyed successfully\n");
    }

    // Cdev cleanup
    cdev_del(&cdev);
    PR_DEBUG("Cdev deleted successfully\n");
    
    // Device unregistration
    unregister_chrdev_region(dev, MAX_DEV_MINORS);
    PR_DEBUG("Device unregistered successfully\n");
}