#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Francesco Masci");
MODULE_DESCRIPTION("Un semplice modulo Hello World");
MODULE_VERSION("0.1");

static int __init hello_init(void) {
    printk(KERN_INFO "Driver: Hello World! Il modulo e' stato caricato.\n");
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_INFO "Driver: Goodbye World! Il modulo e' stato rimosso.\n");
}

module_init(hello_init);
module_exit(hello_exit);