#include <linux/module.h>
#include "memdev.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR ("dawter");
MODULE_DESCRIPTION("A module to hook vfs");

int __init hk_vfs_init(void)
{
	int ret = 0;
	ret = register_device();
	return ret;
}

void __exit hk_vfs_exit(void)
{
	backup_functions();
	unregister_device();
	printk(KERN_ALERT "hk_vfs exit\n"); 
}

module_init(hk_vfs_init);
module_exit(hk_vfs_exit);

