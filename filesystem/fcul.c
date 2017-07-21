#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/cpumask.h>

/*
 * Force unload a kernel module
 */

static int force_unload_state;

static int __init force_init(void)
{

	int cpu;
	struct module *mod, *relate;
	printk(KERN_ALERT "This name: %s, state: %d\n",THIS_MODULE->name,\
		THIS_MODULE->state);
	list_for_each_entry(mod, &THIS_MODULE->list, list) {
		if(0 == strcmp(mod->name, "asfs")) {
			printk(KERN_ALERT "Tagt name:%s state:%d refcnt: %u\n",\
				mod->name, mod->state, module_refcount(mod));
			if(!list_empty(&mod->modules_which_use_me)) {
				list_for_each_entry(relate, &mod->modules_which_use_me,
					modules_which_use_me) {
					printk(KERN_ALERT"%s ", relate->name);
				}
			} else {
				printk(KERN_ALERT "used by NULL\n");
			}

			for_each_possible_cpu(cpu) {
				local_set(__module_ref_addr(mod, cpu), 0);
			}
			printk(KERN_ALERT "Tagt name:%s state:%d refcnt: %u\n",\
				mod->name, mod->state, module_refcount(mod));
		}
	}
	force_unload_state = 1;

	return 0;
}

static void __exit force_exit(void)
{
	force_unload_state = 0;
	return;
}

module_init(force_init);
module_exit(force_exit);

MODULE_AUTHOR("nsfocus");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("force unload a module");

