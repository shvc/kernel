/*
 * Only tested on:
 * 	 Centos 7: 3.10.0-327.28.3.el7.x86_64
 * 	 Centos 6: 2.6.32-642.4.2.el6.x86_64
 * Tue Sep  6 05:07:25 CST 2016
 */
#include <linux/kernel.h> /* training */
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/limits.h>
#include <linux/version.h>

static unsigned long orig_cr0 = 0;

unsigned long clear_cr0(void)
{
        unsigned long ret;
        unsigned long cr0 = 0;
#ifdef __x86_64__
        asm volatile ("movq %%cr0, %%rax"
                        : "=a"(cr0)
                     );
        ret = cr0;
        cr0 &= 0xfffffffffffeffff;

        asm volatile ("movq %%rax, %%cr0"
                        :
                        : "a"(cr0)
                     );
#else
        asm volatile ("movl %%cr0, %%eax"
                        : "=a"(cr0)
                     );
        ret = cr0;
        cr0 &= 0xfffeffff;
        asm volatile ("movl %%eax, %%cr0"
                        :
                        : "a"(cr0)
                     );
#endif
        return ret;
}

void set_cr0(unsigned long val)
{
#ifdef __x86_64__
        asm volatile ("movq %%rax, %%cr0"
                        :
                        : "a"(val)
                     );
#else
        asm volatile ("movl %%eax, %%cr0\r\n"
                        :
                        : "a"(val)
                     );
#endif
}

int __init init_cr0op_file(void)
{
	printk(KERN_NOTICE "init mdule cr0op_file\n");

	orig_cr0 = clear_cr0();

	return 0;
}


void __exit exit_cr0op_file(void)
{
	printk(KERN_NOTICE "exit  mdule cr0op_file\n");
	set_cr0(orig_cr0);
	return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dawter");
MODULE_DESCRIPTION("A module to cr0op file");


module_init(init_cr0op_file);
module_exit(exit_cr0op_file);


