/*
 * hk_syscall: hook syscall on x86_64 linux
 * test and build system centos-6.9 2.6.32
 * Wed Jul 20 12:09:49 CST 2016
 */
#include <linux/module.h> /* needed by all modules */
#include <linux/kernel.h> /* needed for KERN_NFO */
#include <linux/limits.h> /* needed for macro PATH_MAX */
#include <linux/uaccess.h>   /* access_ok() */
#include <asm/unistd.h>   /* micro  __NR_chmod  */
#include <linux/moduleparam.h> /* needed for module_param */

static char hk_path[PATH_MAX];
static char *path = "/tmp/hk_dir/";
module_param(path, charp, 000);
MODULE_PARM_DESC(path, "A directory to test hook");

void **syscall_table;
struct _idt
{
        unsigned short offset_low,segment_sel;
        unsigned char reserved,flags;
        unsigned short offset_high;
};

/* refer to linux/syscalls.h */
asmlinkage long   (*orig_chmod)(const char __user *, mode_t);

asmlinkage long hk_chmod(const char __user *filename, mode_t mode)
{
	long len;
	long retval = 0;
	char *buffer;

	printk("chmod: %s\n", filename);
	retval = access_ok(VERIFY_READ, filename, 3);
	if(0 == retval) {
		printk(KERN_NOTICE "chmod: access_ok(filename) failed\n");
		return orig_chmod(filename, mode);
	}
	len = strlen_user(filename);
	if(0 == len) {
		printk(KERN_NOTICE "chmod: strlen_user(filename) failed\n");
		return orig_chmod(filename, mode);
	}
	buffer = kmalloc(PATH_MAX, GFP_KERNEL);
	if(NULL == buffer) {
		printk(KERN_ERR "chmod kmalloc failed");
		return orig_chmod(filename, mode);
	}

	retval = strncpy_from_user(buffer, filename, len);

	if(strncmp(hk_path, buffer, strlen(hk_path)) == 0) {
		printk(KERN_NOTICE "chmod: forbidden\n");
		retval = -1;
	} else {
		retval = orig_chmod(filename, mode);
	}

	kfree(buffer);
	return retval;
}

unsigned long get_syscall_addr(void)
{
        int i;
	unsigned int sys_call_off;
        unsigned long sys_call_table;
        char idtr[6];
        unsigned short offset_low,offset_high;
        struct _idt *idt;
        char* p;
        asm("sidt %0":"=m"(idtr));
        idt = (struct _idt*)(*(unsigned long*)&idtr[2]+8*0x80);
        offset_low = idt->offset_low;
        offset_high = idt->offset_high;
        sys_call_off = (offset_high<<16)|offset_low;
        p = (char *)sys_call_off;
        for (i=0; i<100; i++) {
                if (p[i]=='\xff' && p[i+1]=='\x14' && p[i+2]=='\x85') {
                        sys_call_table = *(unsigned long*)(p+i+3);
                        return sys_call_table;
                }
        }
        return 0;
}

unsigned long cr0_cnt(void)
{
	unsigned long ret;

	asm volatile ( "movl %%cr0, %0"
			:"=r"(ret)
			:
		     );

	asm volatile ( "movl %0, %%cr0"
			:
			:"r"(ret&0xfffeffff)
		     );
	return ret;
}

void cr0_restore(unsigned long val)
{
	asm volatile ( "movl %0, %%cr0"
			:
			:"r"(val)
		     );
}


int hk_syscall(void)
{
	int retval = 0;

	unsigned long orig_cr0;
	syscall_table = (void*)get_syscall_addr();
	if(NULL == syscall_table) {
		printk("can not get syscall addr\n");
		return 1;
	}
	printk("syscall addr: %p\n", syscall_table);

	orig_chmod = syscall_table[__NR_chmod];
	printk("orig_chmod: %p\n", orig_chmod);

	orig_cr0 = cr0_cnt();
	syscall_table[__NR_chmod] = hk_chmod;
	cr0_restore(orig_cr0);

	return retval;
}

int restore_syscall(void)
{
	int retval = 0;
	unsigned long orig_cr0;

	orig_cr0 = cr0_cnt();
	syscall_table[__NR_chmod] = orig_chmod;
	cr0_restore(orig_cr0);

	return retval;
}

static int __init hk_syscall_init(void)
{
	int ret = 0;
	printk(KERN_INFO "init module hk_syscall\n");
	if(strlen(path) >= PATH_MAX) {
		printk(KERN_INFO "path too long, use default");
	}
	strcpy(hk_path, path);
	printk(KERN_INFO "hook path: %s\n", hk_path);
	ret = hk_syscall();
	return ret;
}

static void __exit hk_syscall_exit(void)
{
	printk(KERN_INFO "exit module hk_syscall\n");
	restore_syscall();
	msleep(999);
	return;
}

module_init(hk_syscall_init);
module_exit(hk_syscall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dawter");
MODULE_DESCRIPTION("A module to hook syscall");

