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
/* refer to linux/syscalls.h */
asmlinkage long   (*orig_chmod)(const char __user *, mode_t);

asmlinkage long hk_chmod(const char __user *filename, mode_t mode)
{
	long len;
	long retval = 0;
	char *buffer;

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

static void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) 
{
	const char *begin; 
	const char *const last_possible = (const char *) haystack + haystack_len - needle_len;

	if (needle_len == 0){ 
		/* The first occurrence of the empty string is deemed to occur at 
		 * the beginning of the string.
		 */ 
		return (void *) haystack;
	}
	/* Sanity check, otherwise the loop might search through the whole memory. */ 
	if (__builtin_expect(haystack_len < needle_len, 0)){ 
		return NULL;
	}

	for (begin = (const char *) haystack; begin <= last_possible; ++begin) { 
		if (begin[0] == ((const char *) needle)[0] 
				&& !memcmp((const void *) &begin[1], 
					(const void *) ((const char *) needle + 1), 
					needle_len - 1)){
			return (void *) begin; 
		}
	}
	return NULL; 
}
void* get_syscall_addr(void)
{
	unsigned long syscall_long, retval;
	char sc_asm[200];
	rdmsrl(MSR_LSTAR, syscall_long);
	memcpy(sc_asm, (char*)syscall_long, 200);
	retval = (unsigned long) memmem(sc_asm, 200, "\xff\x14\xc5", 3);
	if( 0 != retval) {
		retval = (unsigned long)(*(unsigned long*)(retval+3));
		retval |= 0xFFFFFFff00000000;
	} else {
		printk("long mode: memmem found nothing, return NULL\n");
	}

	return (void*)retval;
}

unsigned long cr0_cnt(void)
{
	unsigned long ret;

	asm volatile ( "movq %%cr0, %0"
			:"=r"(ret)
			:
		     );

	asm volatile ( "movq %0, %%cr0"
			:
			:"r"(ret&0xfffffffffffeffff)
		     );
	return ret;
}

void cr0_restore(unsigned long val)
{
	asm volatile ( "movq %0, %%cr0"
			:
			:"r"(val)
		     );
}


int hk_syscall(void)
{
	int retval = 0;

	unsigned long orig_cr0;
	syscall_table = get_syscall_addr();
	if(NULL == syscall_table) {
		printk("can not get syscall addr\n");
		retval = 1;
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
	msleep(99);
	return;
}

module_init(hk_syscall_init);
module_exit(hk_syscall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dawter");
MODULE_DESCRIPTION("A module to hook x86_64 syscall");

