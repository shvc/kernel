/*
 * hk_syscall: hook syscall
 * Wed Jul 20 12:09:49 CST 2016
 */
#include <linux/module.h> /* needed by all modules */
#include <linux/kernel.h> /* needed for KERN_NFO */
#include <linux/limits.h> /* needed for macro PATH_MAX */
#include <linux/moduleparam.h> /* needed for module_param */

static char hk_path[PATH_MAX];
static char *path = "/tmp/hk_dir/";
module_param(path, charp, 000);
MODULE_PARM_DESC(path, "A directory to test hook");

extern void *syscall_table[];
asmlinkage long   (*orig_chmod)(const char __user *, mode_t);

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

int hk_syscall(void)
{
	int retval = 0;
	syscall_table = get_syscall_addr();
	if(NULL == syscall_table) {
		printk("can not get syscall addr\n");
	}
	printk("syscall addr: %p\n", syscall_table);
	
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
	printk(KERN_INFO "syscall_table: %p\n", syscall_table);

	hk_syscall();
	return ret;
}

static void __exit hk_syscall_exit(void)
{
	printk(KERN_INFO "exit module hk_syscall\n");
	return;
}

module_init(hk_syscall_init);
module_exit(hk_syscall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dawter");
MODULE_DESCRIPTION("A module to hook syscall");

