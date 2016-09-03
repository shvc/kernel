/*
 * hk_syscall: hook syscall linux
 * test and build system:
 * -    centos-5 2.6.18-411.el5
 * -    centos-7 3.10.0-327.28.3.el7.x86_64
 * Sat Sep  3 21:49:13 CST 2016
 */
#include <linux/module.h>
#include <linux/kernel.h>  /* for KERN_NFO stuff */
#include <linux/limits.h>  /* for macro PATH_MAX stuff */
#include <linux/uaccess.h> /* for access_ok stuff */
#include <linux/delay.h>   /* for msleep stuff */
#include <linux/vmalloc.h> /* for vmap stuff */
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/unistd.h>    /* micro  __NR_chmod  */
#include <linux/moduleparam.h> /* for module_param stuff */

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

#ifdef __x86_64__
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

unsigned long get_syscall_addr(void)
{
	unsigned long syscall_long, retval = 0;
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

	return retval;
}
#else
unsigned long get_syscall_addr(void)
{
	int i;
	char* ptr;
	char idtr[6];
	unsigned int sys_call_off;
	unsigned long sys_call_table;
	unsigned short offset_low,offset_high;
	struct _idt {
		unsigned short offset_low,segment_sel;
		unsigned char reserved,flags;
		unsigned short offset_high;
	}*idt;

	asm("sidt %0":"=m"(idtr));
	idt = (struct _idt*)(*(unsigned long*)&idtr[2]+8*0x80);
	offset_low = idt->offset_low;
	offset_high = idt->offset_high;
	sys_call_off = (offset_high<<16)|offset_low;
	ptr = (char *)sys_call_off;
	for (i=0; i<100; i++) {
		if (ptr[i]=='\xff' && ptr[i+1]=='\x14' && ptr[i+2]=='\x85') {
			sys_call_table = *(unsigned long*)(ptr+i+3);
			return sys_call_table;
		}
	}
	return 0;
}
#endif

int hk_syscall(void)
{
	struct page *pages[2];
	void *vmap_addr = NULL;
	void **map_syscall_table = NULL;

	syscall_table = (void*)get_syscall_addr();
	if(NULL == syscall_table) {
		printk(KERN_NOTICE "can not get syscall addr\n");
		return 1;
	}
	printk("orig syscall addr: %p\n", syscall_table);
	orig_chmod = syscall_table[__NR_chmod];
	printk("orig_chmod: %p\n", orig_chmod);

	pages[0] = virt_to_page(syscall_table);
	pages[1] = virt_to_page(syscall_table + PAGE_SIZE);
	vmap_addr = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	if(!vmap_addr) {
		printk(KERN_NOTICE "vmap failed\n");
		return 2;
	}
	map_syscall_table = vmap_addr + offset_in_page(syscall_table);
	printk("vmap syscall addr: %p\n", map_syscall_table);
	orig_chmod = map_syscall_table[__NR_chmod];
	printk("vmap orig_chmod: %p\n", orig_chmod);
	map_syscall_table[__NR_chmod] = hk_chmod;
	vunmap(vmap_addr);

	return 0;
}

int restore_syscall(void)
{
	struct page *pages[2];
	void *vmap_addr = NULL;
	void **map_syscall_table = NULL;

	if(NULL == syscall_table) {
		printk(KERN_NOTICE "syscall_table is NULL\n");
		return 1;
	}
	pages[0] = virt_to_page(syscall_table);
	pages[1] = virt_to_page(syscall_table + PAGE_SIZE);
	vmap_addr = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	if(!vmap_addr) {
		printk(KERN_NOTICE "vmap failed\n");
		return 2;
	}
	map_syscall_table = vmap_addr + offset_in_page(syscall_table);
	printk("vmap syscall addr: %p\n", map_syscall_table);
	map_syscall_table[__NR_chmod] = orig_chmod;

	return 0;
}

int hide_this_module(void)
{
#if 0
	/* remove this module from procfs */
	list_del_init(&__this_module.list);

	/* remove this module from sysfs */
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif

	return 0;
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

	hide_this_module();
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
MODULE_DESCRIPTION("A module to hook syscall");

