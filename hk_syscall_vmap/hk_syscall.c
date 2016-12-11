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
#include <linux/syscalls.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm-generic/sections.h> /* for _etext, _edata stuff */
#include <asm/unistd.h>           /* micro  __NR_chmod  */
#include <linux/moduleparam.h>    /* for module_param stuff */

static char hk_path[PATH_MAX];
static char *path = "/tmp/hk_dir/";
module_param(path, charp, 000);
MODULE_PARM_DESC(path, "A directory to test hook");

#ifdef __x86_64__
/* for 32bit syscall on x86_64 system */
void **syscall_tbl_32;
/* ref unistd_32.h */
#define __NR_close_32 6
#define __NR_chmod_32 15
asmlinkage long (*orig_chmod_32)(const char __user *, mode_t);
asmlinkage long hk_chmod_32(const char __user *filename, mode_t mode)
{
	long retval = 0;

	retval = access_ok(VERIFY_READ, filename, 3);
	if(0 == retval) {
		printk(KERN_NOTICE "chmod32: access_ok(filename) failed\n");
		return orig_chmod_32(filename, mode);
	}
	return orig_chmod_32(filename, mode);

	if(strncmp(hk_path, filename, strlen(hk_path)) == 0) {
		printk(KERN_NOTICE "chmod32: forbidden\n");
		retval = -1;
	} else {
		retval = orig_chmod_32(filename, mode);
	}

	return retval;
}

/*
 * find addr of ia32_sys_call_table
 */
void * get_syscall_tbl32_addr(void)
{
	unsigned long **addr_cur = (unsigned long**)PAGE_OFFSET;

	/* You can replace VMALLOC_START with ULONG_MAX below */
	unsigned long **addr_max = (unsigned long**)VMALLOC_START;
	while(addr_cur != addr_max) {
		if(addr_cur[__NR_close_32] == (unsigned long*)sys_close) break;
		addr_cur++;
	}
	return addr_cur==addr_max?0:addr_cur;
}

int hk_syscall_32(void)
{
	struct page *pages[2];
	void *vmap_addr = NULL;
	void **map_syscall_tbl = NULL;

	syscall_tbl_32 = (void*)get_syscall_tbl32_addr();
	if(NULL == syscall_tbl_32) {
		printk(KERN_NOTICE "can not get ia32_sys_call_table addr\n");
		return 1;
	}
	printk("ia32_sys_call_table  %p\n", syscall_tbl_32);
	orig_chmod_32 = syscall_tbl_32[__NR_chmod_32];
	printk("orig_chmod32: %p\n", orig_chmod_32);

	pages[0] = virt_to_page(syscall_tbl_32);
	pages[1] = virt_to_page(syscall_tbl_32 + PAGE_SIZE);
	vmap_addr = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	if(!vmap_addr) {
		printk(KERN_NOTICE "vmap failed\n");
		return 2;
	}
	map_syscall_tbl = vmap_addr + offset_in_page(syscall_tbl_32);
	printk("vmap ia32_sys_call_table  %p\n", map_syscall_tbl);
	orig_chmod_32 = map_syscall_tbl[__NR_chmod_32];
	printk("vmap orig_chmod32: %p\n", orig_chmod_32);
	map_syscall_tbl[__NR_chmod_32] = hk_chmod_32;
	vunmap(vmap_addr);

	return 0;
}

int restore_syscall_32(void)
{
	struct page *pages[2];
	void *vmap_addr = NULL;
	void **map_syscall_tbl = NULL;

	if(NULL == syscall_tbl_32) {
		printk(KERN_NOTICE "syscall_tbl_32 is NULL\n");
		return 1;
	}
	pages[0] = virt_to_page(syscall_tbl_32);
	pages[1] = virt_to_page(syscall_tbl_32 + PAGE_SIZE);
	vmap_addr = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	if(!vmap_addr) {
		printk(KERN_NOTICE "vmap failed\n");
		return 2;
	}
	map_syscall_tbl = vmap_addr + offset_in_page(syscall_tbl_32);
	printk("vmap syscall32 addr: %p\n", map_syscall_tbl);
	map_syscall_tbl[__NR_chmod_32] = orig_chmod_32;

	return 0;
}
#endif

void **syscall_tbl;

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
#if 1
		printk(KERN_NOTICE "chmod: %s", buffer);
#endif
		retval = orig_chmod(filename, mode);
	}

	kfree(buffer);
	return retval;
}

/*
 * find addr of sys_call_table
 */
void* get_syscall_addr(void)
{
	unsigned long **addr_cur = (unsigned long**)PAGE_OFFSET;

	/* You can replace VMALLOC_START with ULONG_MAX below */
	unsigned long **addr_max = (unsigned long**)VMALLOC_START;
	while(addr_cur != addr_max) {
		if(addr_cur[__NR_close] == (unsigned long*)sys_close) break;
		addr_cur++;
	}
	return addr_cur==addr_max?0:addr_cur;
}

int hk_syscall(void)
{
	struct page *pages[2];
	void *vmap_addr = NULL;
	void **map_syscall_tbl = NULL;

	syscall_tbl = (void*)get_syscall_addr();
	if(NULL == syscall_tbl) {
		printk(KERN_NOTICE "can not get sys_call_table addr\n");
		return 1;
	}
	printk("sys_call_table  %p\n", syscall_tbl);
	orig_chmod = syscall_tbl[__NR_chmod];
	printk("orig_chmod: %p\n", orig_chmod);

	pages[0] = virt_to_page(syscall_tbl);
	pages[1] = virt_to_page(syscall_tbl + PAGE_SIZE);
	vmap_addr = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	if(!vmap_addr) {
		printk(KERN_NOTICE "vmap failed\n");
		return 2;
	}
	map_syscall_tbl = vmap_addr + offset_in_page(syscall_tbl);
	printk("vmap sys_call_table  %p\n", map_syscall_tbl);
	orig_chmod = map_syscall_tbl[__NR_chmod];
	printk("vmap orig_chmod: %p\n", orig_chmod);
	map_syscall_tbl[__NR_chmod] = hk_chmod;
	vunmap(vmap_addr);

	return 0;
}

int restore_syscall(void)
{
	struct page *pages[2];
	void *vmap_addr = NULL;
	void **map_syscall_tbl = NULL;

	if(NULL == syscall_tbl) {
		printk(KERN_NOTICE "syscall_tbl is NULL\n");
		return 1;
	}
	pages[0] = virt_to_page(syscall_tbl);
	pages[1] = virt_to_page(syscall_tbl + PAGE_SIZE);
	vmap_addr = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	if(!vmap_addr) {
		printk(KERN_NOTICE "vmap failed\n");
		return 2;
	}
	map_syscall_tbl = vmap_addr + offset_in_page(syscall_tbl);
	printk("vmap syscall addr: %p\n", map_syscall_tbl);
	map_syscall_tbl[__NR_chmod] = orig_chmod;

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
#ifdef __x86_64__
	ret = hk_syscall_32();
#endif

	hide_this_module();
	return ret;
}

static void __exit hk_syscall_exit(void)
{
	printk(KERN_INFO "exit module hk_syscall\n");
	restore_syscall();
#ifdef __x86_64__
	restore_syscall_32();
#endif
	msleep(99);
	return;
}

module_init(hk_syscall_init);
module_exit(hk_syscall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dawter");
MODULE_DESCRIPTION("A module to hook syscall");

