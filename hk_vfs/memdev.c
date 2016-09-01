#include <linux/fs.h>       /* file stuff */
#include <linux/kernel.h>   /* printk() */
#include <linux/errno.h>    /* error codes */
#include <linux/module.h>   /* THIS_MODULE */
#include <linux/cdev.h>     /* char device stuff */
#include <asm/uaccess.h>    /* strncpy_from_user() */
#include <linux/mm_types.h> /* struct vm_area_struct */
#include <linux/mm.h> /* struct vm_area_struct -> vm_flags*/
#include <linux/io.h>

#include "memdev.h"

static int g_device_open = 0;

static ssize_t memdev_write ( struct file *file_ptr
		, const char *buffer
		, size_t length
		, loff_t *offset)
{
	char* pFile_Path;

	pFile_Path = kmalloc(sizeof(char *)*length,GFP_KERNEL);

	if ( strncpy_from_user(pFile_Path,buffer,length)== -EFAULT) {
		printk( KERN_NOTICE "Entered in fault get_user state");
		length=-1;
		goto finish;
	}

	if (strstr(pFile_Path,"\n")) {
		pFile_Path[length - 1] = 0;
		printk( KERN_NOTICE "Entered in end line filter");
	}

	printk( KERN_NOTICE "File path is %s without EOF", pFile_Path);

	if (hook_functions(pFile_Path)==-1) {	
		length=-2;
	}
finish:
	kfree(pFile_Path);
	return length;
}
static int memdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	char *pdata = filp->private_data;
	
	vma->vm_flags |= VM_IO;
	vma->vm_flags |= VM_RESERVED;

	if(remap_pfn_range(vma, vma->vm_start, virt_to_phys(pdata)>>PAGE_SHIFT,
		vma->vm_end-vma->vm_start, vma->vm_page_prot)) {
		ret = -EAGAIN;
	}
	return ret;
}

static int memdev_open(struct inode *inode, struct file *file)
{
	if (g_device_open) {
		return -EBUSY;
	}

	g_device_open++;
	try_module_get(THIS_MODULE);

	return 0;
}

static int memdev_release(struct inode *inode, struct file *file)
{
	g_device_open--;

	module_put(THIS_MODULE);
	return 0;
}

static struct file_operations hk_vfs_fops = 
{
	.owner   = THIS_MODULE,
	.write   = memdev_write,
	.open    = memdev_open,
	.release = memdev_release,
	.mmap    = memdev_mmap,
};

static int memdev_major_number = 0;

static const char device_name[] = "hk_vfs";

int register_device(void)
{
	int result = 0;

	printk( KERN_NOTICE "hk_vfs: register_device() is called." );

	result = register_chrdev( 0, device_name, &hk_vfs_fops );
	if( result < 0 ) {
		printk( KERN_WARNING "hk_vfs: register device with errorcode = %i", result );
		return result;
	}

	memdev_major_number = result;
	printk( KERN_NOTICE "hk_vfs: major number = %i and minor numbers 0...255"
			, memdev_major_number );

	return 0;
}
/*-----------------------------------------------------------------------------------------------*/
void unregister_device(void)
{
	printk( KERN_NOTICE "hk_vfs: unregister_device() is called" );
	if(memdev_major_number != 0) {
		unregister_chrdev(memdev_major_number, device_name);
	}
}

