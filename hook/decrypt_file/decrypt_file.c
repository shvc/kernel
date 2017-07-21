/*
 * Only tested on:
 * 	 Centos 7: 3.10.0-327.28.3.el7.x86_64
 * 	 Centos 6: 2.6.32-642.4.2.el6.x86_64
 * Tue Sep  6 05:07:25 CST 2016
 */
#include <linux/kernel.h> /* training */
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <linux/moduleparam.h>

struct df_name {
	char f_name[PATH_MAX]; /* the name of reg file */
	char t_name[PATH_MAX]; /* the name of current process */
};

/* trust process name */
static char *trust_process = "head";

/* encrypted file */
static char encrypt_filename[PATH_MAX];
static char *filename = "/tmp/test.txt";
module_param(filename, charp, 000);
MODULE_PARM_DESC(filename, "A file has been encrypted");

ssize_t (*orig_read)(struct file*, char __user*, size_t, loff_t*);

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

char * decryptor(char *str, ssize_t len)
{
	int i;
	for(i=0; i<len; i++) {
		if(str[i]>='a' && str[i]<='z') {
			str[i] -= 32;
		}
		else if(str[i]>='A' && str[i]<='Z') {
			str[i] += 32;
		}
	}

	return str;
}

ssize_t df_read(struct file *file, char __user *u, size_t t, loff_t *lf)
{
	char *ptr;
	ssize_t retval;
	struct df_name *buff;
	struct path file_path;

	retval = orig_read(file, u, t, lf);

	buff = kmalloc(sizeof(struct df_name), GFP_KERNEL);
	if(NULL == buff) {
		return retval;
	}
	file_path = file->f_path;
	ptr = d_path(&file_path, buff->f_name, PATH_MAX);
	if(0 == strcmp(encrypt_filename, ptr)) {
		task_lock(current);
		strcpy(buff->t_name, current->comm);
		task_unlock(current);
		printk(KERN_INFO "%s %s: %s\n", buff->t_name, ptr, u);
		if(0 == strcmp(buff->t_name, trust_process)) {
			decryptor(u, retval);
		}
	}

	kfree(buff);
	return retval;
}

int patch_vfs(const char* filename)
{
	unsigned long cr0;
	struct file *filp = NULL;
	struct file_operations *fop;

	filp = filp_open(filename, 0 , 0);
	if(IS_ERR(filp)) {
		printk(KERN_INFO "filp_open\n");
		return 1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	fop = (struct file_operations*)filp->f_dentry->d_inode->i_fop;
#else
	fop = (struct file_operations*)filp->f_inode->i_fop;
#endif
	if(NULL == fop) {
		printk(KERN_INFO "i_fop is null\n");
		return 2;
	}
	orig_read = fop->read;

	cr0 = clear_cr0();
	fop->read = df_read;
	set_cr0(cr0);

	filp_close(filp, 0);
	return 0;
}

int depatch_vfs(const char* filename)
{
	unsigned long cr0;
	struct file *filp = NULL;
	struct file_operations *fop;

	filp = filp_open(filename, 0 , 0);
	if(IS_ERR(filp)) {
		printk(KERN_INFO "filp_open\n");
		return 1;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	fop = (struct file_operations*)filp->f_dentry->d_inode->i_fop;
#else
	fop = (struct file_operations*)filp->f_inode->i_fop;
#endif
	if(NULL == fop) {
		printk(KERN_INFO "i_fop is null\n");
		return 2;
	}

	cr0 = clear_cr0();
	fop->read = orig_read;
	set_cr0(cr0);

	filp_close(filp, 0);
	return 0;

}


int __init init_decrypt_file(void)
{
	int retval = 0;
	printk(KERN_NOTICE "init mdule decrypt_file\n");
	if(strlen(filename) >= PATH_MAX) {
		printk(KERN_NOTICE "filname too long, use default filename\n");
	}
	strcpy(encrypt_filename, filename);
	printk(KERN_INFO "filename: %s\n", encrypt_filename);

	retval = patch_vfs(encrypt_filename);

	return retval;
}


void __exit exit_decrypt_file(void)
{
	printk(KERN_NOTICE "exit  mdule decrypt_file\n");
	depatch_vfs(encrypt_filename);
	return;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dawter");
MODULE_DESCRIPTION("A module to decrypt file");


module_init(init_decrypt_file);
module_exit(exit_decrypt_file);


