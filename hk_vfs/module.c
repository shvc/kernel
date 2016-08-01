#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/list.h>

#include "memdev.h"

struct dentry* g_parent_dentry;
struct nameidata g_root_nd;
/*Number of inodes*/
unsigned long* g_inode_numbers;
int g_inode_count=0;

void** orig_inode_pointer;
void** orig_fop_pointer;
void** orig_iop_pointer;

void** orig_parent_inode_pointer;
void** orig_parent_fop_pointer;

filldir_t real_filldir;


static struct file_operations new_parent_fop =
{
	.owner=THIS_MODULE,
	.readdir=parent_readdir,
};

static int new_filldir (void *buf, const char *name, int namelen, loff_t offset,u64 ux64, unsigned ino)
{
	unsigned int i=0;
	struct dentry* pDentry;
	struct qstr Current_Name;

	Current_Name.name=name;
	Current_Name.len=namelen;
	Current_Name.hash=full_name_hash (name, namelen);

	pDentry=d_lookup(g_parent_dentry, &Current_Name);

	if (pDentry!=NULL) {
		for(i=0; i<=g_inode_count-1; i++) {
			if (g_inode_numbers[i]==pDentry->d_inode->i_ino) {
				return 0;
			}
		}
	}

	return real_filldir (buf, name, namelen, offset, ux64, ino);
}

int parent_readdir (struct file *file, void *dirent, filldir_t filldir)
{	
	g_parent_dentry = file->f_dentry;

	real_filldir = filldir;

	return g_root_nd.path.dentry->d_inode->i_fop->readdir(file, dirent, new_filldir);
}
/********************************FILE OPERATIONS*************************/
static struct file_operations new_fop =
{
	.owner=THIS_MODULE,
	.readdir=new_readdir,
	.release=new_release,
	.open=new_open,
	.read=new_read, 
	.write=new_write,
	.mmap=new_mmap,
};

int new_mmap (struct file * file, struct vm_area_struct * area)
{
	printk( KERN_ALERT "Entered in new_mmap\n");
	return -2;
}

ssize_t new_read (struct file *file1, char __user * u, size_t t, loff_t *ll)
{
	printk( KERN_ALERT "Entered in new_read\n");
	return -2;
}

ssize_t new_write (struct file * file1, const char __user * u, size_t t, loff_t *ll)
{
	printk( KERN_ALERT "Entered in new_write\n");
	return -2;
}

int new_release (struct inode * new_inode, struct file *file)
{
	printk( KERN_ALERT "Entered in new_release \n");
	return -2;
}

int new_flush (struct file *file, fl_owner_t id)
{
	printk( KERN_ALERT "Entered in new_flush \n");
	return -2;
}

int new_readdir (struct file *file, void *dirent, filldir_t filldir)
{
	printk( KERN_ALERT "Entered in new_readdir \n");
	return -2;
}

int new_open (struct inode * old_inode, struct file * old_file)
{
	printk( KERN_ALERT "Entered in new_open \n");
	return -2;
}

/********************************INODE OPERATIONS*************************/
static struct inode_operations new_iop =
{
	.getattr=new_getattr,
	.rmdir=new_rmdir,
};

int new_rmdir (struct inode *new_inode,struct dentry *new_dentry)
{
	printk( KERN_ALERT "Entered in new_rmdir \n");
	return -2;
}

int new_getattr (struct vfsmount *mnt, struct dentry * new_dentry, struct kstat * ks)
{
	printk( KERN_ALERT "Entered in new_getatr \n");
	return -2;
}

/*Allocate memmory for arrays*/
void allocate_memmory()
{
	orig_inode_pointer = kmalloc(sizeof(void*), GFP_KERNEL);
	orig_fop_pointer = kmalloc(sizeof(void*), GFP_KERNEL);
	orig_iop_pointer = kmalloc(sizeof(void*), GFP_KERNEL);

	orig_parent_inode_pointer = kmalloc(sizeof(void*), GFP_KERNEL);
	orig_parent_fop_pointer = kmalloc(sizeof(void*), GFP_KERNEL);

	g_inode_numbers = kmalloc(sizeof(unsigned long), GFP_KERNEL);

}

void reallocate_memmory()
{
	/*Realloc memmory for inode number*/
	g_inode_numbers = krealloc(g_inode_numbers,sizeof(unsigned long*)*(g_inode_count+1), GFP_KERNEL);

	/*Realloc memmory for old pointers*/
	orig_inode_pointer = krealloc(orig_inode_pointer, sizeof(void*)*(g_inode_count+1),GFP_KERNEL);
	orig_fop_pointer = krealloc(orig_fop_pointer, sizeof(void*)*(g_inode_count+1),GFP_KERNEL);
	orig_iop_pointer = krealloc(orig_iop_pointer, sizeof(void*)*(g_inode_count+1),GFP_KERNEL);

	orig_parent_inode_pointer = krealloc(orig_parent_inode_pointer, sizeof(void*)*(g_inode_count+1),GFP_KERNEL);
	orig_parent_fop_pointer = krealloc(orig_parent_fop_pointer, sizeof(void*)*(g_inode_count+1),GFP_KERNEL);
}



/*Function for hook functions of specified file*/
unsigned long hook_functions(const char * file_path) 
{
	int error=0;
	struct nameidata nd;

	error = path_lookup("/root", 0, &g_root_nd);
	if(error) {
		printk( KERN_ALERT "Can't access root\n");
		return -1;
	}

	error = path_lookup(file_path, 0, &nd);
	if(error) {
		printk( KERN_ALERT "Can't access file\n");
		return -1;
	}

	if (g_inode_count==0) {
		allocate_memmory();
	}

	if (g_inode_numbers==NULL) {
		printk( KERN_ALERT "Not enought memmory in buffer\n");
		return -1;
	}

	/*********** orig pointers *******/
	/*Save pointers*/
	orig_inode_pointer[g_inode_count]=nd.path.dentry->d_inode;
	orig_fop_pointer[g_inode_count]=(void *)nd.path.dentry->d_inode->i_fop;
	orig_iop_pointer[g_inode_count]=(void *)nd.path.dentry->d_inode->i_op;

	orig_parent_inode_pointer[g_inode_count]=nd.path.dentry->d_parent->d_inode;
	orig_parent_fop_pointer[g_inode_count]=(void *)nd.path.dentry->d_parent->d_inode->i_fop;

	/*Save inode number*/
	g_inode_numbers[g_inode_count]=nd.path.dentry->d_inode->i_ino;
	g_inode_count=g_inode_count+1;

	reallocate_memmory();

	/*filldir hook*/
	nd.path.dentry->d_parent->d_inode->i_fop=&new_parent_fop;

	/* Hook of commands for file*/
	nd.path.dentry->d_inode->i_op=&new_iop;
	nd.path.dentry->d_inode->i_fop=&new_fop;

	return 0;
}

/*Function for backup inode pointers of the specified file*/
unsigned long backup_functions()
{	
	int i=0;
	struct inode* pInode;
	struct inode* pParentInode;

	for (i=0; i<g_inode_count; i++) {
		pInode=orig_inode_pointer[(g_inode_count-1)-i];
		pInode->i_fop=(void *)orig_fop_pointer[(g_inode_count-1)-i];
		pInode->i_op=(void *)orig_iop_pointer[(g_inode_count-1)-i];

		pParentInode=orig_parent_inode_pointer[(g_inode_count-1)-i];
		pParentInode->i_fop=(void *)orig_parent_fop_pointer[(g_inode_count-1)-i];

	}

	kfree(orig_inode_pointer);
	kfree(orig_fop_pointer);
	kfree(orig_iop_pointer);

	kfree(orig_parent_inode_pointer);
	kfree(orig_parent_fop_pointer);

	kfree(g_inode_numbers);

	return 0;
}

