#include <linux/fs.h> 
#include <linux/init.h> 
#include <linux/mount.h> 
#include <linux/namei.h> 
#include <linux/sched.h> 
#include <linux/module.h> 
#include <linux/version.h> 
#include <linux/pagemap.h> 

#define AUFS_MAGIC  0x64668735  

static struct vfsmount *asfs_mount;
static int asfs_mount_count;

static struct inode *asfs_get_inode(struct super_block *sb, int mode, dev_t dev)
{
	struct inode *inode = new_inode(sb);

	if (inode){
		inode->i_mode = mode;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
		inode->i_uid = current_fsuid();
		inode->i_gid = current_fsgid();
#else
		inode->i_uid = current->fsuid;
		inode->i_gid = current->fsgid;
#endif
		inode->i_blkbits = PAGE_CACHE_SIZE;
		inode->i_blocks = 0;
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT){
			default:  
				init_special_inode(inode, mode, dev);
				break;
			case S_IFREG:  
				printk("creat a  file \n");
				break;
			case S_IFDIR:  
				inode->i_op = &simple_dir_inode_operations;
				inode->i_fop = &simple_dir_operations;
				printk("creat a dir file \n");

				inode->i_nlink++;
				break;
		}
	}
	return inode;
}

/* SMP-safe */  
static int asfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	struct inode *inode;
	int error = -EPERM;

	if (dentry->d_inode) {
		return -EEXIST;
	}

	inode = asfs_get_inode(dir->i_sb, mode, dev);
	if (inode){
		d_instantiate(dentry, inode);
		dget(dentry);
		error = 0;
	}
	return error;
}

static int asfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int res;

	res = asfs_mknod(dir, dentry, mode |S_IFDIR, 0);
	if (!res) {
		dir->i_nlink++;
	}
	return res;
}

static int asfs_create(struct inode *dir, struct dentry *dentry, int mode)
{
	return asfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int asfs_fill_super(struct super_block *sb, void *data, int silent)
{
	static struct tree_descr debug_files[] = {{""}};

	return simple_fill_super(sb, AUFS_MAGIC, debug_files);
}

static int asfs_get_sb(struct file_system_type *fs_type,\
		int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_single(fs_type, flags, data, asfs_fill_super, mnt);
}

static struct file_system_type asfs_type = {
	.owner =    THIS_MODULE,  
	.name =     "asfs",  
	.get_sb =   asfs_get_sb,  
	.kill_sb =  kill_litter_super,  
};

static int asfs_create_by_name(const char *name, mode_t mode, struct dentry *parent,  
		struct dentry **dentry)
{
	int error = 0;

	if (!parent ){
		if (asfs_mount && asfs_mount->mnt_sb){
			parent = asfs_mount->mnt_sb->s_root;
		}
	}
	if (!parent){
		printk("Ah! can not find a parent!\n");
		return -EFAULT;
	}

	*dentry = NULL;
	mutex_lock(&parent->d_inode->i_mutex);
	*dentry = lookup_one_len(name, parent, strlen(name));
	if (!IS_ERR(dentry)){
		if ((mode & S_IFMT)== S_IFDIR) {
			error = asfs_mkdir(parent->d_inode, *dentry, mode);
		} else {
			error = asfs_create(parent->d_inode, *dentry, mode);
		}
	} else {
		error = PTR_ERR(dentry);
	}
	mutex_unlock(&parent->d_inode->i_mutex);

	return error;
}

struct dentry *asfs_create_file(const char *name, mode_t mode, struct dentry *parent,\
		void *data, struct file_operations *fops)
{
	struct dentry *dentry = NULL;
	int error;

	printk("asfs: creating file '%s'\n",name);

	error = asfs_create_by_name(name, mode, parent, &dentry);
	if (error){
		dentry = NULL;
		goto exit;
	}
	if (dentry->d_inode){
		/* Commented by nsccc
		   if (data) {
		   dentry->d_inode->u.generic_ip = data;
		   } */
		if (fops) {
			dentry->d_inode->i_fop = fops;
		}
	}
exit:  
	return dentry;
}

struct dentry *asfs_create_dir(const char *name, struct dentry *parent)
{
	return asfs_create_file(name, S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO,\
			parent, NULL, NULL);
}

static int __init asfs_init(void)
{
	int retval;
	struct dentry *pslot;

	printk(KERN_ALERT"insmod module: %s, state: %d\n",\
		THIS_MODULE->name, THIS_MODULE->state);

	retval = register_filesystem(&asfs_type);
	if (!retval){
		asfs_mount = kern_mount(&asfs_type);
		if (IS_ERR(asfs_mount)){
			printk(KERN_ERR "asfs: could not mount!\n");
			unregister_filesystem(&asfs_type);
			return retval;
		} else {
			asfs_mount_count += 1;
		}
	} else {
		printk(KERN_ERR "register_filesystem failed\n");
		return retval;
	}

	pslot = asfs_create_dir("woman_star",NULL);
	asfs_create_file("lbb", S_IFREG | S_IRUGO, pslot, NULL, NULL);
	asfs_create_file("fbb", S_IFREG | S_IRUGO, pslot, NULL, NULL);
	asfs_create_file("ljl", S_IFREG | S_IRUGO, pslot, NULL, NULL);

	pslot = asfs_create_dir("man_star",NULL);
	asfs_create_file("ldh", S_IFREG | S_IRUGO, pslot, NULL, NULL);
	asfs_create_file("lcw", S_IFREG | S_IRUGO, pslot, NULL, NULL);
	asfs_create_file("jwc", S_IFREG | S_IRUGO, pslot, NULL, NULL);

	return retval;
}
static void __exit asfs_exit(void)
{
	simple_release_fs(&asfs_mount, &asfs_mount_count);
	unregister_filesystem(&asfs_type);
}

module_init(asfs_init);
module_exit(asfs_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A simple filesystem module");
MODULE_VERSION("Ver 1.0");

