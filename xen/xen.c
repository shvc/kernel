#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/file.h>
#include <asm/unistd.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
#include <linux/path.h>
#include <linux/fdtable.h>
#else
#include <asm/semaphore.h>
#endif

#define __XEN__

#ifdef __XEN__
#ifndef __XEN_TOOLS__
#define __XEN_TOOLS__
#endif

#ifdef __x86_64__
#include <asm-x86_64/mach-xen/asm/hypercall.h>
#else
#include <asm-i386/mach-xen/asm/hypercall.h>
#endif

typedef enum {
    ARCH_X86 = 0,
    ARCH_X86_64,
} arch_t;

struct ___vcpu_guest_context {
    /* FPU registers come first so they can be aligned for FXSAVE/FXRSTOR. */
    struct { char x[512]; } fpu_ctxt;       /* User-level FPU registers     */
#define VGCF_I387_VALID                (1<<0)
#define VGCF_HVM_GUEST                 (1<<1)
#define VGCF_IN_KERNEL                 (1<<2)
#define _VGCF_i387_valid               0
#define VGCF_i387_valid                (1<<_VGCF_i387_valid)
#define _VGCF_hvm_guest                1
#define VGCF_hvm_guest                 (1<<_VGCF_hvm_guest)
#define _VGCF_in_kernel                2
#define VGCF_in_kernel                 (1<<_VGCF_in_kernel)
#define _VGCF_failsafe_disables_events 3
#define VGCF_failsafe_disables_events  (1<<_VGCF_failsafe_disables_events)
#define _VGCF_syscall_disables_events  4
#define VGCF_syscall_disables_events   (1<<_VGCF_syscall_disables_events)
    unsigned long flags;                    /* VGCF_* flags                 */
    struct cpu_user_regs user_regs;         /* User-level CPU registers     */
    struct trap_info trap_ctxt[256];        /* Virtual IDT                  */
    unsigned long ldt_base, ldt_ents;       /* LDT (linear address, # ents) */
    unsigned long gdt_frames[16], gdt_ents; /* GDT (machine frames, # ents) */
    unsigned long kernel_ss, kernel_sp;     /* Virtual TSS (only SS1/SP1)   */
    unsigned long ctrlreg[8];               /* CR0-CR7 (control registers)  */
    unsigned long debugreg[8];              /* DB0-DB7 (debug registers)    */
    unsigned long event_callback_eip;
    unsigned long failsafe_callback_eip;
    unsigned long syscall_callback_eip;
    unsigned long vm_assist;                /* VMASST_TYPE_* bitmap */
    /* Segment base addresses. */
    uint64_t      fs_base;
    uint64_t      gs_base_kernel;
    uint64_t      gs_base_user;
};

struct vcpucontext
{
        uint32_t vcpu;
        struct vcpu_guest_context *ctx;
};

struct domctl_t
{
        uint32_t cmd;
        uint32_t interface_version;
        domid_t domain;
        union
        {
                struct vcpucontext cpuctx;
                char pad[128];
        }u;
};

#include <asm-i386/mach-xen/asm/hypervisor.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/mm.h>

struct vmap_result
{
        void *mapping;
        void *addr;
};

#endif

asmlinkage long    (*orig_chmod)(const char __user *, mode_t);
#ifdef __x86_64__
/* the following is for 32bit programs on x64 system */
void **sys_table_32;
struct idtr {
	unsigned short limit;
	unsigned long base; //in 64bit mode, base address is 8 bytes
} __attribute__ ((packed));

struct idt {
	u16 offset_low;
	u16 segment;
	unsigned ist : 3, zero0 : 5, type : 5, dpl :2, p : 1;
	u16 offset_middle;
	u32 offset_high;
	u32 zero1;
} __attribute__ ((packed));

/*
 * The following micros borrow form unistd_32.h
 */
#define __NR_chmod_32               15
asmlinkage long    (*orig_chmod_32)(const char __user *, mode_t);
#endif

/* 系统调用表结构 */
void **sys_table;

struct _idt
{
	unsigned short offset_low,segment_sel;
	unsigned char reserved,flags;
	unsigned short offset_high;
};

/* micro RHEL_RELEASE_CODE not exist beyond rhel */
#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif


#ifdef __XEN__

#if RHEL_RELEASE_CODE == 0
#define XEN_DOMCTL_INTERFACE_VERSION 0x00000003
#elif RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,1)
#define XEN_DOMCTL_INTERFACE_VERSION 0x00000007
#endif

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
//3.7.0之后的版本，putname不再被导出，所以，在此显示定义putname的实现代码
#define __fsp_putname(name)         kmem_cache_free(names_cachep, (void *)(name))
#define __fsp_getname()             kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define EMBEDDED_NAME_MAX       (PATH_MAX - sizeof(struct filename))

static void fsp_final_putname(struct filename *name) {
    if(name->separate) {
        __fsp_putname(name->name);
        kfree(name);
    } else {
        __fsp_putname(name);
    }
}

static struct filename* __kernel_getname_flags(const char __user *filename, int flags, int *empty) {
    struct filename *result, *err;
    int len;
    long max;
    char *kname;

    result = __fsp_getname();
    if(unlikely(!result)) {
        return ERR_PTR(-ENOMEM);
    }

    kname = (char *)result + sizeof(*result);
    result->name = kname;
    result->separate = false;
    max = EMBEDDED_NAME_MAX;

recopy:
    len = strncpy_from_user(kname, filename, max);
    if(unlikely(len < 0)) {
        err = ERR_PTR(len);
        goto error;
    }

    if(len == EMBEDDED_NAME_MAX && max == EMBEDDED_NAME_MAX) {
        kname = (char *)result;

        result = kzalloc(sizeof(*result), GFP_KERNEL);
        if(!result) {
            err = ERR_PTR(-ENOMEM);
            result = (struct filename *)kname;
            goto error;
        }
        result->name = kname;
        result->separate = true;
        max = PATH_MAX;
        goto recopy;
    }

    if(unlikely(!len)) {
        if(empty)
            *empty = 1;
        err = ERR_PTR(-ENOENT);
        if(!(flags & LOOKUP_EMPTY)) 
            goto error;
    }

    err = ERR_PTR(-ENAMETOOLONG);
    if(unlikely(len >= PATH_MAX))
        goto error;

    result->uptr = filename;
    return result;

error:
    fsp_final_putname(result);
    return err;
}

static struct filename* __kernel_getname(const char __user * filename)
{
    return __kernel_getname_flags(filename, 0, NULL);
}

static void fsp_putname(struct filename *name)
{
	fsp_final_putname(name);
}
#endif

static int fsp_getname(const char* filename)
{
	int ret = 0;
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,5)
	struct filename *tmp = NULL;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	struct filename *tmp = NULL;
#else
	char            *tmp = NULL;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	tmp = __kernel_getname(filename);
#else
	tmp = getname(filename);
#endif
	if(IS_ERR(tmp)) { 
		ret = 1;
	} else {
		ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
		fsp_putname(tmp);
#else
		putname(tmp);
#endif
	}
	return ret;
}

/* set memory page read/write perm */
unsigned long clear_and_return_cr0(void)
{
	unsigned long cr0 = 0;
	unsigned long ret;
#ifdef __x86_64__
	asm volatile ("movq %%cr0, %%rax" 
			: "=a"(cr0) 
		     ); 
	ret = cr0;
	/* clear the 20 bit of CR0, a.k.a WP bit */ 
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
	/* clear the 20 bit of CR0, a.k.a WP bit */ 
	cr0 &= 0xfffeffff;
	asm volatile ("movl %%eax, %%cr0"
			:
			: "a"(cr0)
		     );
#endif
	return ret;
}

/* recover memory page read/write perm */
void setback_cr0(unsigned long val)
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

/* hook sys_chmod, protect file mode bits */
asmlinkage long fsp_chmod(const char __user *filename, mode_t mode)
{
	return orig_chmod(filename,mode);
}

#endif


#ifdef __x86_64__
asmlinkage long fsp_chmod_32(const char __user *filename, mode_t mode)
{
	return orig_chmod_32(filename,mode);
}

#endif

#endif

static void *memmem(const void *haystack, size_t haystack_len, 
		const void *needle, size_t needle_len) 
{
	const char *begin; 
	const char *const last_possible = (const char *) haystack + haystack_len - needle_len;

	if (needle_len == 0){ 
		/* The first occurrence of the empty string is deemed to occur at 
		   the beginning of the string. */ 
		return (void *) haystack;
	}
	/* Sanity check, otherwise the loop might search through the whole 
	   memory. */ 
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

#ifndef __XEN__
#ifdef __x86_64__


#endif//__x86_64__
#endif//__XEN__

//获得系统调用表的地址
unsigned long fspGetSysCallTable(void)

#ifdef __XEN__
int get_writable_syscall_table(unsigned long syscall_table, struct vmap_result *vmap_result)
{
	struct page *pages[2];
	void *mapping = NULL;

	if(syscall_table == 0)
	{
		printk("[fsp::get_writable_syscall_table] syscall_table invalid.\n");
		return -1;
	}

	if(vmap_result == NULL)
	{
		printk("[fsp::get_writable_syscall_table] vmap_result invalid\n");
		return -1;
	}

	pages[0] = virt_to_page(syscall_table);
	pages[1] = virt_to_page(syscall_table + PAGE_SIZE);

	mapping = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	if(!mapping)
	{
		printk("[fsp::get_writable_syscall_table] vmap failed\n");
		return -1;
	}

	vmap_result->mapping = mapping;
	vmap_result->addr = mapping + offset_in_page(syscall_table);

	return 0;
}

int release_writable_syscall_table(struct vmap_result *vmap_result)
{
	if(vmap_result == NULL)
	{
		printk("[fsp::release_writable_syscall_table] vmap_result invalid\n");
		return -1;
	}

	if(vmap_result->mapping == NULL)
	{
		printk("[fsp::release_writable_syscall_table] vmap_result->mapping invalid\n");
		return -1;
	}

	vunmap(vmap_result->mapping);

	return 0;
}

static unsigned long hex_str_to_num(const char *str)
{
	unsigned long ret = 0;
	unsigned int len = strlen(str);
	unsigned int i = 0;

	for(; *str && i < len; i++, str++)
	{
		switch(*str)
		{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			ret |= ((unsigned long)(*str  -0x30) << ((len - 1 - i) * 4));
			break;
		case 'a':
		case 'A':
			ret |= ((unsigned long)0x0A << ((len - 1 - i) * 4));
			break;
		case 'b':
		case 'B':
			ret |= ((unsigned long)0x0B << ((len - 1 - i) * 4));
			break;
		case 'c':
		case 'C':
			ret |= ((unsigned long)0x0C << ((len - 1 - i) * 4));
			break;
		case 'd':
		case 'D':
			ret |= ((unsigned long)0x0D << ((len - 1 - i) * 4));
			break;
		case 'e':
		case 'E':
			ret |= ((unsigned long)0x0E << ((len - 1 - i) * 4));
			break;
		case 'f':
		case 'F':
			ret |= ((unsigned long)0x0F << ((len - 1 - i) * 4));
			break;
		default:
			printk("[hex_str_to_num] error: %c\n", *str);
			break;
		}
	}

	return ret;
}

#ifdef __x86_64__
static int get_syscall_table_from_kallsyms(unsigned long *system_call_table, unsigned long *ia32_syscall_table)
#else
static int get_syscall_table_from_kallsyms(unsigned long *system_call_table)
#endif
{
#define KALLSYMS_PATH	"/proc/kallsyms"

#define KALLSYMS_ADDR_LENGTH	64
#define KALLSYMS_TYPE_LENGTH	64
#define KALLSYMS_NAME_LENGTH	128

#define N_BYTES_PER_READ	128

/* 文件解析的状态 */
//解析符号地址，以空格结束
#define PARSE_ADDR	0

//解析符号类型，以空格结束
#define PARSE_TYPE	1

//解析符号名，以空格或换行结束。如果是空格，则状态转到PARSE_OMIT；如果是换行，则状态转到PARSE_ADDR
#define PARSE_NAME	2

//忽略此状态下除了换行外的所有字符
#define PARSE_OMIT	3

	unsigned int ret = -1;				//返回值，默认是失败
	struct file *file = NULL;			//文件指针
	mm_segment_t old_fs;				//原始的fs，因为vfs_read需要的内存是用户态的

	int state = PARSE_ADDR;				//解析kallsyms文件的状态机状态
	unsigned int i = 0;				//读文件时的缓冲区下标
	unsigned char addr[KALLSYMS_ADDR_LENGTH];	//保存符号地址的缓冲区
	unsigned char type[KALLSYMS_TYPE_LENGTH];	//保存符号类型的缓冲区
	unsigned char name[KALLSYMS_NAME_LENGTH];	//保存符号名的缓冲区
	unsigned char *p_addr = addr;			//符号地址缓冲区的指针
	unsigned char *p_type = type;			//符号类型缓冲区的指针
	unsigned char *p_name = name;			//符号名缓冲区的指针

	unsigned char *buf = NULL;			//读文件的缓冲区
	ssize_t n_read = 0;				//每次读到的字节数

	unsigned long system_call = 0;			//system_call函数入口地址
#ifdef __x86_64__
	unsigned long ia32_syscall = 0;			//64位环境下，32位系统调用函数入口地址
#endif
	unsigned char *tmp = NULL;			//一个临时指针

	do
	{
		file = filp_open(KALLSYMS_PATH, O_RDONLY, 0);
		if(IS_ERR(file))
		{
			printk("[fsp::get_syscall_table_from_kallsyms] open %s failed\n", KALLSYMS_PATH);
			break;
		}

		old_fs = get_fs();
		set_fs(KERNEL_DS);

		//初始化缓冲区
		buf = (unsigned char *)kmalloc(N_BYTES_PER_READ, GFP_KERNEL);
		if(buf == NULL)
		{
			printk("[fsp::get_syscall_table_from_kallsyms] kmalloc buf failed\n");
			break;
		}

		n_read = vfs_read(file, buf, N_BYTES_PER_READ, &(file->f_pos));
		while(n_read > 0)
		{
			i = 0;
			while(i < n_read)
			{
				switch(state)
				{
				case PARSE_ADDR:
					if(buf[i] == ' ')
					{
						state = PARSE_TYPE;
						break;
					}
					if(((unsigned long)p_addr - (unsigned long)addr) < KALLSYMS_ADDR_LENGTH)
					{
						*p_addr++ = buf[i];
					}
					break;
				case PARSE_TYPE:
					if(buf[i] == ' ')
					{
						state = PARSE_NAME;
						break;
					}
					if(((unsigned long)p_type - (unsigned long)type) < KALLSYMS_TYPE_LENGTH)
					{
						*p_type++ = buf[i];
					}
					break;
				case PARSE_NAME:
					if(buf[i] == ' ')
					{
						state = PARSE_OMIT;
					}
					else if(buf[i] == '\n')
					{
						state = PARSE_ADDR;
					}

					if(state == PARSE_ADDR || state == PARSE_OMIT)
					{
						*p_addr++ = 0;
						*p_type++ = 0;
						*p_name++ = 0;

						if(system_call == 0 && strcmp(name, "system_call") == 0)
						{
							system_call = hex_str_to_num(addr);
						}
#ifdef __x86_64__
						else if(ia32_syscall == 0 && strcmp(name, "ia32_syscall") == 0)
						{
							ia32_syscall = hex_str_to_num(addr);
						}
#endif

#ifdef __x86_64__
						if(system_call && ia32_syscall)
#else
						if(system_call)
#endif
						{
							ret = 0;
							goto FOUND;
						}

						p_addr = addr;
						p_type = type;
						p_name = name;
						break;
					}

					if(((unsigned long)p_name - (unsigned long)name) < KALLSYMS_NAME_LENGTH)
					{
						*p_name++ = buf[i];
					}
					break;
				case PARSE_OMIT:
					if(buf[i] == '\n')
					{
						state = PARSE_ADDR;
						break;
					}
					break;
				default:
					break;
				}
				i++;
			}
			n_read = vfs_read(file, buf, N_BYTES_PER_READ, &(file->f_pos));
		}
FOUND:
		kfree(buf);
		set_fs(old_fs);
		filp_close(file, NULL);
	}while(0);

	if(ret == 0)
	{
#ifdef __x86_64__
		printk("[fsp::get_syscall_table_from_kallsyms] system_call: %lX\n", system_call);
		printk("[fsp::get_syscall_table_from_kallsyms] ia32_syscall: %lX\n", ia32_syscall);

		tmp = (unsigned char *)memmem((char *)system_call, 200, "\xff\x14\xc5", 3);
		if(tmp == NULL)
		{
			printk("[fsp::get_syscall_table_from_kallsyms] can not find system_call_table address\n");
			return -1;
		}
		*system_call_table = (unsigned long)(*(unsigned int *)(tmp + 3)) | 0xFFFFFFFF00000000;
		printk("[fsp::get_syscall_table_from_kallsyms] system_call_table: %lX\n", *system_call_table);

		tmp = NULL;
		tmp = (unsigned char *)memmem((char *)ia32_syscall, 200, "\xff\x14\xc5", 3);
		if(tmp == NULL)
		{
			printk("[fsp::get_syscall_table_from_kallsyms] can not find ia32_syscall_table address\n");
			return -1;
		}
		*ia32_syscall_table = (unsigned long)(*(unsigned int *)(tmp + 3)) | 0xFFFFFFFF00000000;
		printk("[fsp::get_syscall_table_from_kallsyms] ia32_syscall_table: %lX\n", *ia32_syscall_table);
#else
		printk("[fsp::get_syscall_table_from_kallsyms] system_call: %lX\n", system_call);

		tmp = (unsigned char *)memmem((char *)system_call, 200, "\xff\x14\x85", 3);
		if(tmp == NULL)
		{
			printk("[fsp::get_syscall_table_from_kallsyms] can not find system_call_table address\n");
			return -1;
		}
		*system_call_table = (unsigned long)(*(unsigned int *)(tmp + 3));
		printk("[fsp::get_syscall_table_from_kallsyms] system_call_table: %lX\n", *system_call_table);
#endif
	}

	return ret;
}

#ifdef __x86_64__
static int get_syscall_table_from_xen(unsigned long *system_call_table, unsigned long *ia32_syscall_table)
#else
static int get_syscall_table_from_xen(unsigned long *system_call_table)
#endif
{
#ifdef __x86_64__
#define MIN_DOMCTL_INTERFACE_VERSION	0x03
#define MAX_DOMCTL_INTERFACE_VERSION	0x07
	unsigned long ret = 0;
	struct vcpu_guest_context ctx;
	struct domctl_t domctl;
	unsigned char *tmp = 0;
	unsigned long system_call = 0;
	unsigned int interface_version = 0;

	unsigned long ia32_syscall = 0;
	if(system_call_table == NULL || ia32_syscall_table == NULL)
	{
		printk("[fsp::get_syscall_table_from_xen] system_call == NULL or ia32_syscall == NULL\n");
		return -1;
	}

	for(interface_version = MIN_DOMCTL_INTERFACE_VERSION; interface_version <= MAX_DOMCTL_INTERFACE_VERSION; interface_version++)
	{
		domctl.cmd = 13;
		domctl.domain = 0;
		domctl.interface_version = interface_version;
		domctl.u.cpuctx.vcpu = 0;
		domctl.u.cpuctx.ctx = &ctx;

		ret = _hypercall1(unsigned long, domctl, &domctl);
		if(ret == 0)
		{
			printk("[fsp::get_syscall_table_from_xen] _hypercall1 successed, version %d\n", interface_version);
			break;
		}
		printk("[fsp::get_syscall_table_from_xen] _hypercall1 failed with 0x%lX, version: %d\n", ret, interface_version);
	}

	if(ret != 0)
	{
		printk("[fsp::get_syscall_table_from_xen] _hypercall1 failed\n");
		return -1;
	}

	system_call = ctx.syscall_callback_eip;
	ia32_syscall = ctx.trap_ctxt[0x80].address;

	tmp = (unsigned char *)memmem((char *)system_call, 200, "\xff\x14\xc5", 3);
	if(tmp == NULL)
	{
		printk("[fsp::get_syscall_table_from_xen] can not find system_call_table address\n");
		return -1;
	}
	*system_call_table = (unsigned long)(*(unsigned int *)(tmp + 3)) | 0xFFFFFFFF00000000;

	tmp = (unsigned char *)memmem((char *)ia32_syscall, 200, "\xff\x14\xc5", 3);
	if(tmp == NULL)
	{
		printk("[fsp::get_syscall_table_from_xen] can not find ia32_syscall_table address\n");
		return -1;
	}
	*ia32_syscall_table = (unsigned long)(*(unsigned int *)(tmp + 3)) | 0xFFFFFFFF00000000;

	return 0;
#else
	return -1;
#endif//__x86_64__
}
#endif//__XEN__

// 模块载入时被调用,系统调用劫持
static int init_syscall_table(void)
{
	//下面是获取系统调用表的起始地址
#ifdef __XEN__
	struct vmap_result mapping;
	void **sys_table_orig;

#ifdef __x86_64__
	struct vmap_result mapping_32;
	void **sys_table_32_orig;
	if(get_syscall_table_from_xen((unsigned long *)&sys_table, (unsigned long *)&sys_table_32) != 0)
	{
		printk("[fsp::init_syscall_table] get_syscall_table_from_xen failed, try to get it from /proc/kallsyms\n");
		if(get_syscall_table_from_kallsyms((unsigned long *)&sys_table, (unsigned long *)&sys_table_32) != 0)
		{
			printk("[fsp::init_syscall_table] get_syscall_table_from_kallsyms failed\n");
			return -1;
		}
	}
#else//__x86_64__
	if(get_syscall_table_from_xen((unsigned long *)&sys_table) != 0)
	{
		printk("[fsp::init_syscall_table] get_syscall_table_from_xen failed, try to get it from /proc/kallsyms\n");
		if(get_syscall_table_from_kallsyms((unsigned long *)&sys_table) != 0)
		{
			printk("[fsp::init_syscall_table] get_syscall_table_from_kallsyms failed\n");
			return -1;
		}
	}
#endif//__x86_64__

#else//__XEN__ not defined
	sys_table_32 = (void**)(retval | 0xffffffff00000000);
#else//__x86_64__
	sys_table    = (void**)(retval);
#endif//__x86_64__

#endif//__XEN__

	//下面是把系统调用表的写保护关掉
	//对于xen，通过把系统调用表所在物理页面，映射到一段没有写保护的虚拟地址上，就可以修改系统调用表
#ifdef __XEN__

	if(get_writable_syscall_table((unsigned long)sys_table, &mapping) != 0)
	{
		printk("[fsp::init_syscall_table] mapping sys_table failed\n");
		return -1;
	}
	//把获取到的真实sys_table的地址备份一下，因为vmap过后，需要用新的地址去访问sys_table
	//为了兼容之前的代码，这里把真实的值先备份了，把新地址赋给sys_table，等这个函数完了，再把真实的值恢复回去
	//下面sys_table_32的代码同理
	sys_table_orig = sys_table;
	sys_table = (void **)mapping.addr;

#ifdef __x86_64__
	if(get_writable_syscall_table((unsigned long)sys_table_32, &mapping_32) != 0)
	{
		printk("[fsp::init_syscall_table] mapping sys_table_32 failed\n");
		return -1;
	}
	sys_table_32_orig = sys_table_32;
	sys_table_32 = (void **)mapping_32.addr;
#endif//__x86_64__

#else//__XEN__ not defined
	orig_cr0 = clear_and_return_cr0();
#endif//__XEN__

	orig_chmod      = sys_table[__NR_chmod];
#ifdef __x86_64__
	/* the following is for 32bit programs on x64 system */
	orig_chmod_32     = sys_table_32[__NR_chmod_32];
#endif

	sys_table[__NR_chmod]        = fsp_chmod;
#ifdef __x86_64__
	/* the following is for 32bit programs on x64 system */
	sys_table_32[__NR_chmod_32]     = fsp_chmod_32;
#endif

#ifdef __XEN__
	//把函数开始时vmap的页面都释放掉
	//然后，把sys_table的真实值恢复回去

	if(release_writable_syscall_table(&mapping) != 0)
	{
		printk("[fsp::init_syscall_table] release map for sys_table failed\n");
	}
	sys_table = sys_table_orig;
#ifdef __x86_64__
	if(release_writable_syscall_table(&mapping_32) != 0)
	{
		printk("[fsp::init_syscall_table] release map for sys_table_32 failed\n");
	}
	sys_table_32 = sys_table_32_orig;
#endif
#else//__XEN__ not defined
	setback_cr0(orig_cr0);
#endif//__XEN__
	return 0;
}


/* 模块卸载时被调用，恢复原始系统调用 */
static void clean_sys_call_table(void)
{
#ifdef __XEN__
	struct vmap_result mapping;
	void **sys_table_orig;

#ifdef __x86_64__
	struct vmap_result mapping_32;
	void **sys_table_32_orig;

	if(get_writable_syscall_table((unsigned long)sys_table_32, &mapping_32) != 0)
	{
		printk("[fsp::clean_sys_call_table] mapping sys_table_32 failed\n");
		return;
	}
	sys_table_32_orig = sys_table_32;
	sys_table_32 = (void **)mapping_32.addr;
#endif

	if(get_writable_syscall_table((unsigned long)sys_table, &mapping) != 0)
	{
		printk("[fsp::clean_sys_call_table] mapping sys_table failed\n");
		return;
	}
	sys_table_orig = sys_table;
	sys_table = (void **)mapping.addr;
#else//__XEN__ not defined
	orig_cr0 = clear_and_return_cr0();
#endif//__XEN__
	sys_table[__NR_chmod]        = orig_chmod;
#ifdef __x86_64__
	/* the following is for 32bit programs on x64 system */
	sys_table_32[__NR_chmod_32]     = orig_chmod_32;
#endif

#ifdef __XEN__
	if(release_writable_syscall_table(&mapping) != 0)
	{
		printk("[fsp::clean_sys_call_table] release map for sys_table failed\n");
	}
	sys_table = sys_table_orig;
#ifdef __x86_64__
	if(release_writable_syscall_table(&mapping_32) != 0)
	{
		printk("[fsp::clean_sys_call_table] release map for sys_table_32 failed\n");
	}
	sys_table_32 = sys_table_32_orig;
#endif
#else
	setback_cr0(orig_cr0);
#endif
}

static int __init init_fsp(void)
{
	if(init_syscall_table() != 0) {
		printk("init_syscall_table failed\n");
		return -1;
	}
	return 0;
}

static void __exit exit_fsp(void)
{
	clean_sys_call_table();
	msleep(1000);
}

module_init(init_fsp);
module_exit(exit_fsp);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dawter");

