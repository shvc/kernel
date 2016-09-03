# hook
hook system functions in kernel space
- system call functions
- vfs file operation functions

## hk_syscall
kernel module to hook x64 syscall
- use cr0 register to write WP(write protected) syscall_table

## hk_syscall_32
kernel module to hook x86 syscall
- use cr0 register to write WP(write protected) syscall_table

## hk_syscall_vmap
kernel module to hook x86 and x64 syscall
- use vmap to write WP(write protected) syscall_table
- vmap
```
Name
vmap — map an array of pages into virtually contiguous space

Synopsis
void *vmap (struct page ** pages, unsigned int count, unsigned long flags, pgprot_t prot);
 
Arguments
pages: array of page pointers
count: number of pages to map
flags: vm_area->flags
prot: page protection for the mapping

Description
Maps count pages from pages into contiguous kernel virtual space.
```
- vunmap
```
Name
vunmap — release virtual mapping obtained by vmap

Synopsis
void vunmap (	const void * addr);
 
Arguments
addr: memory base address

Description
Free the virtually contiguous memory area starting at addr, which was created from the page array passed to vmap.  
Must not be called in interrupt context.
```

## hk_vfs
kernel module to hook vfs functions
-  ...

