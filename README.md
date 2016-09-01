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
kernel module to hook x86 syscall
- use vmap to write WP(write protected) syscall_table

## hk_vfs
kernel module to hook vfs functions
- 

