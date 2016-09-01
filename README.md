# hook
hook system functions in kernel space
- system call functions
- vfs file operation functions

## hk_syscall
kernel module to hook x64 syscall

## hk_syscall_32
kernel module to hook x86 syscall

## hk_syscall_vmap
kernel module to hook x86 syscall, and use vmap to wite WP syscall_table

## hk_vfs
kernel module to hook vfs functions

