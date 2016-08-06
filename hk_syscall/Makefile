ifneq ($(KERNELRELEASE),)
$(warning I_am_in_ifneq)  # or $(error in_ifneq), but it would stop progress
	obj-m += hk_syscall.o
else
$(warning I_am_in_else)   # or $(error in_else), it would stop progress too.
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif
