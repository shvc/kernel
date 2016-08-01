ifneq ($(KERNELRELEASE),)
obj-m += hk_syscall.o
else

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif
