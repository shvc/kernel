ifneq ($(KERNELRELEASE),)
$(warning Step into ifneq and current directory is $(PWD))  # or $(error msg), but it would stop progress
	obj-m += hk_syscall.o
else
$(warning Step into else and current directory is $(PWD))   # or $(error msg), it would stop progress too.
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif
