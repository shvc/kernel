ifneq ($(KERNELRELEASE),)
$(warning I am warning in ifneq) # or $(error msg)
$(warning current directory $(PWD)) # or $(error msg)
	obj-m += hk_syscall.o
else
$(warning I am warning in else)  # or $(error msg)
$(warning current directory $(PWD)) # or $(error msg)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

endif
