ifneq ($(KERNELRELEASE), )
	obj-m := cr0op.o
else
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif

