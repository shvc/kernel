TARGET_MODULE:=hk_vfs

# If we run by kernel building system
ifneq ($(KERNELRELEASE),)
	$(TARGET_MODULE)-objs := main.o memdev.o module.o
	obj-m := $(TARGET_MODULE).o

# If we run without kernel build system
else
	KERN_VER?=$(shell uname -r)
all : 
# run kernel build system to make module
	$(MAKE) -C /lib/modules/$(KERN_VER)/build M=$(PWD) modules

clean:
# run kernel build system to cleanup in current dir
	$(MAKE) -C /lib/modules/$(KERN_VER)/build M=$(PWD) clean

load:
	insmod ./$(TARGET_MODULE).ko

unload:
	rmmod ./$(TARGET_MODULE).ko

endif

