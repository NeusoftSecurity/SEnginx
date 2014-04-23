MODULE_NAME = wdfp

ifneq ($(KERNELRELEASE),)
	obj-m := $(MODULE_NAME).o 
	$(MODULE_NAME)-objs := wdfp_main.o wdfp_proc.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd) 

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
