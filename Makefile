obj-m := capture_demo.o


PWD := $(shell pwd)
KERNEL_DIR := "/usr/src/linux-headers-"$(shell uname -r)/

modules:
	@$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	@rm -rf *.ko *.o *.mod.c *symvers *order .nl* .tmp*

	
