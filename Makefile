#Makefile2.6
obj-m += nf_change_header.o        # 产生nf_change_header 模块的目标文件
#obj-m += hellomod.o        # 产生hellomod 模块的目标文件
CURRENT_PATH := $(shell pwd)   #模块所在的当前路径
LINUX_KERNEL := $(shell uname -r)    #Linux内核源代码的当前版本
LINUX_KERNEL_PATH := /usr/src/linux-headers-$(LINUX_KERNEL) #Linux内核源代码的绝对路径
all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules   #编译模块了
clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean    #清理
