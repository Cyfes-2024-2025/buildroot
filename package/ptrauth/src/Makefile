obj-m += ptrauth.o

KERNEL_SOURCES ?= ../../../output/build/linux-6.6.32


all:
	make -C $(KERNEL_SOURCES) M=$(PWD) modules

clean:
	rm -rf ./cache *.cmd *.ko *.order *.o *.mod *.mod.c *.symvers

