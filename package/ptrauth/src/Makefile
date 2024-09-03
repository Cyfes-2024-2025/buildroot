obj-m += ptrauth.o

KERNEL_SOURCES ?= ../../../output/build/linux-6.6.32


all:
	make -C $(KERNEL_SOURCES) M=$(PWD) modules

clean:
	make -C $(KERNEL_SOURCES) M=$(PWD) clean

