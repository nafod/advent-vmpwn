obj-m += pwn3.o

ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

all:
	    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
