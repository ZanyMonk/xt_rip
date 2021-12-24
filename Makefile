obj-m := xt_rip.o
CC = gcc -Wall
CFLAGS = --std=C99
ver := $(shell uname -r)
KDIR := /lib/modules/$(ver)/build
PWD := $(shell pwd)

all: prepare build install

prepare:
	type apt | grep -q 'shell function' || apt install -y build-essential linux-headers-$(ver)

build:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	insmod xt_rip.ko
# grep xt_rip /etc/modules || echo xt_rip >> /etc/modules
# cp xt_rip.ko /lib/modules/$(ver)/kernel/net/netfilter/xt_rip.ko
# insmod /lib/modules/$(ver)/kernel/net/netfilter/xt_rip.ko
# update-initramfs -u

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
