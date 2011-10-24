ifneq ($(KERNELRELEASE),)
dm-mod-y        += dm.o dm-table.o dm-target.o dm-linear.o dm-stripe.o
dm-mod-y	+= dm-ioctl.o dm-io.o dm-kcopyd.o dm-sysfs.o

target-objs     += targ_main.o targ_port.o targ_sess.o targ_group.o

#target-objs    += targ_dummy_buf.o
target-objs     += targ_md_buf.o

obj-m += target.o
obj-m += dm-mod.o
obj-m += raid456.o
obj-m += md-mod.o

raid456-y       += raid5.o
md-mod-y        += md.o bitmap.o

EXTRA_CFLAGS += -DGITVERSION=\"${GITVERSION}\"
EXTRA_CFLAGS += -I$(src)/../../include

else

KVER = $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build

endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) GITVERSION="git-g$(shell git describe --dirty --always)"
