ifneq ($(KERNELRELEASE),)

dm-mod-y	+= dm.o dm-table.o dm-target.o dm-linear.o dm-stripe.o \
		   dm-ioctl.o dm-io.o dm-kcopyd.o dm-sysfs.o

ifeq ($(CONFIG_DM_UEVENT),y)
dm-mod-objs     += dm-uevent.o
endif

dm-mod-objs     += main.o targ_port.o targ_sess.o
dm-mod-objs     += dm-raid4-5.o dm-memcache.o dm-region-hash.o dm-message.o
dm-mod-objs     += dm-log.o

obj-$(CONFIG_BLK_DEV_DM)        += dm-mod.o

EXTRA_CFLAGS += -DGITVERSION=\"${GITVERSION}\"
EXTRA_CFLAGS += -I$(src)/../../include

else

KVER = $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build

endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) GITVERSION="git-g$(shell git describe --dirty --always)"
