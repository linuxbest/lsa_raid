ifneq ($(KERNELRELEASE),)
dm-mod-y        += dm.o dm-table.o dm-target.o dm-linear.o dm-stripe.o
dm-mod-y	+= dm-ioctl.o dm-io.o dm-kcopyd.o dm-sysfs.o

target-objs     += targ_main.o targ_port.o targ_sess.o targ_group.o

#target-objs    += targ_dummy_buf.o
target-objs     += targ_md_buf.o

#obj-m += target.o
dm-mod-y        += ${target-objs}
dm-mod-y        += ${md-mod-y}
dm-mod-y        += ${raid456-y}

obj-m += dm-mod.o
#obj-m += raid456.o
#obj-m += md-mod.o

raid456-y       += raid5.o lsa_rb.o lsa_stream.o
md-mod-y        += md.o bitmap.o

ifeq ($(CONFIG_DM_UEVENT),y)
dm-mod-objs     += dm-uevent.o
endif

EXTRA_CFLAGS += -DGITVERSION=\"${GITVERSION}\"
EXTRA_CFLAGS += -I$(src)/../../include

else

KVER = $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build

endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) GITVERSION="git-g$(shell git describe --dirty --always)"
