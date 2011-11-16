ifneq ($(KERNELRELEASE),)
target-objs     += targ_main.o targ_port.o targ_sess.o targ_group.o
target-objs     += targ_md_buf.o

obj-m += target.o
obj-m  += raid456.o
raid456-y       += raid5.o

EXTRA_CFLAGS += -DGITVERSION=\"${GITVERSION}\"
EXTRA_CFLAGS += -I$(src)/../../include
else

KVER = $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build

endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) GITVERSION="git-g$(shell git describe --dirty --always)"
