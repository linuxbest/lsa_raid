ifneq ($(KERNELRELEASE),)

target-objs     += targ_main.o targ_port.o targ_sess.o
ifeq ($(TARGT_DUMMY_BUF),y)
target-objs     += targ_dummy_buf.o
else
target-objs     += targ_dm_buf.o
endif

obj-m += target.o

EXTRA_CFLAGS += -DGITVERSION=\"${GITVERSION}\"
EXTRA_CFLAGS += -I$(src)/../../include

else

KVER = $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build

endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) GITVERSION="git-g$(shell git describe --dirty --always)"
