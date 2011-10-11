ifneq ($(KERNELRELEASE),)
#SCST_INC_DIR := /p/prod/d/scst/scst/include

obj-m = raidif.o

raidif-objs += main.o dev.o mem.o bus.o

EXTRA_CFLAGS := -I$(src)/../include

else
ifeq ($(KDIR),)
KVER = $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
endif

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) GITVERSION="git-g$(shell git describe --dirty --always)"

install: all
	$(MAKE) -C $(KDIR) SUBDIRS=$(shell pwd) \
	modules_install
	-depmod -a $(KVER)

uninstall:
	rm -f $(INSTALL_DIR)/scst_*.ko
endif

EXTRA_CFLAGS += -I$(SUBDIRS) -I$(SCST_INC_DIR) -Wextra -Wno-unused-parameter
EXTRA_CFLAGS += -I$(SUBDIRS)/../include/ -I$(NVRAM_INC_DIR)
EXTRA_CFLAGS += -DEXTRACHECKS
#EXTRA_CFLAGS += -DTRACING
EXTRA_CFLAGS += -DDEBUG -g
EXTRA_CFLAGS += -Werror
EXTRA_CFLAGS += -DGITVERSION=\"${GITVERSION}\"

clean:
	rm -f *.o *.ko .*.cmd *.mod.c .*.d .depend Modules.symvers \
	   Module.symvers Module.markers modules.order
	   rm -rf .tmp_versions

extraclean:  clean

.PHONY: all install uninstall clean extraclean
