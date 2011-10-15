#
# Makefile for the kernel software RAID and LVM drivers.
#

dm-mod-y	+= dm.o dm-table.o dm-target.o dm-linear.o dm-stripe.o \
		   dm-ioctl.o dm-io.o dm-kcopyd.o dm-sysfs.o

obj-$(CONFIG_BLK_DEV_DM)        += dm-mod.o
