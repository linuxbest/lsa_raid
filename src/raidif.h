#ifndef _RAID_INT_H_
#define _RAID_INT_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ctype.h>

#include <linux/workqueue.h>
#include <linux/blkdev.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>

struct raidif {
	struct kobject kobj;
	struct completion done;
	struct {
		struct list_head list;
		spinlock_t lock;
	} device;
	struct {
		struct list_head list;
		spinlock_t lock;
	} port;
};

extern struct raidif raidif;

struct raid_device {
	struct kobject kobj;
	struct list_head list;
	uint64_t uuid;
	uint64_t blocks;

	struct linear_c {
		struct dm_dev *dev;
		sector_t start;
	} lc;
};

#define MAX_ARGS  16
int args(char *frame, char *argv[], int argv_max);

struct targ_port {
	struct kobject kobj;
	struct list_head list;
	void *data;
	struct {
		void *data;
		char wwpn[16];
	} port;
	struct {
		struct list_head list;
		spinlock_t lock;
	} sess;
};

struct targ_sess {
	struct kobject kobj;
	struct list_head list;
	void *data;
	struct {
		char wwpn[16];
	} remote;
	struct {
		struct list_head list;
		spinlock_t lock;
		int nr;
	} dev;
};

struct targ_port * targ_port_find_by_data (void *data);
int                targ_port_add_sess     (struct targ_port *port, struct targ_sess *sess);

int __init dm_linear_init(void);
void       dm_linear_exit(void);

#endif
