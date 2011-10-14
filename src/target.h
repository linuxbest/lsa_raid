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

struct target {
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

extern struct target target;

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
		char wwpn[64];
	} port;
	struct {
		struct list_head list;
		spinlock_t lock;

		struct list_head del_sess_list;
		struct timer_list sess_del_timer;
	} sess;
};

struct targ_sess {
	struct kobject kobj;
	struct list_head list;

	/* for delete */
	struct list_head del_sess_list;
	int deleted;
	unsigned long jiffies, expires;

	/* private data */
	struct targ_port *port;
	void *data;
	struct {
		char wwpn[64];
		void *data;
	} remote;
	struct {
		struct list_head list;
		spinlock_t lock;
		int nr;
	} dev;
};

struct targ_port * targ_port_find_by_data (void *data);
int                targ_port_sess_add     (struct targ_port *port, struct targ_sess *sess);
void               targ_port_sess_remove  (struct targ_port *port, struct targ_sess *sess);
struct targ_sess * targ_port_sess_find    (struct targ_port *port, const char *wwpn);

int __init dm_linear_init(void);
void       dm_linear_exit(void);

#endif
