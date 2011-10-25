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

#include "raid_if.h"

struct raid_set;
struct raid_req;
struct dm_table;

struct target {
	struct kobject kobj;
	struct completion done;
	struct {
		struct list_head list;
		spinlock_t lock;
	} raid;
	struct {
		struct list_head list;
		spinlock_t lock;
	} device;
	struct {
		struct list_head list;
		spinlock_t lock;
	} port;
	struct {
		struct list_head list;
		spinlock_t lock;
	} group;
};

extern struct target target;

struct raid_device {
	struct kobject kobj;
	struct list_head list;
	struct dm_target *ti;
	uint64_t blocks;

	struct linear_c {
		struct dm_dev *dev;
		sector_t start;
	} lc;

	struct dm_table *table;
};

#define MAX_ARGS  16
int args(char *frame, char *argv[], int argv_max);
int tokenize(char *buf, char *words[], int maxwords);

typedef struct targ_group {
	struct kobject kobj;
	struct list_head list;

	struct list_head head[3];
} targ_group_t;

int targ_group_init(void);
int targ_group_exit(void);
int targ_port_init(void);
int targ_port_exit(void);

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
		struct targ_dev *array;
		spinlock_t lock;
		int nr;
	} dev;
	struct {
		struct list_head list;
		spinlock_t lock;
		int cnts;
	} req;
};

struct attr_list;
struct targ_dev {
	int lun;
	struct targ_sess *sess;
	struct attr_list *dl;
	struct mddev_s *t;
	sector_t start, len;
};
void targ_md_buf_init(struct mddev_s *t);

struct targ_port * targ_port_find_by_data (void *data);
int                targ_port_sess_add     (struct targ_port *port, struct targ_sess *sess);
void               targ_port_sess_remove  (struct targ_port *port, struct targ_sess *sess);
struct targ_sess * targ_port_sess_find    (struct targ_port *port, const char *wwpn);

int                targ_group_sess_init   (struct targ_sess *sess);
int                targ_group_sess_exit   (struct targ_sess *sess);

int  req_cache_init(void);
void req_cache_exit(void);

struct stripe_head;
struct r5dev;
struct stripe_buf {
	struct page *page;
	unsigned offset, len;
	struct stripe_head *sh;
	struct r5dev *dev;
};

struct targ_buf {
	struct stripe_buf *sb;
	struct sg_table sg_table;
	int nents;
};

typedef struct target_req {
	struct list_head list;
	struct targ_buf buf;
	struct targ_dev *dev;
	uint64_t sector;
	uint16_t num;
	int rw, state;
	buf_cb_t cb;
	void *priv;
	struct bio_list bio_list;
	atomic_t bios_inflight;
} targ_req_t;

int targ_req_show(targ_req_t *req, char *data, int len);

#define BIO_REQ_BUF   16
#define BIO_REQ_DONE  17
#define debug(fmt, ...) pr_debug("%-15s:%04d: " fmt, __func__, __LINE__, ##__VA_ARGS__);

#define STRIPE_SS_SHIFT         16
#define STRIPE_SHIFT            STRIPE_SS_SHIFT
#define STRIPE_SIZE             (1UL<<STRIPE_SHIFT)
#define STRIPE_SECTORS          (STRIPE_SIZE>>9)
#define STRIPE_ORDER            (STRIPE_SHIFT - PAGE_SHIFT)

#endif
