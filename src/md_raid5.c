#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/raid/pq.h>
#include <linux/async_tx.h>
#include <linux/async.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include "md.h"
#include "bitmap.h"

#include "md_raid5.h"
#include "qp_port.h"
#include "qp_lsa.h"

enum {
	BLOCK_SECTORS = 128,
};

struct raid5_private_data {
	spinlock_t device_lock;
	short max_degraded;
	short raid_disks;
};

static int
raid5_make_request(struct request_queue *q, struct bio *bi)
{
	bio_endio(bi, 0);
	return 0;
}

static void 
raid5_unplug_device(struct request_queue *q)
{
	WARN_ON(1);
}

static int 
raid5_congested(void *data, int bits)
{
	/* nothing */
	return 0;
}

static sector_t
raid5_size(mddev_t *mddev, sector_t sectors, int raid_disks)
{
	raid5_conf_t *conf = mddev->private;
	if (!sectors)
		sectors = mddev->dev_sectors;
	if (!raid_disks)
		raid_disks = conf->raid_disks;
	sectors &= ~((sector_t)mddev->chunk_sectors - 1);
	sectors &= ~((sector_t)mddev->new_chunk_sectors - 1);
	return sectors * (raid_disks - conf->max_degraded);
}

static raid5_conf_t *
setup_conf(mddev_t *mddev)
{
	raid5_conf_t *conf;
	
	if (mddev->new_level != 5) {
		printk(KERN_ERR "md/raid5:%s raid level not set to 5 (%d).\n",
		       mdname(mddev), mddev->new_level);
		return ERR_PTR(-EIO);
	}
	if (mddev->new_chunk_sectors != BLOCK_SECTORS) {
		printk(KERN_ERR "md/raid5:%s invalid chunk size %d.\n",
		       mdname(mddev), mddev->new_chunk_sectors << 9);
		return ERR_PTR(-EINVAL);
	}
	if (mddev->chunk_sectors != BLOCK_SECTORS) {
		printk(KERN_ERR "md/raid5:%s: invalid chunk size %d.\n",
		       mdname(mddev), mddev->chunk_sectors);
		return ERR_PTR(-EINVAL);
	}
	
	conf = kzalloc(sizeof(raid5_conf_t), GFP_KERNEL);
	if (conf == NULL)
		return NULL;
	spin_lock_init(&conf->device_lock);

	conf->max_degraded = 1;
	conf->raid_disks   = mddev->raid_disks;
	
	return conf;
}

static void
free_conf(raid5_conf_t *conf)
{
	kfree(conf);
}

static int
raid5_run(mddev_t *mddev)
{
	raid5_conf_t *conf;
	
	if (mddev->private == NULL)
		conf = setup_conf(mddev);
	else 
		conf = mddev->private;
	if (IS_ERR(conf))
		return PTR_ERR(conf);
	
	mddev->private = conf;
	blk_queue_max_hw_sectors(mddev->queue, mddev->chunk_sectors);
	
	mddev->queue->queue_lock = &conf->device_lock;
	mddev->queue->unplug_fn = raid5_unplug_device;
	mddev->queue->backing_dev_info.congested_data = mddev;
	mddev->queue->backing_dev_info.congested_fn = raid5_congested;
	
	md_set_array_sectors(mddev, raid5_size(mddev, 0, 0));
	
	return 0;
}

static int
raid5_stop(mddev_t *mddev)
{
	raid5_conf_t *conf = (raid5_conf_t *) mddev->private;
	mddev->queue->backing_dev_info.congested_fn = NULL;
	blk_sync_queue(mddev->queue); /* the unplug fn references 'conf'*/
	free_conf(conf);
	mddev->private = NULL;
	return 0;
}

static sector_t
raid5_sync_request(mddev_t *mddev, sector_t sector_nr, int *skipped, int go_faster)
{
	WARN_ON(1);
	return 0;
}

static void
raid5_status(struct seq_file *seq, mddev_t *mddev)
{
	WARN_ON(1);
}

static void
raid5_error(mddev_t *mddev, mdk_rdev_t *rdev)
{
	WARN_ON(1);
}

static int
raid5_spare_active(mddev_t *mddev)
{
	WARN_ON(1);
	return 0;
}

static int
raid5_remove_disk(mddev_t *mddev, int number)
{
	WARN_ON(1);
	return 0;
}

static int
raid5_add_disk(mddev_t *mddev, mdk_rdev_t *rdev)
{
	WARN_ON(1);
	return 0;
}

static int
raid5_resize(mddev_t *mddev, sector_t sectors)
{
	WARN_ON(1);
	return 0;
}

static int
raid5_start_reshape(mddev_t *mddev)
{
	WARN_ON(1);
	return 0;
}

/* This is called from the raid5d thread with mddev_lock held.
 * It makes config changes to the device.
 */
static void 
raid5_finish_reshape(mddev_t *mddev)
{
	WARN_ON(1);
}

static void 
raid5_quiesce(mddev_t *mddev, int state)
{
	WARN_ON(1);
}

static int
raid5_check_reshape(mddev_t *mddev)
{
	WARN_ON(1);
	return 0;
}

static void *
raid5_takeover(mddev_t *mddev)
{
	WARN_ON(1);
	return ERR_PTR(-EINVAL);
}

static struct mdk_personality raid5_personality =
{
	.name		= "raid5",
	.level		= 5,
	.owner		= THIS_MODULE,
	.make_request	= raid5_make_request,
	.run		= raid5_run,
	.stop		= raid5_stop,
	.status		= raid5_status,
	.error_handler	= raid5_error,
	.hot_add_disk	= raid5_add_disk,
	.hot_remove_disk= raid5_remove_disk,
	.spare_active	= raid5_spare_active,
	.sync_request	= raid5_sync_request,
	.resize		= raid5_resize,
	.size		= raid5_size,
	.check_reshape	= raid5_check_reshape,
	.start_reshape  = raid5_start_reshape,
	.finish_reshape = raid5_finish_reshape,
	.quiesce	= raid5_quiesce,
	.takeover	= raid5_takeover,
};

int raid5_init(void)
{
	register_md_personality(&raid5_personality);
	return 0;
}

void raid5_exit(void)
{
	unregister_md_personality(&raid5_personality);
}
