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

struct raid5_private_data {
	spinlock_t device_lock;
};

static int
raid5_make_request(struct request_queue *q, struct bio * bi)
{
	/* TODO */
	return 0;
}

static void 
raid5_unplug_device(struct request_queue *q)
{
	/* TODO */
}

static int 
raid5_congested(void *data, int bits)
{
	/* TODO */
	return 0;
}

static sector_t
raid5_size(mddev_t *mddev, sector_t sectors, int raid_disks)
{
	return 0;
}

static raid5_conf_t *
setup_conf(mddev_t *mddev)
{
	raid5_conf_t *conf;
	
	if (mddev->new_level != 5) {
		printk(KERN_ERR "md/raid5:%s raid level not set to 5 (%d)\n",
		       mdname(mddev), mddev->new_level);
		return ERR_PTR(-EIO);
	}
	if (mddev->new_chunk_sectors != 128) {
		printk(KERN_ERR "md/raid5:%s invalid chunk size %d\n",
		       mdname(mddev), mddev->new_chunk_sectors << 9);
		return ERR_PTR(-EINVAL);
	}
	
	conf = kzalloc(sizeof(raid5_conf_t), GFP_KERNEL);
	if (conf == NULL)
		return NULL;
	spin_lock_init(&conf->device_lock);

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
	int ret;
	
	if (mddev->chunk_sectors == 128) {
		printk(KERN_ERR "md/raid5:%s: chunk size must be 128.\n",
		       mdname(mddev));
		return -EINVAL;
	}
	blk_queue_max_hw_sectors(mddev->queue, mddev->chunk_sectors);
	
	if (mddev->private == NULL) {
		conf = setup_conf(mddev);
	} else 
		conf = mddev->private;
	if (IS_ERR(conf))
		return PTR_ERR(conf);
	
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
	return 0;
}

static void
raid5_status(struct seq_file *seq, mddev_t *mddev)
{
}

static void
raid5_error(mddev_t *mddev, mdk_rdev_t *rdev)
{
}

static int
raid5_spare_active(mddev_t *mddev)
{
	/* TODO */
	return 0;
}

static int
raid5_remove_disk(mddev_t *mddev, int number)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
	return 0;
}

static int
raid5_add_disk(mddev_t *mddev, mdk_rdev_t *rdev)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
	return 0;
}

static int
raid5_resize(mddev_t *mddev, sector_t sectors)
{
	/* TODO */
	return 0;
}

static int
raid5_start_reshape(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
	return 0;
}

/* This is called from the raid5d thread with mddev_lock held.
 * It makes config changes to the device.
 */
static void 
raid5_finish_reshape(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
}

static void 
raid5_quiesce(mddev_t *mddev, int state)
{
	/* TODO */
}

static int
raid5_check_reshape(mddev_t *mddev)
{
	/* TODO */
	return 0;
}

static void *
raid5_takeover(mddev_t *mddev)
{
	/* TODO */
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
