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

static int raid5_make_request(struct request_queue *q, struct bio * bi)
{
	/* TODO */
	return 0;
}

static int raid5_run(mddev_t *mddev)
{
	raid5_conf_t *conf;
	/* TODO */
	return -EIO;
}

static int raid5_stop(mddev_t *mddev)
{
	raid5_conf_t *conf = (raid5_conf_t *) mddev->private;
	/* TODO */
	return 0;
}

static sector_t
raid5_size(mddev_t *mddev, sector_t sectors, int raid_disks)
{
	return 0;
}

static sector_t
raid5_sync_request(mddev_t *mddev, sector_t sector_nr, int *skipped, int go_faster)
{
	return 0;
}

static void raid5_status(struct seq_file *seq, mddev_t *mddev)
{
}

static void raid5_error(mddev_t *mddev, mdk_rdev_t *rdev)
{
}

static int raid5_spare_active(mddev_t *mddev)
{
	/* TODO */
	return 0;
}

static int raid5_remove_disk(mddev_t *mddev, int number)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
	return 0;
}

static int raid5_add_disk(mddev_t *mddev, mdk_rdev_t *rdev)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
	return 0;
}

static int raid5_resize(mddev_t *mddev, sector_t sectors)
{
	/* TODO */
	return 0;
}

static int raid5_start_reshape(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
	return 0;
}

/* This is called from the reshape thread and should make any
 * changes needed in 'conf'
 */
static void end_reshape(raid5_conf_t *conf)
{
	/* TODO */
}

/* This is called from the raid5d thread with mddev_lock held.
 * It makes config changes to the device.
 */
static void raid5_finish_reshape(mddev_t *mddev)
{
	raid5_conf_t *conf = mddev->private;
	/* TODO */
}

static void raid5_quiesce(mddev_t *mddev, int state)
{
	/* TODO */
}

static int raid5_check_reshape(mddev_t *mddev)
{
	/* TODO */
	return 0;
}

static void *raid5_takeover(mddev_t *mddev)
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

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RAID4/5/6 (striping with parity) personality for MD");
