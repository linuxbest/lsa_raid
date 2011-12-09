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

#include "qp_port.h"
#include "md_raid5.h"
#include "qp_lsa.h"

enum {
	BLOCK_SECTORS = 128,
};

struct raid5_private_data {
	spinlock_t device_lock;
	short max_degraded;
	short raid_disks;
	short chunk_sectors;
};

/* RAID5 BIO context helper -------------------------------------------------*/
struct raid5_bio_context {
	raid5_conf_t *conf;
	struct bio *bi;
	unsigned int offset;
	unsigned int idx;
	unsigned int total;
};

static void
raid5_bio_buf_init(struct raid5_bio_context *ctx, struct bio *bi, raid5_conf_t *conf)
{
	bi->bi_phys_segments = 1;
	ctx->bi     = bi;
	ctx->conf   = conf;
	ctx->offset = 0;
	ctx->idx    = 0;
	ctx->total  = bi->bi_size;
}

static void
raid5_bio_buf_end(struct raid5_bio_context *ctx)
{
	struct bio *bi = ctx->bi;
	raid5_conf_t *conf = ctx->conf;
	unsigned long flags;
	
	spin_lock_irqsave(&conf->device_lock, flags);
	bi->bi_phys_segments --;
	if (bi->bi_phys_segments == 0) {
		QS_BEGIN(QS_BIO_DONE, QS_apObj_);
		QS_U32_HEX(8, (uint32_t)bi);
		QS_U32_HEX(8, bi->bi_sector);
		QS_U32_HEX(4, bi->bi_size >> SECTOR_SHIFT);
		QS_U32_HEX(1, bio_data_dir(bi));
		QS_END();
		bio_endio(bi, 0);
	}
	spin_unlock_irqrestore(&conf->device_lock, flags);
}

static void
raid5_bio_buf_add(struct raid5_bio_context *ctx, int len, int vec_len)
{
	ctx->offset += len;
	ctx->total  -= len;
	if (ctx->offset >= vec_len) {
		ctx->offset = 0;
		ctx->idx ++;
	}
}

static int
raid5_bio_buf_next(struct raid5_bio_context *ctx, struct raid5_bio_buf *buf)
{
	struct bio_vec *vec = bio_iovec_idx(ctx->bi, ctx->idx);
	int len = min_t(int, vec->bv_len - ctx->offset, STRIPE_SIZE);
	
	if (ctx->total <= 0)
		return -1;
	if (ctx->idx > ctx->bi->bi_vcnt)
		return -2;
	
	buf->bi     = ctx->bi;
	buf->page   = vec->bv_page;
	buf->offset = vec->bv_offset + ctx->offset;
	buf->length = len;

	raid5_bio_buf_add(ctx, len, vec->bv_len);
	ctx->bi->bi_phys_segments ++;
	
	/* done */
	if (len == STRIPE_SIZE || ctx->total == 0)
		return 0;
	
	vec = bio_iovec_idx(ctx->bi, ctx->idx);
	len = min_t(int, vec->bv_len - ctx->offset, len);
	buf->page_next   = vec->bv_page;
	buf->offset_next = vec->bv_offset + ctx->offset;
	buf->length_next = len;
	raid5_bio_buf_add(ctx, len, vec->bv_len);
	
	return 0;
}
/*..........................................................................*/
static int
raid5_make_request(struct request_queue *q, struct bio *bi)
{
	mddev_t *mddev = q->queuedata;
	raid5_conf_t *conf = mddev->private;
	sector_t blknr = bi->bi_sector;
	sector_t offset = bi->bi_sector;
	sector_t remainning = bi->bi_size >> SECTOR_SHIFT;
	int res = 0;
	struct raid5_bio_context ctx;
	
	QS_BEGIN(QS_BIO_REQ, QS_apObj_);
	QS_U32_HEX(8, (uint32_t)bi);
	QS_U32_HEX(8, blknr);
	QS_U32_HEX(4, remainning);
	QS_U32_HEX(1, bio_data_dir(bi));
	QS_END();
	
	if (bio_rw_flagged(bi, BIO_RW_BARRIER)) {
		bio_endio(bi, -EOPNOTSUPP);
		return res;
	}

	raid5_bio_buf_init(&ctx, bi, conf);
	do {
		CacheRWEvt *pe = Q_NEW(CacheRWEvt, CACHE_RW_REQUEST_SIG);
		sector_t split_io = STRIPE_SECTORS;
		sector_t boundary = ((offset + split_io) & ~(split_io - 1)) - offset;
		sector_t len      = min_t(sector_t, remainning, boundary);
		
		sector_t track    = blknr & ~((sector_t)STRIPE_SECTORS-1);
		sector_div(track, conf->chunk_sectors);
	
		pe->sector = blknr;
		pe->track  = (uint32_t)track;
		pe->offset = (uint16_t)(blknr & (STRIPE_SECTORS-1));
		pe->len    = (uint16_t)len;
		pe->flags  = bio_data_dir(bi) | BIO_BUF;
		pe->conf   = conf;
		pe->ao     = AO_raid5;
		res = raid5_bio_buf_next(&ctx, &pe->buf.bio);
		BUG_ON(res != 0);
		QACTIVE_POST(AO_cache, (QEvent *)pe, AO_raid5);
		remainning -= len;
		blknr      += len;
	} while (remainning);
	
	BUG_ON(ctx.total != 0);
	raid5_bio_buf_end(&ctx);

	return res;
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
	conf->chunk_sectors= mddev->chunk_sectors;

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

int  raid5_init(void)
{
	register_md_personality(&raid5_personality);
	return 0;
}

void raid5_exit(void)
{
	unregister_md_personality(&raid5_personality);
}

typedef struct Raid5Tag {
	QActive super;
	
} Raid5;

static QState Raid5_initial (Raid5 *me, QEvent const *e);
static QState Raid5_final   (Raid5 *me, QEvent const *e);
static QState Raid5_idle    (Raid5 *me, QEvent const *e);

static Raid5 l_raid5;
QActive * const AO_raid5 = (QActive *)&l_raid5;

/*..........................................................................*/
void Raid5_ctor(void)
{
	Raid5 *me = &l_raid5;
	QActive_ctor(&me->super, (QStateHandler)(Raid5_initial));
}

/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Raid5_initial(Raid5 *me, QEvent const *e)
{
	QActive_subscribe((QActive *)me, TERMINATE_SIG);
	
	QS_OBJ_DICTIONARY(&l_raid5);
	
	QS_FUN_DICTIONARY(&Raid5_initial);
	QS_FUN_DICTIONARY(&Raid5_final);
	QS_FUN_DICTIONARY(&Raid5_initial);

	QS_SIG_DICTIONARY(CACHE_RW_REPLY_SIG, &l_raid5);

	return Q_TRAN(&Raid5_idle);
}
/*..........................................................................*/
static QState Raid5_final(Raid5 *me, QEvent const *e)
{
	switch (e->sig) {
	case Q_ENTRY_SIG:
		QActive_stop(&me->super);
		return Q_HANDLED();
	}
	return Q_SUPER(&QHsm_top);	
}
/*..........................................................................*/
static QState Raid5_reply(Raid5 *me, QEvent const *e);
/*..........................................................................*/
static QState Raid5_idle(Raid5 *me, QEvent const *e)
{
	switch (e->sig) {
	case TERMINATE_SIG:
		return Q_TRAN(&Raid5_final);
	case CACHE_RW_REPLY_SIG:
		return Raid5_reply(me, e);
	}

	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Raid5_reply(Raid5 *me, QEvent const *e)
{
	CacheRWRly *re = (CacheRWRly *)e;
	struct raid5_bio_context ctx;

	/* TODO handle the errno */
	WARN_ON(re->errno);
	
	ctx.bi   = re->buf.bio.bi;
	ctx.conf = re->conf;
	raid5_bio_buf_end(&ctx);
	
	return Q_SUPER(&QHsm_top);
}
