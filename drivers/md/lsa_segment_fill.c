#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>

#include "md.h"
#include "bitmap.h"
#include "target.h"
#include "lsa.h"
#include "raid5.h"

#include "lsa_segment.h"
#include "lsa_segment_status.h"
#include "lsa_segment_fill.h"
#include "lsa_closed_segment.h"
#include "lsa_dirtory.h"

#define LSA_DIR_INF "segment_dirtory"

typedef struct lsa_track {
	struct list_head entry;
	atomic_t count;
	struct lsa_dirtory *dir;
	struct segment_buffer *segbuf;
	lsa_track_buffer_t *buf;
	struct lsa_segment_fill *segfill;
	struct lsa_track_cookie cookie[0];
} lsa_track_t;

static lsa_track_t *
__lsa_track_get(struct lsa_segment_fill *segfill)
{
	lsa_track_t *lt;

	if (list_empty(&segfill->free))
		return NULL;

	segfill->free_cnt --;
	lt = list_entry(segfill->free.next, lsa_track_t, entry);
	list_del_init(&lt->entry);
	atomic_set(&lt->count, 1);
	debug("track %p, ref %d, free %d\n", 
			lt, atomic_read(&lt->count), segfill->free_cnt);
	lt->buf = segfill->segbuf->track;

	return lt;
}

static void 
__lsa_track_put(lsa_track_t *track)
{
	struct lsa_segment_fill *segfill = track->segfill;
	debug("track %p, ref %d, free %d\n",
			track, atomic_read(&track->count), segfill->free_cnt);
	BUG_ON(atomic_read(&track->count) == 0);
	if (atomic_dec_and_test(&track->count) == 0)
		return;

	segfill->free_cnt ++;
	list_add_tail(&track->entry, &segfill->free);
}

static void 
__lsa_track_ref(lsa_track_t *track)
{
	debug("track %p, ref %d\n", track, atomic_read(&track->count));
	atomic_inc(&track->count);
}

static void
__lsa_track_update_sum(lsa_track_t *track, lsa_track_entry_t *lt)
{
	int i;
	uint32_t *d = (uint32_t *)lt;
	/* the entry may update reorder, so we using sum is better. */
	for (i = 0; i < sizeof(lsa_track_entry_t)/4; i ++, d++)
		track->buf->sum += *d;
}

static void
__lsa_segment_write_init(struct segment_buffer *segbuf)
{
	debug("segid %x, pins %d\n", segbuf->seg_id,
			atomic_read(&segbuf->pins));
	atomic_set(&segbuf->pins, 1);
}

static void
__lsa_segment_write_ref(struct segment_buffer *segbuf, int ref)
{
	debug("segid %x, pins %d, %d\n", segbuf->seg_id,
			atomic_read(&segbuf->pins), ref);
	atomic_add(ref, &segbuf->pins);
}

int 
__lsa_segment_write_put(struct segment_buffer *segbuf)
{
	debug("segid %x, pins %d\n", segbuf->seg_id,
			atomic_read(&segbuf->pins));
	BUG_ON(atomic_read(&segbuf->pins) == 0);
	if (atomic_dec_and_test(&segbuf->pins) == 0)
		return 0;

	lsa_segment_event(segbuf, SS_SEG_CLOSING);
	set_segbuf_uptodate(segbuf);
	lsa_segment_dirty(segbuf->seg, segbuf);
	return 0;
}

static uint8_t
__lsa_entry_flag(lsa_entry_t *o, lsa_entry_t *n)
{
	uint8_t flags = DATA_VALID;
	if ((o->status & DATA_VALID) &&
	    ((o->status & DATA_PARTIAL) ||
	     (n->length < o->length) ||
	     (n->offset > o->offset) ||
	     (n->offset + n->length < o->offset + o->length)))
		flags |= DATA_PARTIAL;
	return flags;
}

static void
__lsa_track_cookie_update(struct lsa_track_cookie *cookie)
{
	struct entry_buffer *eb = cookie->eb;
	lsa_track_entry_t *lt = cookie->lt;
	lsa_track_t *track = cookie->track;
	lsa_entry_t *ln = &lt->new;
	lsa_entry_t *lo = &eb->e;

	lsa_entry_dump("old", lo);
	lsa_entry_dump("new", ln);
	if ((lo->status & DATA_VALID) && lo->log_track_id != ln->log_track_id) {
		printk("LSA:DIR WARN-0001, %08x,%08x, %x\n",
				lo->log_track_id, ln->log_track_id,
				lo->status);
	}

	lt->new.status = __lsa_entry_flag(lo, ln);
	memcpy((void *)&lt->old, lo, sizeof(lsa_entry_t));
	memcpy((void *)&eb->e,   ln, sizeof(lsa_entry_t));

	set_entry_uptodate(eb);
	lsa_entry_dirty(track->dir, eb);
	lsa_entry_put(track->dir, eb);
	__lsa_track_update_sum(track, lt);

	if (track->segbuf)
		__lsa_segment_write_put(track->segbuf);
	else
		__lsa_track_put(track);
}

static void
__lsa_track_add(struct lsa_segment_fill *segfill, struct lsa_bio *bi,
		struct lsa_track_cookie **ck, uint32_t log_track_id)
{
	lsa_track_t *track = segfill->track;
	lsa_track_entry_t *lt = &track->buf->entry[track->buf->total];
	struct lsa_track_cookie *cookie = &track->cookie[track->buf->total];

	track->buf->total ++;
	lt->new.log_track_id = log_track_id;
	lt->new.seg_id       = segfill->segbuf->seg_id;
	lt->new.seg_column   = segfill->data_column;
	lt->new.offset       = bi->bi_sector & segfill->mask_offset;
	lt->new.length       = bi->bi_size>>9;

	lt->new.age          = 0;
	lt->new.status       = 0;
	lt->new.activity     = 0;

	/* setup the cookie */
	*ck = cookie;
	cookie->track = track;
	cookie->lt    = lt;
	cookie->eb    = NULL;
	__lsa_track_ref(track);
}

static void
__lsa_track_open(struct lsa_segment_fill *segfill)
{
	raid5_conf_t *conf = container_of(segfill, raid5_conf_t, segment_fill);
	lsa_track_t *track;

	BUG_ON(segfill->track);
	segfill->track = track = __lsa_track_get(segfill);

	/* make sure the track is clean */
	BUG_ON(segfill->track == NULL);
	
	/* TODO __lsa_track_get may return NULL */
	track->buf->magic       = TRACK_MAGIC;
	track->buf->sum         = 0;
	track->buf->total       = 0;
	
	track->segbuf = NULL;
}

/*
 * adding the meta data into segment as data 
 */
static void
__lsa_track_close(struct lsa_segment_fill *segfill)
{
	int data_column = segfill->data_column;
	struct lsa_track *track = segfill->track;
	lsa_track_buffer_t *track_buffer;
	struct segment_buffer *segbuf = segfill->segbuf;
	int res;

	BUG_ON(track == NULL);
	track_buffer = track->buf;

	track->buf->seq_id  = segbuf->seq;
	track->buf->sum += track->buf->total;
	track->buf->sum += track->buf->seq_id;

	segfill->data_column ++;
	segfill->track       = NULL;

	/* moving the ref into segbuf, to make sure the track is sync 
	 * before write to disk.
	 */
	BUG_ON(track->segbuf != NULL);

	res = atomic_read(&track->count);
	BUG_ON(res == 0);
	res --;
	__lsa_segment_write_ref(segbuf, res);
	atomic_set(&track->count, 1);

	track->segbuf = segbuf;
	debug("segid %x, col %d, res %d, total %x, sum %08x\n",
			segfill->meta_id, segfill->meta_column, res,
			track->buf->total, track->buf->sum);
}

int
__lsa_segment_fill_write_done(struct lsa_segment *seg,
		struct segment_buffer *segbuf)
{
	raid5_conf_t *conf = container_of(seg, raid5_conf_t, data_segment);
	struct lsa_segment_fill *segfill = &conf->segment_fill;
	unsigned long flags;

	debug("segid %x, meta %d, seg %p\n",
			segbuf->seg_id, segbuf->meta, segbuf->seg);
	lsa_segment_event(segbuf, SS_SEG_CLOSED);
	if (segbuf_checkpoint(segbuf)) {
#if 0
		lsa_lcs_commit(&conf->lsa_closed_status, 
				segbuf);
#endif
	}
	lsa_segment_release(segbuf, 0);

	return 0;
}

static void
__lsa_segment_fill_close(struct lsa_segment_fill *segfill)
{
	raid5_conf_t *conf =
		container_of(segfill, raid5_conf_t, segment_fill);
	int res;

	BUG_ON(segfill->segbuf == NULL);
	__lsa_track_close(segfill);
#if 0
	res = lsa_lcs_insert(&conf->lsa_closed_status,
			segfill->segbuf);
	if (res == LCS_NEED_CHECKPOINT) {
		set_segbuf_checkpoint(segfill->segbuf);
		lsa_dirtory_checkpoint(&conf->lsa_dirtory);
		lsa_ss_checkpoint(&conf->lsa_segment_status);
	}
#endif
	__lsa_segment_write_put(segfill->segbuf);
	segfill->segbuf = NULL;
}

static int
__lsa_segment_fill_open(struct lsa_segment_fill *segfill)
{
	raid5_conf_t *conf =
		container_of(segfill, raid5_conf_t, segment_fill);
	uint32_t seg;
	struct segment_buffer *segbuf;

	BUG_ON(segfill->segbuf);

	/* TODO, adding real segment id allocate. */
	seg = lsa_seg_alloc(&conf->lsa_dirtory);

	segbuf = lsa_segment_find_or_create(segfill->seg, /* handle */
			seg,  /* ID */
			NULL);/* no entry for callback */
	debug("segid %x, %p\n", seg, segbuf);
	/* TODO making this never happen */
	BUG_ON(segbuf == NULL);
	__lsa_segment_write_init(segbuf);

	segbuf->seq          = segfill->seq;
	segfill->segbuf      = segbuf;
	segfill->data_column = 0;
	segfill->seq ++;
	lsa_segment_event(segbuf, SS_SEG_OPEN);

	__lsa_track_open(segfill);

	return 0;
}

static void
__lsa_segment_fill_add(struct lsa_segment_fill *segfill, struct lsa_bio *bi)
{
	raid5_conf_t *conf =
		container_of(segfill, raid5_conf_t, segment_fill);
	int offset = bi->bi_sector & segfill->mask_offset;
	int data = segfill->data_column &  LSA_BLOCKDEPTH_MASK;
	int depth= segfill->data_column >> LSA_BLOCKDEPTH_SHIFT;
	struct segment_buffer *segbuf = segfill->segbuf;
	struct page *page = segbuf->column[depth].data.page[data];
	__lsa_segment_write_ref(segbuf, 1);
	bi->bi_add_page(conf->mddev, bi, segbuf, page, offset, (STRIPE_SIZE-offset)>>9);
	segfill->data_column ++;
	BUG_ON(segfill->data_column > segfill->max_column);
}

static void 
__lsa_segment_fill_timeout_update(struct lsa_segment_fill *segfill);
/* first checking the data can put into this segment.
 * then adding the track information into.
 * then adding the data information into.
 */
static int
__lsa_segment_fill_append(struct lsa_segment_fill *segfill, struct lsa_bio *bi,
		struct lsa_track_cookie **cookie, uint32_t log_track_id)
{
	if (segfill->segbuf == NULL)
		__lsa_segment_fill_open(segfill);
	debug("bio %llu, column %d/%d\n",
			(unsigned long long)bi->bi_sector,
			segfill->data_column, segfill->max_column);
	if (segfill->data_column == segfill->max_column) {
		__lsa_segment_fill_close(segfill);
		__lsa_segment_fill_open(segfill);
	}
	__lsa_track_add(segfill, bi, cookie, log_track_id);
	__lsa_segment_fill_add(segfill, bi);
	__lsa_segment_fill_timeout_update(segfill);

	return 0;
}

int
lsa_segment_fill_write(struct lsa_segment_fill *segfill, struct lsa_bio *bi)
{
	unsigned long flags;
	int res;
	struct lsa_track_cookie *cookie;
	raid5_conf_t *conf =
		container_of(segfill, raid5_conf_t, segment_fill);

	spin_lock_irqsave(&segfill->lock, flags);
	res = __lsa_segment_fill_append(segfill, bi, &cookie, bi->lt);
	spin_unlock_irqrestore(&segfill->lock, flags);

	cookie->done = __lsa_track_cookie_update;
	res = lsa_entry_find_or_create(&conf->lsa_dirtory, bi->lt, cookie);
	debug("ltid %x, res %d\n", bi->lt, res);
	if (res != -EINPROGRESS) {
		__lsa_track_cookie_update(cookie);
	}
	lsa_bio_endio(bi, 0);

	return res;
}

static void
__lsa_segment_fill_timeout_update(struct lsa_segment_fill *segfill)
{
	unsigned long deadline = jiffies + 10*HZ;
	unsigned long expiry = round_jiffies_up(deadline);

	if (!timer_pending(&segfill->timer) ||
			time_before(deadline, segfill->timer.expires))
		mod_timer(&segfill->timer, expiry);
}

static void
lsa_segment_fill_timeout(unsigned long data)
{
	struct lsa_segment_fill *segfill = (struct lsa_segment_fill *)data;
	unsigned long flags;

	del_timer(&segfill->timer);

	spin_lock_irqsave(&segfill->lock, flags);
	if (segfill->track || segfill->segbuf) {
		debug("segbuf %p\n", segfill->segbuf);
		if (segfill->segbuf)
			__lsa_segment_fill_close(segfill);
	}
	spin_unlock_irqrestore(&segfill->lock, flags);
}

static int
proc_segfill_read_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	struct lcs_segment_buffer *lcs = container_of(se,
			struct lcs_segment_buffer , segbuf_entry);
	complete(&lcs->done);
	return 0;
}

static lsa_track_buffer_t *
lsa_segfill_segbuf2track(struct segment_buffer *segbuf, int col, 
		int *valid, uint32_t *sum_o)
{
	lsa_track_buffer_t *track_buffer;
	struct page *page;
	uint32_t sum = 0, *dbuf;
	int i;
#if 0
	if (segbuf->column[col].meta_page)
		page = segbuf->column[col].meta_page;
	else
		page = segbuf->column[col].page;
	track_buffer = page_address(page);
#endif
	sum += track_buffer->total;
	sum += track_buffer->seq_id;
	dbuf = (uint32_t *)track_buffer->entry;
	for (i = 0; i < (track_buffer->total*sizeof(lsa_track_entry_t))/4; i ++, dbuf ++)
		sum += *dbuf;

	*valid = track_buffer->magic == TRACK_MAGIC && 
		track_buffer->sum == sum;
	*sum_o = sum;

	return track_buffer;
}

int
lsa_segfill_find_meta(struct lsa_segment_fill *segfill, 
		struct lsa_segfill_meta *meta)
{
	struct segment_buffer *segbuf;
	struct lcs_segment_buffer lcs_se;
	raid5_conf_t *conf = container_of(segfill, raid5_conf_t, segment_fill);
	lsa_track_buffer_t *track_buffer;
	uint32_t sum;
	int valid, i;

	init_completion(&lcs_se.done);
	segment_buffer_entry_init(&lcs_se.segbuf_entry);
	lcs_se.segbuf_entry.rw = READ;
	lcs_se.segbuf_entry.done = proc_segfill_read_done;

	segbuf = lsa_segment_find_or_create(&conf->data_segment,
			meta->meta, &lcs_se.segbuf_entry);
	wait_for_completion(&lcs_se.done);

	track_buffer = lsa_segfill_segbuf2track(segbuf, meta->col, 
			&valid, &sum);

	debug("segid %08x/%02x, %08x, total %03x, %sVALID\n",
			meta->meta, meta->col, track_buffer->seq_id,
			track_buffer->total, valid ? "" : "IN");
	if (valid == 0) {
		lsa_segment_release(segbuf, 0);
		/* TODO 
		 * howto handle data corruption.
		 */
		return -1;
	}

	valid = 0;
	i = track_buffer->total-1;
	do {
		lsa_track_entry_t *n = &track_buffer->entry[i];
		valid ++;
		if (meta->callback(meta, n) != 0)
			break;
	} while (i--);

	lsa_segment_release(segbuf, 0);

	return valid;
}

static void *
proc_segfill_read(struct seq_file *p, struct lsa_segment_fill *segfill, loff_t seq)
{
	struct segment_buffer *segbuf;
	struct lcs_segment_buffer lcs_se;
	raid5_conf_t *conf = container_of(segfill, raid5_conf_t, segment_fill);
	lsa_track_buffer_t *track_buffer;
	uint32_t sum;
	int valid, col = segfill->seq_show.cur_col;

	debug("meta %08x/%02x, valid %d\n", segfill->seq_show.cur_meta,
			segfill->seq_show.cur_col, segfill->seq_show.valid);

	if (segfill->seq_show.valid == 0 || col > segfill->max_column)
		return NULL;

	init_completion(&lcs_se.done);
	segment_buffer_entry_init(&lcs_se.segbuf_entry);
	lcs_se.segbuf_entry.rw = READ;
	lcs_se.segbuf_entry.done = proc_segfill_read_done;

	segbuf = lsa_segment_find_or_create(&conf->data_segment,
			segfill->seq_show.cur_meta,
			&lcs_se.segbuf_entry);
	wait_for_completion(&lcs_se.done);

	track_buffer = lsa_segfill_segbuf2track(segbuf, col, &valid, &sum);

	seq_printf(p, "magic %08x, segid %08x/%02x, %08x, sum %08x/%08x, total %03x\n",
			track_buffer->magic, segfill->seq_show.cur_meta, col,
			track_buffer->seq_id, track_buffer->sum, sum,
			track_buffer->total);
	seq_printf(p, " ID LBA      SEGID             COL   OFFSET  LENGTH\n");
	/*              00 000000e0 00008202/00008204 00/01 000/078 08/08" */
	segfill->seq_show.valid    = valid;
	segfill->seq_show.track_buffer = (char *)track_buffer;
		
	lsa_segment_release(segbuf, 0);

	return segfill;
}

static void *
proc_segfill_start(struct seq_file *p, loff_t *pos)
{
	struct lsa_segment_fill *segfill = p->private;

	debug("%d\n", (int)*pos);
	if (segfill == NULL)
		return NULL;
	if (*pos == 0) {
		segfill->seq_show.cur_meta = segfill->meta_id;
		segfill->seq_show.cur_col  = segfill->meta_column;
		segfill->seq_show.valid    = 1;
	}
	return proc_segfill_read(p, segfill, *pos);
}

static void *
proc_segfill_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct lsa_segment_fill *segfill = p->private;
	(*pos) ++; 
	return proc_segfill_read(p, segfill, *pos);
}

static void
proc_segfill_stop(struct seq_file *p, void *v)
{	
}

static int
proc_segfill_show(struct seq_file *p, void *v)
{
	struct lsa_segment_fill *segfill = p->private;
	lsa_track_buffer_t *track_buffer =
		(lsa_track_buffer_t *)segfill->seq_show.track_buffer;
	int i;

	debug("\n");
	
	for (i = 0; i < track_buffer->total; i ++) {
		lsa_entry_t *n = &track_buffer->entry[i].new;
		lsa_entry_t *o = &track_buffer->entry[i].old;
		seq_printf(p, " %02x %08x %08x/%08x %02x/%02x %03x/%03x %02x/%02x\n", 
				i, n->log_track_id, /*o->log_track_id,*/
				n->seg_id, o->seg_id,
				n->seg_column, o->seg_column,
				n->offset, o->offset,
				n->length, o->length);
	}

	return 0;
}

static ssize_t
proc_segfill_write(struct file *file, const char __user *buf,
		size_t size, loff_t *_pos)
{
	return size;
}

static const struct seq_operations proc_segfill_ops = {
	.start = proc_segfill_start,
	.next  = proc_segfill_next,
	.stop  = proc_segfill_stop,
	.show  = proc_segfill_show,
};

static int 
proc_segfill_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &proc_segfill_ops);
	if (!res) {
		((struct seq_file *)file->private_data)->private = PDE(inode)->data;
	}
	return 0;
}

static const struct file_operations proc_segfill_fops = {
	.open  = proc_segfill_open,
	.read  = seq_read,
	.write = proc_segfill_write,
	.llseek = seq_lseek,
	.release = seq_release,
	.owner = THIS_MODULE,
};

void
lsa_segment_fill_update(struct lsa_segment_fill *segfill,
		uint32_t meta_id, int col, uint32_t seq)
{
	debug("id %x, col %x, seq %x\n", meta_id, col, seq);
	segfill->meta_id = meta_id;
	segfill->meta_column = col;
	segfill->seq = seq;
}

int
lsa_segment_fill_init(struct lsa_segment_fill *segfill)
{
	raid5_conf_t *conf =
		container_of(segfill, raid5_conf_t, segment_fill);
	int data_disks = conf->raid_disks - conf->max_degraded, i;
	int max_tracks, lt_len;

	INIT_LIST_HEAD(&segfill->head);
	INIT_LIST_HEAD(&segfill->free);
	spin_lock_init(&segfill->lock);

	segfill->seg         = &conf->data_segment;
	segfill->meta_max    = 256;
	segfill->mask_offset = (STRIPE_SIZE>>9)-1;
	segfill->max_column  = data_disks * LSA_BLOCKDEPTH;

	/* TODO loading from the super block */
	segfill->meta_id     = 0;
	segfill->meta_column = COLUMN_NULL;
	segfill->seq         = 0;

	segfill->free_cnt    = 0;

	max_tracks = segfill->meta_max;
	lt_len = sizeof(lsa_track_t) + max_tracks*sizeof(lsa_track_cookie_t);

	for (i = 0; i < max_tracks; i ++) {
		lsa_track_t *track = kzalloc(lt_len, GFP_KERNEL);
		if (track == NULL)
			return -1;

		track->dir = &conf->lsa_dirtory;
		track->segfill = segfill;
		list_add_tail(&track->entry, &segfill->free);
		segfill->free_cnt ++;
	}

	init_timer(&segfill->timer);
	segfill->timer.data = (unsigned long)segfill;
	segfill->timer.function = lsa_segment_fill_timeout;

	segfill->proc = proc_create(LSA_DIR_INF, 0, conf->proc,
			&proc_segfill_fops);
	if (segfill->proc == NULL)
		return -1;
	segfill->proc->data = (void *)segfill;

	return 0;
}

static void
__lsa_track_free(struct lsa_segment_fill *segfill, lsa_track_t *lt)
{
	list_del_init(&lt->entry);
	kfree(lt);
	segfill->free_cnt --;
}

int
lsa_segment_fill_exit(struct lsa_segment_fill *segfill)
{
	raid5_conf_t *conf =
		container_of(segfill, raid5_conf_t, segment_fill);
	del_timer(&segfill->timer);
	while (!list_empty(&segfill->head)) {
		/* TODO */
		lsa_track_t *lt = container_of(segfill->head.next,
				lsa_track_t, entry);
		__lsa_track_free(segfill, lt);
	}
	while (!list_empty(&segfill->free)) {
		/* TODO */
		lsa_track_t *lt = container_of(segfill->free.next,
				lsa_track_t, entry);
		__lsa_track_free(segfill, lt);
	}
	remove_proc_entry(LSA_DIR_INF, conf->proc);
	debug("free_cnt %d\n", segfill->free_cnt);
	return 0;
}
