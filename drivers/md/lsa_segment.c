#include <linux/blkdev.h>
#include <linux/kthread.h>

#include "md.h"
#include "bitmap.h"
#include "target.h"
#include "lsa.h"
#include "raid5.h"

#include "lsa_segment.h"

/*
 * LSA segment operations
 *
 */
static inline sector_t
SEG2PSECTOR(struct lsa_segment *seg, uint32_t seg_id)
{
	sector_t lba = seg_id;
	return lba << seg->shift_sector;
}

static void 
__segbuf_tree_delete(struct lsa_segment *seg, struct segment_buffer *segbuf)
{
	rb_erase(&segbuf->node, &seg->tree);
}

static struct segment_buffer *
__segbuf_tree_search(struct lsa_segment *seg, uint32_t seg_id)
{
	struct rb_node *node = seg->tree.rb_node;

	while (node) {
		struct segment_buffer *data = container_of(node,
				struct segment_buffer, node);
		int result = data->seg_id - seg_id;

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static int
__segbuf_tree_insert(struct lsa_segment *seg, struct segment_buffer *data)
{
	struct rb_node **new = &(seg->tree.rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct segment_buffer *this = container_of(*new,
				struct segment_buffer, node);
		int result = this->seg_id - data->seg_id;

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return 0;
	}

	/* Add new node and rebalance tree */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, &seg->tree);

	return 1;
}

static void 
__lsa_column_meta_bio_init(struct column_meta *meta,
		struct segment_buffer *segbuf)
{
	bio_init(&meta->req);
	meta->req.bi_flags    = 1 << BIO_UPTODATE;
	meta->req.bi_idx      = 0;
	meta->req.bi_next     = NULL;
	meta->req.bi_io_vec   = &meta->vec;
	meta->req.bi_vcnt     = 1;
	meta->req.bi_max_vecs = 1;
	meta->req.bi_size     = 1<<segbuf->seg->shift;
	meta->vec.bv_page     = meta->page;
	meta->vec.bv_len      = 1<<segbuf->seg->shift;
	meta->vec.bv_offset   = 0;
	meta->req.bi_private = segbuf;
}

static void 
__lsa_column_data_bio_init(struct column_data *data,
		struct segment_buffer *segbuf)
{
	int i;
	bio_init(&data->req);
	data->req.bi_flags    = 1 << BIO_UPTODATE;
	data->req.bi_idx      = 0;
	data->req.bi_next     = NULL;
	data->req.bi_io_vec   = &data->vec[i];
	data->req.bi_vcnt     = LSA_BLOCKDEPTH;
	data->req.bi_max_vecs = LSA_BLOCKDEPTH;
	data->req.bi_size     = (1<<segbuf->seg->shift) * LSA_BLOCKDEPTH;
	for (i = 0; i < LSA_BLOCKDEPTH; i ++) {
		data->vec[i].bv_page     = data->page[i];
		data->vec[i].bv_len      = 1<<segbuf->seg->shift;
		data->vec[i].bv_offset   = 0;
	}
	data->req.bi_private = segbuf;
}

static void
__lsa_column_bio_init(union column *dev, struct segment_buffer *segbuf)
{
	if (segbuf->type == COLUMN_META) {
		__lsa_column_meta_bio_init(&dev->meta, segbuf);
	} 
	if (segbuf->type == COLUMN_DATA) {
		__lsa_column_data_bio_init(&dev->data, segbuf);
	}
}

static int 
__lsa_column_init(struct lsa_segment *seg, struct segment_buffer *segbuf)
{
	raid5_conf_t *conf = seg->conf;
	union column *column = segbuf->column;
	int i;

	for (i = 0; i < conf->raid_disks; i ++, column ++) {
		column->meta.flags  = 0;
	}
	segbuf->track = page_address(segbuf->column[0].data.page[0]);

	return 0;
}

static const char *segment_event_str(segment_event_t type)
{
	const char *str[] = { 
		"free",
		"open",
		"closing",
		"closed",
	};

	return str[type & SS_SEG_MASK];
};

static int
lsa_ss_update(struct lsa_segment_status *ss, struct segment_buffer *segbuf);
static int
lsa_segment_read_done(struct lsa_segment *seg, struct segment_buffer *segbuf);
static int
lsa_segment_write_done(struct lsa_segment *seg, struct segment_buffer *segbuf);

static void 
lsa_segment_bio_init(struct segment_buffer *segbuf)
{
	atomic_set(&segbuf->bios, 1);
}

static void 
lsa_segment_bio_ref(struct segment_buffer *segbuf)
{
	atomic_inc(&segbuf->bios);
}

static void 
lsa_segment_bio_put(struct segment_buffer *segbuf, int rw)
{
	if (atomic_dec_and_test(&segbuf->bios) == 0)
		return;

	clear_segbuf_locked(segbuf);

	if (rw & WRITE) {
		lsa_segment_write_done(segbuf->seg, segbuf);
	} else {
		lsa_segment_read_done(segbuf->seg, segbuf);
	}
}

static void 
lsa_column_end_write(struct bio *bi, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bi->bi_flags);
	struct segment_buffer *segbuf = bi->bi_private;
	/*raid5_conf_t *conf = container_of(segbuf->seg, raid5_conf_t, lsa_segment);*/
	int disks = segbuf->seg->disks, i;
	union column *column;
	for (i = 0; i < disks; i ++)
		if (bi == &segbuf->column[i].meta.req)
			break;

	column = &segbuf->column[i];
	debug("segid %x, col %d, bios %d, uptodate %d.\n", segbuf->seg_id, disks,
			atomic_read(&segbuf->bios), uptodate);

	if (!uptodate) {
		/*set_bit(R5_WriteError, &column->flags);*/
	}

	lsa_segment_bio_put(segbuf, WRITE);
}

static void 
lsa_column_end_read(struct bio *bi, int error)
{
	int uptodate = test_bit(BIO_UPTODATE, &bi->bi_flags);
	struct segment_buffer *segbuf = bi->bi_private;
	/*raid5_conf_t *conf = container_of(segbuf->seg, raid5_conf_t, lsa_segment);*/
	int disks = segbuf->seg->disks, i;
	union column *column;
	for (i = 0; i < disks; i ++)
		if (bi == &segbuf->column[i].meta.req)
			break;

	column = &segbuf->column[i];
	debug("segid %x, col %d, bios %d, uptodate %d.\n", segbuf->seg_id, disks,
			atomic_read(&segbuf->bios), uptodate);

	if (uptodate) {
		set_bit(R5_UPTODATE, &column->meta.flags);
	} else {
		clear_bit(R5_UPTODATE, &column->meta.flags);
	}

	lsa_segment_bio_put(segbuf, READ);
}

static struct segment_buffer *
__lsa_segment_freed(struct lsa_segment *seg, uint32_t seg_id)
{
	struct segment_buffer *segbuf = NULL;

	if (list_empty(&seg->lru))
		return NULL;

	segbuf = list_entry(seg->lru.next, struct segment_buffer, lru_entry);
	debug("segid %x, %x, state %d, flags %lx, free %d\n",
			segbuf->seg_id, seg_id, segbuf->status, segbuf->flags,
			seg->free_cnt);

	/* the segment must be in CLOSED or FREE state */
	BUG_ON(segbuf->status != SEG_FREE && segbuf->status != SEG_CLOSED);
	/* must not in active */
	BUG_ON(!list_empty(&segbuf->active_entry));
	/* must not dirty */
	BUG_ON(!list_empty(&segbuf->dirty_entry));
	BUG_ON(segbuf_dirty(segbuf));
	/* read/write queue must empty */
	BUG_ON(!list_empty(&segbuf->write));
	BUG_ON(!list_empty(&segbuf->read));
	/* not LCS reserved entry */
	BUG_ON(segbuf_lcs(segbuf));
	/* must not locked */
	BUG_ON(segbuf_locked(segbuf));
	/* meta must cleared */
	BUG_ON(segbuf_checkpoint(segbuf));

	seg->free_cnt --;
	list_del_init(&segbuf->lru_entry);
	if (test_clear_segbuf_tree(segbuf))
		__segbuf_tree_delete(seg, segbuf);
	clear_segbuf_uptodate(segbuf);
	clear_segbuf_lru(segbuf);

	/* ok, reused it */
	segbuf->status = SEG_FREE;
	segbuf->seg_id = seg_id;
	segbuf->sector = SEG2PSECTOR(seg, segbuf->seg_id);
	__lsa_column_init(seg, segbuf);

	return segbuf;
}

void
lsa_segment_buffer_chain(struct segment_buffer *segbuf, 
		struct segment_buffer_entry *se)
{
	struct lsa_segment *seg = segbuf->seg;
	unsigned long flags;

	BUG_ON(se->done == NULL);
	BUG_ON(!list_empty(&se->entry));
	spin_lock_irqsave(&seg->lock, flags);
	list_add_tail(&se->entry, &segbuf->write);
	spin_unlock_irqrestore(&seg->lock, flags);
}

struct segment_buffer *
lsa_segment_find_or_create(struct lsa_segment *seg, uint32_t seg_id,
		struct segment_buffer_entry *se)
{
	struct segment_buffer *segbuf;
	unsigned long flags;

	spin_lock_irqsave(&seg->lock, flags);
	segbuf = __segbuf_tree_search(seg, seg_id);
	if (segbuf && test_clear_segbuf_lru(segbuf)) {
		list_del_init(&segbuf->lru_entry);
		seg->free_cnt --;
	} else if (segbuf == NULL) {
		segbuf = __lsa_segment_freed(seg, seg_id);
		/* TODO */
		BUG_ON(segbuf == NULL);
		set_segbuf_tree(segbuf);
		BUG_ON(__segbuf_tree_insert(seg, segbuf) == 0);
	}
	if (segbuf) 
		lsa_segment_ref(segbuf);
	/* insert into the queue before enable IRQ */
	if (segbuf && se) {
		BUG_ON(!list_empty(&se->entry));
		BUG_ON(se->done == NULL);
		if (segbuf_uptodate(segbuf))
			se->done(segbuf, se, 0);
		else
			list_add_tail(&se->entry, &segbuf->read);
	}
	/* when se is NULL, meaning we doing fill segment */
	if (segbuf && se && !segbuf_uptodate(segbuf) && !segbuf_locked(segbuf) &&
			list_empty(&segbuf->active_entry)) {
		list_add_tail(&segbuf->active_entry, &seg->active);
		tasklet_schedule(&seg->tasklet);
	}
	debug("segid %x, ref %d, event %d, flags %lx, free %d\n",
			segbuf->seg_id, atomic_read(&segbuf->count), 0,
			segbuf->flags, seg->free_cnt);
	spin_unlock_irqrestore(&seg->lock, flags);

	return segbuf;
}

int
lsa_segment_event(struct segment_buffer *segbuf, segment_event_t type)
{
	raid5_conf_t *conf =
		container_of(segbuf->seg, raid5_conf_t, data_segment);
	int res = 0;

	debug("segid %x, state (%s)%d -> (%s)%d\n",
			segbuf->seg_id,
			segment_event_str(segbuf->status), segbuf->status,
			segment_event_str(type), type);
	switch (segbuf->status) {
	case SEG_FREE: if (type == SEG_OPEN)
			       segbuf->status = type;
		       break;
	case SEG_OPEN: if (type == SEG_CLOSING)
			       segbuf->status = type;
		       break;
	case SEG_CLOSING:
		       if (type == SEG_CLOSED)
			       segbuf->status = type;
		       break;
	case SEG_CLOSED:
		       if (type == SEG_FREE)
			       segbuf->status = type;
		       break;
	default:
		       debug("invalid state %d -> %d\n",
				       segbuf->status, type);
		       res = -1;
		       break;
	}

	/* TODO state change invalid */
	BUG_ON(segbuf->status != type);

	res = lsa_ss_update(&conf->lsa_segment_status, segbuf);

	return res;
}

char *
lsa_segment_meta_buf_addr(struct segment_buffer *segbuf, int offset, int *len)
{
	struct lsa_segment *seg = segbuf->seg;
	int data = offset > seg->shift;
	struct page *page = segbuf->column[data].meta.page;
	char *addr = page_address(page);
	
	offset &= ((1<<seg->shift)-1);
	*len = 1<<seg->shift;
	*len -= offset;

	return addr + offset;
}

/* 
 * TODO:
 * 0) parity data write.
 * 1) recover data by parity data.
 */
static int
lsa_segment_handle(struct lsa_segment *seg, struct segment_buffer *segbuf)
{
	raid5_conf_t *conf = seg->conf;
	int disks = seg->disks, i;
	int rw = segbuf_dirty(segbuf) ? WRITE : READ;
	union column *column = segbuf->column;

	lsa_segment_bio_init(segbuf);

	for (i = 0; i < disks; i ++, column ++) {
		mdk_rdev_t *rdev;
		struct bio *bi = &column->meta.req;

		__lsa_column_bio_init(column, segbuf);
		bi->bi_rw = rw;
		if (rw & WRITE)
			bi->bi_end_io = lsa_column_end_write;
		else
			bi->bi_end_io = lsa_column_end_read;

		rcu_read_lock();
		rdev = rcu_dereference(conf->disks[i].rdev);
		if (rdev && test_bit(Faulty, &rdev->flags))
			rdev = NULL;
		rcu_read_unlock();

		if (rdev) {
			bi->bi_bdev = rdev->bdev;
			bi->bi_sector = segbuf->sector + rdev->data_offset;
			debug("segid %x/%llu/%llu, op %ld on disc %d, %s\n",
					segbuf->seg_id, 
					(unsigned long long)bi->bi_sector,
					(unsigned long long)rdev->data_offset,
					bi->bi_rw, i,
					bi->bi_rw & WRITE ? "WRT" : "RDT");
			lsa_segment_bio_ref(segbuf);
			generic_make_request(bi);
		} else {
			debug("segid %x, op %ld on disc %d, -\n",
					segbuf->seg_id, bi->bi_rw, i);
		}
	}

	lsa_segment_bio_put(segbuf, rw);

	return 0;
}

int
lsa_segment_dirty(struct lsa_segment *seg, struct segment_buffer *segbuf)
{
	unsigned long flags;

	if (test_set_segbuf_dirty(segbuf))
		return -EEXIST;

	/* must uptodate */
	BUG_ON(!segbuf_uptodate(segbuf));
	/* must in LRU */
	/*BUG_ON(list_empty(&segbuf->lru_entry));*/
	/* must not in any queue list */
	BUG_ON(!list_empty(&segbuf->dirty_entry));

	spin_lock_irqsave(&seg->lock, flags);
	list_add_tail(&segbuf->dirty_entry, &seg->dirty);
	spin_unlock_irqrestore(&seg->lock, flags);

	tasklet_schedule(&seg->tasklet);

	return 0;
}

static int
__lsa_segment_fill_write_done(struct lsa_segment *seg, 
		struct segment_buffer *segbuf);

static int
lsa_segment_done_callback(struct segment_buffer *segbuf,
		struct list_head *head)
{
	struct lsa_segment *seg = segbuf->seg;
	int chain = 0;
	unsigned long flags;

	spin_lock_irqsave(&seg->lock, flags);
	while (!list_empty(head)) {
		struct segment_buffer_entry *se = container_of(head->next,
				struct segment_buffer_entry, entry);
		list_del_init(&se->entry);
		spin_unlock_irqrestore(&seg->lock, flags);

		se->done(segbuf, se, 0);

		chain ++;
		spin_lock_irqsave(&seg->lock, flags);
	}
	spin_unlock_irqrestore(&seg->lock, flags);

	return chain;
}

/*
 * TODO:
 *  must checking the disks flag, when detect failed disk, recover data using
 *  parity disk
 */
static int
lsa_segment_read_done(struct lsa_segment *seg, struct segment_buffer *segbuf)
{
	set_segbuf_uptodate(segbuf);
	lsa_segment_done_callback(segbuf, &segbuf->read);
	return 0;
}

static int
lsa_segment_write_done(struct lsa_segment *seg, struct segment_buffer *segbuf)
{
	clear_segbuf_dirty(segbuf);
	if (lsa_segment_done_callback(segbuf, &segbuf->write) == 0)
		__lsa_segment_fill_write_done(seg, segbuf);
	return 0;
}

int
lsa_segment_release(struct segment_buffer *segbuf, segbuf_event_t type)
{
	struct lsa_segment *seg = segbuf->seg;
	unsigned long flags;

	debug("segid %x, ref %d, event %d, flags %lx, free %d\n",
			segbuf->seg_id, atomic_read(&segbuf->count), type,
			segbuf->flags, seg->free_cnt);
	BUG_ON(atomic_read(&segbuf->count) == 0);
	if (!atomic_dec_and_test(&segbuf->count))
		return 0;

	spin_lock_irqsave(&seg->lock, flags);
	/* LCS entry must reserved, not in the lru tree */
	if (!segbuf_lcs(segbuf)) {
		set_segbuf_lru(segbuf);
		seg->free_cnt ++;
		list_add_tail(&segbuf->lru_entry, &seg->lru);

		if (!lsa_segment_almost_full(&seg->conf->data_segment) && 
				seg == &seg->conf->data_segment)
			tasklet_schedule(&seg->conf->lsa_tasklet);
	}
	spin_unlock_irqrestore(&seg->lock, flags);

	return 0;
}

/* write the dirty segment into disk 
 */
static void
lsa_segment_tasklet(unsigned long data)
{
	struct lsa_segment *seg = (struct lsa_segment *)data;
	/*raid5_conf_t *conf = container_of(seg, raid5_conf_t, lsa_segment);*/
	unsigned long flags;

	spin_lock_irqsave(&seg->lock, flags);
	while (!list_empty(&seg->active)) {
		struct segment_buffer *segbuf = container_of(seg->active.next,
				struct segment_buffer, active_entry);
		list_del_init(&segbuf->active_entry);
		set_segbuf_locked(segbuf);
		spin_unlock_irqrestore(&seg->lock, flags);
		debug("segid %x,\n", segbuf->seg_id);
		lsa_segment_handle(seg, segbuf);
		spin_lock_irqsave(&seg->lock, flags);
	}
	while (!list_empty(&seg->dirty)) {
		struct segment_buffer *segbuf = container_of(seg->dirty.next,
				struct segment_buffer, dirty_entry);
		list_del_init(&segbuf->dirty_entry);
		set_segbuf_locked(segbuf);
		spin_unlock_irqrestore(&seg->lock, flags);
		debug("segid %x,\n", segbuf->seg_id);
		lsa_segment_handle(seg, segbuf);
		spin_lock_irqsave(&seg->lock, flags);
	}
	spin_unlock_irqrestore(&seg->lock, flags);
}

static int 
__lsa_column_meta_alloc(struct segment_buffer *segbuf,
		struct column_meta *meta, int shift)
{
	meta->page = alloc_pages(GFP_KERNEL, shift - PAGE_SHIFT);
	if (meta->page == NULL)
		return -1;
	return 0;
}

static int
__lsa_column_data_alloc(struct segment_buffer *segbuf,
		struct column_data *data, int shift)
{
	int i;
	for (i = 0; i < LSA_BLOCKDEPTH; i ++) {
		data->page[i] = alloc_pages(GFP_KERNEL, shift - PAGE_SHIFT);
		if (data->page[i] == NULL)
			return -1;
	}
	return 0;
}
static int
lsa_column_alloc(struct segment_buffer *segbuf, union column *column,
		int shift)
{
	int i;
	for (i = 0; i < segbuf->extent; i ++, column ++) {
		if ((segbuf->type == COLUMN_META &&
		     __lsa_column_meta_alloc(segbuf, &column->meta, shift) != 0) ||
		    (segbuf->type == COLUMN_DATA &&
		     __lsa_column_data_alloc(segbuf, &column->data, shift) != 0))
			    return -1;
	}
	return 0;
}

int 
lsa_segment_init(struct lsa_segment *seg, int disks, int nr, int shift,
		struct raid5_private_data *conf, int meta)
{
	int i;

	INIT_LIST_HEAD(&seg->lru);
	INIT_LIST_HEAD(&seg->active);
	INIT_LIST_HEAD(&seg->dirty);
	spin_lock_init(&seg->lock);
	
	INIT_LIST_HEAD(&seg->lcs_head);

	seg->shift = shift;
	seg->shift_sector = shift - 9;
	seg->disks = disks;
	seg->conf  = conf;
	seg->tree = RB_ROOT;
	seg->free_cnt = 0;

	
	tasklet_init(&seg->tasklet, lsa_segment_tasklet, (unsigned long)seg);

	for (i = 0; i < nr; i ++) {
		struct segment_buffer *segbuf;
		int blen = sizeof(*segbuf);
		blen += sizeof(union column)*disks;
		segbuf = kzalloc(blen, GFP_KERNEL);
		if (segbuf == NULL)
			return -1;
		segbuf->type = meta ? COLUMN_META : COLUMN_DATA;
		segbuf->seg = seg;
		segbuf->extent = disks;
		if (lsa_column_alloc(segbuf, segbuf->column, shift) != 0)
			return -2;
		list_add_tail(&segbuf->lru_entry, &seg->lru);
		INIT_LIST_HEAD(&segbuf->active_entry);
		INIT_LIST_HEAD(&segbuf->dirty_entry);
		INIT_LIST_HEAD(&segbuf->write);
		INIT_LIST_HEAD(&segbuf->read);
		seg->free_cnt ++;
	}
	seg->total_cnt = seg->free_cnt;

	return 0;
}

static void
__lsa_column_meta_free(struct segment_buffer *segbuf,
		struct column_meta *meta, int shift)
{
	__free_pages(meta->page, shift - PAGE_SHIFT);
}

static void
__lsa_column_data_free(struct segment_buffer *segbuf,
		struct column_data *data, int shift)
{
	int i;
	for (i = 0; i < LSA_BLOCKDEPTH; i ++) {
		__free_pages(data->page[i], shift - PAGE_SHIFT);
	}
}
static void
lsa_column_free(struct segment_buffer *segbuf, union column *column, int shift)
{
	int i;
	for (i = 0; i < segbuf->extent; i ++, column ++) {
		if (segbuf->type == COLUMN_META)
			__lsa_column_meta_free(segbuf, &column->meta, shift);
		if (segbuf->type == COLUMN_DATA)
			__lsa_column_data_free(segbuf, &column->data, shift);
	}
}

static void 
__segment_buffer_free(struct lsa_segment *seg, 
		struct segment_buffer *segbuf, int disks)
{
	if (test_clear_segbuf_tree(segbuf))
		__segbuf_tree_delete(seg, segbuf);
	list_del_init(&segbuf->lru_entry);
	lsa_column_free(segbuf, segbuf->column, seg->shift);
	kfree(segbuf);
}

int
lsa_segment_exit(struct lsa_segment *seg, int disks)
{
	while (!list_empty(&seg->active)) {
		/* TODO */
		struct segment_buffer *sb = container_of(seg->active.next,
				struct segment_buffer, active_entry);
		__segment_buffer_free(seg, sb, disks);
	}
	while (!list_empty(&seg->lru)) {
		struct segment_buffer *sb = container_of(seg->lru.next,
				struct segment_buffer, lru_entry);
		__segment_buffer_free(seg, sb, disks);
	}
	return 0;
}
