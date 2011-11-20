#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>

#include "md.h"
#include "bitmap.h"
#include "target.h"
#include "lsa.h"
#include "raid5.h"

#include "lsa_segment.h"
#include "lsa_dirtory.h"

#define LSA_DIRTORY "dirtory_entry"

static inline int
DIR2OFFSET(struct lsa_dirtory *dir, uint32_t log_track_id)
{
	int off = log_track_id & (dir->per_page-1);
	return off * sizeof(lsa_entry_t);
}

static inline uint32_t
DIR2SEG(struct lsa_dirtory *dir, uint32_t log_track_id)
{
	return dir->seg_id + (log_track_id/dir->per_page);
}

/* LSA dirtory operations
 * including
 *  bitmap.
 *  rbtree.
 *  segment page.
 */ 
uint32_t lsa_seg_alloc(struct lsa_dirtory *dir)
{
	/* TODO
	 * doing real free space manager.
	 */
	return dir->seg++;
}

void lsa_seg_update(struct lsa_dirtory *dir, uint32_t seg_id)
{
	dir->seg = seg_id;
}

static struct entry_buffer *
__lsa_entry_search(struct lsa_dirtory *dir, uint32_t log_track_id)
{
	struct rb_node *node = dir->tree.rb_node;

	while (node) {
		struct entry_buffer *data = container_of(node, 
				struct entry_buffer, node);
		int result = data->e.log_track_id - log_track_id;

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
__lsa_entry_insert(struct lsa_dirtory *dir, struct entry_buffer *data)
{
	struct rb_node **new = &(dir->tree.rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct entry_buffer *this = container_of(*new,
				struct entry_buffer, node);
		int result = this->e.log_track_id - data->e.log_track_id;

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
	rb_insert_color(&data->node, &dir->tree);

	return 1;
}

static void 
__lsa_entry_delete(struct lsa_dirtory *dir, struct entry_buffer *data)
{
	rb_erase(&data->node, &dir->tree);
}

static struct entry_buffer *
__lsa_entry_freed(struct lsa_dirtory *dir)
{
	struct entry_buffer *eh = NULL;

	if (list_empty(&dir->lru)) 
		return NULL;

	eh = list_entry(dir->lru.next, struct entry_buffer, lru);
	/* must not dirty entry */
	BUG_ON(entry_dirty(eh));
	list_del_init(&eh->lru);
	if (test_clear_entry_tree(eh))
		__lsa_entry_delete(dir, eh);
	clear_entry_uptodate(eh);
	clear_entry_lru(eh);
	segment_buffer_entry_init(&eh->segbuf_entry);
	dir->free_cnt --;

	return eh;
}

static void 
__lsa_entry_cookie_push(struct entry_buffer *eb, lsa_track_cookie_t *cookie)
{
	list_add_tail(&cookie->entry, &eb->cookie);
}

static void
__lsa_entry_dirty(struct lsa_dirtory *dir, struct entry_buffer *eh)
{
	set_entry_uptodate(eh);
	set_entry_dirty(eh);
	BUG_ON(!list_empty(&eh->lru));
	list_add_tail(&eh->lru, &dir->dirty);
	atomic_inc(&dir->dirty_cnt);
	atomic_inc(&eh->count);
}

/*
 * LSA entry get 
 *
 * result:
 *  -ENOENT       logic address not found.
 *  -EBUSY        this entry is reference by other, using careful.
 *  -EINPROGRESS: entry must reading from disk, the bio has been push into 
 *                entry bio list, will call the lsa_page_read when disk
 *                request is finished.
 */
int
lsa_entry_find_or_create(struct lsa_dirtory *dir, uint32_t log_track_id,
		lsa_track_cookie_t *cookie)
{
	int res = 0;
	unsigned long flags;
	struct entry_buffer *eh = NULL;

	spin_lock_irqsave(&dir->lock, flags);
	cookie->eb = eh = __lsa_entry_search(dir, log_track_id);
	if (eh && test_clear_entry_lru(eh)) {
		list_del_init(&eh->lru);
		dir->free_cnt --;
	} else if (eh == NULL) { /* alloc new entry, schedule it doing IO request */
		cookie->eb = eh = __lsa_entry_freed(dir);
		BUG_ON(eh == NULL);
		/* TODO handle when LRU is empty */
		eh->e.log_track_id = log_track_id;
		list_add_tail(&eh->lru, &dir->queue);
		if (!test_set_entry_tree(eh))
			BUG_ON(__lsa_entry_insert(dir, eh) == 0);
		tasklet_schedule(&dir->tasklet);
	}
	debug("ltid %x, ref %d, flags %lx, free %d\n", 
			eh->e.log_track_id, atomic_read(&eh->count), 
			eh->flags, dir->free_cnt);
	if (!entry_uptodate(eh)) {
		__lsa_entry_cookie_push(eh, cookie);
		res = -EINPROGRESS;
	}
	atomic_inc(&eh->count);
	spin_unlock_irqrestore(&dir->lock, flags);

	return res;
}

void
lsa_entry_put(struct lsa_dirtory *dir, struct entry_buffer *eh)
{
	unsigned long flags;

	debug("ltid %x, ref %d, flags %lx, free %d\n",
			eh->e.log_track_id, atomic_read(&eh->count),
			eh->flags, dir->free_cnt);
	spin_lock_irqsave(&dir->lock, flags);
	BUG_ON(atomic_read(&eh->count) == 0);
	if (atomic_dec_and_test(&eh->count)) {
		BUG_ON(!list_empty(&eh->lru));
		BUG_ON(entry_dirty(eh));
		BUG_ON(entry_lru(eh));

		set_entry_lru(eh);
		list_add_tail(&eh->lru, &dir->lru);
		dir->free_cnt ++;
	}
	spin_unlock_irqrestore(&dir->lock, flags);
}

void
lsa_entry_dirty(struct lsa_dirtory *dir, struct entry_buffer *eh)
{
	unsigned long flags;

	if (entry_dirty(eh))
		return;

	/* must not in any list */
	BUG_ON(!list_empty(&eh->lru));
	/* must in the rb tree */
	BUG_ON(!entry_tree(eh));
	/* must be uptodate */
	BUG_ON(!entry_uptodate(eh));

	spin_lock_irqsave(&dir->lock, flags);
	__lsa_entry_dirty(dir, eh);
	spin_unlock_irqrestore(&dir->lock, flags);
}

/* TODO:
 *  may need put commit page into a list, let commit process check it 
 *  before doing checkpoing
 */
static int
lsa_dirtory_write_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	struct entry_buffer *eh = container_of(se,
			struct entry_buffer, segbuf_entry);
	debug("dirtory %d\n", eh->e.log_track_id);
	clear_entry_dirty(eh);
	lsa_entry_put(eh->dir, eh);
	lsa_segment_release(segbuf, 0);
	return 0;
}

#define lsa_entry_dump(s, x) \
do { \
	debug(s " lba %x, segid %x, col %d, off %03d, len %d, sts %x\n", \
		x->log_track_id, x->seg_id, x->seg_column, \
			x->offset, x->length, x->status); \
} while (0)

static int
lsa_dirtory_copy(struct lsa_segment *seg, struct segment_buffer *segbuf,
		struct entry_buffer *eh)
{
	int fromseg = !entry_uptodate(eh);
	int len = 0;
	int offset = DIR2OFFSET(eh->dir, eh->e.log_track_id);
	const char *buf = lsa_segment_meta_buf_addr(segbuf, offset, &len);
	lsa_entry_t *lo = (lsa_entry_t *)buf;
	lsa_entry_t *ln = &eh->e;

	debug("ltid %x, fromseg %d, off %d, len %d\n",
			eh->e.log_track_id, fromseg, offset, len);

	lsa_entry_dump(" mem", ln);
	lsa_entry_dump("disk", lo);
	BUG_ON(len < sizeof(*lo));

	/* when copy to segment, mark the segment is dirty */
	if (!fromseg) {
		memcpy(lo, &eh->e, sizeof(*lo));

		/* TODO, this should be column uptodate or dirty */
		eh->segbuf_entry.done = lsa_dirtory_write_done;
		lsa_segment_buffer_chain(segbuf, &eh->segbuf_entry);
		set_segbuf_uptodate(segbuf);
		lsa_segment_dirty(seg, segbuf);
	} else {
		/* TODO checksum */
		/* only copy when ondisk contain valid data */
		if (lo->status & DATA_VALID) {
			memcpy(&eh->e, lo, sizeof(*lo));
		} else {
			uint32_t lt = eh->e.log_track_id;
			memset(&eh->e, 0, sizeof(*lo));
			eh->e.log_track_id = lt;
		}
		set_entry_uptodate(eh);
		if ((lo->status & DATA_VALID) && lo->log_track_id != eh->e.log_track_id) {
			printk("LSA:DIR WARN-0002, %08x,%08x, %x\n",
					lo->log_track_id, eh->e.log_track_id, lo->status);
		}
	}

	return 0;
}

static int
lsa_dirtory_uptodate_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	struct lsa_segment *seg = segbuf->seg;
	struct entry_buffer *eh = container_of(se,
			struct entry_buffer, segbuf_entry);
	raid5_conf_t *conf = seg->conf;
	struct lsa_dirtory *dir = &conf->lsa_dirtory;
	unsigned long flags;
	LIST_HEAD(head);

	debug("ltid %x, rw %d\n", eh->e.log_track_id, se->rw);
	if (se->rw == WRITE) {
		lsa_dirtory_copy(seg, segbuf, eh);
		return 0;
	}

	lsa_dirtory_copy(seg, segbuf, eh);

	spin_lock_irqsave(&dir->lock, flags);
	list_splice_init(&eh->cookie, &head);
	spin_unlock_irqrestore(&dir->lock, flags);

	while (!list_empty(&head)) {
		lsa_track_cookie_t *cookie = list_entry(head.next, 
				lsa_track_cookie_t, entry);
		list_del_init(&cookie->entry);
		cookie->done(cookie);
	}
	
	lsa_segment_release(segbuf, 0);

	return 0;
}

static int
__lsa_dirtory_rw(struct lsa_segment *seg, struct lsa_dirtory *dir, 
		struct entry_buffer *eh, int rw)
{
	int res = 0;
	struct segment_buffer *segbuf;
	struct segment_buffer_entry *se = &eh->segbuf_entry;

	debug("ltid %x, rw %d\n", eh->e.log_track_id, rw);
	BUG_ON(!list_empty(&se->entry));
	se->rw = rw;
	se->done = lsa_dirtory_uptodate_done;
	segbuf = lsa_segment_find_or_create(seg,
			DIR2SEG(dir, eh->e.log_track_id), se);
	BUG_ON(segbuf == NULL);

	return res;
}

static void 
lsa_dirtory_job(struct lsa_segment *seg, struct lsa_dirtory *dir,
		struct list_head *head, int rw)
{
	unsigned long flags;

	spin_lock_irqsave(&dir->lock, flags);
	while (!list_empty(head)) {
		struct entry_buffer *eh = list_entry(head->next,
				struct entry_buffer, lru);
		list_del_init(&eh->lru);
		if (rw == WRITE)
			atomic_dec(&dir->checkpoint_cnt);
		spin_unlock_irqrestore(&dir->lock, flags);

		__lsa_dirtory_rw(seg, dir, eh, rw);

		spin_lock_irqsave(&dir->lock, flags);
	}
	spin_unlock_irqrestore(&dir->lock, flags);
}

/* doing retry job.
 * doing queue job.
 * update the dirty entry to segment.
 */
static void
lsa_dirtory_tasklet(unsigned long data)
{
	struct lsa_dirtory *dir = (struct lsa_dirtory *)data;
	raid5_conf_t *conf = container_of(dir, raid5_conf_t, lsa_dirtory);
	lsa_dirtory_job(&conf->meta_segment, dir, &dir->retry, READ);
	lsa_dirtory_job(&conf->meta_segment, dir, &dir->queue, READ);
}

void 
lsa_dirtory_commit(struct lsa_dirtory *dir)
{
	raid5_conf_t *conf = container_of(dir, raid5_conf_t, lsa_dirtory);
	debug("dirty %d, point %d, empty %d\n", atomic_read(&dir->dirty_cnt),
			atomic_read(&dir->checkpoint_cnt),
			list_empty(&dir->checkpoint));
	lsa_dirtory_job(&conf->meta_segment, dir, &dir->checkpoint, WRITE);
}

static void
lsa_dirtory_checkpoint_sts(struct lsa_dirtory *dir, int *dirty, int *point)
{
	*dirty = atomic_read(&dir->dirty_cnt);
	*point = atomic_read(&dir->checkpoint_cnt);
}

void
lsa_dirtory_checkpoint(struct lsa_dirtory *dir)
{
	int res;
	unsigned long flags;

	BUG_ON(!list_empty(&dir->checkpoint));
	BUG_ON(atomic_read(&dir->checkpoint_cnt) != 0);

	spin_lock_irqsave(&dir->lock, flags);
	res = atomic_read(&dir->dirty_cnt);
	if (res) {
		BUG_ON(list_empty(&dir->dirty));
		atomic_set(&dir->dirty_cnt, 0);
		atomic_set(&dir->checkpoint_cnt, res);
		list_splice_init(&dir->dirty, &dir->checkpoint);
		BUG_ON(list_empty(&dir->checkpoint));
	}
	spin_unlock_irqrestore(&dir->lock, flags);
}

static int
__entry_buffer_free(struct lsa_dirtory *dir, struct entry_buffer *eh)
{
	list_del_init(&eh->lru);
	if (entry_tree(eh))
		__lsa_entry_delete(dir, eh);
	kfree(eh);
	dir->free_cnt --;
	return 0;
}

static void 
proc_dirtory_read_done(struct lsa_track_cookie *cookie)
{
	debug("cookie %p\n", cookie);
	complete(cookie->comp);
}

int
lsa_entry_live(struct lsa_dirtory *dir, lsa_entry_t *n, int *live)
{
	struct completion done;
	struct lsa_track_cookie cookie;
	int res = 0;
	lsa_entry_t *x;

	init_completion(&done);
	INIT_LIST_HEAD(&cookie.entry);
	cookie.track= NULL;
	cookie.lt   = NULL;
	cookie.eb   = NULL;
	cookie.done = proc_dirtory_read_done;
	cookie.comp = &done;
	res = lsa_entry_find_or_create(dir, n->log_track_id, &cookie);
	if (res == -EINPROGRESS) {
		wait_for_completion(&done);
	}
	x = &cookie.eb->e;

	*live = x->seg_id == n->seg_id && 
		x->seg_column == n->seg_column &&
		x->offset == n->offset &&
		x->length == n->length;

	lsa_entry_put(dir, cookie.eb);

	return 0;
}

static void *
proc_dirtory_read(struct seq_file *p, struct lsa_dirtory *dir, loff_t seq)
{
	struct completion done;
	struct lsa_track_cookie cookie;
	int res;
	lsa_entry_t *x;

	init_completion(&done);
	INIT_LIST_HEAD(&cookie.entry);
	cookie.track= NULL;
	cookie.lt   = NULL;
	cookie.eb   = NULL;
	cookie.done = proc_dirtory_read_done;
	cookie.comp = &done;
	res = lsa_entry_find_or_create(dir, seq, &cookie);
	debug("ltid %x, res %d, cookie %p\n", (uint32_t)seq, res, &cookie);
	if (res == -EINPROGRESS) {
		wait_for_completion(&done);
	}
	x = &cookie.eb->e;
	/*        (p, "-------- -------- --- ------- ------- ---- ------  ---\n");*/
	seq_printf(p, "%08x %08x %03x %07x %07x %04x %06x %03x\n",
			x->log_track_id, x->seg_id, x->seg_column,
			x->offset, x->length, x->age, x->status, x->activity);
	lsa_entry_put(dir, cookie.eb);

	return dir;
}

static void *
proc_dirtory_start(struct seq_file *p, loff_t *pos)
{
	struct lsa_dirtory *dir = p->private;
	
	if (dir == NULL)
		return NULL;

	if (*pos == 0) {
		seq_printf(p, "MAX LBA: %08x\n", dir->max_lba);
		seq_printf(p, "LBA      SEGID    COL OFFSET  LENGTH  AGE  STATUS ACT\n");
		seq_printf(p, "-------- -------- --- ------- ------- ---- ------ ---\n");
	}

	if (*pos < dir->max_lba)
		return proc_dirtory_read(p, dir, *pos);
	return NULL;
}

static void *
proc_dirtory_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct lsa_dirtory *dir = p->private;

	(*pos) ++;
	if (*pos < dir->max_lba)
		return proc_dirtory_read(p, dir, *pos);
	return NULL;
}

static void
proc_dirtory_stop(struct seq_file *p, void *v)
{
}

static int
proc_dirtory_show(struct seq_file *m, void *v)
{
	return 0;
}

static ssize_t
proc_dirtory_write(struct file *file, const char __user *buf,
		size_t size, loff_t *_pos)
{
	return size;
}

static const struct seq_operations proc_dirtory_ops = {
	.start = proc_dirtory_start,
	.next  = proc_dirtory_next,
	.stop  = proc_dirtory_stop,
	.show  = proc_dirtory_show,
};

static int 
proc_dirtory_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &proc_dirtory_ops);
	if (!res) {
		((struct seq_file *)file->private_data)->private = PDE(inode)->data;
	}
	return 0;
}

static const struct file_operations proc_dirtory_fops = {
	.open  = proc_dirtory_open,
	.read  = seq_read,
	.write = proc_dirtory_write,
	.llseek= seq_lseek,
	.release = seq_release,
	.owner = THIS_MODULE,
};

int
lsa_dirtory_init(struct lsa_dirtory *dir, sector_t size)
{
	raid5_conf_t *conf = container_of(dir, raid5_conf_t, lsa_dirtory);
	int i;

	spin_lock_init(&dir->lock);
	dir->tree = RB_ROOT;
	dir->seg  = DATA_SEG_ID;
	INIT_LIST_HEAD(&dir->dirty);
	INIT_LIST_HEAD(&dir->checkpoint);
	INIT_LIST_HEAD(&dir->lru);
	INIT_LIST_HEAD(&dir->queue);
	INIT_LIST_HEAD(&dir->retry);
	tasklet_init(&dir->tasklet, lsa_dirtory_tasklet, (unsigned long)dir);

	BUG_ON(PAGE_SIZE != 4096);
	BUG_ON(sizeof(lsa_entry_t) != 16);
	dir->per_page = PAGE_SIZE/sizeof(lsa_entry_t);
	dir->seg_id = DIR_SEG_ID;

	dir->max_lba = size >> (STRIPE_SS_SHIFT-SECTOR_SHIFT);
	dir->proc = proc_create(LSA_DIRTORY, 0, conf->proc, &proc_dirtory_fops);
	if (dir->proc == NULL)
		return -1;
	dir->proc->data = (void *)dir;

	for (i = 0; i < ENTRY_HEAD_NR; i ++) {
		struct entry_buffer *eh = kzalloc(sizeof(*eh), GFP_KERNEL);
		if (eh == NULL)
			return -2;
		eh->dir = dir;
		list_add_tail(&eh->lru, &dir->lru);
		INIT_LIST_HEAD(&eh->cookie);
		dir->free_cnt ++;
	}
	return 0;
}

int
lsa_dirtory_exit(struct lsa_dirtory *dir)
{
	raid5_conf_t *conf = container_of(dir, raid5_conf_t, lsa_dirtory);
	while (!list_empty(&dir->dirty)) {
		/* TODO we must flush the dirty entry into disk */
		struct entry_buffer *eh = container_of(dir->dirty.next,
				struct entry_buffer, lru);
		__entry_buffer_free(dir, eh);
	}
	while (!list_empty(&dir->lru)) {
		struct entry_buffer *eh = container_of(dir->lru.next,
				struct entry_buffer, lru);
		__entry_buffer_free(dir, eh);
	}
	remove_proc_entry(LSA_DIRTORY, conf->proc);
	debug("free_cnt %d\n", dir->free_cnt);
	return 0;
}
