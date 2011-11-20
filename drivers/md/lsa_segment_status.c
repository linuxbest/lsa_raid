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

#define LSA_SEG_STS "segment_status"

static inline uint32_t
SS2SEG(struct lsa_segment_status *ss, uint32_t seg_id)
{
	return ss->seg_id + (seg_id/ss->per_page);
}

static inline int
SS2OFFSET(struct lsa_segment_status *ss, uint32_t seg_id)
{
	int off = seg_id & (ss->per_page-1);
	return off * sizeof(segment_status_t);
}

/*
 * LSA segment status 
 */
/* we using 16Mbyte LRU cache for entry */
#define SEGSTAT_HEAD_SIZE (16*1024*1024)
#define SEGSTAT_HEAD_NR   (SEGSTAT_HEAD_SIZE/sizeof(segment_status_t))

struct ss_buffer {
	struct segment_buffer_entry segbuf_entry;
	struct rb_node node;
	struct list_head entry, cookie;
	atomic_t count;
	struct lsa_segment_status *ss;
#define SEGSTAT_TREE     0
#define SEGSTAT_DIRTY    1
#define SEGSTAT_UPTODATE 2
#define SEGSTAT_LRU      3
	unsigned long flags;
	uint32_t seg_id;
	segment_status_t e;
};

#define SEGSTAT_FNS(bit, name) \
static inline void set_ss_##name(struct ss_buffer *eh) \
{ \
	set_bit(SEGSTAT_##bit, &eh->flags); \
} \
static inline void clear_ss_##name(struct ss_buffer *eh) \
{ \
	clear_bit(SEGSTAT_##bit, &eh->flags); \
} \
static inline int ss_##name(struct ss_buffer *eh) \
{ \
	return test_bit(SEGSTAT_##bit, &eh->flags); \
} \
static inline int test_set_ss_##name(struct ss_buffer *eh) \
{ \
	return test_and_set_bit(SEGSTAT_##bit, &eh->flags); \
} \
static inline int test_clear_ss_##name(struct ss_buffer *eh) \
{ \
	return test_and_clear_bit(SEGSTAT_##bit, &eh->flags); \
}

SEGSTAT_FNS(TREE,     tree)
SEGSTAT_FNS(DIRTY,    dirty)
SEGSTAT_FNS(UPTODATE, uptodate)
SEGSTAT_FNS(LRU,      lru)

static struct ss_buffer *
__ss_entry_search(struct lsa_segment_status *ss, uint32_t seg_id)
{
	struct rb_node *node = ss->tree.rb_node;

	while (node) {
		struct ss_buffer *data = container_of(node, 
				struct ss_buffer, node);
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
__ss_entry_insert(struct lsa_segment_status *ss, struct ss_buffer *data)
{
	struct rb_node **new = &(ss->tree.rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct ss_buffer *this = container_of(*new,
				struct ss_buffer, node);
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
	rb_insert_color(&data->node, &ss->tree);

	return 1;
}

static void 
__ss_entry_delete(struct lsa_segment_status *ss, struct ss_buffer *data)
{
	rb_erase(&data->node, &ss->tree);
}

static void 
__ss_buffer_free(struct lsa_segment_status *ss, struct ss_buffer *ssbuf)
{
	list_del_init(&ssbuf->entry);
	if (ss_tree(ssbuf))
		__ss_entry_delete(ss, ssbuf);
	kfree(ssbuf);
}

static struct ss_buffer *
__lsa_ss_freed(struct lsa_segment_status *ss)
{
	struct ss_buffer *ssbuf = NULL;

	if (list_empty(&ss->lru))
		return NULL;

	ssbuf = list_entry(ss->lru.next, struct ss_buffer, entry);
	list_del_init(&ssbuf->entry);
	segment_buffer_entry_init(&ssbuf->segbuf_entry);
	clear_ss_uptodate(ssbuf);
	clear_ss_lru(ssbuf);
	ss->free_cnt --;

	return ssbuf;
}

static void 
__lsa_ss_dirty(struct lsa_segment_status *ss, struct ss_buffer *ssbuf)
{
	if (test_set_ss_dirty(ssbuf))
		return;

	BUG_ON(!list_empty(&ssbuf->entry));
	list_add_tail(&ssbuf->entry, &ss->dirty);
	atomic_inc(&ss->dirty_cnt);
	debug("ssid %x\n", ssbuf->seg_id);
}

static void 
lsa_ss_put(struct lsa_segment_status *ss, struct ss_buffer *ssbuf)
{
	unsigned long flags;
	
	debug("ssid %x, ref %d, free %d\n",
			ssbuf->seg_id, atomic_read(&ssbuf->count),
			ss->free_cnt);

	spin_lock_irqsave(&ss->lock, flags);
	BUG_ON(atomic_read(&ssbuf->count) == 0);
	if (atomic_dec_and_test(&ssbuf->count)) {
		BUG_ON(!list_empty(&ssbuf->entry));
		BUG_ON(ss_dirty(ssbuf));
		BUG_ON(ss_lru(ssbuf));

		set_ss_lru(ssbuf);
		list_add_tail(&ssbuf->entry, &ss->lru);
		ss->free_cnt ++;
	}
	spin_unlock_irqrestore(&ss->lock, flags);
}

typedef struct lsa_ss_cookie {
	struct list_head       entry;
	struct ss_buffer       *ssbuf;
	int rw;
	struct completion      *comp;
	void (*done)(struct lsa_ss_cookie *);
} lsa_ss_cookie_t;

static int 
lsa_ss_find_or_create(struct lsa_segment_status *ss, uint32_t seg_id,
		lsa_ss_cookie_t *cookie)
{
	int res = 0;
	unsigned long flags;
	struct ss_buffer *ssbuf;

	spin_lock_irqsave(&ss->lock, flags);
	cookie->ssbuf = ssbuf = __ss_entry_search(ss, seg_id);
	if (ssbuf && test_clear_ss_lru(ssbuf)) {
		list_del_init(&ssbuf->entry);
		ss->free_cnt --;
	} else if (ssbuf == NULL) {
		cookie->ssbuf = ssbuf = __lsa_ss_freed(ss);
		BUG_ON(ssbuf == NULL);
		/* TODO handle when LRU is null */
		ssbuf->seg_id    = seg_id;
		BUG_ON(__ss_entry_insert(ss, ssbuf) == 0);
		if (cookie && cookie->rw == READ) {
			list_add_tail(&ssbuf->entry, &ss->queue);
			tasklet_schedule(&ss->tasklet);
		} else {
			set_ss_uptodate(ssbuf);
		}
	}
	debug("ssid %x, ref %d, flags %lx, free %d\n",
			ssbuf->seg_id, atomic_read(&ssbuf->count),
			ssbuf->flags, ss->free_cnt);
	if (!ss_uptodate(ssbuf)) {
		list_add_tail(&cookie->entry, &ssbuf->cookie);
		res = -EINPROGRESS;
	}
	atomic_inc(&ssbuf->count);
	spin_unlock_irqrestore(&ss->lock, flags);

	return res;
}

int
lsa_ss_update(struct lsa_segment_status *ss, struct segment_buffer *segbuf)
{
	struct lsa_ss_cookie cookie = {.rw = WRITE,};
	int res = lsa_ss_find_or_create(ss, segbuf->seg_id, &cookie);
	struct ss_buffer *ssbuf;

	ssbuf = cookie.ssbuf;
	BUG_ON(res != 0);
	if (ssbuf) {
		unsigned long flags;

		ssbuf->e.seq       = segbuf->seq;
		ssbuf->e.status    = segbuf->status;
		ssbuf->e.timestamp = get_seconds();
		ssbuf->e.jiffies   = jiffies;
		ssbuf->e.meta      = segbuf->meta;

		spin_lock_irqsave(&ss->lock, flags);
		__lsa_ss_dirty(ss, ssbuf);
		spin_unlock_irqrestore(&ss->lock, flags);
	}

	return ssbuf != NULL;
}

static int 
lsa_ss_write_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	struct ss_buffer *ssbuf = container_of(se,
			struct ss_buffer, segbuf_entry);
	struct lsa_segment_status *ss = ssbuf->ss;

	debug("ssid %x, free %d\n",
			ssbuf->seg_id, ss->free_cnt);

	clear_ss_dirty(ssbuf);

	lsa_ss_put(ss, ssbuf);
	
	lsa_segment_release(segbuf, 0);
	
	return 0;
}

#define lsa_ss_dump(segid, s, x) \
do { \
	debug(s " segid %x, seq %x, time %x, occup %x, sts %x\n", \
		segid, x->seq, x->timestamp, x->occupancy, x->status); \
} while (0)

static int
lsa_ss_copy(struct lsa_segment *seg, struct segment_buffer *segbuf,
		struct ss_buffer *ssbuf)
{
	int fromseg = !ss_uptodate(ssbuf);
	int len = 0;
	int offset = SS2OFFSET(ssbuf->ss, ssbuf->seg_id);
	const char *buf = lsa_segment_meta_buf_addr(segbuf, offset, &len);
	segment_status_t *n = &ssbuf->e;
	segment_status_t *o = (segment_status_t *)buf;

	debug("ssid %x, fromseg %d, off %d, len %d\n", 
			ssbuf->seg_id, fromseg, offset, len);
	lsa_ss_dump(ssbuf->seg_id, "new", n);
	lsa_ss_dump(ssbuf->seg_id, "old", o);
	BUG_ON(len < sizeof(*n));

	/* when copy to segment, mark the segment is dirty */
	if (!fromseg) {
		memcpy(o, n, sizeof(*o));

		/* TODO, this should be column uptodate or dirty */
		ssbuf->segbuf_entry.done = lsa_ss_write_done;
		lsa_segment_buffer_chain(segbuf, &ssbuf->segbuf_entry);
		set_segbuf_uptodate(segbuf);
		lsa_segment_dirty(seg, segbuf);
	} else {
		memcpy(n, o, sizeof(*o));
		set_ss_uptodate(ssbuf);
	}

	return 0;
}

static int 
lsa_ss_uptodate_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	struct ss_buffer *ssbuf = container_of(se,
			struct ss_buffer, segbuf_entry);
	struct lsa_segment_status *ss = ssbuf->ss;
	unsigned long flags;
	LIST_HEAD(head);

	debug("ssid %x, %d\n", ssbuf->seg_id, se->rw);
	if (se->rw == WRITE) {
		lsa_ss_copy(segbuf->seg, segbuf, ssbuf);
		return 0;
	}
	lsa_ss_copy(segbuf->seg, segbuf, ssbuf);

	spin_lock_irqsave(&ss->lock, flags);
	list_splice_init(&ssbuf->cookie, &head);
	spin_unlock_irqrestore(&ss->lock, flags);

	while (!list_empty(&head)) {
		lsa_ss_cookie_t *cookie = list_entry(head.next, 
				lsa_ss_cookie_t, entry);
		list_del_init(&cookie->entry);
		cookie->done(cookie);
	}

	lsa_segment_release(segbuf, 0);
	return 0;
}

static int
lsa_ss_rw(struct lsa_segment_status *ss, struct ss_buffer *ssbuf, int rw)
{
	int res = 0;
	struct segment_buffer *segbuf;
	raid5_conf_t *conf = container_of(ss, raid5_conf_t, lsa_segment_status);
	struct segment_buffer_entry *se = &ssbuf->segbuf_entry;

	debug("ssid %x, rw %d\n", ssbuf->seg_id, rw);
	BUG_ON(!list_empty(&se->entry));
	se->rw = rw;
	se->done = lsa_ss_uptodate_done;
	segbuf = lsa_segment_find_or_create(&conf->meta_segment,
			SS2SEG(ss, ssbuf->seg_id), se);
	BUG_ON(segbuf == NULL);

	return res;
}

static void 
lsa_ss_job(struct lsa_segment_status *ss, struct list_head *head, int rw)
{
	unsigned long flags;

	spin_lock_irqsave(&ss->lock, flags);
	while (!list_empty(head)) {
		struct ss_buffer *ssbuf = list_entry(head->next,
				struct ss_buffer, entry);
		list_del_init(&ssbuf->entry);
		if (rw == WRITE)
			atomic_dec(&ss->checkpoint_cnt);
		spin_unlock_irqrestore(&ss->lock, flags);

		lsa_ss_rw(ss, ssbuf, rw);

		spin_lock_irqsave(&ss->lock, flags);
	}
	spin_unlock_irqrestore(&ss->lock, flags);
}

void
lsa_ss_checkpoint_sts(struct lsa_segment_status *ss, int *dirty, int *point)
{
	*dirty = atomic_read(&ss->dirty_cnt);
	*point = atomic_read(&ss->checkpoint_cnt);
}

void
lsa_ss_checkpoint(struct lsa_segment_status *ss)
{
	int res;
	unsigned long flags;

	BUG_ON(!list_empty(&ss->checkpoint));
	BUG_ON(atomic_read(&ss->checkpoint_cnt) != 0);

	spin_lock_irqsave(&ss->lock, flags);
	res = atomic_read(&ss->dirty_cnt);
	if (res) {
		BUG_ON(list_empty(&ss->dirty));
		atomic_set(&ss->dirty_cnt, 0);
		atomic_set(&ss->checkpoint_cnt, res);
		list_splice_init(&ss->dirty, &ss->checkpoint);
		BUG_ON(list_empty(&ss->checkpoint));
	}
	spin_unlock_irqrestore(&ss->lock, flags);
}

void 
lsa_ss_commit(struct lsa_segment_status *ss)
{
	debug("dirty %d, point %d, empty %d\n", atomic_read(&ss->dirty_cnt),
			atomic_read(&ss->checkpoint_cnt),
			list_empty(&ss->checkpoint));
	lsa_ss_job(ss, &ss->checkpoint, WRITE);
}

static void 
proc_ss_read_done(struct lsa_ss_cookie *cookie)
{
	debug("cookie %p\n", cookie);
	complete(cookie->comp);
}

/*
 * find the segment directory by data of segment id
 */
static int
lsa_ss_find_meta_uptodate_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	complete(se->comp);
	return 0;
}

int
lsa_ss_find_meta(struct lsa_segment_status *ss, struct lsa_ss_meta *meta)
{
	raid5_conf_t *conf = container_of(ss, raid5_conf_t, lsa_segment_status);
	struct segment_buffer *segbuf;
	struct segment_buffer_entry segbuf_entry;
	struct segment_buffer_entry *se = &segbuf_entry;
	struct completion done;
	uint32_t seg_id = meta->data_id;

	int offset, len;
	const char *buf;
	segment_status_t *o;

	for (;;) {
		/* TODO FIXME deadloop */
		init_completion(&done);
		segment_buffer_entry_init(se);
		se->rw = READ;
		se->done = lsa_ss_find_meta_uptodate_done;
		se->comp = &done;
		segbuf = lsa_segment_find_or_create(&conf->meta_segment,
				SS2SEG(ss, seg_id), se);
		wait_for_completion(&done);

		offset = SS2OFFSET(ss, seg_id);
		buf = lsa_segment_meta_buf_addr(segbuf, offset, &len);
		o = (segment_status_t *)buf;
		do {
			lsa_ss_dump(seg_id, "ondisk", o);
			if ((o->status & SS_SEG_MASK) == SS_SEG_FREE) {
				lsa_segment_release(segbuf, 0);
				return -1;
			}
			if (o->status & SS_SEG_META) {
				meta->meta_id = seg_id;
				meta->meta_col = o->meta;
				lsa_segment_release(segbuf, 0);
				return 0;
			}
			len -= sizeof(segment_status_t);
			o ++; seg_id ++;
		} while (len > 0);
		lsa_segment_release(segbuf, 0);
	}

	return 0;
}

static void *
proc_ss_read(struct seq_file *p, struct lsa_segment_status *ss, loff_t seq)
{
	struct completion done;
	struct lsa_ss_cookie cookie;
	int res;
	segment_status_t *x;

	init_completion(&done);
	INIT_LIST_HEAD(&cookie.entry);
	cookie.rw   = READ;
	cookie.ssbuf= NULL;
	cookie.done = proc_ss_read_done;
	cookie.comp = &done;
	seq += DATA_SEG_ID;
	res = lsa_ss_find_or_create(ss, seq, &cookie);
	debug("segid %x, res %d, cookie %p\n", (uint32_t)seq, res, &cookie);
	if (res == -EINPROGRESS) {
		wait_for_completion(&done);
	}
	x = &cookie.ssbuf->e;
	seq_printf(p, "%08x %08x %08x.%04x %02x/%02x\n",
			(uint32_t)seq, x->seq,
			x->timestamp, x->jiffies,
			x->status, x->meta);
	lsa_ss_put(ss, cookie.ssbuf);

	return ss;
}

static void *
proc_ss_start(struct seq_file *p, loff_t *pos)
{
	struct lsa_segment_status *ss = p->private;
	
	if (ss == NULL)
		return NULL;

	if (*pos == 0) {
		seq_printf(p, "MAX SEG: %08x\n", ss->max_seg);
		seq_printf(p, "SEGID    SEQ      TIME          status\n");
		/*             01234567 01234567 01234567.0123 02/02 */
	}

	if (*pos < ss->max_seg)
		return proc_ss_read(p, ss, *pos);
	return NULL;
}

static void *
proc_ss_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct lsa_segment_status *ss = p->private;

	(*pos) ++;
	if (*pos < ss->max_seg)
		return proc_ss_read(p, ss, *pos);
	return NULL;
}

static void
proc_ss_stop(struct seq_file *p, void *v)
{
}

static int
proc_ss_show(struct seq_file *m, void *v)
{
	return 0;
}

static ssize_t
proc_ss_write(struct file *file, const char __user *buf,
		size_t size, loff_t *_pos)
{
	return size;
}

static const struct seq_operations proc_ss_ops = {
	.start = proc_ss_start,
	.next  = proc_ss_next,
	.stop  = proc_ss_stop,
	.show  = proc_ss_show,
};

static int 
proc_ss_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &proc_ss_ops);
	if (!res) {
		((struct seq_file *)file->private_data)->private = PDE(inode)->data;
	}
	return 0;
}

static const struct file_operations proc_ss_fops = {
	.open  = proc_ss_open,
	.read  = seq_read,
	.write = proc_ss_write,
	.llseek= seq_lseek,
	.release = seq_release,
	.owner = THIS_MODULE,
};

static void
lsa_ss_tasklet(unsigned long data)
{
	struct lsa_segment_status *ss = (struct lsa_segment_status*)data;
	lsa_ss_job(ss, &ss->queue, READ);
}

int
lsa_ss_init(struct lsa_segment_status *ss, int seg_nr)
{
	raid5_conf_t *conf = container_of(ss, raid5_conf_t, lsa_segment_status);
	int i;

	spin_lock_init(&ss->lock);
	ss->tree = RB_ROOT;
	INIT_LIST_HEAD(&ss->dirty);
	INIT_LIST_HEAD(&ss->checkpoint);
	INIT_LIST_HEAD(&ss->lru);
	INIT_LIST_HEAD(&ss->queue);
	atomic_set(&ss->dirty_cnt, 0);

	BUG_ON(sizeof(segment_status_t) != 16);
	ss->per_page = PAGE_SIZE/sizeof(segment_status_t);
	ss->seg_id = SS_SEG_ID;

	tasklet_init(&ss->tasklet, lsa_ss_tasklet, (unsigned long)ss);

	ss->max_seg = seg_nr;
	ss->proc = proc_create(LSA_SEG_STS,  0, conf->proc, &proc_ss_fops);
	if (ss->proc == NULL)
		return -1;
	ss->proc->data = (void *)ss;

	for (i = 0; i < SEGSTAT_HEAD_NR; i ++) {
		struct ss_buffer *ssbuf;
		ssbuf = kzalloc(sizeof(*ssbuf), GFP_KERNEL);
		if (ssbuf == NULL)
			return -1;
		ssbuf->ss = ss;
		list_add_tail(&ssbuf->entry, &ss->lru);
		INIT_LIST_HEAD(&ssbuf->cookie);
		ss->free_cnt ++;
	}

	return 0;
}

int
lsa_ss_exit(struct lsa_segment_status *ss)
{
	raid5_conf_t *conf = container_of(ss, raid5_conf_t, lsa_segment_status);
	while (!list_empty(&ss->dirty)) {
		/* TODO we must flush the dirty ss into disk */
		struct ss_buffer *ssbuf = container_of(ss->dirty.next,
				struct ss_buffer, entry);
		__ss_buffer_free(ss, ssbuf);
	}
	while (!list_empty(&ss->lru)) {
		struct ss_buffer *ssbuf = container_of(ss->lru.next,
				struct ss_buffer, entry);
		__ss_buffer_free(ss, ssbuf);
	}
	remove_proc_entry(LSA_SEG_STS, conf->proc);
	return 0;
}
