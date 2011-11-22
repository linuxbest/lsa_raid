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
#include "lsa_segment_status.h"
#include "lsa_segment_fill.h"
#include "lsa_closed_segment.h"

#define LSA_LCS_STS "segment_closed"

static inline uint32_t
LCS2SEG(struct lsa_closed_segment *lcs, int id)
{
	return lcs->seg_id + (id * 0x100);
}

static void
__lcs_buffer_free(struct lsa_closed_segment *lcs, struct lcs_buffer *lcsbuf)
{
	list_del_init(&lcsbuf->lru);
	kfree(lcsbuf);
	lcs->free_cnt --;
}

static lcs_buffer_t *
__lsa_lcs_freed(struct lsa_closed_segment *lcs)
{
	lcs_buffer_t *lb = NULL;

	if (list_empty(&lcs->lru))
		return NULL;

	lb = list_entry(lcs->lru.next, lcs_buffer_t, lru);
	list_del_init(&lb->lru);
	segment_buffer_entry_init(&lb->segbuf_entry);
	lcs->free_cnt --;

	lb->ondisk = (lcs_ondisk_t *)page_address(lb->page);
	lb->ondisk->magic = SEG_LCS_MAGIC;
	lb->ondisk->total = 0;

	lb->ondisk->timestamp = get_seconds();
	lb->ondisk->jiffies   = jiffies;
	lb->ondisk->sum = lb->ondisk->timestamp;

	return lb;
}

static lcs_buffer_t *
lsa_lcs_freed(struct lsa_closed_segment *lcs)
{
	lcs_buffer_t *lb;
	unsigned long flags;

	spin_lock_irqsave(&lcs->lock, flags);
	lb = __lsa_lcs_freed(lcs);
	spin_unlock_irqrestore(&lcs->lock, flags);

	return lb;
}

void 
lsa_lcs_insert(lcs_buffer_t *lb, uint32_t seg_id)
{
	BUG_ON(lb->ondisk->total == lb->lcs->max);
	if (seg_id == lb->ondisk->seg[lb->ondisk->total])
		return;

	lb->ondisk->sum += seg_id;
	lb->ondisk->seg[lb->ondisk->total] = seg_id;
	lb->ondisk->total ++;
}

static int
lsa_lcs_write_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	unsigned long flags;
	lcs_buffer_t *lb = container_of(se, lcs_buffer_t, segbuf_entry);
	struct lsa_closed_segment *lcs = lb->lcs;
	raid5_conf_t *conf = container_of(lcs, raid5_conf_t, lsa_closed_status);

	spin_lock_irqsave(&lcs->lock, flags);
	list_del(&lb->lru);
	list_add_tail(&lb->lru, &lcs->lru);
	lcs->free_cnt ++;
	spin_unlock_irqrestore(&lcs->lock, flags);

	debug("lb %d, free %d\n", lb->seg, lcs->free_cnt);

	/* now it's time to flush the checkpoint dirty page
	 *  1) LSA dirtory 
	 *  2) LSA segment status 
	 * into disk
	 */
	lsa_dirtory_commit(&conf->lsa_dirtory);
	lsa_ss_commit(&conf->lsa_segment_status);
	return 0;
}

void
lsa_lcs_commit(lcs_buffer_t *lb, uint32_t seg_id, int col, uint32_t seq)
{
	struct lsa_closed_segment *lcs = lb->lcs;
	raid5_conf_t *conf = container_of(lcs, raid5_conf_t, lsa_closed_status);
	struct segment_buffer *segbuf;
	unsigned long flags;
	int i;

	/* saving the seg id and col for meta data */
	lb->ondisk->meta_seg_id = seg_id;
	lb->ondisk->meta_column = col;
	lb->ondisk->seq_id = seq;
	/* sum the seg id & col */
	lb->ondisk->sum += seg_id;
	lb->ondisk->sum += col;
	lb->ondisk->sum += seq;

	spin_lock_irqsave(&lcs->lock, flags);
	list_add_tail(&lb->lru, &lcs->dirty);
	i = lcs->seg & lcs->max_mask;
	lcs->seg ++;
	spin_unlock_irqrestore(&lcs->lock, flags);

	segbuf = lcs->segbuf[i];
	lb->seg = i;
	lb->segbuf_entry.done = lsa_lcs_write_done;

	set_segbuf_uptodate(segbuf);
	lsa_segment_buffer_chain(segbuf, &lb->segbuf_entry);
	i = lsa_segment_dirty(&conf->meta_segment, segbuf);
	
	debug("lb %d write, %d\n", lb->seg, i);
}

static lcs_ondisk_t *
lsa_lcs_buf(struct lsa_closed_segment *lcs, int i,
		int *valid, uint32_t *sum_o)
{
	struct segment_buffer *segbuf = lcs->segbuf[i];
	struct page *page = segbuf->column[0].meta.page;
	lcs_ondisk_t *ondisk;
	uint32_t sum;
	int j;

	ondisk = (lcs_ondisk_t *)page_address(page);

	sum = ondisk->timestamp;
	for (j = 0; j < ondisk->total; j ++) {
		sum += ondisk->seg[j];
	}
	sum += ondisk->meta_seg_id;
	sum += ondisk->meta_column;
	sum += ondisk->seq_id;

	*sum_o = sum;
	*valid = sum == ondisk->sum && ondisk->magic == SEG_LCS_MAGIC;

	return ondisk;
}

static void *
proc_lcs_read(struct seq_file *p, struct lsa_closed_segment *lcs, loff_t seq)
{
	int i = seq & lcs->max_mask, valid;
	uint32_t sum_except;
	lcs_ondisk_t *ondisk = lsa_lcs_buf(lcs, i, &valid, &sum_except);

	if (ondisk == NULL)
		return NULL;

	seq_printf(p, "[%d] magic %08x, total %04x, seq %08x, sum %08x/%08x, time %08x.%04x, meta %08x/%d\n",
			(int)seq, ondisk->magic, ondisk->total, ondisk->seq_id,
			ondisk->sum, sum_except, ondisk->timestamp, ondisk->jiffies,
			ondisk->meta_seg_id, ondisk->meta_column);
	seq_printf(p, "    ");
	for (i = 0; i < ondisk->total; i ++) {
		if (i && (i&3) == 0)
			seq_printf(p, "\n    ");
		seq_printf(p, "%03x: %08x ", i, ondisk->seg[i]);
	}
	seq_printf(p, "\n");

	return lcs;
}

static void *
proc_lcs_start(struct seq_file *p, loff_t *pos)
{
	struct lsa_closed_segment *lcs = p->private;
	
	if (lcs == NULL)
		return NULL;

	if (*pos == 0) {
		seq_printf(p, "MAX LCS: %08x\n", lcs->max_lcs);
//		seq_printf(p, "LBA      SEGID    COL OFFSET  LENGTH  AGE  STATUS ACT\n");
//		seq_printf(p, "-------- -------- --- ------- ------- ---- ------ ---\n");
	}

	if (*pos < lcs->max_lcs)
		return proc_lcs_read(p, lcs, *pos);
	return NULL;
}

static void *
proc_lcs_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct lsa_closed_segment *lcs = p->private;

	(*pos) ++;
	if (*pos < lcs->max_lcs)
		return proc_lcs_read(p, lcs, *pos);
	return NULL;
}

static void
proc_lcs_stop(struct seq_file *p, void *v)
{
}

static int
proc_lcs_show(struct seq_file *m, void *v)
{
	return 0;
}

static ssize_t
proc_lcs_write(struct file *file, const char __user *buf,
		size_t size, loff_t *_pos)
{
	return size;
}

static const struct seq_operations proc_lcs_ops = {
	.start = proc_lcs_start,
	.next  = proc_lcs_next,
	.stop  = proc_lcs_stop,
	.show  = proc_lcs_show,
};

static int 
proc_lcs_open(struct inode *inode, struct file *file)
{
	int res = seq_open(file, &proc_lcs_ops);
	if (!res) {
		((struct seq_file *)file->private_data)->private = PDE(inode)->data;
	}
	return 0;
}

static const struct file_operations proc_lcs_fops = {
	.open  = proc_lcs_open,
	.read  = seq_read,
	.write = proc_lcs_write,
	.llseek= seq_lseek,
	.release = seq_release,
	.owner = THIS_MODULE,
};

static int 
lsa_lcs_select(struct lsa_closed_segment *lcs)
{
	int i, sel = -1;
	uint32_t time = 0;
	uint16_t jif = 0;

	printk("  index magic    seq      sum/except        time.jiffies  status\n");
	for (i = 0; i < lcs->max_lcs; i ++) {
		uint32_t sum_except;
		int valid = 0;
		lcs_ondisk_t *ondisk = lsa_lcs_buf(lcs, i, &valid, &sum_except);

		if (ondisk == NULL)
			continue;
		printk(" LCS:%02d %08x %08x %08x/%08x %08x.%04x %sVALID\n", i, 
				ondisk->magic, ondisk->seq_id,
				ondisk->sum, sum_except,
				ondisk->timestamp, ondisk->jiffies,
				valid ? "" : "IN");
		if (!valid)
			continue;

		if (ondisk->timestamp > time) {
			time = ondisk->timestamp;
			sel = i;
		} else if (ondisk->timestamp == time && ondisk->jiffies > jif) {
			jif = ondisk->jiffies;
			sel = i;
		}
	}
	return sel;
}
 
static int 
lsa_lcs_recover(struct lsa_closed_segment *lcs)
{
	raid5_conf_t *conf = container_of(lcs, raid5_conf_t, lsa_closed_status);
	int i;
	struct segment_buffer *segbuf;
	struct page *page;
	lcs_ondisk_t *ondisk;

	i = lsa_lcs_select(lcs);
	if (i == -1) {
		printk("LSA: skip LCS recovery.\n");
		return 0;
	}
	printk("LCS: select %d doing recovery\n", i);

	segbuf = lcs->segbuf[i];
	page = segbuf->column[0].meta.page;
	ondisk = (lcs_ondisk_t *)page_address(page);

	/* TODO checking the dirtory & ss information by redo the closed
	 * segment */
	lsa_segment_fill_update(&conf->segment_fill, 
			ondisk->meta_seg_id,
			ondisk->meta_column,
			ondisk->seq_id);
	lsa_seg_update(&conf->lsa_dirtory, ondisk->meta_seg_id+1);

	return 0;
}

static int 
lsa_lcs_uptodate_done(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se, int error)
{
	struct lcs_segment_buffer *lcs = container_of(se,
			struct lcs_segment_buffer , segbuf_entry);
	debug("lcsseg %p\n", lcs);
	complete(&lcs->done);
	/* set lcs flag to not free to lru head */
	set_segbuf_lcs(segbuf);
	lsa_segment_release(segbuf, 0);
	return 0;
}

int
lsa_cs_init(struct lsa_closed_segment *lcs)
{
	int order = 2;
	int max = ((PAGE_SIZE<<order) - sizeof(lcs_ondisk_t))/sizeof(uint32_t), i;
	raid5_conf_t *conf = container_of(lcs, raid5_conf_t, lsa_closed_status);

	lcs->max = max;
	spin_lock_init(&lcs->lock);
	INIT_LIST_HEAD(&lcs->lru);
	INIT_LIST_HEAD(&lcs->dirty);
	INIT_LIST_HEAD(&lcs->segbuf_head);
	lcs->seg_id = LCS_SEG_ID;

	lcs->max_lcs = NR_LCS;
	lcs->max_mask= lcs->max_lcs-1;

	lcs->proc = proc_create(LSA_LCS_STS, 0, conf->proc, &proc_lcs_fops);
	if (lcs->proc == NULL)
		return -1;
	lcs->proc->data = (void *)lcs;

	lcs->segbuf = kmalloc(sizeof(struct segment_buffer *)*NR_LCS, GFP_KERNEL);
	if (lcs->segbuf == NULL)
		return -1;

	for (i = 0; i < lcs->max_lcs; i ++) {
		struct segment_buffer *segbuf;
		struct lcs_segment_buffer lcs_se;
		struct lcs_buffer *lcs_buf;
		
		init_completion(&lcs_se.done);
		segment_buffer_entry_init(&lcs_se.segbuf_entry);
		lcs_se.segbuf_entry.rw = READ;
		lcs_se.segbuf_entry.done = lsa_lcs_uptodate_done;

		segbuf = lsa_segment_find_or_create(&conf->meta_segment,
				LCS2SEG(lcs, i),
				&lcs_se.segbuf_entry);
		wait_for_completion(&lcs_se.done);

		BUG_ON(segbuf == NULL);
		lcs->segbuf[i] = segbuf;
		
		lcs_buf = kzalloc(sizeof(*lcs_buf), GFP_KERNEL);
		if (lcs_buf == NULL)
			return -1;
		lcs_buf->page = segbuf->column[0].meta.page;
		lcs_buf->lcs = lcs;
		list_add_tail(&lcs_buf->lru, &lcs->lru);
		lcs->free_cnt ++;
	}

	return lsa_lcs_recover(lcs);
}

int
lsa_cs_exit(struct lsa_closed_segment *lcs)
{
	raid5_conf_t *conf = container_of(lcs, raid5_conf_t, lsa_closed_status);
	int i;
	for (i = 0; i < 4; i ++) {
		struct segment_buffer *segbuf = lcs->segbuf[i];
		lsa_segment_ref(segbuf);
		clear_segbuf_lcs(segbuf);
		lsa_segment_release(segbuf, 0);
	}
	while (!list_empty(&lcs->dirty)) {
		/* TODO we must flush the dirty lcs into disk */
		struct lcs_buffer *lcs_buf = container_of(lcs->dirty.next,
				struct lcs_buffer, lru);
		__lcs_buffer_free(lcs, lcs_buf);
	}
	while (!list_empty(&lcs->lru)) {
		struct lcs_buffer *lcs_buf = container_of(lcs->lru.next,
				struct lcs_buffer, lru);
		__lcs_buffer_free(lcs, lcs_buf);
	}
	kfree(lcs->segbuf);
	remove_proc_entry(LSA_LCS_STS, conf->proc);
	debug("free_cnt %d\n", lcs->free_cnt);
	return 0;
}
