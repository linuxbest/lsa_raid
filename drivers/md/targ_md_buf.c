#include "target.h"
#include "raid_if.h"
#include "md.h"

#define REQ_TIMEOUT (10*HZ)

#include <linux/dma-mapping.h>

enum {
	IO_INIT = 0,
	IO_REQ  = 1,
	IO_PAGE = 2,
	IO_TASK = 3,
	IO_TARG = 4,
	IO_MAP  = 5,
	IO_UNMAP= 6,
	IO_DONE = 7,
	IO_END  = 8,
};

#define targ_bio_list_for_each(bio, bl) \
	for (bio = (bl)->head; bio; bio = (struct bio *)bio->bi_bdev)

static inline void targ_bio_list_add(struct bio_list *bl, struct bio *bio)
{
	bio->bi_next = NULL;

	if (bl->tail)
		bl->tail->bi_bdev = (void *)bio;
	else
		bl->head = bio;

	bl->tail = bio;
}

static inline struct bio *targ_bio_list_pop(struct bio_list *bl)
{
	struct bio *bio = bl->head;

	if (bio) {
		bl->head = (void *)bl->head->bi_bdev;
		if (!bl->head)
			bl->tail = NULL;

		bio->bi_next = NULL;
	}

	return bio;
}

int targ_req_show(targ_req_t *req, char *data, int len)
{
	struct bio *bio;

	len += sprintf(data+len, "%s, %d, state %d, flight %d, bitmap %08lx, bi#%llu\n",
			req->rw ? "W" : "R", req->num, req->state,
			atomic_read(&req->bios_inflight), req->bios,
			req->sector);
	targ_bio_list_for_each(bio, &req->bio_list) {
		len += sprintf(data+len, " #%d, state %d/%d, %d @ bi#%llu\n",
				bio->bi_idx, bio->bi_max_vecs,
				bio->bi_phys_segments,
				bio->bi_size>>9, bio->bi_sector);
	}

	return len;
}

static int targ_buf_init(struct targ_buf *buf, int bios)
{
	int res = sg_alloc_table(&buf->sg_table, bios, GFP_ATOMIC);
	buf->nents = 0; 
	buf->sb = kmalloc(sizeof(struct stripe_buf)*bios, GFP_ATOMIC);
	return res;
}

static int _targ_buf_free(struct targ_buf *buf, int dirty)
{
	int i;
	struct stripe_buf *sb = buf->sb;
	targ_req_t *req = container_of(buf, targ_req_t, buf);
	struct mdk_personality *mdk = req->dev->t->pers;
	for (i = 0; i < buf->nents; i ++, sb ++) {
		mdk->targ_page_put(sb->sh, sb->dev);
	}
	sg_free_table(&buf->sg_table);
	kfree(buf->sb);
	return 0;
}

static void targ_bio_put(targ_req_t *req);

static int targ_page_add(mddev_t *mddev, struct bio *bio, 
		struct stripe_head *sh, struct r5dev *dev,
		struct page *page, unsigned offset)
{
	targ_req_t *req = bio->bi_private;
	int tlen = bio->bi_size;

	debug("buf %p, bi#%llu, stripe %p, tlen %04d @ %05d, %d\n",
			&req->buf, bio->bi_sector, sh, tlen>>9, 
			offset, bio->bi_idx);

	req->buf.sb[bio->bi_idx].page   = page;
	req->buf.sb[bio->bi_idx].offset = offset;
	req->buf.sb[bio->bi_idx].len    = tlen;
	req->buf.sb[bio->bi_idx].sh     = sh;
	req->buf.sb[bio->bi_idx].dev    = dev;

	req->buf.nents ++;

	WARN_ON(test_and_clear_bit(bio->bi_idx, &req->bios) == 0);
	bio->bi_max_vecs = IO_PAGE;

	targ_bio_put(req);

	return 0;
}

static void targ_buf_set_page(targ_buf_t *buf)
{
	targ_req_t *req = container_of(buf, targ_req_t, buf);
	int i, tlen = req->num << 9;
	struct stripe_buf *sb = buf->sb;
	struct scatterlist *sg = buf->sg_table.sgl;

	for (i = 0; i < buf->nents; i ++, sg = sg_next(sg), sb ++) {
		sg_set_page(sg, sb->page, sb->len, sb->offset);
		tlen -= sb->len;
	}

	WARN_ON(tlen != 0);
}

static struct kmem_cache *req_cache;
static void targ_tasklet(unsigned long data);

int req_cache_init(void)
{
	req_cache = kmem_cache_create("targ_req", sizeof(targ_req_t), 
			0, 0, NULL);
	if (!req_cache)
		return -ENOMEM;

	spin_lock_init(&target.task.lock);
	INIT_LIST_HEAD(&target.task.list);
	tasklet_init(&target.task.tasklet, targ_tasklet, (unsigned long)0);

	return 0;
}

void req_cache_exit(void)
{
	kmem_cache_destroy(req_cache);
}

static void targ_bio_init(targ_req_t *req, int bios)
{
	atomic_set(&req->bios_inflight, bios+1);
}

static void targ_bio_put(targ_req_t *req)
{
	if (atomic_dec_and_test(&req->bios_inflight)) {
		targ_buf_set_page(&req->buf);
		req->state = IO_TASK;

		spin_lock_bh(&target.task.lock);
		list_add_tail(&req->task_list, &target.task.list);
		spin_unlock_bh(&target.task.lock);

		tasklet_schedule(&target.task.tasklet);
	}
}

static void targ_bio_end_io(struct bio *bi, int error)
{
	bi->bi_max_vecs = IO_END;
	bio_put(bi);
}

static int targ_remap_req(struct mddev_s *t, struct bio *bio)
{
	return 0;
}

targ_buf_t *targ_buf_new(targ_dev_t *dev, uint64_t blknr, 
		uint16_t blks, int rw, buf_cb_t cb, void *priv)
{
	targ_req_t *req;
	struct bio *bio;
	sector_t remaining = blks;
	int bios = 0, cmds;
	sector_t len = 0;
	unsigned long flags, expiry;

	if (rw == READ) {
		dev->read_count ++;
		dev->read_sectors += blks;
	} else {
		dev->write_count ++;
		dev->write_sectors += blks;
	}

	req = kmem_cache_zalloc(req_cache, GFP_ATOMIC);
	req->dev   = dev;
	req->sector= blknr;
	req->num   = blks;
	req->rw    = rw;
	req->cb    = cb;
	req->priv  = priv;
	req->state = IO_INIT;
	req->bios  = 0;
	bio_list_init(&req->bio_list);
	req->deadline = jiffies + REQ_TIMEOUT;
	req->jiffies  = jiffies;
	expiry = round_jiffies_up(req->deadline);

	blknr += dev->start;

	spin_lock_irqsave(&dev->sess->req.lock, flags);
	if (!timer_pending(&dev->sess->req.timer) || time_before(req->deadline, 
				dev->sess->req.timer.expires)) {
		mod_timer(&dev->sess->req.timer, expiry);
	}
	cmds = dev->sess->req.cnts ++;
	list_add_tail(&req->list, &dev->sess->req.list);
	spin_unlock_irqrestore(&dev->sess->req.lock, flags);

	do {
		sector_t split_io = STRIPE_SECTORS;
		sector_t offset   = blknr;
		sector_t boundary = ((offset + split_io) & ~(split_io - 1)) - offset;
		len = min_t(sector_t, remaining, boundary);

		debug("buf %p/%d, bi#%llu, len %d, %s\n", 
				&req->buf, bios, blknr, (uint16_t)len, rw ? "W" : "R");
		bio = bio_alloc(GFP_ATOMIC, 1);
		bio->bi_rw       = rw;
		bio->bi_end_io   = targ_bio_end_io;
		bio->bi_private  = req;
		bio->bi_bdev     = NULL;
		bio->bi_sector   = blknr;
		bio->bi_flags    = (1<<BIO_UPTODATE) | (1<<BIO_REQ_BUF);
		bio->bi_next     = NULL;

		bio->bi_idx      = bios;
		bio->bi_io_vec   = NULL;
		bio->bi_size     = len << 9;

		bio->bi_phys_segments = 1;
		bio->bi_vcnt     = 1;
		bio->bi_max_vecs = IO_INIT; /* overload as state */

		targ_bio_list_add(&req->bio_list, bio);
		bios ++;
		blknr += len;
	} while (remaining -= len);

	targ_buf_init(&req->buf, bios);
	targ_bio_init(req, bios);

	req->state = IO_REQ;
	targ_bio_list_for_each(bio, &req->bio_list) {
		set_bit(bio->bi_idx, &req->bios);
		bio->bi_max_vecs = IO_REQ;
		bio_get(bio);
		dev->t->pers->targ_page_req(dev->t, bio);
	}

	targ_bio_put(req);

	return &req->buf;
}

int targ_buf_free(targ_buf_t *buf)
{
	targ_req_t *req = container_of(buf, targ_req_t, buf);
	targ_dev_t *dev = req->dev;
	unsigned long flags;
	int cmds;
	struct bio *bio;

	spin_lock_irqsave(&dev->sess->req.lock, flags);
	list_del(&req->list);
	cmds = dev->sess->req.cnts --;
	if (!list_empty(&dev->sess->req.list)) {
		targ_req_t *next = container_of(dev->sess->req.list.next, targ_req_t, list);
		if (time_before(dev->sess->req.timer.expires, next->deadline))
			mod_timer(&dev->sess->req.timer, next->deadline);
	} else {
		del_timer(&dev->sess->req.timer);
	}
	spin_unlock_irqrestore(&dev->sess->req.lock, flags);

	while ((bio = targ_bio_list_pop(&req->bio_list))) {
		bio->bi_max_vecs = IO_DONE;
		bio_put(bio);
	}

	debug("buf %p, req %p, %s, %d\n", buf, req, req->rw ? "W" : "R", cmds);
	_targ_buf_free(&req->buf, req->rw == WRITE);
	kmem_cache_free(req_cache, req);
	return 0;
}

void targ_md_buf_init(struct mddev_s *t)
{
	t->targ_page_add = targ_page_add;
	t->targ_remap_req= targ_remap_req;
}

targ_sg_t *targ_buf_map(targ_buf_t *buf, struct device *dev, int dir, int *sg_cnt)
{
	targ_req_t *req = container_of(buf, targ_req_t, buf);
	debug("buf %p, sg %p, nents %d\n", buf, buf->sg_table.sgl, buf->nents);
	req->state = IO_MAP;
	*sg_cnt = dma_map_sg(dev, buf->sg_table.sgl, buf->nents, dir);
	return buf->sg_table.sgl;
}

void targ_buf_unmap(targ_buf_t *buf, struct device *dev, int dir)
{
	targ_req_t *req = container_of(buf, targ_req_t, buf);
	req->state = IO_DONE;
	dma_unmap_sg(dev, buf->sg_table.sgl, buf->nents, dir);
}

EXPORT_SYMBOL(targ_buf_map);
EXPORT_SYMBOL(targ_buf_unmap);
EXPORT_SYMBOL(targ_buf_free);
EXPORT_SYMBOL(targ_buf_new);

void targ_req_timeout(unsigned long data)
{
	struct targ_sess *sess = (struct targ_sess *)data;
	targ_req_t *req;
	unsigned long flags;

	spin_lock_irqsave(&sess->req.lock, flags);
	del_timer(&sess->req.timer);
	list_for_each_entry(req, &sess->req.list, list) {
		targ_req_show(req, sess->buf, 0);
		printk("%s", sess->buf);
	}
	spin_unlock_irqrestore(&sess->req.lock, flags);
}

static void targ_tasklet(unsigned long data)
{
	while (!list_empty(&target.task.list)) {
		targ_req_t *req = list_entry(target.task.list.next,
				targ_req_t, task_list);
		list_del(&req->task_list);
		req->state = IO_TARG;
		req->cb(req->dev, &req->buf, req->priv, 0);
	}
}
