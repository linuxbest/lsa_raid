#include "target.h"
#include "raid_if.h"
#include "md.h"

#include <linux/dma-mapping.h>

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

int req_cache_init(void)
{
	req_cache = kmem_cache_create("targ_req", sizeof(targ_req_t), 
			0, 0, NULL);
	if (!req_cache)
		return -ENOMEM;
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
		req->cb(req->dev, &req->buf, req->priv, 0);
	}
}

static void targ_bio_end_io(struct bio *bi, int error)
{
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
	struct bio *bio, *hbio = NULL, *tbio = NULL;
	sector_t remaining = blks;
	int bios = 0, cmds;
	sector_t len = 0;
	unsigned long flags;

	req = kmem_cache_zalloc(req_cache, GFP_ATOMIC);
	req->dev   = dev;
	req->sector= blknr;
	req->num   = blks;
	req->rw    = rw;
	req->cb    = cb;
	req->priv  = priv;

	spin_lock_irqsave(&dev->sess->req.lock, flags);
	cmds = dev->sess->req.cnts ++;
	list_add_tail(&req->list, &dev->sess->req.list);
	spin_unlock_irqrestore(&dev->sess->req.lock, flags);

	do {
		sector_t split_io = STRIPE_SECTORS;
		sector_t offset   = blknr;
		sector_t boundary = ((offset + split_io) & ~(split_io - 1)) - offset;
		len = min_t(sector_t, remaining, boundary);

		debug("buf %p, bi#%llu, len %d, %s\n", 
				&req->buf, blknr, (uint16_t)len, rw ? "W" : "R");
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

		bio->bi_vcnt     = 1;
		bio->bi_max_vecs = 1;

		if (!hbio)
			hbio = tbio = bio;
		else
			tbio = tbio->bi_next = bio;

		bios ++;
		blknr += len;
	} while (remaining -= len);

	targ_buf_init(&req->buf, bios);
	targ_bio_init(req, bios);

	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
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
	spin_lock_irqsave(&dev->sess->req.lock, flags);
	list_del(&req->list);
	cmds = dev->sess->req.cnts --;
	spin_unlock_irqrestore(&dev->sess->req.lock, flags);
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
	debug("buf %p, sg %p, nents %d\n", buf, buf->sg_table.sgl, buf->nents);
	*sg_cnt = dma_map_sg(dev, buf->sg_table.sgl, buf->nents, dir);
	return buf->sg_table.sgl;
}

void targ_buf_unmap(targ_buf_t *buf, struct device *dev, int dir)
{
	dma_unmap_sg(dev, buf->sg_table.sgl, buf->nents, dir);
}

EXPORT_SYMBOL(targ_buf_map);
EXPORT_SYMBOL(targ_buf_unmap);
EXPORT_SYMBOL(targ_buf_free);
EXPORT_SYMBOL(targ_buf_new);
