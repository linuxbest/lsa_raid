#define DEBUG

#include "target.h"
#include "raid_if.h"
#include "dm.h"
#include "dm-raid45.h"
#include <linux/dm-io.h>

static int targ_buf_init(struct targ_buf *buf, int bios, int len)
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
	for (i = 0; i < buf->nents; i ++, sb ++) {
		targ_page_put(sb->stripe, sb->page, dirty, sb->chunk);
	}
	sg_free_table(&buf->sg_table);
	kfree(buf->sb);
	return 0;
}

static void targ_bio_put(targ_req_t *req);

int targ_page_add(struct bio *bio, struct stripe *stripe, struct page *page,
		unsigned offset, struct stripe_chunk *chunk)
{
	targ_req_t *req = bio->bi_private;
	int tlen = bio->bi_size;

	debug("buf %p, stripe %p, chunk %p, pg %p, tlen %05d @ %05d, %d\n",
			&req->buf, stripe, chunk, page, tlen, offset, bio->bi_idx);

	req->buf.sb[bio->bi_idx].stripe = stripe;
	req->buf.sb[bio->bi_idx].chunk  = chunk;
	req->buf.sb[bio->bi_idx].page   = page;
	req->buf.sb[bio->bi_idx].offset = offset;

	req->buf.nents ++;

	targ_bio_put(req);

	return 0;
}

static void targ_buf_set_page(targ_buf_t *buf)
{
	int i;
	struct stripe_buf *sb = buf->sb;
	struct scatterlist *sg = buf->sg_table.sgl;

	for (i = 0; i < buf->nents; i ++, sg = sg_next(sg), sb ++) {
		sg_set_page(sg, sb->page, DM_PAGE_SIZE - sb->offset, sb->offset);
	}
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
		debug("buf %p, done\n", &req->buf);
		targ_buf_set_page(&req->buf);
		req->cb(req->dev, &req->buf, req->priv, 0);
	}
}

static void targ_bio_end_io(struct bio *bi, int error)
{
	bio_put(bi);
}

targ_buf_t *targ_buf_new(targ_dev_t *dev, uint64_t blknr, 
		uint16_t blks, int rw, buf_cb_t cb, void *priv)
{
	struct dm_target *ti = dm_table_find_target(dev->t, blknr);
	targ_req_t *req;
	struct bio *bio, *hbio = NULL, *tbio = NULL;
	sector_t remaining = blks;
	int bios = 0;
	sector_t len = 0;

	req = kmem_cache_zalloc(req_cache, GFP_ATOMIC);
	req->dev   = dev;
	req->sector= blknr;
	req->num   = blks;
	req->rw    = rw;
	req->cb    = cb;
	req->priv  = priv;

	debug("buf %p, req %p, %s, %04d @ %lld\n", &req->buf, req, 
			rw ? "W" : "R", blks, blknr);
	do {
		sector_t max = max_io_len(NULL, blknr, ti);
		len = min_t(sector_t, blks, max);

		bio = bio_alloc(GFP_ATOMIC, 1);
		bio->bi_rw = rw;
		bio->bi_end_io = targ_bio_end_io;
		bio->bi_private = req;
		bio->bi_bdev = NULL;
		bio->bi_sector = blknr;
		bio->bi_flags = (1<<BIO_UPTODATE) | (1<<BIO_REQ_BUF);
		bio->bi_next = NULL;

		bio->bi_idx = bios;
		bio->bi_io_vec = NULL;
		bio->bi_size = to_bytes(len);

		bio->bi_vcnt = 0;
		bio->bi_max_vecs = 0;

		if (!hbio)
			hbio = tbio = bio;
		else
			tbio = tbio->bi_next = bio;

		bios ++;
		blknr += len;
		blks  -= len;
	} while (remaining -= len);

	targ_buf_init(&req->buf, bios, blks<<9);
	targ_bio_init(req, bios);

	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		dm_raid45_req_queue(ti, bio);
	}

	targ_bio_put(req);

	return &req->buf;
}

int targ_buf_free(targ_buf_t *buf)
{
	targ_req_t *req = container_of(buf, targ_req_t, buf);
	debug("buf %p, req %p, %s\n", buf, req, req->rw ? "W" : "R");
	_targ_buf_free(&req->buf, req->rw == WRITE);
	kmem_cache_free(req_cache, req);
	return 0;
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
