#define DEBUG
#include "target.h"
#include "raid_if.h"
#include "dm.h"

static int targ_buf_init(struct targ_buf *buf, int bios)
{
	int res = sg_alloc_table(&buf->sg_table, bios, GFP_ATOMIC);
	return res;
}

static int _targ_buf_free(struct targ_buf *buf)
{
	sg_free_table(&buf->sg_table);
	return 0;
}

int targ_buf_add_page(struct targ_buf *buf, struct stripe *stripe, 
		struct page *page, unsigned offset)
{
	return 0;
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
		req->cb(req->dev, &req->buf, req->priv, 0);
	}
}

static void targ_bio_end_io(struct bio *bi, int error)
{
	targ_req_t *req = bi->bi_private;
	pr_debug("bio %p, req %p\n", bi, req);
	targ_bio_put(req);
	bio_put(bi);
}

targ_buf_t *targ_buf_new(targ_dev_t *dev, uint64_t blknr, 
		uint16_t blks, int rw, buf_cb_t cb, void *priv)
{
	struct dm_target *ti = dm_table_find_target(dev->t, blknr);
	targ_req_t *req;
	struct bio *bio, *hbio = NULL, *tbio = NULL;
	sector_t remaining = blks;
	sector_t len = 0;
	int bios = 0;

	req = kmem_cache_zalloc(req_cache, GFP_ATOMIC);
	req->dev   = dev;
	req->sector= blknr;
	req->num   = blks;
	req->rw    = rw;
	req->cb    = cb;
	req->priv  = priv;

	pr_debug("buf %p, req %p, %lld, %d, %s\n", &req->buf, req, blknr, 
			blks, rw ? "W" : "R");
	do {
		sector_t max = max_io_len(NULL, blknr, ti);
		bio = bio_alloc(GFP_ATOMIC, 1);

		/* TODO bio check */
		len = min_t(sector_t, blks, max);

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
	} while (remaining -= len);

	targ_buf_init(&req->buf, bios);
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
	pr_debug("buf %p, req %p\n", buf, req);
	_targ_buf_free(&req->buf);
	kmem_cache_free(req_cache, req);
	return 0;
}

targ_sg_t *targ_buf_sg(targ_buf_t *buf, int *count)
{
	pr_debug("buf %p, sg %p, nents %d\n", buf, buf->sg_table.sgl,
			buf->nents);
	*count = buf->nents;
	return buf->sg_table.sgl;
}

EXPORT_SYMBOL(targ_buf_sg);
EXPORT_SYMBOL(targ_buf_free);
EXPORT_SYMBOL(targ_buf_new);
