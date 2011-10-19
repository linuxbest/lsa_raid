#include "target.h"
#include "raid_if.h"
#include "dm.h"

#include <linux/dma-mapping.h>

#define BUF_SHIFT      (16)
#define BUF_SIZE       (1<<BUF_SHIFT)
#define BUF_ORDER      (BUF_SHIFT-PAGE_SHIFT)
#define BUF_PFN_UP(x)  (((x) + BUF_SIZE-1) >> BUF_SHIFT)

static int _targ_buf_init(struct targ_buf *buf, int dlen)
{
	struct scatterlist *sg;
	int res, i = 0;

	buf->nents = BUF_PFN_UP(dlen);
	res = sg_alloc_table(&buf->sg_table, buf->nents, GFP_ATOMIC);
	sg = buf->sg_table.sgl;
	pr_debug("sg %p, %d, %d\n", sg, buf->nents, dlen);

	for (i = 0; i < buf->nents; i ++, sg = sg_next(sg)) {
		struct page *pg = alloc_pages(GFP_ATOMIC, BUF_ORDER);
		sg_set_page(sg, pg, BUF_SIZE, 0);
	}

	return 0;
}

static int _targ_buf_free(struct targ_buf *buf)
{
	struct scatterlist *sg;
	int i = 0;

	for_each_sg(buf->sg_table.sgl, sg, buf->nents, i) {
		struct page *pg = sg_page(sg);
		__free_pages(pg, BUF_ORDER);
	}
	sg_free_table(&buf->sg_table);

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

targ_buf_t *targ_buf_new(targ_dev_t *dev, uint64_t blknr, 
		uint16_t blks, int rw, buf_cb_t cb, void *priv)
{
	targ_req_t *req;
	req = kmem_cache_zalloc(req_cache, GFP_ATOMIC);
	req->dev   = dev;
	req->sector= blknr;
	req->num   = blks;
	req->rw    = rw;
	req->cb    = cb;
	req->priv  = priv;

	pr_debug("buf %p, req %p, %lld, %d, %s\n", &req->buf, req, blknr, 
			blks, rw ? "W" : "R");
	_targ_buf_init(&req->buf, blks << 9);
	cb(dev, &req->buf, priv, 0);

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
EXPORT_SYMBOL(targ_buf_sg);
EXPORT_SYMBOL(targ_buf_free);
EXPORT_SYMBOL(targ_buf_new);
