#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ctype.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/err.h>

#include "lsa.h"

struct lsa_root {
	spinlock_t lock;
	struct rb_root root;

	unsigned long **bitmap;
	uint32_t cnt, seg, mseg;
};

struct lsa_node {
	uint32_t log_vol_id;
	struct   rb_node node;
	struct   lsa_entry *next;
};

enum {
	LSA_BIT_SHIFT = PAGE_SHIFT+3,
	LSA_BIT_SIZE  = 1<<LSA_BIT_SHIFT,
	LSA_BIT_MASK  = LSA_BIT_SIZE-1,
};

struct lsa_root *
lsa_init(uint32_t cnt)
{
	struct lsa_root *lsa_root;
	int i;

	pr_debug("lsa_init: nr is %d\n", cnt);
	lsa_root = kzalloc(sizeof(*lsa_root), GFP_KERNEL);
	if (lsa_root == NULL)
		return NULL;

	lsa_root->root = RB_ROOT;
	lsa_root->cnt  = cnt;
	lsa_root->mseg = cnt;
	lsa_root->seg  = 0;

	cnt = cnt >> (PAGE_SHIFT+3);
	cnt ++;

	lsa_root->bitmap = kmalloc(sizeof(unsigned long *)*cnt, GFP_KERNEL);
	if (lsa_root->bitmap == NULL)
		return NULL;

	for (i = 0; i < cnt; i ++) {
		unsigned long *bitmap;
		bitmap = (unsigned long *)get_zeroed_page(GFP_KERNEL);
		if (bitmap == NULL)
			return NULL;
		lsa_root->bitmap[i] = bitmap;
	}

	return lsa_root;
}

static unsigned long *
lsa_bitmap(struct lsa_root *root, uint32_t ti, uint32_t *offset)
{
	uint32_t idx;
	idx    = ti >> LSA_BIT_SHIFT;
	*offset= ti & LSA_BIT_MASK;

	return root->bitmap[idx];
}

static int 
lsa_test_bit(struct lsa_root *root, uint32_t ti)
{
	uint32_t offset;
	unsigned long *bitmap = lsa_bitmap(root, ti, &offset);
	return test_bit(offset, bitmap);
}

static void
lsa_set_bit(struct lsa_root *root, uint32_t ti)
{
	uint32_t offset;
	unsigned long *bitmap = lsa_bitmap(root, ti, &offset);
	__set_bit(offset, bitmap);
}

static struct lsa_node *
lsa_rb_find_by_ti(struct lsa_root *root, uint32_t ti)
{
	struct rb_node * n = root->root.rb_node;
	struct lsa_node * le;

	while (n) {
		le = rb_entry(n, struct lsa_node, node);

		if (ti < le->log_vol_id)
			n = n->rb_left;
		else if (ti > le->log_vol_id)
			n = n->rb_right;
		else
			return le;
	}

	return NULL;
}

static struct lsa_node *
__lsa_rb_insert(struct lsa_root *root, struct lsa_node *new)
{
	struct rb_node ** p = &root->root.rb_node;
	struct rb_node * parent = NULL;
	struct lsa_node * le;
	uint32_t ti = new->log_vol_id;

	while (*p) {
		parent = *p;
		le = rb_entry(parent, struct lsa_node, node);

		if (ti < le->log_vol_id)
			p = &(*p)->rb_left;
		else if (ti > le->log_vol_id)
			p = &(*p)->rb_right;
		else
			return le;
	}

	rb_link_node(&new->node, parent, p);
	return NULL;
}

static struct lsa_node *
lsa_rb_insert(struct lsa_root *root, struct lsa_node *new)
{
	struct lsa_node * le = __lsa_rb_insert(root, new);
	if (le)
		goto out;
	rb_insert_color(&new->node, &root->root);
out:
	return le;
}

lsa_entry_t *
lsa_find_by_ti(struct lsa_root *root, uint32_t ti)
{
	struct lsa_node *node = NULL;
	unsigned long flags;

	spin_lock_irqsave(&root->lock, flags);

	if (ti < root->cnt && lsa_test_bit(root, ti))
		node = lsa_rb_find_by_ti(root, ti);

	spin_unlock_irqrestore(&root->lock, flags);

	return node ? node->next : NULL;
}

static void lsa_entry_copy(lsa_entry_t *n, lsa_entry_t *o)
{
	n->log_vol_id   = o->log_vol_id;
	n->log_track_id = o->log_track_id;
	n->seg_id       = o->seg_id;
	n->seg_column   = o->seg_column;
	n->offset       = o->offset;
	n->length       = o->length;
}

static void lsa_entry_show(lsa_entry_t *n, char *prefix)
{
	pr_debug("%s: %u, offset %d, length %d, seg %d, colum %d\n",
			prefix, n->log_vol_id, n->offset, n->length,
			n->seg_id, n->seg_column);
}

int 
lsa_insert(struct lsa_root *root, lsa_entry_t *le)
{
	uint32_t ti = le->log_vol_id;
	unsigned long flags;
	struct lsa_node *new = kzalloc(sizeof(*new), GFP_ATOMIC), *o;
	int res = 0;

	lsa_entry_show(le, "lsa_insert");
	if (new == NULL)
		return -ENOMEM;
	if (root->cnt < ti)
		return -EINVAL;

	new->log_vol_id = ti;
	new->next = le;

	spin_lock_irqsave(&root->lock, flags);
	o = lsa_rb_insert(root, new);
	if (o) {
		memcpy(o, le, sizeof(*o));
		kfree(new);
		kfree(le);
	}
	lsa_set_bit(root, ti);
	spin_unlock_irqrestore(&root->lock, flags);

	return res;
}

uint32_t
lsa_seg_alloc(struct lsa_root *root)
{
	uint32_t seg;
	unsigned long flags;
	spin_lock_irqsave(&root->lock, flags);
	seg = root->seg ++;
	spin_unlock_irqrestore(&root->lock, flags);
	return seg;
}
