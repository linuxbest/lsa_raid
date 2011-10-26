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
	int cnt;
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
	
	lsa_root = kzalloc(sizeof(*lsa_root), GFP_KERNEL);
	if (lsa_root == NULL)
		return NULL;

	lsa_root->root = RB_ROOT;
	lsa_root->cnt = cnt;

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

static int 
lsa_test_and_set_bit(struct lsa_root *root, uint32_t ti)
{
	uint32_t offset;
	unsigned long *bitmap = lsa_bitmap(root, ti, &offset);
	return test_and_set_bit(offset, bitmap);
}

static lsa_entry_t *
lsa_rb_find_by_ti(struct lsa_root *root, uint32_t ti)
{
	struct rb_node * n = root->root.rb_node;
	lsa_entry_t * le;

	while (n) {
		le = rb_entry(n, lsa_entry_t, node);

		if (le->log_vol_id < ti)
			n = n->rb_left;
		else if (le->log_vol_id > ti)
			n = n->rb_right;
		else
			return le;
	}

	return NULL;
}

static lsa_entry_t *
__lsa_rb_insert(struct lsa_root *root, lsa_entry_t *new)
{
	struct rb_node ** p = &root->root.rb_node;
	struct rb_node * parent = NULL;
	lsa_entry_t * le;
	uint32_t ti = new->log_vol_id;

	while (*p) {
		parent = *p;
		le = rb_entry(parent, lsa_entry_t, node);

		if (le->log_vol_id < ti)
			p = &(*p)->rb_left;
		else if (le->log_vol_id > ti)
			p = &(*p)->rb_right;
		else
			return le;
	}

	rb_link_node(&new->node, parent, p);
	return NULL;
}

static lsa_entry_t *
lsa_rb_insert(struct lsa_root *root, lsa_entry_t *new)
{
	lsa_entry_t * le = __lsa_rb_insert(root, new);
	if (le)
		goto out;
	rb_insert_color(&new->node, &root->root);
out:
	return le;
}

lsa_entry_t *
lsa_find_by_ti(struct lsa_root *root, uint32_t ti)
{
	lsa_entry_t *le = NULL;
	unsigned long flags;

	spin_lock_irqsave(&root->lock, flags);

	if (root->cnt < ti && lsa_test_bit(root, ti))
		le = lsa_rb_find_by_ti(root, ti);

	spin_unlock_irqrestore(&root->lock, flags);

	return le;
}

int 
lsa_insert(struct lsa_root *root, lsa_entry_t *le)
{
	uint32_t ti = le->log_vol_id;
	unsigned long flags;
	int res = 0;

	if (root->cnt < ti)
		return -EINVAL;

	spin_lock_irqsave(&root->lock, flags);
	if (lsa_test_and_set_bit(root, ti)) 
		res = -EEXIST;
	else
		res = lsa_rb_insert(root, le) == NULL;
	spin_unlock_irqrestore(&root->lock, flags);

	return res;
}
