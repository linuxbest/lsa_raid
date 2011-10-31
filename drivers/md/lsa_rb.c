#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ctype.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/err.h>

#include "target.h"
#include "lsa.h"

/*
 * as 64k block size.
 *
 * 1T
 *  strip  16,777,216 
 *  bitmap  2,097,152 byte
 *  table 268,435,456 byte
 *
 */
struct lsa_root {
	spinlock_t lock;
	meta_page_op_t ops;

	unsigned long **bitmap;
	uint32_t cnt, seg, mseg;

	struct {
		struct hlist_head *hashtbl;
		struct list_head dirty_list;
		struct list_head inactive_list;
		atomic_t active_entry;
	} entry;
	struct {
		struct list_head inactive_list;
		struct radix_tree_root root;
	} page;
};

struct lsa_buffer_head {
	uint32_t log_vol_id;
	struct hlist_node hash;
	struct list_head lru;

	struct lsa_entry *data;
	struct lsa_node *b_this_page;
};

#define NR_HASH    (PAGE_SIZE/sizeof(struct hlist_head))
#define HASH_MASK  (NR_HASH-1)
#define entry_hash(root, lba) \
	(&((root)->entry.hashtbl[((lba) >> STRIPE_SHIFT) & HASH_MASK]))

static inline void 
remove_hash(struct lsa_buffer_head *lh)
{
	hlist_del_init(&lh->hash);
}

static inline void 
insert_hash(struct lsa_root *root,  struct lsa_buffer_head *lh)
{
	struct hlist_head *hp = entry_hash(root, lh->log_vol_id);
	hlist_add_head(&lh->hash, hp);
}

static struct lsa_buffer_head *
get_free_lsa_buffer(struct lsa_root *root)
{
	struct lsa_buffer_head *lh = NULL;
	struct list_head *first;

	if (list_empty(&root->entry.inactive_list))
		goto out;
	first = root->entry.inactive_list.next;
	lh = list_entry(first, struct lsa_buffer_head, lru);
	list_del_init(first);
	remove_hash(lh);
	atomic_inc(&root->entry.active_entry);
out:
	return lh;
}

enum {
	LSA_BIT_SHIFT = PAGE_SHIFT+3,
	LSA_BIT_SIZE  = 1<<LSA_BIT_SHIFT,
	LSA_BIT_MASK  = LSA_BIT_SIZE-1,
};

struct lsa_root *
lsa_init(meta_page_op_t *ops)
{
	struct lsa_root *lsa_root;
	int i, cnt = ops->stripe_nr;

	pr_debug("lsa_init: nr is %d\n", cnt);
	lsa_root = kzalloc(sizeof(*lsa_root), GFP_KERNEL);
	if (lsa_root == NULL)
		return NULL;

	lsa_root->ops  = *ops;
	lsa_root->cnt  = cnt;
	lsa_root->mseg = cnt;
	lsa_root->seg  = 0;

	cnt = cnt >> (PAGE_SHIFT+3);
	cnt ++;

	lsa_root->bitmap = kmalloc(sizeof(unsigned long *)*cnt,
			GFP_KERNEL);
	if (lsa_root->bitmap == NULL)
		return NULL;

	for (i = 0; i < cnt; i ++) {
		unsigned long *bitmap;
		bitmap = (unsigned long *)get_zeroed_page(GFP_KERNEL);
		if (bitmap == NULL)
			return NULL;
		lsa_root->bitmap[i] = bitmap;
	}

	lsa_root->entry.hashtbl = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (lsa_root->entry.hashtbl == NULL)
		return NULL;

	INIT_LIST_HEAD(&lsa_root->entry.dirty_list);
	INIT_LIST_HEAD(&lsa_root->entry.inactive_list);
	atomic_set(&lsa_root->entry.active_entry, 0);

	for (i = 0; i < 65536; i ++) {
		struct lsa_buffer_head *lh = kzalloc(sizeof(*lh), GFP_KERNEL);
		list_add_tail(&lh->lru, &lsa_root->entry.inactive_list);
	}

	INIT_LIST_HEAD(&lsa_root->page.inactive_list);
	INIT_RADIX_TREE(&lsa_root->page.root, GFP_KERNEL);

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

lsa_entry_t *
lsa_find_by_ti(struct lsa_root *root, uint32_t ti)
{
	struct lsa_buffer_head *lh = NULL;
	unsigned long flags;

	spin_lock_irqsave(&root->lock, flags);
	if (ti < root->cnt && lsa_test_bit(root, ti))
		lh = NULL;
	spin_unlock_irqrestore(&root->lock, flags);

	return lh ? lh->data : NULL;
}

int 
lsa_insert(struct lsa_root *root, lsa_entry_t *le)
{
	struct lsa_buffer_head *lh = NULL;
	unsigned long flags;

	spin_lock_irqsave(&root->lock, flags);
	spin_unlock_irqrestore(&root->lock, flags);

	return lh ? 0 : -1;
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
