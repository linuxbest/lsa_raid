#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define PAGE_SHIFT 12
#define GFP_KERNEL 0 
#define EINVAL     -1
#define get_zeroed_page(gfp) malloc(4096)
#define spin_lock_irqsave
#define spin_unlock_irqrestore
#define kfree(x)        free(x)
#define pr_debug  printf

typedef struct {
} spinlock_t;

#include "rbtree.h"
#include "rbtree.c"

#include "../lsa_rb.c"

int main(int argc, char *argv[])
{
	lsa_root_t *root = lsa_init(65536);
	lsa_entry_t *le, *new;
	int i, idx = 0;

	for (0 ; i < 4096; i ++) {
		le = lsa_find_by_ti(root, 0);
		assert(le == NULL);
	}

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	new->log_vol_id = 1024;
	new->offset     = 32;
	new->length     = 32;
	i = lsa_insert(root, new);
	assert(i == 0);

	/* replace */
	new = kzalloc(sizeof(*new), GFP_KERNEL);
	new->log_vol_id = 1024;
	new->offset     = 32;
	new->length     = 16;
	i = lsa_insert(root, new);
	assert(i == 0);

	/* insert before */
	new = kzalloc(sizeof(*new), GFP_KERNEL);
	new->log_vol_id = 1024;
	new->offset     = 0;
	new->length     = 49;
	i = lsa_insert(root, new);
	assert(i == 0);

	printk("--DUMP--\n");
	struct rb_node *n;
	for (n = rb_first(&root->root); n; n = rb_next(n)) {
		struct lsa_node *ln = rb_entry(n, struct lsa_node, node);
		le = ln->next;
		pr_debug("ti %d, offset %d, length %d\n",
				le->log_vol_id, le->offset, le->length);
		assert(le->offset == 0);
		assert(le->length == 49);
		assert(le->next   != NULL);
		le = le->next;
		pr_debug("ti %d, offset %d, length %d\n",
				le->log_vol_id, le->offset, le->length);
		assert(le->offset == 49);
		assert(le->length == 15);
		assert(le->next   == NULL);
	}

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	new->log_vol_id = 1024;
	new->offset     = 3;
	new->length     = 4;
	i = lsa_insert(root, new);
	assert(i == 0);
	
	printk("--DUMP--\n");
	for (n = rb_first(&root->root); n; n = rb_next(n)) {
		struct lsa_node *ln = rb_entry(n, struct lsa_node, node);
		le = ln->next;
		pr_debug("ti %d, offset %d, length %d\n",
				le->log_vol_id, le->offset, le->length);
		assert(le->offset == 0);
		assert(le->length == 3);
		assert(le->next   != NULL);
		
		le = le->next;
		pr_debug("ti %d, offset %d, length %d\n",
				le->log_vol_id, le->offset, le->length);
		assert(le->offset == 3);
		assert(le->length == 4);
		assert(le->next   != NULL);
		
		le = le->next;
		pr_debug("ti %d, offset %d, length %d\n",
				le->log_vol_id, le->offset, le->length);
		assert(le->offset == 7);
		assert(le->length == 42);
		assert(le->next   != NULL);
		
		le = le->next;
		pr_debug("ti %d, offset %d, length %d\n",
				le->log_vol_id, le->offset, le->length);
		assert(le->offset == 49);
		assert(le->length == 15);
		assert(le->next   == NULL);
	}

}
