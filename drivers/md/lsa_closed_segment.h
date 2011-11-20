#ifndef _LSA_CLOSED_SEGMENT_H
#define _LSA_CLOSED_SEGMENT_H

int
lsa_cs_init(struct lsa_closed_segment *lcs);
int
lsa_cs_exit(struct lsa_closed_segment *lcs);

/*
 * LSA closed segment list 
 *
 */
typedef struct lcs_buffer {
	struct segment_buffer_entry segbuf_entry;
	struct list_head lru;
	struct lsa_closed_segment *lcs;
	struct page *page;
	lcs_ondisk_t *ondisk;
	int          seg;
} lcs_buffer_t;

void
lsa_lcs_commit(lcs_buffer_t *lb, uint32_t seg_id, int col, uint32_t seq);
void 
lsa_lcs_insert(lcs_buffer_t *lb, uint32_t seg_id);

struct lcs_segment_buffer {
	struct segment_buffer_entry segbuf_entry;
	struct completion done;
};

#endif
