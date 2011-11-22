#ifndef _LSA_CLOSED_SEGMENT_H
#define _LSA_CLOSED_SEGMENT_H

int
lsa_lcs_init(struct lsa_closed_segment *lcs);
int
lsa_lcs_exit(struct lsa_closed_segment *lcs);

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

#if 0
void lsa_lcs_commit(struct lsa_closed_segment *lcs, uint32_t seg_id, int col, uint32_t seq);
int  lsa_lcs_insert(struct lsa_closed_segment *lcs, uint32_t seg_id);
#endif

struct lcs_segment_buffer {
	struct segment_buffer_entry segbuf_entry;
	struct completion done;
};

#endif
