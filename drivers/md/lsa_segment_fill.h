#ifndef _LSA_SEGMENT_FILL_H_
#define _LSA_SEGMENT_FILL_H_

struct lsa_segfill_meta {
	uint32_t meta;
	int col;
	uint32_t lba;
	int (*callback)(struct lsa_segfill_meta *meta, lsa_track_entry_t *n);
	void *data;
	raid5_conf_t *conf;
	unsigned long *bitmap;
};

int
lsa_segment_fill_init(struct lsa_segment_fill *segfill);
int
lsa_segment_fill_exit(struct lsa_segment_fill *segfill);

int
lsa_segfill_find_meta(struct lsa_segment_fill *segfill, 
		struct lsa_segfill_meta *meta);
int
lsa_segment_fill_write(struct lsa_segment_fill *segfill,
		struct lsa_bio *bi, uint32_t log_track_id);
int 
__lsa_segment_write_put(struct segment_buffer *segbuf);


#endif
