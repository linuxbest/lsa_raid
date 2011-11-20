#ifndef _LSA_SEGMENT_STATUS_H
#define _LSA_SEGMENT_STATUS_H

struct lsa_ss_meta {
	uint32_t data_id;
	uint32_t meta_id;
	int meta_col;
	uint32_t log_track_id;
	struct lsa_track_cookie *cookie;
};

int
lsa_ss_update(struct lsa_segment_status *ss, struct segment_buffer *segbuf);
void 
lsa_ss_commit(struct lsa_segment_status *ss);
void
lsa_ss_checkpoint(struct lsa_segment_status *ss);
int
lsa_ss_find_meta(struct lsa_segment_status *ss, struct lsa_ss_meta *meta);

	
int
lsa_ss_init(struct lsa_segment_status *ss, int seg_nr);
int
lsa_ss_exit(struct lsa_segment_status *ss);

#endif
