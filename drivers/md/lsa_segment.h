#ifndef _LSA_SEGMENT_
#define _LSA_SEGMENT_

typedef struct lsa_segment     lsa_segment_t;
typedef struct lsa_segment_buf lsa_segment_buf_t;

typedef struct {
	struct mddev_s *t;
	unsigned int data_blocksize, meta_blocksize;
	uint32_t data_start, data_end;
	uint32_t meta_start, meta_end;
	unsigned int column;
} lsa_segment_new_t;

typedef int (*seg_buf_done_t)(struct lsa_segment_buf *buf, int error);
struct lsa_segment_buf {
	char **page;
	uint32_t seg;
	unsigned data, rw;
	seg_buf_done_t done;
};

lsa_segment_t     *lsa_segment_init  (lsa_segment_new_t *layout);
void               lsa_segment_exit  (lsa_segment_t *seg);

int                lsa_segment_rw    (lsa_segment_t *seg, lsa_segment_buf_t *buf);

#endif
