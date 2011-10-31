#ifndef _LOG_STRUCTED_ARRAY_
#define _LOG_STRUCTED_ARRAY_

typedef struct lsa_root  lsa_root_t;
typedef struct lsa_entry lsa_entry_t;

typedef struct meta_page_op {
	struct mddev_s *mddev;
	unsigned int stripe_nr, disks;
	int (*read_page)  (struct mddev_s *mddev, int strip,  struct page  *page);
	int (*write_page) (struct mddev_s *mddev, int stripe, struct page **page);
} meta_page_op_t;

struct lsa_entry {
	uint32_t log_vol_id;   /* logic track address */
	uint32_t log_track_id; /* segment number */
	uint8_t  seg_id;       /* segment id */
	uint8_t  seg_column;   /* 0 - N+M */
	uint8_t  offset;       /* 0 - number of sector per segment column */
	uint8_t  length;       /* 0 - number of sector per segment column */
	uint8_t  age;
	uint8_t  status;       /* IDLE, GC */
	uint16_t activity;
};


lsa_root_t  *lsa_init       (struct meta_page_op *ops);
lsa_entry_t *lsa_find_by_ti (lsa_root_t *, uint32_t ti);
int          lsa_insert     (lsa_root_t *, lsa_entry_t *le);

uint32_t     lsa_seg_alloc  (lsa_root_t *);

#endif
