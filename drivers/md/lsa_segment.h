#ifndef _LSA_SEGMENT_H_
#define _LSA_SEGMENT_H_

enum {
	COLUMN_NULL = 0xFFFF,
	STRIPE_MASK = STRIPE_SIZE-1,
	TRACK_MAGIC   = 0xABCD0000, /* TODO */
	SEG_LCS_MAGIC = 0xABCD0001,

	SUPER_ID   = 0x0,
	DIR_SEG_ID = 0x1,     /* block size 4k */
	SS_SEG_ID  = 0x40000, /* block size 4k */
	LCS_SEG_ID = 0x70000, /* block size 4k */
	DATA_SEG_ID= 0x8000 , /* data segment block size is 64k byte */
};
/*
 * FREE: meaning the segment contains no valid data and is ready to opened.
 * OPEN: meaning the segment is available to hold logical track. 
 * CLOSING: meaning no more destage data can be futher assigned to it, and it
 *  is in the process of begin closed and writing to disk.
 * CLOSED: meaning all of data has been writen to disk.
 */
typedef enum {
	SEG_FREE    = SS_SEG_FREE,
	SEG_OPEN    = SS_SEG_OPEN,
	SEG_CLOSING = SS_SEG_CLOSING,
	SEG_CLOSED  = SS_SEG_CLOSED,
} segment_event_t;

typedef enum {
	WRITE_DONE  = 1,
	READ_DONE   = 2,
	WRITE_WANT  = 3,
} segbuf_event_t;
typedef enum {
	COLUMN_META = 0,
	COLUMN_DATA = 1,
} column_type_t;
struct column_meta {
	unsigned long  flags;
	struct bio     req;
	struct bio_vec vec;
	struct page   *page, *meta_page;
};
struct column_data {
	unsigned long  flags;
	struct bio     req;
	struct bio_vec vec[LSA_BLOCKDEPTH];
	struct page   *page[LSA_BLOCKDEPTH];
};
struct segment_buffer {
	struct rb_node   node;
	struct list_head lru_entry, active_entry, dirty_entry, write, read;
	unsigned long    flags;
	atomic_t         count, bios, pins;
	unsigned int     status, meta;
	uint32_t         seg_id;
	uint32_t         seq;
	struct lsa_segment *seg;
	sector_t         sector;

	lsa_track_buffer_t *track;
	column_type_t    type;
	/*unsigned int     depth;*/
	unsigned int     extent;
	union column {
		struct column_data data;
		struct column_meta meta;
	} column[1];
};
enum {
	SEGBUF_TREE     = 0,
	SEGBUF_UPTODATE = 1,
	SEGBUF_DIRTY    = 2,
	SEGBUF_CHECKPOINT = 3,
	SEGBUF_LCS      = 4,
	SEGBUF_LOCKED   = 5,
	SEGBUF_LRU      = 6,
};

#define SEGBUF_FNS(bit, name) \
static inline void set_segbuf_##name(struct segment_buffer *eh) \
{ \
	set_bit(SEGBUF_##bit, &eh->flags); \
} \
static inline void clear_segbuf_##name(struct segment_buffer *eh) \
{ \
	clear_bit(SEGBUF_##bit, &eh->flags); \
} \
static inline int segbuf_##name(struct segment_buffer *eh) \
{ \
	return test_bit(SEGBUF_##bit, &eh->flags); \
} \
static inline int test_set_segbuf_##name(struct segment_buffer *eh) \
{ \
	return test_and_set_bit(SEGBUF_##bit, &eh->flags); \
} \
static inline int test_clear_segbuf_##name(struct segment_buffer *eh) \
{ \
	return test_and_clear_bit(SEGBUF_##bit, &eh->flags); \
}

SEGBUF_FNS(TREE,     tree)
SEGBUF_FNS(DIRTY,    dirty)
SEGBUF_FNS(UPTODATE, uptodate)
SEGBUF_FNS(CHECKPOINT, checkpoint)
SEGBUF_FNS(LCS,      lcs)
SEGBUF_FNS(LOCKED,   locked)
SEGBUF_FNS(LRU,      lru)

struct segment_buffer_entry {
	int rw;
	int (*done)(struct segment_buffer *segbuf,
			struct segment_buffer_entry *se, int error);
	struct list_head entry;
	struct completion *comp;
};

static void inline
segment_buffer_entry_init(struct segment_buffer_entry *se)
{
	INIT_LIST_HEAD(&se->entry);
}

void 
lsa_segment_buffer_chain(struct segment_buffer *segbuf,
		struct segment_buffer_entry *se);
int 
lsa_segment_init(struct lsa_segment *seg, int disks, int nr, int shift,
		struct raid5_private_data *conf, int meta);
int
lsa_segment_exit(struct lsa_segment *seg, int disks);
int
lsa_segment_release(struct segment_buffer *segbuf, segbuf_event_t type);

static int inline
lsa_segment_almost_full(struct lsa_segment *seg)
{
	return seg->free_cnt < (seg->total_cnt/8);
}
static void inline
lsa_segment_ref(struct segment_buffer *segbuf)
{
	atomic_inc(&segbuf->count);
}

struct segment_buffer *
lsa_segment_find_or_create(struct lsa_segment *seg, uint32_t seg_id,
		struct segment_buffer_entry *se);
char *lsa_segment_meta_buf_addr(struct segment_buffer *segbuf, int offset, int *len);
int   lsa_segment_dirty(struct lsa_segment *seg, struct segment_buffer *segbuf);
int   lsa_segment_event(struct segment_buffer *segbuf, segment_event_t type);

#endif
