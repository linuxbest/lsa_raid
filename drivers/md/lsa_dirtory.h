#ifndef _LSA_DIRTORY_H_
#define _LSA_DIRTORY_H_

struct entry_buffer {
	struct segment_buffer_entry segbuf_entry;
	struct rb_node node;
	struct list_head lru, cookie;
	atomic_t count;
	struct lsa_dirtory *dir;
	unsigned long flags;
	lsa_entry_t e;
};
#define ENTRY_HEAD_SIZE (16*1024*1024)
#define ENTRY_HEAD_NR   (ENTRY_HEAD_SIZE/sizeof(struct entry_buffer))

#define EH_TREE     0
#define EH_DIRTY    1
#define EH_UPTODATE 2
#define EH_LRU      3

#define ENTRY_FNS(bit, name) \
static inline void set_entry_##name(struct entry_buffer *eh) \
{ \
	set_bit(EH_##bit, &eh->flags); \
} \
static inline void clear_entry_##name(struct entry_buffer *eh) \
{ \
	clear_bit(EH_##bit, &eh->flags); \
} \
static inline int entry_##name(struct entry_buffer *eh) \
{ \
	return test_bit(EH_##bit, &eh->flags); \
} \
static inline int test_set_entry_##name(struct entry_buffer *eh) \
{ \
	return test_and_set_bit(EH_##bit, &eh->flags); \
} \
static inline int test_clear_entry_##name(struct entry_buffer *eh) \
{ \
	return test_and_clear_bit(EH_##bit, &eh->flags); \
}

ENTRY_FNS(TREE,     tree)
ENTRY_FNS(DIRTY,    dirty)
ENTRY_FNS(UPTODATE, uptodate)
ENTRY_FNS(LRU,      lru)

#define lsa_entry_dump(s, x) \
do { \
	debug(s " lba %x, segid %x, col %d, off %03d, len %d, sts %x\n", \
		x->log_track_id, x->seg_id, x->seg_column, \
			x->offset, x->length, x->status); \
} while (0)

/* TODO 
 * packed data into cookie */
typedef struct {
	uint32_t seg_id;
	uint8_t  seg_col;
	uint8_t  status;
	uint16_t offset;
	uint16_t length;
} lsa_read_buf_t;

typedef struct lsa_track_cookie {
	struct list_head       entry;
	struct lsa_track       *track;
	lsa_track_entry_t      *lt;
	struct entry_buffer    *eb;
	void (*done)(struct lsa_track_cookie *);
	struct completion      *comp;
	struct rb_root          tree;
	raid5_conf_t           *conf;
	struct lsa_bio         *lsa_bio;
	lsa_read_buf_t          lrb;
} lsa_track_cookie_t;

void 
lsa_dirtory_commit(struct lsa_dirtory *dir);
void
lsa_dirtory_checkpoint(struct lsa_dirtory *dir);
int
lsa_entry_find_or_create(struct lsa_dirtory *dir, uint32_t log_track_id,
		lsa_track_cookie_t *cookie);
void
lsa_entry_dirty(struct lsa_dirtory *dir, struct entry_buffer *eh);
void
lsa_entry_put(struct lsa_dirtory *dir, struct entry_buffer *eh);
int
lsa_entry_live(struct lsa_dirtory *dir, lsa_entry_t *n, int *live);

void 
lsa_seg_update(struct lsa_dirtory *dir, uint32_t seg_id);
uint32_t 
lsa_seg_alloc(struct lsa_dirtory *dir);


int
lsa_dirtory_init(struct lsa_dirtory *dir, sector_t size);
int
lsa_dirtory_exit(struct lsa_dirtory *dir);

#endif
