#ifndef _LOG_STRUCTED_ARRAY_
#define _LOG_STRUCTED_ARRAY_

typedef struct {
	uint32_t log_track_id; /* logic track address */
	uint32_t seg_id;       /* segment number */
	uint8_t  seg_column;   /* 0 - N+M */
	uint8_t  age;
	uint8_t  status;       /* IDLE, GC */
#define DATA_PARTIAL (1<<0)
	uint8_t  activity;
	uint16_t offset;       /* 0 - number of sector per segment column */
	uint16_t length;       /* 0 - number of sector per segment column */
} __attribute__ ((packed)) lsa_entry_t;

typedef struct {
	uint32_t seq;
	uint32_t timestamp;
	uint16_t jiffies;
	uint32_t occupancy;
	uint8_t  status;
#define SS_SEG_FREE     0
#define SS_SEG_OPEN     1
#define SS_SEG_CLOSING  2
#define SS_SEG_CLOSED   3
#define SS_SEG_MASK     3
#define SS_SEG_META    (1<<7)
	uint8_t  meta;
} __attribute__ ((packed)) segment_status_t;

typedef struct {
	lsa_entry_t old;
	lsa_entry_t new;
} __attribute__ ((packed)) lsa_track_entry_t;

typedef struct {
	uint32_t magic;
	uint32_t sum;
	uint16_t total;
	uint16_t prev_column;
	uint32_t prev_seg_id;
	uint32_t seq_id;
	uint32_t reserved;
	lsa_track_entry_t entry[0];
} __attribute__ ((packed)) lsa_track_buffer_t;

typedef struct {
	uint32_t magic;
	uint32_t total;
	uint32_t sum;
	uint32_t timestamp;
	uint16_t jiffies;
	uint8_t  reserved[2];
	uint16_t meta_column; /* last segment dirtory col */
	uint32_t meta_seg_id; /* last segment information id */
	uint32_t seq_id;
	uint32_t seg[0];
} __attribute__ ((packed)) lcs_ondisk_t;

#endif
