#ifndef _LOG_STRUCTED_ARRAY_
#define _LOG_STRUCTED_ARRAY_

typedef struct lsa_entry lsa_entry_t;

struct lsa_entry {
	uint32_t log_track_id; /* logic track address */
	uint32_t seg_id;       /* segment number */
	uint8_t  seg_column;   /* 0 - N+M */
	uint8_t  age;
	uint8_t  status;       /* IDLE, GC */
	uint8_t  activity;
	uint16_t offset;       /* 0 - number of sector per segment column */
	uint16_t length;       /* 0 - number of sector per segment column */
} __attribute__ ((packed));

#endif
