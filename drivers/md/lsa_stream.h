#ifndef _LSA_STREAM__
#define _LSA_STREAM_

typedef struct lsa_stream     lsa_stream_t;
typedef struct lsa_stream_buf lsa_stream_buf_t;

typedef enum {
	LSA_DATA = 0,
	LSA_META = 1,
} lsa_stream_type_t;

typedef struct lsa_stream_key {
	lsa_stream_type_t type;
	sector_t          lba; /* sector offset */
	unsigned          len; /* sector number */
} lsa_stream_key_t;

lsa_stream_t      *lsa_stream_init    (lsa_segment_t *segment);
void               lsa_stream_exit    (lsa_stream_t *stream);

lsa_stream_buf_t  *lsa_stream_buf_new (lsa_stream_t *stream, lsa_stream_key_t *key);
const char        *lsa_stream_buf_virt(lsa_stream_buf_t *buf);
void               lsa_stream_buf_put (lsa_stream_buf_t *buf);

#endif
