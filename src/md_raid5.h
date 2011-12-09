#ifndef _RAID5_H
#define _RAID5_H

typedef struct raid5_private_data raid5_conf_t;

int  raid5_init(void);
void raid5_exit(void);

enum {CacheRWEvt_BIO, CacheRWEvt_TGT};

struct CacheRWEvtTag {
	QEvent        super;
	uint32_t      sector;
	uint32_t      track;
	uint16_t      offset;
	uint16_t      len;
	uint8_t       flags;
#define BIO_BUF (1<<7)
#define TGT_BUF (1<<6)
	union {
		struct raid5_bio_buf {
			struct bio   *bi;
			struct page  *page;
			uint16_t      offset;
			uint16_t      length;
			struct page  *page_next;
			uint16_t      offset_next;
			uint16_t      length_next;
		} bio;
		struct {
		} tgt;
	} buf;
	raid5_conf_t *conf;
	QActive      *ao;
};
struct CacheRWRlyTag {
	QEvent  super;
	uint8_t errno;
	union {
		struct raid5_bio_reply {
			struct bio *bi;
		} bio;
	} buf;
};

#define STRIPE_SS_SHIFT         16
#define STRIPE_SHIFT            STRIPE_SS_SHIFT
#define STRIPE_SIZE             (1UL<<STRIPE_SHIFT)
#define STRIPE_SECTORS          (STRIPE_SIZE>>9)
#define STRIPE_ORDER            (STRIPE_SHIFT - PAGE_SHIFT)
#define SECTOR_SHIFT            9

#endif
