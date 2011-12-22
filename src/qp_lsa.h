#ifndef _QP_LSA_H
#define _QP_LSA_H

enum QP_LSA_Signals {
	TERMINATE_SIG = Q_USER_SIG,
	
	CACHE_WRITE_REQUEST_SIG,
	CACHE_WRITE_REPLY_SIG,
	CACHE_WRITE_DONE_SIG,

	CACHE_READ_REQUEST_SIG,
	CACHE_READ_REPLY_SIG,
	CACHE_READ_DONE_SIG,

	SEG_WRITE_REQUEST_SIG,
	SEG_WRITE_REPLY_SIG,
	
	SEG_READ_REQUEST_SIG,
	SEG_READ_REPLY_SIG,
	
	MAX_PUB_SIG,

	MAX_SIG,
};

enum {
	QS_CACHE_RW = QS_USER,
	QS_BIO_REQ,
	QS_BIO_DONE,
};

void Cache_ctor(void);
void Raid5_ctor(void);

extern QActive * const AO_cache;
extern QActive * const AO_raid5;
extern QActive * const AO_segment;

typedef struct CacheRWEvtTag CacheRWEvt;
typedef struct CacheRWRlyTag CacheRWRly;

typedef struct SegmentEvtTag SegmentEvt;
typedef struct SegemtnRlyTag SegmentRly;

int  lsa_raid_init(void);
void lsa_raid_exit(void);

struct raid5_private_data;
void Track_dispatch(struct raid5_private_data *conf, QEvent const *e);

#endif
