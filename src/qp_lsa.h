#ifndef _QP_LSA_H
#define _QP_LSA_H

enum QP_LSA_Signals {
	TERMINATE_SIG = Q_USER_SIG,
	
	CACHE_RW_REQUEST_SIG,
	CACHE_RW_REPLY_SIG,
	
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

typedef struct CacheRWEvtTag CacheRWEvt;
typedef struct CacheRWRlyTag CacheRWRly;

int  lsa_raid_init(void);
void lsa_raid_exit(void);

struct raid5_track;
void Track_dispatch(struct raid5_track *rt, QEvent const *e);

#endif
