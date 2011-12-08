#ifndef _QP_LSA_H
#define _QP_LSA_H

enum QP_LSA_Signals {
	TERMINATE_SIG = Q_USER_SIG,
	
	CACHE_RW_SIG,
	MAX_PUB_SIG,

	MAX_SIG,
};

void Cache_ctor(void);
void Raid5_ctor(void);

extern QActive * const AO_cache;
extern QActive * const AO_raid5;

typedef struct CacheRWEvtTag {
	QEvent super;
	uint32_t track;
	uint16_t offset;
	uint16_t len;
} CacheRWEvt;

int  lsa_raid_init(void);
void lsa_raid_exit(void);

#endif
