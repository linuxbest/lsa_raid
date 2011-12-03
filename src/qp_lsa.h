#ifndef _QP_LSA_H
#define _QP_LSA_H

enum QP_LSA_Signals {
	TERMINATE_SIG = Q_USER_SIG,
	
	CACHE_WRITE_SIG,
	CACHE_READ_SIG,

	MAX_SIG,
};

void Cache_ctor(void);

extern QActive * const AO_Cache;

#endif
