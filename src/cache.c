#include "qp_port.h"
#include "qp_lsa.h"
#include "md_raid5.h"

Q_DEFINE_THIS_FILE

typedef struct CacheTag {
	QActive super;
} Cache;

static QState Cache_initial(Cache *me, QEvent const *e);
static QState Cache_final  (Cache *me, QEvent const *e);
static QState Cache_idle   (Cache *me, QEvent const *e);
static QState Cache_rw     (Cache *me, QEvent const *e);

static Cache l_cache;

QActive * const AO_cache = (QActive *)&l_cache;

/*..........................................................................*/
void Cache_ctor(void)
{
	Cache *me = &l_cache;
	QActive_ctor(&me->super, (QStateHandler)(Cache_initial));
}
/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
static QState Cache_initial(Cache *me, QEvent const *e)
{
	QActive_subscribe((QActive *)me, TERMINATE_SIG);

	QS_OBJ_DICTIONARY(&l_cache);
	
	QS_FUN_DICTIONARY(&Cache_initial);
	QS_FUN_DICTIONARY(&Cache_final);
	QS_FUN_DICTIONARY(&Cache_idle);
	QS_FUN_DICTIONARY(&Cache_rw);
	
	QS_SIG_DICTIONARY(CACHE_RW_REQUEST_SIG, &l_cache);
	
	return Q_TRAN(&Cache_idle);
}
/*..........................................................................*/
static QState Cache_final(Cache *me, QEvent const *e)
{
	switch (e->sig) {
	case Q_ENTRY_SIG:
		QActive_stop(&me->super);
		return Q_HANDLED();
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
static QState Cache_idle(Cache *me, QEvent const *e)
{
	switch (e->sig) {
	case TERMINATE_SIG:
		return Q_TRAN(&Cache_final);
	case CACHE_RW_REQUEST_SIG:
		return Cache_rw(me, e);
	}
	return Q_SUPER(&QHsm_top);
}

/*..........................................................................*/
static QState Cache_rw(Cache *me, QEvent const *e)
{
	CacheRWEvt *pe = (CacheRWEvt *)e;
	CacheRWRly *re = Q_NEW(CacheRWRly, CACHE_RW_REPLY_SIG);

	QS_BEGIN(QS_CACHE_RW, QS_apObj_);
	QS_U32_HEX(8, pe->sector);
	QS_U32_HEX(8, pe->track);
	QS_U32_HEX(4, pe->offset);
	QS_U32_HEX(4, pe->len);
	QS_U32_HEX(2, pe->flags);
	QS_END();
	
	Track_dispatch(pe->rt, e);
	
	/* doing a fake bio finish */
	re->conf  = pe->conf;
	re->errno = 0;
	re->buf.bio.bi = pe->buf.bio.bi;
	QACTIVE_POST(pe->ao, (QEvent *)re, AO_cache);

	return Q_SUPER(&QHsm_top);
}
