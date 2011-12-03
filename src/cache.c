#include "qp_port.h"
#include "qp_lsa.h"

typedef struct CacheTag {
	QActive super;
	
	struct list_head head;
} Cache;

static QState Cache_initial(Cache *me, QEvent const *e);
static QState Cache_final  (Cache *me, QEvent const *e);
static QState Cache_idle   (Cache *me, QEvent const *e);

static Cache l_cache;

QActive * const AO_cache = (QActive *)&l_cache;

/*..........................................................................*/
void Cache_ctor(void)
{
	Cache *me = &l_cache;
	QActive_ctor(&me->super, (QStateHandler)(Cache_initial));
	INIT_LIST_HEAD(&me->head);
}

/* HSM definition ----------------------------------------------------------*/
/*..........................................................................*/
QState Cache_initial(Cache *me, QEvent const *e)
{
	QActive_subscribe((QActive *)me, CACHE_WRITE_SIG);
	QActive_subscribe((QActive *)me, CACHE_READ_SIG);

	QS_OBJ_DICTIONARY(&l_cache);
	QS_OBJ_DICTIONARY(&l_cache.head);
	
	QS_FUN_DICTIONARY(&Cache_initial);
	QS_FUN_DICTIONARY(&Cache_final);
	QS_FUN_DICTIONARY(&Cache_idle);
	
	QS_SIG_DICTIONARY(CACHE_WRITE_SIG, &l_cache);
	QS_SIG_DICTIONARY(CACHE_READ_SIG,  &l_cache);
	
	return Q_TRAN(&Cache_idle);
}
/*..........................................................................*/
QState Cache_final(Cache *me, QEvent const *e)
{
	switch (e->sig) {
	case Q_ENTRY_SIG:
		QActive_stop(&me->super);
		return Q_HANDLED();
	}
	return Q_SUPER(&QHsm_top);
}
/*..........................................................................*/
QState Cache_idle(Cache *me, QEvent const *e)
{
	switch (e->sig) {
	case TERMINATE_SIG:
		return Q_TRAN(&Cache_final);
	}
	return Q_SUPER(&QHsm_top);
}
