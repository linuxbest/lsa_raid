#include "qp_port.h"
#include "qp_lsa.h"
#include "bsp.h"
#include "md_raid5.h"

static struct event_pool {
	void *sto;
	int pool_size;
	int event_size;
} EventPool[2];

static QEvent const *l_cacheQueueSto[64];
static QSubscrList  l_subscrSto[MAX_PUB_SIG];

int lsa_raid_init(void)
{
	int i;
	
	Cache_ctor();
	BSP_init(0, NULL);
	
	QF_init();
	
	for (i = 0; i < Q_DIM(EventPool); i++) {
		struct event_pool *ep = &EventPool[i];
		QF_poolInit(ep->sto, ep->pool_size, ep->event_size);
	}
	QF_psInit(l_subscrSto, Q_DIM(l_subscrSto));   /* init publish-subscribe */

	QS_OBJ_DICTIONARY(&EventPool[0]);
	QS_OBJ_DICTIONARY(&EventPool[1]);

	QS_SIG_DICTIONARY(TERMINATE_SIG,   0);	
	QS_SIG_DICTIONARY(CACHE_WRITE_SIG, 0);
	QS_SIG_DICTIONARY(CACHE_READ_SIG,  0);

	QActive_start(AO_cache,
		      1,
		      l_cacheQueueSto, Q_DIM(l_cacheQueueSto),
		      (void *)0, 0,
		      (QEvent *)0);
	
	QF_run();

	return 0;
}

void
lsa_raid_exit(void)
{
}
