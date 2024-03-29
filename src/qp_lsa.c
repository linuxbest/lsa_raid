#include "qp_port.h"
#include "qp_lsa.h"
#include "bsp.h"
#include "md_raid5.h"

static QEvent const *l_cacheQueueSto[64];
static QEvent const *l_raid5QueueSto[64];
static QEvent const *l_segQueueSto  [64];
static QEvent const *l_dirQueueSto  [64];
static QSubscrList l_subscrSto[MAX_PUB_SIG];

union SmallEvents {
	void   *e0;
	uint8_t e1[sizeof(QEvent)];
};

union MediumEvents {
	void   *e0;
	uint8_t e1[sizeof(CacheRWEvt)];
};

static struct event_pool {
	void *sto;
	int pool_size;
	int event_size;
} EventPool[2] = {
	[0] = {
		.pool_size = 1024,
		.event_size = sizeof(union SmallEvents),
	},
	[1] = {
		.pool_size = 1024,
		.event_size = sizeof(union MediumEvents),
	},
};

int lsa_raid_init(void)
{
	int i;
	
	Cache_ctor();
	Raid5_ctor();
	
	BSP_init(0, NULL);
	
	QF_init();
	
	QF_psInit(l_subscrSto, Q_DIM(l_subscrSto));   /* init publish-subscribe */
	for (i = 0; i < Q_DIM(EventPool); i++) {
		struct event_pool *ep = &EventPool[i];
		int tlen = ep->pool_size * ep->event_size;
		ep->sto = kmalloc(tlen, GFP_KERNEL);
		QS_OBJ_DICTIONARY(ep->sto);
		QF_poolInit(ep->sto, tlen, ep->event_size);
	}

	QS_OBJ_DICTIONARY(&EventPool[0]);
	QS_OBJ_DICTIONARY(&EventPool[1]);

	QS_SIG_DICTIONARY(TERMINATE_SIG,           0);

	QActive_start(AO_dirtory,
		      1,
		      l_dirQueueSto, Q_DIM(l_dirQueueSto),
		      (void *)0, 0,
		      (QEvent *)0);
	
	QActive_start(AO_segment,
		      1,
		      l_segQueueSto, Q_DIM(l_segQueueSto),
		      (void *)0, 0,
		      (QEvent *)0);
	
	QActive_start(AO_cache,
		      2,
		      l_cacheQueueSto, Q_DIM(l_cacheQueueSto),
		      (void *)0, 0,
		      (QEvent *)0);

	QActive_start(AO_raid5,
		      3,
		      l_raid5QueueSto, Q_DIM(l_raid5QueueSto),
		      (void *)0, 0,
		      (QEvent *)0);

	QF_run();

	return 0;
}

void
lsa_raid_exit(void)
{
	int i;
	for (i = 0; i < Q_DIM(EventPool); i++) {
		struct event_pool *ep = &EventPool[i];
		kfree(ep->sto);
	}
}
